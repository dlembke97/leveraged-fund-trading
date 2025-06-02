import os
import re
import boto3
import requests
import xml.etree.ElementTree as ET
from botocore.exceptions import ClientError
from boto3.dynamodb.conditions import Key, Attr

# ── Configuration from environment ────────────────────────────────
USERS_TABLE = os.environ["USERS_TABLE"]  # e.g. "Users"
STATE_TABLE = os.environ["STATE_TABLE"]  # "TweetState"
SIGNALS_TABLE = os.environ["SIGNALS_TABLE"]  # "TweetSignals"
AWS_REGION = os.environ.get("AWS_REGION", "us-east-2")

ddb = boto3.resource("dynamodb", region_name=AWS_REGION)
users_tbl = ddb.Table(USERS_TABLE)
state_tbl = ddb.Table(STATE_TABLE)
signals_tbl = ddb.Table(SIGNALS_TABLE)

# ── RegEx patterns ────────────────────────────────────────────────────────
TICKER_RE = re.compile(r"\$([A-Za-z]{1,5})")
BUY_WORDS = re.compile(r"\b(buy|long|accumulate|moon|bullish)\b", re.IGNORECASE)
SELL_WORDS = re.compile(r"\b(sell|short|profit|bearish)\b", re.IGNORECASE)


def extract_tickers(text: str) -> list[str]:
    """Return uppercase tickers found via $TICKER syntax."""
    return [m.group(1).upper() for m in TICKER_RE.finditer(text)]


def classify_tweet(text: str) -> str:
    """
    Keyword‐based classification:
      • If bullish keywords → "buy"
      • If bearish keywords → "sell"
      • Otherwise → "hold"
    """
    if BUY_WORDS.search(text):
        return "buy"
    if SELL_WORDS.search(text):
        return "sell"
    return "hold"


def get_last_id(state_key: str) -> str | None:
    """
    Fetch the last seen tweet_id from TweetState for a given state_key.
    state_key is of the form "{user_id}#{handle}".
    Returns None if no record exists.
    """
    try:
        resp = state_tbl.get_item(Key={"state_key": state_key})
    except ClientError as e:
        print(f"[ERROR] get_last_id: {e}")
        return None
    return resp.get("Item", {}).get("last_tweet_id")


def set_last_id(state_key: str, tweet_id: str) -> None:
    """
    Write (or overwrite) the last seen tweet_id for this state_key into TweetState.
    """
    try:
        state_tbl.put_item(Item={"state_key": state_key, "last_tweet_id": tweet_id})
    except ClientError as e:
        print(f"[ERROR] set_last_id: {e}")


def fetch_rss_for_handle(handle: str, since_id: str | None) -> list[dict]:
    """
    1) GET https://nitter.net/<handle>/rss
    2) Parse each <item>:
       - Extract tweet_id from link (/status/<ID>)
       - If tweet_id > since_id, include it
       - Return sorted list (oldest first) of {tweet_id, pub_date, text}
    """
    rss_url = f"https://nitter.net/{handle}/rss"
    try:
        resp = requests.get(rss_url, timeout=10)
        resp.raise_for_status()
    except Exception as e:
        print(f"[ERROR] Failed to GET RSS for {handle}: {e}")
        return []

    root = ET.fromstring(resp.text)
    items = []
    for item in root.findall("./channel/item"):
        link = item.findtext("link", "")
        m = re.search(r"/status/(\d+)", link or "")
        if not m:
            continue
        tid = m.group(1)  # tweet_id as string

        # Skip if <= since_id
        if since_id:
            # Compare as strings if same length, else compare ints
            if len(tid) == len(since_id):
                if tid <= since_id:
                    continue
            else:
                if int(tid) <= int(since_id):
                    continue

        text = item.findtext("title", "").strip()
        pub_date = item.findtext("pubDate", "")
        items.append({"tweet_id": tid, "pub_date": pub_date, "text": text})

    # Sort ascending by numeric tweet_id so oldest first
    items.sort(key=lambda x: int(x["tweet_id"]))
    return items


def lambda_handler(event, context):
    # 1) Scan Users where twitter_config.enabled == True and handles list is non-empty
    try:
        resp = users_tbl.scan(FilterExpression=Attr("twitter_config.enabled").eq(True))
    except ClientError as e:
        print(f"[ERROR] Scanning Users: {e}")
        return {"statusCode": 500, "body": "Error scanning Users table"}

    users = resp.get("Items", [])

    total_processed = 0
    for user_item in users:
        user_id = user_item["user_id"]
        tcfg = user_item.get("twitter_config", {})
        handles = tcfg.get("handles", [])

        # If enabled==True but no handles, skip
        if not handles:
            continue

        # For each handle, maintain a separate state_key = "{user_id}#{handle}"
        for handle in handles:
            state_key = f"{user_id}#{handle}"
            last_seen = get_last_id(state_key)

            # Fetch new items from RSS for this handle > last_seen
            new_items = fetch_rss_for_handle(handle, last_seen)
            if not new_items:
                continue  # no new tweets for this handle

            max_seen = last_seen
            for entry in new_items:
                tid = entry["tweet_id"]
                txt = entry["text"]
                pub = entry["pub_date"]

                # Update max_seen
                if not max_seen or int(tid) > int(max_seen):
                    max_seen = tid

                # 2) Extract tickers (e.g. ["AAPL", "TSLA"])
                tickers = extract_tickers(txt)
                if not tickers:
                    continue  # skip tweets with no $TICKER

                # 3) Classify
                category = classify_tweet(txt)  # "buy"/"sell"/"hold"
                if category == "hold":
                    continue  # skip storing holds

                # 4) Write into TweetSignals
                item = {
                    "user_id": user_id,
                    "tweet_id": tid,
                    "handle": handle,
                    "pub_date": pub,
                    "text": txt,
                    "tickers": tickers,
                    "category": category,
                }
                try:
                    signals_tbl.put_item(Item=item)
                    total_processed += 1
                except ClientError as e:
                    print(
                        f"[ERROR] Writing TweetSignals for {user_id}, handle={handle}, tid={tid}: {e}"
                    )
                    # continue to next tweet

            # 5) Update TweetState for this user+handle with new max_seen
            if max_seen and max_seen != last_seen:
                set_last_id(state_key, max_seen)

    return {
        "statusCode": 200,
        "body": f"Scraper completed. Total new signals written: {total_processed}",
    }
