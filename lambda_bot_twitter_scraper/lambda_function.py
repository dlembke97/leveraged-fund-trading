import os
import re
import boto3
import requests
from botocore.exceptions import ClientError
from boto3.dynamodb.conditions import Attr

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

TWEET_LINK_RE = re.compile(r'<a[^>]+href="/[A-Za-z0-9_]+/status/(\d+)"', re.IGNORECASE)
TIME_RE = re.compile(r'<time datetime="([^"]+)"', re.IGNORECASE)
CONTENT_RE = re.compile(
    r'<div class="tweet-content[^"]*">(.*?)</div>', re.IGNORECASE | re.DOTALL
)


def extract_tickers(text: str) -> list[str]:
    """Return uppercase tickers found via $TICKER syntax."""
    return [m.group(1).upper() for m in TICKER_RE.finditer(text)]


def classify_tweet(text: str) -> str:
    """
    Keyword-based classification:
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


def fetch_html_items(handle: str, since_id: str | None) -> list[dict]:
    """
    1) GET https://nitter.net/<handle> (HTML page).
    2) Find all tweet IDs via regex on <a href="/<user>/status/<ID>">
    3) For each ID > since_id:
         • Extract a preview of the text from <div class="tweet-content">
         • Extract the <time datetime="..."> as pub_date
    4) Return sorted list (oldest first) of {tweet_id, pub_date, text}
    """
    url = f"https://nitter.net/{handle}"
    try:
        resp = requests.get(url, timeout=10, headers={"User-Agent": "Mozilla/5.0"})
        resp.raise_for_status()
    except Exception as e:
        print(f"[ERROR] Failed to GET HTML for {handle}: {e}")
        return []

    html = resp.text

    # 1) Find all tweet IDs in order of appearance (newest→oldest)
    all_ids = TWEET_LINK_RE.findall(html)
    if not all_ids:
        return []

    # Deduplicate while preserving order
    seen = set()
    unique_ids = []
    for tid in all_ids:
        if tid not in seen:
            seen.add(tid)
            unique_ids.append(tid)

    items = []
    for tid in unique_ids:
        # Skip if <= since_id
        if since_id:
            if len(tid) == len(since_id):
                if tid <= since_id:
                    continue
            else:
                if int(tid) <= int(since_id):
                    continue

        # 2) Extract pub_date for this tweet (search near the <a href> occurrence)
        snippet_start = html.find(f"/status/{tid}")
        pub_date = ""
        if snippet_start != -1:
            window = html[snippet_start : snippet_start + 200]
            m_time = TIME_RE.search(window)
            if m_time:
                pub_date = m_time.group(1)  # ISO-8601 string

        # 3) Extract a short “text” preview (strip tags from tweet-content)
        text = ""
        if snippet_start != -1:
            content_window = html[snippet_start : snippet_start + 800]
            m_content = CONTENT_RE.search(content_window)
            if m_content:
                raw_html = m_content.group(1)
                text = re.sub(r"<[^>]+>", "", raw_html).strip()

        items.append({"tweet_id": tid, "pub_date": pub_date, "text": text})

    # Reverse to get oldest→newest
    items.reverse()
    return items


def lambda_handler(event, context):
    # 1) Scan Users where twitter_config.enabled == True
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

            # Fetch new items from HTML for this handle > last_seen
            new_items = fetch_html_items(handle, last_seen)
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

            # 5) Update TweetState for this user+handle with new max_seen
            if max_seen and max_seen != last_seen:
                set_last_id(state_key, max_seen)

    return {
        "statusCode": 200,
        "body": f"Scraper completed. Total new signals written: {total_processed}",
    }
