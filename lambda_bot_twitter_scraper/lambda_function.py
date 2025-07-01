import os
import re
import boto3
import requests
from botocore.exceptions import ClientError
from boto3.dynamodb.conditions import Attr
from common.common_functions import EmailManager, setup_logger

# ── Configuration from environment ────────────────────────────────
USERS_TABLE = os.environ["USERS_TABLE"]  # e.g. "Users"
STATE_TABLE = os.environ["STATE_TABLE"]  # e.g. "TweetState"
SIGNALS_TABLE = os.environ["SIGNALS_TABLE"]  # e.g. "TweetSignals"
TWITTER_BEARER = os.environ["TWITTER_BEARER_TOKEN"]

ddb = boto3.resource("dynamodb")
users_tbl = ddb.Table(USERS_TABLE)
state_tbl = ddb.Table(STATE_TABLE)
signals_tbl = ddb.Table(SIGNALS_TABLE)

logger = setup_logger("lambda_bot_twitter_scraper")


def get_last_id(state_key: str) -> str | None:
    """
    Fetch the last seen tweet_id from TweetState for a given state_key.
    state_key format: "<user_id>#<twitter_user_id>".
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


def fetch_twitter_items(twitter_user_id: str, since_id: str | None) -> list[dict]:
    """
    1) GET https://api.twitter.com/2/users/:id/tweets
       • QueryParams: "tweet.fields=created_at,text", "max_results=5"
       • If since_id is provided, pass it in as ?since_id=<since_id>
    2) Return a list of { "tweet_id", "pub_date", "text" } sorted oldest→newest.
    """
    headers = {
        "Authorization": f"Bearer {TWITTER_BEARER}",
        "User-Agent": "v2UserTweetsPython",
    }
    params = {
        "max_results": 5,  # up to 5 at a time (you can bump to 100)
        "tweet.fields": "created_at,text,entities",
    }
    if since_id:
        params["since_id"] = since_id

    url = f"https://api.twitter.com/2/users/{twitter_user_id}/tweets"
    try:
        r = requests.get(url, params=params, headers=headers, timeout=10)
        r.raise_for_status()
    except Exception as e:
        print(f"[ERROR] Twitter API request failed for user {twitter_user_id}: {e}")
        return []

    data = r.json().get("data", [])
    if not data:
        return []

    # Sort ascending by numeric tweet_id so oldest→newest
    sorted_data = sorted(data, key=lambda x: int(x["id"]))
    items = []
    for tweet in sorted_data:
        items.append(
            {
                "tweet_id": tweet["id"],
                "pub_date": tweet.get("created_at", ""),
                "text": tweet.get("text", ""),
            }
        )
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
        handles = tcfg.get(
            "handles", []
        )  # now a list of {"handle": ..., "user_id": ...}

        # If enabled==True but no handles, skip
        if not handles:
            continue

        for handle_obj in handles:
            handle = handle_obj.get("handle")
            twitter_user_id = handle_obj.get("user_id")
            if not twitter_user_id:
                continue  # skip if no numeric user_id

            state_key = f"{user_id}#{twitter_user_id}"
            last_seen = get_last_id(state_key)

            # Fetch new items from Twitter API for this user > last_seen
            new_items = fetch_twitter_items(twitter_user_id, last_seen)
            if not new_items:
                continue  # no new tweets

            max_seen = last_seen
            for entry in new_items:
                tid = entry["tweet_id"]
                txt = entry["text"]
                pub = entry["pub_date"]
                cashtags = [
                    c["tag"] for c in entry.get("entities", {}).get("cashtags", [])
                ]
                print(entry)
                logger.info("Debugging entry: ", entry)
                logger.info("Debugging txt: ", txt)
                logger.info("Debugging cashtags: ", cashtags)

                tickers = cashtags
                # Update max_seen to the highest ID
                if not max_seen or int(tid) > int(max_seen):
                    max_seen = tid

                if not tickers:
                    continue  # skip tweets with no $TICKER

                # Write raw signal into TweetSignals (no classification here)
                item = {
                    "user_id": user_id,
                    "tweet_id": tid,
                    "handle": handle,
                    "pub_date": pub,
                    "text": txt,
                    "tickers": tickers,
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
