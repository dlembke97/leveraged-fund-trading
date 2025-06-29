import os
from alpaca.broker.client import BrokerClient
from alpaca.broker.requests import CreateACHTransferRequest  # for ACH deposits
from alpaca.broker.enums import TransferDirection, TransferTiming
from common.common_functions import EmailManager, setup_logger


# ─── CONFIG ─────────────────────────────────────────────────────────────
API_KEY = os.environ["APCA_API_KEY_ID"]
API_SECRET = os.environ["APCA_API_SECRET_KEY"]
# (Optional) If you manage multiple Alpaca accounts:
ACCOUNT_ID = os.environ["APCA_ACCOUNT_ID"]

DEPOSIT_AMOUNT = "375.00"  # change to your desired weekly amount

# ─── LOGGER ─────────────────────────────────────────────────────────────
logger = setup_logger("lambda_bot_weekly_deposit")


def lambda_handler(event, context):
    logger.info("FULL ENV: %s", dict(os.environ))
    # broker_client = BrokerClient(API_KEY, API_SECRET, sandbox=False)

    # ach_rels = broker_client.get_ach_relationships_for_account(ACCOUNT_ID)
    # rel_id = ach_rels[0].id  # pick the one you want
    # transfer_req = CreateACHTransferRequest(
    #     amount=DEPOSIT_AMOUNT,
    #     direction=TransferDirection.DEPOSIT,  # “deposit” for bank→Alpaca
    #     timing=TransferTiming.NORMAL,
    #     relationship_id=rel_id,
    # )

    try:
        # transfer = broker_client.create_transfer_for_account(ACCOUNT_ID, transfer_req)
        logger.info(f"Transfer requested: id={transfer.id}, status={transfer.status}")
        return {"statusCode": 200, "body": "Deposit requested"}
    except Exception as e:
        logger.error(f"Failed to create transfer: {e}", exc_info=True)
