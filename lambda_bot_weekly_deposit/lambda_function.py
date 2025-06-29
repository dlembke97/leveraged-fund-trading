import os
import logging
from alpaca.broker.client import BrokerClient
from alpaca.broker.requests import CreateACHTransferRequest  # for ACH deposits
from alpaca.broker.enums import TransferDirection, TransferTiming


# ─── CONFIG ─────────────────────────────────────────────────────────────
API_KEY = os.getenv("APCA_API_KEY_ID")
API_SECRET = os.getenv("APCA_API_SECRET_KEY")
# (Optional) If you manage multiple Alpaca accounts:
ACCOUNT_ID = os.getenv("APCA_ACCOUNT_ID", None)

DEPOSIT_AMOUNT = "375.00"  # change to your desired weekly amount

# ─── LOGGER ─────────────────────────────────────────────────────────────
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)


def make_weekly_deposit(event=None, context=None):
    broker_client = BrokerClient(API_KEY, API_SECRET, sandbox=False)

    ach_rels = broker_client.get_ach_relationships_for_account(ACCOUNT_ID)
    rel_id = ach_rels[0].id  # pick the one you want
    transfer_req = CreateACHTransferRequest(
        amount=DEPOSIT_AMOUNT,
        direction=TransferDirection.DEPOSIT,  # “deposit” for bank→Alpaca
        timing=TransferTiming.NORMAL,
        relationship_id=rel_id,
    )

    try:
        transfer = broker_client.create_transfer_for_account(ACCOUNT_ID, transfer_req)
        logger.info(f"Transfer requested: id={transfer.id}, status={transfer.status}")
        return {"statusCode": 200, "body": "Deposit requested"}
    except Exception as e:
        logger.error(f"Failed to create transfer: {e}", exc_info=True)


if __name__ == "__main__":
    make_weekly_deposit()
