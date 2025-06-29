import os
import logging
from alpaca.trading.client import TradingClient
from alpaca.trading.requests import CreateTransferRequest
from alpaca.trading.enums import TransferDirection

# ─── CONFIG ─────────────────────────────────────────────────────────────
API_KEY = os.getenv("APCA_API_KEY_ID")
API_SECRET = os.getenv("APCA_API_SECRET_KEY")
# (Optional) If you manage multiple Alpaca accounts:
ACCOUNT_ID = os.getenv("APCA_ACCOUNT_ID", None)

DEPOSIT_AMOUNT = "375.00"  # change to your desired weekly amount

# ─── LOGGER ─────────────────────────────────────────────────────────────
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)


def make_weekly_deposit():
    client = TradingClient(API_KEY, API_SECRET, paper=False, account_id=ACCOUNT_ID)

    transfer_req = CreateTransferRequest(
        amount=DEPOSIT_AMOUNT,
        direction=TransferDirection.DEPOSIT,  # “deposit” for bank→Alpaca
    )

    try:
        transfer = client.transfers.create_transfer(transfer_req)
        logger.info(f"Transfer requested: id={transfer.id}, status={transfer.status}")
    except Exception as e:
        logger.error(f"Failed to create transfer: {e}", exc_info=True)


if __name__ == "__main__":
    make_weekly_deposit()
