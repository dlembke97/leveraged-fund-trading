# Shared utility functions for bots
import logging
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import json
import boto3


def setup_logger(name: str, level=logging.INFO):
    logger = logging.getLogger(name)
    logger.setLevel(level)
    if not logger.hasHandlers():
        handler = logging.StreamHandler()
        fmt = "%(asctime)s - %(levelname)s - %(name)s - %(message)s"
        handler.setFormatter(logging.Formatter(fmt))
        logger.addHandler(handler)
    return logger


def send_push(endpoint_arn, title, body):
    sns = boto3.client("sns")
    payload = {
        "default": body,
        "GCM": json.dumps({"notification": {"title": title, "body": body}}),
    }
    sns.publish(
        TargetArn=endpoint_arn, MessageStructure="json", Message=json.dumps(payload)
    )


class EmailManager:
    def __init__(self, sender_email, receiver_email, sender_password):
        self.sender_email = sender_email
        self.receiver_email = receiver_email
        self.sender_password = sender_password

    def send_trigger_alert(self, event_desc):
        subject = "Trade Trigger Alert"
        body = f"<p>{event_desc}</p>"
        msg = MIMEMultipart("alternative")
        msg["From"] = self.sender_email
        msg["To"] = self.receiver_email
        msg["Subject"] = subject
        msg.attach(MIMEText(body, "html"))
        try:
            server = smtplib.SMTP("smtp.gmail.com", 587)
            server.starttls()
            server.login(self.sender_email, self.sender_password)
            server.sendmail(self.sender_email, self.receiver_email, msg.as_string())
            server.quit()
        except Exception as e:
            logger = logging.getLogger(__name__)
            logger.error(f"Failed to send email: {e}")
