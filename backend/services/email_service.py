import smtplib
import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

class EmailManager:
    def __init__(self, sender_email, receiver_email, sender_password):
        self.sender_email = sender_email
        self.receiver_email = receiver_email
        self.sender_password = sender_password

    def send_email(self, subject, body, is_html=True):
        """Compose and send an email with the given subject and body."""
        msg = MIMEMultipart('alternative')
        msg['From'] = self.sender_email
        msg['To'] = self.receiver_email
        msg['Subject'] = subject

        part = MIMEText(body, 'html' if is_html else 'plain')
        msg.attach(part)
        try:
            server = smtplib.SMTP("smtp.gmail.com", 587)
            server.starttls()
            server.login(self.sender_email, self.sender_password)
            server.sendmail(self.sender_email, self.receiver_email, msg.as_string())
            server.quit()
            return "Email sent successfully!"
        except Exception as e:
            return f"Failed to send email: {e}"

    def send_trigger_alert(self, event_description):
        """Send an alert email when a trigger event occurs."""
        subject = "Trade Trigger Alert"
        timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        body = f"""
        <p>A trigger event occurred at {timestamp}.</p>
        <p><strong>Event Details:</strong> {event_description}</p>
        """
        result = self.send_email(subject, body)
        print(result)
        return result
