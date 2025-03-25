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
