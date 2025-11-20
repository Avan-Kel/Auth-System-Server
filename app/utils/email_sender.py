# app/utils/email_sender.py
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
from app.core.config import settings
import ssl
import certifi
import urllib3

# Create a verified SSL context using certifi
ssl_context = ssl.create_default_context(cafile=certifi.where())
http = urllib3.PoolManager(ssl_context=ssl_context)

def send_email(to_email: str, subject: str, html_content: str):
    message = Mail(
        from_email=settings.EMAIL_FROM,
        to_emails=to_email,
        subject=subject,
        html_content=html_content,
    )

    sg = SendGridAPIClient(settings.SENDGRID_API_KEY)

    # Explicitly pass the PoolManager with verified SSL
    response = sg.client.mail.send.post(
        request_body=message.get(),
        _pool_manager=http
    )

    return response.status_code
