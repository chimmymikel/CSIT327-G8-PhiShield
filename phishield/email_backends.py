"""
Custom email backend for Resend API integration.
This allows Django's send_mail to work with Resend instead of SMTP.
"""
import os
import logging
from django.core.mail.backends.base import BaseEmailBackend
from django.conf import settings

logger = logging.getLogger('phishield')

try:
    import resend
    from resend import Resend
except ImportError:
    resend = None
    Resend = None
    logger.warning("Resend package not installed. Please install it with: pip install resend")


class ResendEmailBackend(BaseEmailBackend):
    """
    Email backend that uses Resend API to send emails.
    This is compatible with Railway and other cloud platforms that block SMTP.
    """
    
    def __init__(self, fail_silently=False, **kwargs):
        super().__init__(fail_silently=fail_silently, **kwargs)
        
        if resend is None or Resend is None:
            raise ImportError("Resend package is required. Install it with: pip install resend")
        
        # Get Resend API key from environment variable
        api_key = os.getenv('RESEND_API_KEY')
        if not api_key:
            logger.error("RESEND_API_KEY environment variable is not set")
            if not fail_silently:
                raise ValueError("RESEND_API_KEY environment variable is required")
        
        # Initialize Resend client
        self.resend_client = Resend(api_key=api_key)
        
        # Get from email from settings or environment
        self.from_email = getattr(settings, 'DEFAULT_FROM_EMAIL', None) or os.getenv('RESEND_FROM_EMAIL')
        if not self.from_email:
            logger.warning("DEFAULT_FROM_EMAIL or RESEND_FROM_EMAIL not set. Using default.")
            self.from_email = 'onboarding@resend.dev'  # Resend default
    
    def send_messages(self, email_messages):
        """
        Send one or more EmailMessage objects and return the number of emails sent.
        """
        if not email_messages:
            return 0
        
        num_sent = 0
        for message in email_messages:
            try:
                # Extract email data
                from_email = message.from_email or self.from_email
                to_emails = message.to
                subject = message.subject
                
                # Get email body
                if message.body:
                    body = message.body
                else:
                    # If no plain text body, try to get from alternatives
                    body = ""
                    if message.alternatives:
                        for content, mimetype in message.alternatives:
                            if mimetype == 'text/plain':
                                body = content
                                break
                
                # Prepare email parameters for Resend API
                # Resend accepts a single email string or a list of emails
                recipient = to_emails if to_emails else [getattr(settings, 'CONTACT_EMAIL', 'phishield001@gmail.com')]
                if isinstance(recipient, str):
                    recipient = [recipient]
                
                params = {
                    "from": from_email,
                    "to": recipient,
                    "subject": subject,
                    "text": body,
                }
                
                # Add HTML content if available
                if message.alternatives:
                    for content, mimetype in message.alternatives:
                        if mimetype == 'text/html':
                            params["html"] = content
                            break
                
                # Send the email via Resend API
                result = self.resend_client.emails.send(params)
                
                # Check if email was sent successfully
                if result and hasattr(result, 'id'):
                    logger.info(f"Email sent successfully via Resend. ID: {result.id}")
                    num_sent += 1
                elif result and isinstance(result, dict) and 'id' in result:
                    logger.info(f"Email sent successfully via Resend. ID: {result['id']}")
                    num_sent += 1
                else:
                    logger.error(f"Failed to send email via Resend. Response: {result}")
                    if not self.fail_silently:
                        raise Exception(f"Resend API returned unexpected response: {result}")
                
            except Exception as e:
                logger.error(f"Error sending email via Resend: {e}", exc_info=True)
                if not self.fail_silently:
                    raise
        
        return num_sent

