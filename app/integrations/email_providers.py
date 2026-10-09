"""Live email providers adapted from Ajo to the DHMIS async provider contract."""

import asyncio
import smtplib
from email.message import EmailMessage
from typing import Protocol

import httpx

from app.integrations.contracts import IntegrationFailure, MessageRequest


class ProviderContext(Protocol):
    options: dict


def required(options: dict, key: str) -> str:
    value = str(options.get(key, "")).strip()
    if not value:
        raise IntegrationFailure(f"Selected email provider is missing {key}")
    return value


class SMTPEmailProvider:
    def __init__(self, context: ProviderContext):
        self.options = context.options

    async def send(self, request: MessageRequest) -> dict:
        if request.channel != "email":
            raise IntegrationFailure("SMTP supports email messages only")
        host = required(self.options, "host")
        sender = required(self.options, "from_email")
        port = int(self.options.get("port", 587))
        username = str(self.options.get("username", ""))
        password = str(self.options.get("password", ""))
        use_tls = bool(self.options.get("use_tls", True))
        message = EmailMessage()
        message["From"] = sender
        message["To"] = request.destination
        message["Subject"] = request.subject
        message.set_content(request.body)

        def deliver():
            with smtplib.SMTP(host, port, timeout=20) as client:
                if use_tls:
                    client.starttls()
                if username:
                    client.login(username, password)
                client.send_message(message)

        try:
            await asyncio.to_thread(deliver)
        except (OSError, smtplib.SMTPException) as error:
            raise IntegrationFailure("SMTP delivery failed") from error
        return {"reference": request.idempotency_key, "status": "sent", "sandbox": False}


class MailjetEmailProvider:
    def __init__(self, context: ProviderContext):
        self.options = context.options

    async def send(self, request: MessageRequest) -> dict:
        if request.channel != "email":
            raise IntegrationFailure("Mailjet supports email messages only")
        public_key = required(self.options, "api_key")
        private_key = required(self.options, "api_secret")
        sender = required(self.options, "from_email")
        payload = {
            "Messages": [
                {
                    "From": {"Email": sender, "Name": self.options.get("from_name", "DHMIS")},
                    "To": [{"Email": request.destination}],
                    "Subject": request.subject,
                    "TextPart": request.body,
                    "CustomID": request.idempotency_key[:100],
                }
            ]
        }
        try:
            async with httpx.AsyncClient(timeout=20) as client:
                response = await client.post(
                    "https://api.mailjet.com/v3.1/send", json=payload, auth=(public_key, private_key)
                )
                response.raise_for_status()
        except httpx.HTTPError as error:
            raise IntegrationFailure("Mailjet delivery failed") from error
        result = response.json()
        reference = str(result.get("Messages", [{}])[0].get("To", [{}])[0].get("MessageID", ""))
        return {"reference": reference or request.idempotency_key, "status": "sent", "sandbox": False}
