from dataclasses import dataclass
from django.core.mail import EmailMessage


@dataclass
class EmailData:
    subject: str
    body: str
    to: tuple[str]


class Mail:
    @staticmethod
    def send_email(data: EmailData):
        email = EmailMessage(subject=data.subject, body=data.body, to=data.to)
        email.send()
