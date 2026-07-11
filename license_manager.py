import secrets
import smtplib
import json
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
import os

SMTP_SERVER = os.getenv("SMTP_SERVER", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", 587))
SMTP_USERNAME = os.getenv("SMTP_EMAIL")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")
FROM_EMAIL = SMTP_USERNAME

def generate_license_key(email: str, tier: str) -> str:
    prefix = "PREMIUM" if tier.lower() == "premium" else "ENTERPRISE"
    random_part = secrets.token_hex(8).upper()
    return f"{prefix}-{random_part}"

def send_license_email(recipient_email: str, license_key: str, api_key: str, tier: str, expiry_date: str = "бессрочно"):
    subject = f"Ваша лицензия {tier} для API Security Scanner"
    body = f"""
Здравствуйте!

Благодарим за приобретение подписки {tier}.

Ваши ключи для доступа к приложению:

Лицензионный ключ: {license_key}
API-ключ: {api_key}
Срок действия: {expiry_date}

Сохраните их в файле settings.json (или введите в интерфейсе).

С уважением,
Команда API Security Scanner
"""
    msg = MIMEMultipart()
    msg["From"] = FROM_EMAIL
    msg["To"] = recipient_email
    msg["Subject"] = subject
    # Явно указываем кодировку UTF-8 для тела письма
    msg.attach(MIMEText(body, "plain", "utf-8"))

    lic_content = json.dumps({
        "license_key": license_key,
        "api_key": api_key,
        "tier": tier,
        "expiry": expiry_date
    }, indent=2)

    part = MIMEBase("application", "octet-stream")
    part.set_payload(lic_content.encode("utf-8"))
    encoders.encode_base64(part)
    part.add_header(
        "Content-Disposition",
        f"attachment; filename=license_{license_key[:8]}.lic"
    )
    msg.attach(part)

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USERNAME, SMTP_PASSWORD)
            server.send_message(msg)
        return True
    except Exception as e:
        print(f"Ошибка отправки письма: {e}")
        return False
