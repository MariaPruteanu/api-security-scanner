import os
import smtplib
from email.mime.text import MIMEText
from dotenv import load_dotenv

load_dotenv()

server = os.getenv("SMTP_SERVER")
port = int(os.getenv("SMTP_PORT"))
username = os.getenv("SMTP_EMAIL")
password = os.getenv("SMTP_PASSWORD")
from_email = username
to_email = input("Введите ваш email для теста: ")

msg = MIMEText("Тест SMTP – письмо от API Security Scanner", "plain", "utf-8")
msg["Subject"] = "Тест отправки"
msg["From"] = from_email
msg["To"] = to_email

try:
    with smtplib.SMTP(server, port) as smtp:
        smtp.starttls()
        smtp.login(username, password)
        smtp.send_message(msg)
    print("✅ Письмо отправлено!")
except Exception as e:
    print(f"❌ Ошибка: {e}")
