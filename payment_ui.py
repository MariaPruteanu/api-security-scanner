import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import webbrowser
import secrets
from stripe_config import create_checkout_session
from license_manager import generate_license_key
from database import SessionLocal, User
import os

class PaymentWindow:
    def __init__(self, root):
        self.root = root
        self.root.title("Оплата лицензии API Security Scanner")
        self.root.geometry("500x450")
        self.root.resizable(False, False)

        # Заголовок
        title = ttk.Label(root, text="💳 Оплата лицензии", font=("Arial", 16, "bold"))
        title.pack(pady=10)

        # Описание тарифов
        desc = ttk.Label(root, text="Выберите тариф и введите ваш email для получения лицензии.", wraplength=400)
        desc.pack(pady=5)

        # Поле email
        ttk.Label(root, text="Ваш email:").pack(pady=(10, 2))
        self.email_entry = ttk.Entry(root, width=40)
        self.email_entry.pack(pady=2)

        # Фрейм для тарифов
        tariff_frame = ttk.LabelFrame(root, text="Тарифы", padding=10)
        tariff_frame.pack(pady=10, padx=20, fill="x")

        self.tariff_var = tk.StringVar(value="premium")

        premium_rb = ttk.Radiobutton(tariff_frame, text="Premium – 1000 руб/мес", variable=self.tariff_var, value="premium")
        premium_rb.pack(anchor="w")
        enterprise_rb = ttk.Radiobutton(tariff_frame, text="Enterprise – 5000 руб/мес", variable=self.tariff_var, value="enterprise")
        enterprise_rb.pack(anchor="w")

        # Кнопка оплаты
        self.pay_button = ttk.Button(root, text="Оплатить", command=self.start_payment)
        self.pay_button.pack(pady=15)

        # Статус
        self.status_label = ttk.Label(root, text="", foreground="blue")
        self.status_label.pack()

        # Поле для вывода ключей (при симуляции)
        self.keys_output = scrolledtext.ScrolledText(root, height=5, state="disabled", wrap="word")
        self.keys_output.pack(pady=10, padx=20, fill="x")

    def start_payment(self):
        email = self.email_entry.get().strip()
        if not email or "@" not in email or "." not in email:
            messagebox.showerror("Ошибка", "Введите корректный email")
            return

        tariff = self.tariff_var.get()
        if tariff == "premium":
            price_id = "price_premium_123"  # заглушка
        else:
            price_id = "price_enterprise_456"

        self.status_label.config(text="Обработка...")
        self.pay_button.config(state="disabled")

        try:
            checkout_url = create_checkout_session(email, price_id)
            if checkout_url.startswith("http"):
                webbrowser.open(checkout_url)
                self.status_label.config(text="Переход на страницу оплаты...")
                # В симуляции – генерируем ключи и показываем
                if not checkout_url.startswith("https://checkout.stripe.com/"):
                    # Это симуляция
                    self.simulate_payment(email, tariff)
            else:
                messagebox.showerror("Ошибка", "Не удалось создать сессию")
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось создать сессию:\n{str(e)}")
            self.status_label.config(text="")
        finally:
            self.pay_button.config(state="normal")

    def simulate_payment(self, email, tariff):
        # Генерируем лицензию и API-ключ
        license_key = generate_license_key(email, tariff)
        api_key = secrets.token_urlsafe(32)

        # Сохраняем в БД (если есть)
        try:
            db = SessionLocal()
            user = db.query(User).filter(User.email == email).first()
            if user:
                user.license_key = license_key
                user.api_key = api_key
                user.subscription_active = True
            else:
                new_user = User(
                    email=email,
                    license_key=license_key,
                    api_key=api_key,
                    subscription_active=True
                )
                db.add(new_user)
            db.commit()
            db.close()
        except Exception as e:
            print("Ошибка сохранения в БД:", e)

        # Показываем ключи в окне
        self.keys_output.config(state="normal")
        self.keys_output.delete(1.0, tk.END)
        self.keys_output.insert(tk.END, f"✅ Лицензия активирована!\n\n🔑 Лицензионный ключ: {license_key}\n🔐 API-ключ: {api_key}\n\nСохраните их для доступа к приложению.")
        self.keys_output.config(state="disabled")
        self.status_label.config(text="✅ Лицензия сгенерирована (режим симуляции)")

        # Отправка письма (если SMTP настроен)
        try:
            from license_manager import send_license_email
            if os.getenv("SMTP_EMAIL") and os.getenv("SMTP_PASSWORD"):
                send_license_email(email, license_key, api_key, tariff)
                self.status_label.config(text="✅ Письмо отправлено на ваш email")
        except Exception as e:
            print("Ошибка отправки письма:", e)

if __name__ == "__main__":
    root = tk.Tk()
    app = PaymentWindow(root)
    root.mainloop()
EOFcat > payment_ui.py <<'EOF'
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import webbrowser
import secrets
from stripe_config import create_checkout_session
from license_manager import generate_license_key
from database import SessionLocal, User
import os

class PaymentWindow:
    def __init__(self, root):
        self.root = root
        self.root.title("Оплата лицензии API Security Scanner")
        self.root.geometry("500x450")
        self.root.resizable(False, False)

        # Заголовок
        title = ttk.Label(root, text="💳 Оплата лицензии", font=("Arial", 16, "bold"))
        title.pack(pady=10)

        # Описание тарифов
        desc = ttk.Label(root, text="Выберите тариф и введите ваш email для получения лицензии.", wraplength=400)
        desc.pack(pady=5)

        # Поле email
        ttk.Label(root, text="Ваш email:").pack(pady=(10, 2))
        self.email_entry = ttk.Entry(root, width=40)
        self.email_entry.pack(pady=2)

        # Фрейм для тарифов
        tariff_frame = ttk.LabelFrame(root, text="Тарифы", padding=10)
        tariff_frame.pack(pady=10, padx=20, fill="x")

        self.tariff_var = tk.StringVar(value="premium")

        premium_rb = ttk.Radiobutton(tariff_frame, text="Premium – 1000 руб/мес", variable=self.tariff_var, value="premium")
        premium_rb.pack(anchor="w")
        enterprise_rb = ttk.Radiobutton(tariff_frame, text="Enterprise – 5000 руб/мес", variable=self.tariff_var, value="enterprise")
        enterprise_rb.pack(anchor="w")

        # Кнопка оплаты
        self.pay_button = ttk.Button(root, text="Оплатить", command=self.start_payment)
        self.pay_button.pack(pady=15)

        # Статус
        self.status_label = ttk.Label(root, text="", foreground="blue")
        self.status_label.pack()

        # Поле для вывода ключей (при симуляции)
        self.keys_output = scrolledtext.ScrolledText(root, height=5, state="disabled", wrap="word")
        self.keys_output.pack(pady=10, padx=20, fill="x")

    def start_payment(self):
        email = self.email_entry.get().strip()
        if not email or "@" not in email or "." not in email:
            messagebox.showerror("Ошибка", "Введите корректный email")
            return

        tariff = self.tariff_var.get()
        if tariff == "premium":
            price_id = "price_premium_123"  # заглушка
        else:
            price_id = "price_enterprise_456"

        self.status_label.config(text="Обработка...")
        self.pay_button.config(state="disabled")

        try:
            checkout_url = create_checkout_session(email, price_id)
            if checkout_url.startswith("http"):
                webbrowser.open(checkout_url)
                self.status_label.config(text="Переход на страницу оплаты...")
                # В симуляции – генерируем ключи и показываем
                if not checkout_url.startswith("https://checkout.stripe.com/"):
                    # Это симуляция
                    self.simulate_payment(email, tariff)
            else:
                messagebox.showerror("Ошибка", "Не удалось создать сессию")
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось создать сессию:\n{str(e)}")
            self.status_label.config(text="")
        finally:
            self.pay_button.config(state="normal")

    def simulate_payment(self, email, tariff):
        # Генерируем лицензию и API-ключ
        license_key = generate_license_key(email, tariff)
        api_key = secrets.token_urlsafe(32)

        # Сохраняем в БД (если есть)
        try:
            db = SessionLocal()
            user = db.query(User).filter(User.email == email).first()
            if user:
                user.license_key = license_key
                user.api_key = api_key
                user.subscription_active = True
            else:
                new_user = User(
                    email=email,
                    license_key=license_key,
                    api_key=api_key,
                    subscription_active=True
                )
                db.add(new_user)
            db.commit()
            db.close()
        except Exception as e:
            print("Ошибка сохранения в БД:", e)

        # Показываем ключи в окне
        self.keys_output.config(state="normal")
        self.keys_output.delete(1.0, tk.END)
        self.keys_output.insert(tk.END, f"✅ Лицензия активирована!\n\n🔑 Лицензионный ключ: {license_key}\n🔐 API-ключ: {api_key}\n\nСохраните их для доступа к приложению.")
        self.keys_output.config(state="disabled")
        self.status_label.config(text="✅ Лицензия сгенерирована (режим симуляции)")

        # Отправка письма (если SMTP настроен)
        try:
            from license_manager import send_license_email
            if os.getenv("SMTP_EMAIL") and os.getenv("SMTP_PASSWORD"):
                send_license_email(email, license_key, api_key, tariff)
                self.status_label.config(text="✅ Письмо отправлено на ваш email")
        except Exception as e:
            print("Ошибка отправки письма:", e)

if __name__ == "__main__":
    root = tk.Tk()
    app = PaymentWindow(root)
    root.mainloop()
