from PyQt5.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QLabel, 
                             QPushButton, QMessageBox, QFrame, QApplication)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont, QClipboard
from payment import PRICING
import os

class SimplePaymentDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("💎 Оплата лицензии")
        self.setMinimumSize(700, 600)
        self.setModal(True)
        
        # Твой TON кошелек
        self.wallet_address = "EQAvlWFDxGF2lXm67y4yzC17wYKD9A0guwPkMs1gOsM__NOT"
        self.email = "mashatira@gmail.com"
        
        self.selected_plan = None
        self.selected_period = 'monthly'
        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(15)
        layout.addWidget(QLabel("<h2 style='color:#e94560; text-align:center;'>🛡️ Оплата лицензии</h2>"), alignment=Qt.AlignCenter)
        
        # Выбор плана
        plans_layout = QHBoxLayout()
        for plan, color, title in [("premium", "#f39c12", "⭐ Premium"), ("enterprise", "#9b59b6", "🚀 Enterprise")]:
            card = QFrame()
            card.setStyleSheet(f"background:#16213e; border:2px solid {color}; border-radius:10px; padding:15px;")
            c_layout = QVBoxLayout(card)
            c_layout.addWidget(QLabel(f"<b style='color:{color}; font-size:16px;'>{title}</b>"), alignment=Qt.AlignCenter)
            btn = QPushButton(f"Выбрать")
            btn.setStyleSheet(f"background-color:{color}; color:white; font-weight:bold; border-radius:5px; padding:8px;")
            btn.clicked.connect(lambda checked, p=plan, c=color: self._select_plan(p, c))
            c_layout.addWidget(btn)
            plans_layout.addWidget(card)
        layout.addLayout(plans_layout)

        # Период
        from PyQt5.QtWidgets import QComboBox
        p_layout = QHBoxLayout()
        p_layout.addWidget(QLabel("Период:"))
        self.period_combo = QComboBox()
        self.period_combo.addItems(["Ежемесячно", "Ежегодно (скидка 17%)"])
        self.period_combo.currentIndexChanged.connect(self._update_price)
        p_layout.addWidget(self.period_combo)
        layout.addLayout(p_layout)

        # Цена
        self.price_label = QLabel("Выберите план")
        self.price_label.setFont(QFont("Arial", 16, QFont.Bold))
        self.price_label.setAlignment(Qt.AlignCenter)
        self.price_label.setStyleSheet("color: #2ecc71; padding: 10px;")
        layout.addWidget(self.price_label)

        # Кнопка оплаты
        self.pay_btn = QPushButton("💰 Оплатить через TON")
        self.pay_btn.setStyleSheet("""
            QPushButton {
                background: linear-gradient(135deg, #0088cc 0%, #00a8e6 100%);
                color: white; font-size: 16px; font-weight: bold; padding: 15px; border-radius: 8px;
            }
            QPushButton:hover { background: linear-gradient(135deg, #00a8e6 0%, #0088cc 100%); }
        """)
        self.pay_btn.clicked.connect(self._show_payment_info)
        layout.addWidget(self.pay_btn)
        
        cancel_btn = QPushButton("Отмена")
        cancel_btn.clicked.connect(self.reject)
        layout.addWidget(cancel_btn)

        # Инфо
        info_label = QLabel("🔹 TON (The Open Network)\n🔹 Быстро • Низкие комиссии • Безопасно")
        info_label.setAlignment(Qt.AlignCenter)
        info_label.setStyleSheet("color: #95a5a6; font-size: 11px;")
        layout.addWidget(info_label)

    def _select_plan(self, plan, color):
        self.selected_plan = plan
        self._update_price()

    def _update_price(self):
        if not self.selected_plan:
            self.price_label.setText("Выберите план")
            return
        period = 'yearly' if self.period_combo.currentIndex() == 1 else 'monthly'
        self.selected_period = period
        prices = PRICING[self.selected_plan][period]
        amount = prices['usd']
        per_text = "месяц" if period == 'monthly' else "год"
        self.price_label.setText(f"Сумма: ${amount} / {per_text} (TON)")

    def _show_payment_info(self):
        if not self.selected_plan:
            return QMessageBox.warning(self, "Выберите план", "Пожалуйста, выберите тарифный план")
        
        period = 'yearly' if self.period_combo.currentIndex() == 1 else 'monthly'
        prices = PRICING[self.selected_plan][period]
        amount = prices['usd']
        
        # Конвертируем USD в TON (примерный курс 1 TON = $5)
        ton_amount = amount / 5.0
        
        message = f"""
        💎 Оплата лицензии {self.selected_plan.title()} ({period})
        
        💰 Сумма: {ton_amount:.2f} TON (≈ ${amount})
        
        📮 Адрес кошелька:
        {self.wallet_address}
        
         После оплаты отправьте:
        • Чек/скриншот транзакции
        • Email для лицензии
        На адрес: {self.email}
        
        ⏱️ Лицензия будет выслана в течение 24 часов
        
        Нажмите "Копировать адрес" чтобы скопировать адрес кошелька
        """
        
        msg = QMessageBox(self)
        msg.setWindowTitle("Оплата через TON")
        msg.setText(message)
        msg.setIcon(QMessageBox.Information)
        
        copy_btn = msg.addButton("📋 Копировать адрес", QMessageBox.ActionRole)
        ok_btn = msg.addButton("✅ Я оплатил(а)", QMessageBox.AcceptRole)
        cancel_btn = msg.addButton("Отмена", QMessageBox.RejectRole)
        
        msg.exec_()
        
        clicked_btn = msg.clickedButton()
        if clicked_btn == copy_btn:
            clipboard = QApplication.clipboard()
            clipboard.setText(self.wallet_address)
            QMessageBox.information(self, "Скопировано", f"Адрес скопирован:\n{self.wallet_address}")
        elif clicked_btn == ok_btn:
            QMessageBox.information(self, "Спасибо!", 
                f"После подтверждения платежа лицензия будет отправлена на ваш email.\n\n"
                f"Если у вас есть вопросы: {self.email}")

dialog = SimplePaymentDialog()
dialog.exec_()
