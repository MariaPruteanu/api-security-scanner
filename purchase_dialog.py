from PyQt5.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, 
                             QComboBox, QMessageBox, QFrame, QApplication)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont
from payment import PRICING

class PurchaseDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("💎 Upgrade Plan")
        self.setMinimumSize(700, 600)
        self.setModal(True)
        self.selected_plan = None
        self.selected_period = 'monthly'
        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(15)
        layout.addWidget(QLabel("<h2 style='color:#e94560; text-align:center;'>️ Upgrade Your Plan</h2>"), alignment=Qt.AlignCenter)
        
        plans_layout = QHBoxLayout()
        for plan, color, title in [("premium", "#f39c12", "⭐ Premium"), ("enterprise", "#9b59b6", "🚀 Enterprise")]:
            card = QFrame()
            card.setStyleSheet(f"background:#16213e; border:2px solid {color}; border-radius:10px; padding:15px;")
            c_layout = QVBoxLayout(card)
            c_layout.addWidget(QLabel(f"<b style='color:{color}; font-size:16px;'>{title}</b>"), alignment=Qt.AlignCenter)
            btn = QPushButton(f"Select {title.split()[1]}")
            btn.setStyleSheet(f"background-color:{color}; color:white; font-weight:bold; border-radius:5px; padding:8px;")
            btn.clicked.connect(lambda checked, p=plan, c=color: self._select_plan(p, c))
            c_layout.addWidget(btn)
            plans_layout.addWidget(card)
        layout.addLayout(plans_layout)

        p_layout = QHBoxLayout()
        p_layout.addWidget(QLabel("Billing:"))
        self.period_combo = QComboBox()
        self.period_combo.addItems(["Monthly", "Yearly (Save 17%)"])
        self.period_combo.currentIndexChanged.connect(self._update_price)
        p_layout.addWidget(self.period_combo)
        layout.addLayout(p_layout)

        self.price_label = QLabel("Select a plan above")
        self.price_label.setFont(QFont("Arial", 16, QFont.Bold))
        self.price_label.setAlignment(Qt.AlignCenter)
        self.price_label.setStyleSheet("color: #2ecc71; padding: 10px;")
        layout.addWidget(self.price_label)

        self.pay_btn = QPushButton("💰 Pay with TON")
        self.pay_btn.setStyleSheet("""
            QPushButton {
                background: linear-gradient(135deg, #0088cc 0%, #00a8e6 100%);
                color: white; font-size: 16px; font-weight: bold; padding: 15px; border-radius: 8px;
            }
            QPushButton:hover { background: linear-gradient(135deg, #00a8e6 0%, #0088cc 100%); }
        """)
        self.pay_btn.clicked.connect(self._show_payment)
        layout.addWidget(self.pay_btn)
        
        cancel_btn = QPushButton("Cancel")
        cancel_btn.clicked.connect(self.reject)
        layout.addWidget(cancel_btn)

    def _select_plan(self, plan, color):
        self.selected_plan = plan
        self._update_price()

    def _update_price(self):
        if not self.selected_plan:
            self.price_label.setText("Select a plan above")
            return
        period = 'yearly' if self.period_combo.currentIndex() == 1 else 'monthly'
        self.selected_period = period
        prices = PRICING[self.selected_plan][period]
        amount = prices['usd']
        per_text = "month" if period == 'monthly' else "year"
        self.price_label.setText(f"Total: ${amount} / {per_text} (TON)")

    def _show_payment(self):
        if not self.selected_plan:
            return QMessageBox.warning(self, "Select Plan", "Please select a plan first")
        
        # Импортируем простой диалог
        from simple_payment import SimplePaymentDialog
        dialog = SimplePaymentDialog(self)
        dialog.selected_plan = self.selected_plan
        dialog.selected_period = self.selected_period
        dialog.period_combo.setCurrentIndex(0 if self.selected_period == 'monthly' else 1)
        dialog._update_price()
        dialog.exec_()
        self.accept()
