#!/usr/bin/env python3
import sys
from PyQt5.QtWidgets import QApplication, QLabel, QVBoxLayout, QWidget

app = QApplication(sys.argv)
window = QWidget()
window.setWindowTitle("Тест")
layout = QVBoxLayout()
label = QLabel("Привет! Если вы это видите, PyQt работает.")
layout.addWidget(label)
window.setLayout(layout)
window.resize(300, 100)
window.show()
sys.exit(app.exec_())
