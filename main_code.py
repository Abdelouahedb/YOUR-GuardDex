import sys
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton, QTextEdit, QMessageBox
)
from PyQt5.QtGui import QFont, QPixmap, QIcon
from PyQt5.QtCore import Qt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64
import os

# AES Helper Functions
def pad(text):
    return text + ' ' * (16 - len(text) % 16)

def unpad(text):
    return text.rstrip()

def encrypt(text, key):
    key = key.encode().ljust(32, b'\0')[:32]
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padded_text = pad(text).encode()
    encrypted = iv + encryptor.update(padded_text) + encryptor.finalize()
    return base64.b64encode(encrypted).decode()

def decrypt(encrypted_text, key):
    key = key.encode().ljust(32, b'\0')[:32]
    encrypted_data = base64.b64decode(encrypted_text)
    iv = encrypted_data[:16]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted = decryptor.update(encrypted_data[16:]) + decryptor.finalize()
    return unpad(decrypted.decode())

# Main GUI Application
class AESApp(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()
    
    def initUI(self):
        # Set window properties
        self.setWindowTitle("YOUR GuardDex")
        self.setGeometry(100, 100, 650, 500)

        # Dynamically locate the logo
        base_path = getattr(sys, '_MEIPASS', os.path.dirname(os.path.abspath(__file__)))
        logo_path = os.path.join(base_path, 'logo.png')
        self.setWindowIcon(QIcon(logo_path))

        # Set the application style with Montserrat font
        self.setStyleSheet("""
            QWidget {
                background-color: #121212;
                color: #E0E0E0;
                font-family: 'Montserrat', 'Segoe UI', sans-serif;
            }
            QLabel {
                color: #E0E0E0;
            }
            QTextEdit, QLineEdit {
                background-color: #1D1D1D;
                color: #D0D0D0;
                border: 1px solid #2A2A2A;
                border-radius: 6px;
                padding: 10px;
                font-size: 13px;
                selection-background-color: #3D0000;
            }
            QTextEdit:focus, QLineEdit:focus {
                border: 1px solid #880000;
            }
            QPushButton {
                border-radius: 6px;
                padding: 10px;
                font-size: 13px;
                font-weight: bold;
            }
            QPushButton:hover {
                border: 1px solid #CC0000;
            }
        """)

        # Main layout
        main_layout = QVBoxLayout()
        main_layout.setSpacing(15)
        main_layout.setContentsMargins(25, 25, 25, 25)

        # Header layout with logo on the side
        header_layout = QHBoxLayout()
        
        # Logo
        logo_label = QLabel()
        pixmap = QPixmap(logo_path)
        if pixmap.isNull():
            print(f"Error: Unable to load {logo_path}")
        else:
            # Scale the logo to a larger size (e.g., 150x150)
            logo_label.setPixmap(pixmap.scaled(250, 250, Qt.KeepAspectRatio, Qt.SmoothTransformation))
        logo_label.setAlignment(Qt.AlignCenter)  # Center the logo
        main_layout.addWidget(logo_label)

        main_layout.addLayout(header_layout)

        # Text Input
        input_label = QLabel("Enter Text:")
        input_label.setStyleSheet("color: #909090; font-size: 12px; margin-left: 5px;")
        main_layout.addWidget(input_label)
        
        self.text_input = QTextEdit()
        self.text_input.setPlaceholderText("Enter text here...")
        main_layout.addWidget(self.text_input)

        # Key Input
        key_label = QLabel("Enter Key:")
        key_label.setStyleSheet("color: #909090; font-size: 12px; margin-left: 5px;")
        main_layout.addWidget(key_label)
        
        self.key_input = QLineEdit()
        self.key_input.setPlaceholderText("Enter key here...")
        self.key_input.setEchoMode(QLineEdit.Password)
        main_layout.addWidget(self.key_input)

        # Button Layout
        button_layout = QHBoxLayout()
        button_layout.setSpacing(15)

        # Encrypt Button
        encrypt_button = QPushButton("ENCRYPT")
        encrypt_button.setStyleSheet("""
            background-color: #9B1C31;
            color: #FFFFFF;
            padding: 10px;
            border-radius: 6px;
            font-weight: bold;
            font-size: 13px;
        """)
        encrypt_button.clicked.connect(self.encrypt_text)
        button_layout.addWidget(encrypt_button)

        # Decrypt Button
        decrypt_button = QPushButton("DECRYPT")
        decrypt_button.setStyleSheet("""
            background-color: #1E1E1E;
            color: #C41E3A;
            padding: 10px;
            border-radius: 6px;
            font-weight: bold;
            font-size: 13px;
            border: 1px solid #2A2A2A;
        """)
        decrypt_button.clicked.connect(self.decrypt_text)
        button_layout.addWidget(decrypt_button)
        
        main_layout.addLayout(button_layout)

        # Output Area
        result_label = QLabel("Result:")
        result_label.setStyleSheet("color: #909090; font-size: 12px; margin-left: 5px;")
        main_layout.addWidget(result_label)
        
        self.result_output = QTextEdit()
        self.result_output.setReadOnly(True)
        self.result_output.setPlaceholderText("Result will appear here...")
        main_layout.addWidget(self.result_output)

        self.setLayout(main_layout)
    
    def encrypt_text(self):
        text = self.text_input.toPlainText()
        key = self.key_input.text()
        if not text or not key:
            QMessageBox.warning(self, "Input Error", "Please provide both text and key.")
            return
        try:
            encrypted = encrypt(text, key)
            self.result_output.setPlainText(encrypted)
            self.result_output.setStyleSheet("background-color: #1D1D1D; color: #C41E3A;")
        except Exception as e:
            QMessageBox.critical(self, "Error", "Something went wrong !!!")

    def decrypt_text(self):
        encrypted_text = self.text_input.toPlainText()
        key = self.key_input.text()
        if not encrypted_text or not key:
            QMessageBox.warning(self, "Input Error", "Please provide both encrypted text and key.")
            return
        try:
            decrypted = decrypt(encrypted_text, key)
            self.result_output.setPlainText(decrypted)
            self.result_output.setStyleSheet("background-color: #1D1D1D; color: #50C878;")
        except Exception as e:
            QMessageBox.critical(self, "Error", "Check the key and try again.")

# Run the Application
if __name__ == "__main__":
    app = QApplication(sys.argv)
    
    aes_app = AESApp()
    aes_app.show()
    sys.exit(app.exec_())
