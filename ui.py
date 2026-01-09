from PyQt6.QtWidgets import (QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
                             QLabel, QLineEdit, QTextEdit, QPushButton, 
                             QFileDialog, QFrame)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QFont, QTextCursor
from widevine import WidevineExtractor
import re
import ast

class ExtractorThread(QThread):
    log_signal = pyqtSignal(str)
    finished = pyqtSignal(list, str)
    
    def __init__(self, wvd_path, pssh_b64, license_url, headers_dict):
        super().__init__()
        self.wvd_path = wvd_path
        self.pssh_b64 = pssh_b64
        self.license_url = license_url
        self.headers_dict = headers_dict
        
    def run(self):
        extractor = WidevineExtractor(
            self.wvd_path,
            self.pssh_b64,
            self.license_url,
            self.headers_dict
        )
        keys, error = extractor.extract_keys(self.log_signal.emit)
        self.finished.emit(keys, error)


class WidevineUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.init_ui()
        
    def init_ui(self):
        self.setWindowTitle("Widevine GUI")
        self.setMinimumSize(1000, 750)
        
        self.set_dark_theme()
        
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        main_layout = QVBoxLayout(central_widget)
        main_layout.setSpacing(15)
        main_layout.setContentsMargins(20, 20, 20, 20)
        
        title = QLabel("Widevine GUI")
        title.setFont(QFont("Segoe UI", 20, QFont.Weight.Bold))
        title.setStyleSheet("color: #00d4ff; margin-bottom: 5px;")
        main_layout.addWidget(title)
        
        divider = QFrame()
        divider.setFrameShape(QFrame.Shape.HLine)
        divider.setStyleSheet("background-color: #444;")
        main_layout.addWidget(divider)
        
        input_widget = QWidget()
        input_layout = QVBoxLayout(input_widget)
        input_layout.setSpacing(10)
        
        input_layout.addWidget(self.create_label("WVD File:"))
        wvd_layout = QHBoxLayout()
        self.wvd_input = self.create_input("")
        wvd_browse = self.create_button("Browse", self.browse_wvd, small=True)
        wvd_layout.addWidget(self.wvd_input)
        wvd_layout.addWidget(wvd_browse)
        input_layout.addLayout(wvd_layout)
        
        input_layout.addWidget(self.create_label("PSSH:"))
        self.pssh_input = self.create_input("")
        input_layout.addWidget(self.pssh_input)
        
        input_layout.addWidget(self.create_label("License Fetch (from Browser DevTools):"))
        
        self.fetch_input = QTextEdit()
        self.fetch_input.setFont(QFont("Consolas", 8))
        self.fetch_input.setMinimumHeight(150)
        self.fetch_input.setMaximumHeight(150)
        self.fetch_input.setStyleSheet("""
            QTextEdit {
                background-color: #0d1117;
                border: 2px solid #30363d;
                border-radius: 6px;
                padding: 8px;
                color: #c9d1d9;
            }
            QTextEdit:focus {
                border: 2px solid #58a6ff;
            }
        """)
        self.fetch_input.setPlaceholderText('await fetch("https://drm.examplesite.org/...");');
        input_layout.addWidget(self.fetch_input)
        
        self.extract_btn = self.create_button("Extract L3 Decryption Keys", self.extract_keys)
        self.extract_btn.setMinimumHeight(45)
        input_layout.addWidget(self.extract_btn)
        
        main_layout.addWidget(input_widget)
        
        console_widget = QWidget()
        console_layout = QVBoxLayout(console_widget)
        console_layout.setSpacing(5)
        console_layout.setContentsMargins(0, 10, 0, 0)
        
        console_label = QLabel("Console Output:")
        console_label.setFont(QFont("Segoe UI", 11, QFont.Weight.Bold))
        console_label.setStyleSheet("color: #58a6ff;")
        console_layout.addWidget(console_label)
        
        self.console_text = QTextEdit()
        self.console_text.setReadOnly(True)
        self.console_text.setFont(QFont("Consolas", 9))
        self.console_text.setMinimumHeight(150)
        self.console_text.setMaximumHeight(150)
        self.console_text.setStyleSheet("""
            QTextEdit {
                background-color: #0d1117;
                color: #00ff00;
                border: 2px solid #30363d;
                border-radius: 8px;
                padding: 10px;
            }
        """)
        console_layout.addWidget(self.console_text)
        
        main_layout.addWidget(console_widget)
        
    def parse_fetch_request(self):
        fetch_text = self.fetch_input.toPlainText().strip()
        
        if not fetch_text:
            self.log_to_console("ERROR: Fetch request is empty")
            return None, None
        
        try:
            license_url_match = re.search(r'fetch\s*\(\s*["\']([^"\']+)["\']', fetch_text)
            if not license_url_match:
                self.log_to_console("ERROR: Could not extract license URL")
                return None, None
            
            license_url = license_url_match.group(1)
            
            headers_match = re.search(r'["\']headers["\']\s*:\s*\{([^}]+(?:\{[^}]*\}[^}]*)*)\}', fetch_text, re.DOTALL)
            
            if headers_match:
                headers_str = "{" + headers_match.group(1) + "}"
                headers_str = re.sub(r'"([^"]+)"\s*:', r"'\1':", headers_str)
                headers_str = re.sub(r':\s*"([^"]*)"', r": '\1'", headers_str)
                headers_str = headers_str.replace('\n', ' ')
                headers_str = re.sub(r',\s*}', '}', headers_str)
                
                try:
                    headers_dict = ast.literal_eval(headers_str)
                    return license_url, headers_dict
                except:
                    self.log_to_console("ERROR: Failed to parse headers")
                    return None, None
            else:
                self.log_to_console("ERROR: No headers found")
                return None, None
            
        except Exception as e:
            self.log_to_console(f"ERROR: {str(e)}")
            return None, None
    
    def set_dark_theme(self):
        self.setStyleSheet("""
            QMainWindow {
                background-color: #0d1117;
            }
            QWidget {
                background-color: #161b22;
                color: #c9d1d9;
            }
        """)
        
    def create_label(self, text):
        label = QLabel(text)
        label.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
        label.setStyleSheet("color: #58a6ff; margin-top: 5px;")
        return label
        
    def create_input(self, placeholder=""):
        input_field = QLineEdit()
        input_field.setPlaceholderText(placeholder)
        input_field.setText(placeholder)
        input_field.setFont(QFont("Segoe UI", 9))
        input_field.setMinimumHeight(35)
        input_field.setStyleSheet("""
            QLineEdit {
                background-color: #0d1117;
                border: 2px solid #30363d;
                border-radius: 6px;
                padding: 6px;
                color: #c9d1d9;
            }
            QLineEdit:focus {
                border: 2px solid #58a6ff;
            }
        """)
        return input_field
        
    def create_button(self, text, callback, small=False):
        button = QPushButton(text)
        button.setFont(QFont("Segoe UI", 9 if small else 10, QFont.Weight.Bold))
        if small:
            button.setMaximumWidth(100)
        button.setMinimumHeight(35)
        button.setCursor(Qt.CursorShape.PointingHandCursor)
        button.setStyleSheet("""
            QPushButton {
                background-color: #238636;
                color: white;
                border: none;
                border-radius: 6px;
                padding: 8px;
            }
            QPushButton:hover {
                background-color: #2ea043;
            }
            QPushButton:pressed {
                background-color: #1a7f37;
            }
            QPushButton:disabled {
                background-color: #30363d;
                color: #8b949e;
            }
        """)
        button.clicked.connect(callback)
        return button
        
    def browse_wvd(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select WVD File",
            "",
            "WVD Files (*.wvd);;All Files (*.*)"
        )
        if file_path:
            self.wvd_input.setText(file_path)
            
    def log_to_console(self, message):
        self.console_text.append(message)
        self.console_text.moveCursor(QTextCursor.MoveOperation.End)
        
    def clear_console(self):
        self.console_text.clear()
        self.console_text.setPlainText("-> Console cleared\n-> Ready to extract keys...\n")
        
    def extract_keys(self):
        if not self.wvd_input.text() or not self.pssh_input.text():
            self.log_to_console("ERROR: WVD file and PSSH required")
            return
        
        license_url, headers_dict = self.parse_fetch_request()
        
        if not license_url or not headers_dict:
            self.log_to_console("ERROR: Invalid fetch request")
            return
        
        for key, value in headers_dict.items():
            if any(ord(c) > 127 for c in str(value)):
                self.log_to_console(f"ERROR: Header '{key}' contains invalid characters")
                return
            
        self.extract_btn.setEnabled(False)
        self.extract_btn.setText("Extracting...")
                
        self.thread = ExtractorThread(
            self.wvd_input.text(),
            self.pssh_input.text(),
            license_url,
            headers_dict
        )
        self.thread.log_signal.connect(self.log_to_console)
        self.thread.finished.connect(self.on_extraction_finished)
        self.thread.start()
        
    def on_extraction_finished(self, keys, error):
        self.extract_btn.setEnabled(True)
        self.extract_btn.setText("Extract L3 Decryption Keys")