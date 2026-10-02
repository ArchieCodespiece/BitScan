import re

with open('src/ui/carver_tab.py', 'r', encoding='utf-8') as f:
    content = f.read()

content = re.sub(
    r'self\.btn_start\.setStyleSheet\(\"\"\"[\s\S]*?\"\"\"\)',
    'self.btn_start.setStyleSheet(\"\"\"\\n            QPushButton {\\n                background-color: #188038; color: white; font-weight: 500; border-radius: 16px; padding: 6px 16px; \\n                border: 1px solid #188038;\\n            }\\n            QPushButton:hover { background-color: #137333; }\\n            QPushButton:pressed { background-color: #0d652d; border: 1px solid #137333; }\\n            QPushButton:disabled { background-color: #f1f3f4; color: #9aa0a6; border: 1px solid #f1f3f4; }\\n        \"\"\")',
    content
)

content = re.sub(
    r'self\.btn_stop\.setStyleSheet\(\"\"\"[\s\S]*?\"\"\"\)',
    'self.btn_stop.setStyleSheet(\"\"\"\\n            QPushButton {\\n                background-color: #d93025; color: white; font-weight: 500; border-radius: 16px; padding: 6px 16px; \\n                border: 1px solid #d93025;\\n            }\\n            QPushButton:hover { background-color: #c5221f; }\\n            QPushButton:pressed { background-color: #b31412; border: 1px solid #c5221f; }\\n            QPushButton:disabled { background-color: #f1f3f4; color: #9aa0a6; border: 1px solid #f1f3f4; }\\n        \"\"\")',
    content
)

content = re.sub(
    r'self\.btn_extract_selected\.setStyleSheet\(\"\"\"[\s\S]*?\"\"\"\)',
    'self.btn_extract_selected.setStyleSheet(\"\"\"\\n            QPushButton {\\n                background-color: #1a73e8; color: white; font-weight: 500; border-radius: 16px; padding: 6px 16px; \\n                border: 1px solid #1a73e8;\\n            }\\n            QPushButton:hover { background-color: #185abc; }\\n            QPushButton:pressed { background-color: #174ea6; border: 1px solid #185abc; }\\n            QPushButton:disabled { background-color: #f1f3f4; color: #9aa0a6; border: 1px solid #f1f3f4; }\\n        \"\"\")',
    content
)

with open('src/ui/carver_tab.py', 'w', encoding='utf-8') as f:
    f.write(content)
