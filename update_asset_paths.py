import os
import re

files_to_update = [
    'src/ui/carver_tab.py',
    'src/ui/shredder_tab.py',
    'src/ui/main_window.py'
]

for filepath in files_to_update:
    if os.path.exists(filepath):
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Replace occurrences of image names (e.g. "start.png", 'recover.png') with "assets/start.png"
        # We need to be careful not to double prefix if they are already prefixed.
        # Match standard icons used
        icons = [
            "start.png", "stop.png", "recover.png", "forensic_report.png", 
            "manifest.png", "photo.png", "documents.png", "archives.png", "jpg.png"
        ]
        
        for icon in icons:
            # Replace string literals like "start.png"
            content = content.replace(f'"{icon}"', f'"assets/{icon}"')
            content = content.replace(f"'{icon}'", f"'assets/{icon}'")
            
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)
