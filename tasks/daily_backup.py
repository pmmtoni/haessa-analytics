# -*- coding: utf-8 -*-
"""
Created on Thu Oct  9 09:45:28 2025

@author: Paul
"""

import csv, os
from datetime import datetime
from database import get_db
from config import BACKUP_DIR
from app import send_email

def backup_database():
    os.makedirs(BACKUP_DIR, exist_ok=True)
    filename = f"components_{datetime.now().strftime('%Y%m%d')}.csv"
    filepath = os.path.join(BACKUP_DIR, filename)

    conn = get_db()
    rows = conn.execute("SELECT * FROM components").fetchall()
    conn.close()

    with open(filepath, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(rows[0].keys() if rows else [])
        for row in rows:
            writer.writerow(list(row))

    send_email("Daily Backup Completed", "Database successfully backed up.", attachment_path=filepath)

if __name__ == "__main__":
    backup_database()
