# -*- coding: utf-8 -*-
"""
Created on Wed Oct  8 22:56:12 2025

@author: Paul
"""

import os, csv
from datetime import datetime
from apscheduler.schedulers.background import BackgroundScheduler
from database import query_all
from email_utils import send_email
from config import DOWNLOAD_FOLDER, ADMIN_EMAIL, DAILY_EXPORT_HOUR, DAILY_EXPORT_MINUTE

def daily_export_to_csv():
    rows = query_all()
    if not rows:
        print("No rows to export.")
        return
    filename = f"haessa_export_{datetime.now():%Y%m%d_%H%M%S}.csv"
    path = os.path.join(DOWNLOAD_FOLDER, filename)
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)
    send_email(ADMIN_EMAIL, "HAESSA DB Export Saved",
               f"Database successfully saved to {path} at {datetime.now()}")
    print(f"✅ Exported to {path}")

def start_scheduler():
    sched = BackgroundScheduler()
    sched.add_job(daily_export_to_csv, 'cron', hour=DAILY_EXPORT_HOUR, minute=DAILY_EXPORT_MINUTE)
    sched.start()
    print("🕓 Scheduler started for daily export.")
