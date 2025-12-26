# -*- coding: utf-8 -*-
"""
Created on Tue Dec 23 12:17:19 2025

@author: pmmto
"""

# component_edit_stats.py
import pandas as pd
from app import app, db, AuditLog
from datetime import datetime

with app.app_context():
    edits = AuditLog.query.filter(AuditLog.action == "Edited component").all()
    if edits:
        data = []
        for log in edits:
            changes = log.get_changes()
            data.append({
                "Time": log.timestamp.strftime("%Y-%m-%d %H:%M"),
                "User": log.username,
                "Target": log.target,
                "Changed Fields": len(changes),
                "Details": "; ".join([f"{k}: {v['old']} → {v['new']}" for k, v in changes.items()])
            })
        df = pd.DataFrame(data)
        print(f"\n📊 Component Edit Statistics - {datetime.now().strftime('%Y-%m-%d')}")
        print("="*80)
        print(f"Total Edits: {len(df)}")
        print("\nEdits by User:")
        print(df["User"].value_counts())
        print("\nLatest 10 Edits:")
        print(df.sort_values("Time", ascending=False).head(10)[["Time", "User", "Target", "Details"]].to_string(index=False))
    else:
        print("No component edits recorded yet.")