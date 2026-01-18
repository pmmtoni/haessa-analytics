# -*- coding: utf-8 -*-
"""
Created on Tue Dec 23 11:21:00 2025

@author: pmmto
"""

# add_details_column.py
from app import app, db
from sqlalchemy import text

with app.app_context():
    try:
        # Correct way in SQLAlchemy 2.0+
        db.session.execute(text("ALTER TABLE audit_log ADD COLUMN details TEXT"))
        db.session.commit()
        print("✅ Column 'details' added successfully to audit_log table.")
    except Exception as e:
        print("⚠️ Could not add column (might already exist or another issue):")
        print(e)