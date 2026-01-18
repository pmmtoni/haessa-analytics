# -*- coding: utf-8 -*-
"""
Created on Wed Dec 24 14:58:36 2025

@author: pmmto
"""
from app import app, db  # import your Flask app and db
from sqlalchemy import text

with app.app_context():
    try:
        # Step 1: Add new column with desired name
        db.session.execute(text("ALTER TABLE Components ADD COLUMN Coach_Type TEXT"))

        # Step 2: Copy data from old Section to new Coach_Type
        db.session.execute(text("UPDATE Components SET Coach_Type = Section"))

        # Step 3: Drop old Section column
        db.session.execute(text("ALTER TABLE Components DROP COLUMN Section"))

        db.session.commit()
        print("✅ Successfully renamed Section → Coach_Type in database")
    except Exception as e:
        print("Error:", e)
        db.session.rollback()