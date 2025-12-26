# -*- coding: utf-8 -*-
"""
Created on Fri Nov 14 14:03:47 2025

@author: Paul
"""

from sqlalchemy import create_engine

# Path to your existing SQLite DB
db_path = r"C:\Users\Paul\compare_xlsx\pyscript\haessa_app\components.db"

engine = create_engine(f"sqlite:///{db_path}")

with engine.connect() as conn:
    try:
        conn.execute('ALTER TABLE users ADD COLUMN updated_at DATETIME')
        print("✔ added updated_at")
    except Exception as e:
        print("updated_at already exists:", e)

    try:
        conn.execute('ALTER TABLE users ADD COLUMN updated_by VARCHAR(100)')
        print("✔ added updated_by")
    except Exception as e:
        print("updated_by already exists:", e)
