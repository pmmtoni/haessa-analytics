# -*- coding: utf-8 -*-
"""
Created on Wed Oct  8 22:53:26 2025

@author: Paul
"""

import sqlite3
from config import DATABASE

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS components (
            Item_no INTEGER PRIMARY KEY AUTOINCREMENT,
            Coach_no TEXT NOT NULL,
            Component TEXT NOT NULL,
            Coach_Type TEXT,
            Quantity INTEGER,
            HAESSA_Order_Date DATE,
            HAESSA_Paydate DATE,
            HAESSA_Delivery_Date DATE,
            CTED_Due_Date DATE,
            Component_Status TEXT
        )
    """)
    conn.commit()
    conn.close()
