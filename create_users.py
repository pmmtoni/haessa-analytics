# -*- coding: utf-8 -*-
"""
Created on Mon Oct 27 23:30:27 2025

@author: Paul
"""

from app import app, db, User
from werkzeug.security import generate_password_hash

with app.app_context():
    admin = User(username="admin", password=generate_password_hash("admin123"), role="admin")
    editor = User(username="editor", password=generate_password_hash("editor123"), role="editor")
    viewer = User(username="viewer", password=generate_password_hash("viewer123"), role="viewer")

    db.session.add_all([admin, editor, viewer])
    db.session.commit()
    print("✅ Users created successfully!")
