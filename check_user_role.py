# -*- coding: utf-8 -*-
"""
Created on Tue Dec 23 11:40:43 2025

@author: pmmto
"""

# check_user_role.py
from app import app, db, User

with app.app_context():
    admin_user = User.query.filter_by(username="admin").first()
    if admin_user:
        print("Username:", admin_user.username)
        print("Role:", repr(admin_user.role))  # repr shows exact string including case/None
        print("Is authenticated:", admin_user.is_authenticated)
    else:
        print("No user with username 'admin' found.")