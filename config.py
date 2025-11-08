# -*- coding: utf-8 -*-
"""
Created on Wed Oct  8 22:51:32 2025

@author: Paul
"""

import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DATABASE = os.path.join(BASE_DIR, 'components.db')
BACKUP_DIR = os.path.join(BASE_DIR, 'backups')

# Email Settings

ADMIN_EMAIL = "pmmtoni@gmail.com"
EMAIL_USER = "pmmtoni@gmail.com"
EMAIL_PASS = "your_email_password_here"  # Use app password for Gmail
EMAIL_HOST = "smtp.gmail.com"
EMAIL_PORT = 587
EMAIL_USE_TLS = True

USERNAME = "admin"
PASSWORD = "haessa123"
SECRET_KEY = "supersecretkey"
