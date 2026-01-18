# -*- coding: utf-8 -*-
"""
Created on Sun Oct 26 12:27:03 2025

@author: Paul
"""

from app import db, Components

# List all components
all_components = Components.query.all()
for c in all_components:
    print(c.id, c.name, c.category, c.status, c.due_date)
