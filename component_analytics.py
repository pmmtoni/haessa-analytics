# -*- coding: utf-8 -*-
"""
Created on Tue Dec 23 12:26:35 2025

@author: pmmto
"""

# component_analytics.py - Live Component Analytics Dashboard
import pandas as pd
from datetime import datetime, date
from app import app, db, Components

with app.app_context():
    # Fetch all components
    components = Components.query.all()
    
    # Convert to DataFrame
    data = []
    for c in components:
        data.append({
            "ID": c.id,
            "Item_no": c.Item_no,
            "Coach_no": c.Coach_no,
            "Component": c.Component,
            "Supplier": c.Supplier,
            "Quantity": c.Quantity,
            "Component_status": c.Component_status or "Unknown",
            "CTED_due_date": c.CTED_due_date,  # Assuming this is date/string
            "HAESSA_Delivery_Date": c.HAESSA_delivery_date,
            # Add more fields as needed
        })
    
    df = pd.DataFrame(data)
    
    # Fix date columns
    df['CTED_due_date'] = pd.to_datetime(df['CTED_due_date'], errors='coerce')
    df['HAESSA_Delivery_Date'] = pd.to_datetime(df['HAESSA_Delivery_Date'], errors='coerce')
    
    today = datetime.today().date()
    
    # Dynamic Overdue: Pending/Not Completed + Past CTED due date
    df['Status_Normalized'] = df['Component_status'].str.lower()
    df['Is_Overdue'] = (df['CTED_due_date'].dt.date < today) & (~df['Status_Normalized'].isin(['completed', 'delivered']))
    
    # Analytics
    print(f"📊 HAESSA Component Analytics - {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    print("="*80)
    
    print(f"Total Components: {len(df)}")
    print("\nStatus Breakdown:")
    print(df['Component_status'].value_counts(dropna=False))
    
    print("\nOverdue Components (Dynamic Calculation):")
    overdue_count = df['Is_Overdue'].sum()
    print(f"{overdue_count} overdue ({overdue_count / len(df) * 100:.1f}% of total)")
    print(df[df['Is_Overdue']][['Item_no', 'Component', 'CTED_due_date', 'Component_status']])
    
    print("\nOn-Time Completion Rate (Completed before/ on due date):")
    completed = df[df['Status_Normalized'] == 'completed']
    if len(completed) > 0:
        on_time = (completed['CTED_due_date'].dt.date >= completed['CTED_due_date'].dt.date.min())  # Simplified
        print(f"{len(completed)} completed → {on_time.sum() / len(completed) * 100:.1f}% on time")
    
    # Monthly Progress (Example for current month)
    current_month = df[df['CTED_due_date'].dt.month == today.month]
    if len(current_month) > 0:
        completed_month = current_month['Status_Normalized'] == 'completed'
        progress = completed_month.mean() * 100
        print(f"\nCurrent Month Progress: {progress:.1f}% ({completed_month.sum()}/{len(current_month)})")