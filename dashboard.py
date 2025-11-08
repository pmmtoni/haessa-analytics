# -*- coding: utf-8 -*-
"""
Created on Sat Nov  8 15:47:08 2025

@author: Paul
"""

# --- Dashboard Title ---
st.title("📅 Interactive Task Dashboard with Progress (CRUD)")

# Pick month & year
today = datetime.today()
month = st.sidebar.selectbox("Select Month", list(range(1, 13)), index=today.month - 1)
year = st.sidebar.number_input("Select Year", min_value=2000, max_value=2100, value=today.year)

# Filter tasks for month
month_tasks = df[(df["Due Date"].dt.month == month) & (df["Due Date"].dt.year == year)]

# --- Calculate Monthly Progress ---
if not month_tasks.empty:
    total_month = len(month_tasks)
    completed_month = len(month_tasks[month_tasks["Status"].str.lower() == "completed"])
    monthly_progress = int((completed_month / total_month * 100))
    
    st.subheader(f"📊 Monthly Progress for {calendar.month_name[month]} {year}")
    st.progress(monthly_progress / 100)
    st.write(f"✅ {monthly_progress}% complete ({completed_month}/{total_month} tasks)")
else:
    st.info("No tasks for this month.")
