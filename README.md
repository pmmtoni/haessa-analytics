# HAESSA Component Delivery Dashboard

A full-stack web application for tracking, managing, and visualizing component delivery lifecycles across coaches in a manufacturing/assembly environment.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Features

- **Component Management**  
  Full CRUD operations with complete audit trail (add/edit/delete)

- **Intelligent Derived Status**  
  Automatically computed from dates (priority order):  
  - Delivered  
  - Being processed  
  - Haessa to order  
  - CTED due date not provided  
  - Lead time not provided  
  - CTED to place order  
  - Unknown  
  - Overdue

- **Dashboard**  
  - Multi-field search  
  - Filter by derived status  
  - Overdue alert banner  
  - Sortable table with color-coded badges & missing fields display

- **Gantt Chart**  
  - Timeline visualization (Frappe Gantt)  
  - Clear "Today" marker  
  - Status-based bar coloring

- **Analytics**  
  - Coach-level status breakdown  
  - Supplier performance trends  
  - Daily/weekly/monthly on-time metrics  
  - Current period alert (<90% on-time)

- **Security & Auditing**  
  - Role-based access (admin, editor, viewer)  
  - Full audit log of all actions

## Tech Stack

- **Backend**: Python 3 + Flask + SQLAlchemy  
- **Database**: SQLite (local) / PostgreSQL (production)  
- **Frontend**: Bootstrap 5 + Frappe Gantt + vanilla JS  
- **Deployment**: Render.com (GitHub auto-deploy)  
- **Authentication**: Flask-Login  
- **Scheduling**: APScheduler (daily summaries)

## Badges

[![Python](https://img.shields.io/badge/Python-3.11+-blue?logo=python&logoColor=white)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-3.0.3-success?logo=flask&logoColor=white)](https://flask.palletsprojects.com/)
[![Render](https://img.shields.io/badge/Deployed%20on-Render-46a0e8?logo=render&logoColor=white)](https://render.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Installation (Local Development)

1. Clone the repo
   ```bash
   git clone https://github.com/pmmtoni/haessa-analytics.git
   cd haessa-analytics
