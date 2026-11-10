# FloodWatch Community
### Community-Based Flood Alert System — Student Project

A community-driven flood awareness and early reporting platform built with Python Flask, SQLite, Leaflet, and Chart.js.

---

## 📋 Features

| Feature | Status |
|---|---|
| Dashboard with live statistics (total, high-severity, unresolved, recent) | ✅ |
| Transparent, rule-based risk assessment with explanations | ✅ |
| Severity & trend charts (Chart.js doughnut + bar) | ✅ |
| Interactive Leaflet/OpenStreetMap with colour-coded markers | ✅ |
| Click-to-select map location for report coordinates | ✅ |
| AJAX report submission with client + server validation | ✅ |
| Report filtering by severity, status, and search keyword | ✅ |
| Report status tracking: New → Under Review → Resolved | ✅ |
| Community follow-up flagging (per-IP, duplicate-safe) | ✅ |
| Geographic cluster detection for nearby high-severity reports | ✅ |
| Dedicated flood safety guide (Before / During / After) | ✅ |
| Responsive design for desktop, tablet, and mobile | ✅ |
| Safe database migration (no data loss on schema changes) | ✅ |

---

## 🛠️ Technology Stack

- **Backend:** Python 3, Flask
- **Database:** SQLite (via built-in `sqlite3` module)
- **Frontend:** HTML5, CSS3 (vanilla), JavaScript (ES6+)
- **Map:** Leaflet 1.9.4 + OpenStreetMap
- **Charts:** Chart.js 4.4

No React, TypeScript, or heavy frontend framework is used. The project is intentionally simple and easy to run without a build step.

---

## 🚀 Installation & Running Locally

### Prerequisites

- Python 3.8 or later
- pip
- Internet connection (for CDN-hosted Leaflet and Chart.js)

### 1. Clone or download the project

```bash
# If using git:
git clone <your-repo-url>
cd CommunityFloodAlert

# Or simply place the project folder on your machine and open a terminal in it.
```

### 2. Install dependencies

```bash
pip install flask
```

### 3. Start the server

```bash
py app.py
```

The server will start at **http://127.0.0.1:5000**

### 4. Open in your browser

Visit: [http://127.0.0.1:5000](http://127.0.0.1:5000)

---

## 📁 Project Structure

```
CommunityFloodAlert/
│
├── app.py                      # Flask backend — all routes and logic
├── flood_reports.db            # SQLite database (auto-created on first run)
├── flood_reports_backup.db     # Database backup (do not delete)
├── README.md                   # This file
│
├── templates/
│   ├── index.html              # Dashboard (main page)
│   └── safety.html             # Flood safety guide
│
└── static/
    └── style.css               # Complete design system stylesheet
```

---

## 🔌 API Routes

| Route | Method | Description |
|---|---|---|
| `/` | GET | Main dashboard. Accepts `?severity=`, `?status=`, `?q=` filter params. |
| `/report` | POST | Submit a flood report. Returns JSON if called via AJAX. |
| `/update_status` | POST | Update a report's status (New / Under Review / Resolved). |
| `/followup` | POST | Flag a report as needing follow-up (IP-based deduplication). |
| `/api/stats` | GET | JSON endpoint returning stats, risk assessment, and 7-day trend data. |
| `/safety` | GET | Flood safety guide page. |

---

## ⚠️ Disclaimer

This is a **student demonstration project**. It is not an official flood monitoring, forecasting, or emergency management system.

- Data shown is community-submitted and unverified.
- Risk assessments are rule-based and for educational purposes only.
- No real-time sensor data, rainfall data, or government alerts are integrated.
- Emergency contact information is intentionally omitted — always contact your local district disaster management authority for official guidance.
- Demo data is clearly labelled and kept separate from user-submitted reports.

---

## 🧪 Testing Checklist

After starting `py app.py`, verify the following:

- [ ] Dashboard loads with statistics cards
- [ ] Risk level card shows a level and explanation
- [ ] Both charts render (Severity doughnut + 7-day trend bar)
- [ ] Map loads with OpenStreetMap tiles
- [ ] Clicking the map fills latitude/longitude in the form
- [ ] Submitting a report shows a success message and updates the dashboard
- [ ] Markers appear on the map for reports with valid coordinates
- [ ] Severity, status, and search filters work correctly
- [ ] Changing a report status shows a toast notification
- [ ] Clicking "Flag" on a report increments the follow-up counter
- [ ] Safety Guide page loads correctly
- [ ] Application is usable on a mobile screen

---

## 📸 Screenshots

_(Take screenshots after running the application and replace this section with images.)_

---

## 👨‍💻 Development Notes

- The database is initialised automatically on first run. New columns are added via safe `ALTER TABLE` migrations — existing data is never lost.
- The risk assessment uses only data from the database (severity, recency, coordinates). No external APIs, rainfall data, or sensor readings are fabricated.
- Follow-up flags use a SHA-256 hash of the user's IP address — the raw IP is never stored.

---

*Student Project — Community-Based Flood Alert System | FloodWatch Community*
