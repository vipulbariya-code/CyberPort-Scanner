# 🛰️ CyberPort Scanner

<div align="center">

**A premium, cyberpunk-themed network port scanner built for educational and authorized security testing.**

![Python](https://img.shields.io/badge/Python-3.10+-00ff9d?style=flat-square&logo=python&logoColor=black)
![Flask](https://img.shields.io/badge/Flask-3.0-00e5ff?style=flat-square&logo=flask&logoColor=black)
![SQLite](https://img.shields.io/badge/SQLite-3-00ff9d?style=flat-square&logo=sqlite&logoColor=black)
![License](https://img.shields.io/badge/License-MIT-00e5ff?style=flat-square)

</div>

---

## ⚠️ Disclaimer — Read Before Use

**CyberPort Scanner is built strictly for educational purposes and authorized security testing.**

- Only scan hosts, networks, or IP ranges that **you own** or have **explicit written permission** to test.
- Unauthorized port scanning may violate computer-crime laws in your jurisdiction (e.g. the U.S. Computer Fraud and Abuse Act, the UK Computer Misuse Act, or equivalents elsewhere).
- The scanning engine performs a standard **TCP connect scan** only — no exploitation, no vulnerability probing, no packet crafting.
- The author(s) of this project accept **no liability** for misuse of this software. By using it, you agree to use it responsibly and legally.

---

## ✨ Features

- 🎨 **Futuristic cyberpunk UI** — glassmorphism cards, animated Matrix rain, neon green/cyan glow, animated grid background
- ⚡ **Multi-threaded TCP port scanning** via Python sockets (`ThreadPoolExecutor`)
- 📊 **Live scan progress** — real-time progress bar, elapsed timer, open-port counter (polling-based)
- 🔍 **Searchable & sortable results table** with open/closed filtering
- 🏷️ **Common service name detection** (HTTP, HTTPS, SSH, FTP, SMTP, DNS, RDP, MySQL, and more)
- 📁 **CSV export** and **one-click clipboard copy** of results
- 🕓 **Persistent scan history** stored in SQLite, with search, pagination, per-record delete, and clear-all
- 📈 **Dashboard widgets** — total scans, open ports, closed ports, last scan, scan duration
- 🛡️ **Input validation & rate limiting** on every scan request
- 📱 **Fully responsive** — desktop, tablet, and mobile layouts
- ♿ **Accessible** — visible focus states, semantic HTML, `prefers-reduced-motion` support
- 🚀 **Production-ready** — clean modular architecture, Gunicorn-ready, deploy configs included for Render & Railway

---

## 🖼️ Screenshots

> _Add your own screenshots here after running the app locally._

| Home | Dashboard | History |
|---|---|---|
| `screenshots/home.png` | `screenshots/dashboard.png` | `screenshots/history.png` |

---

## 🧱 Folder Structure

```
cyberport-scanner/
├── backend/
│   ├── app.py              # Flask application factory & entry point
│   ├── config.py           # Environment configuration
│   ├── models.py           # SQLite data access layer
│   ├── routes.py           # Page + REST API routes
│   └── scanner.py          # Multi-threaded TCP scan engine
├── templates/
│   ├── base.html            # Shared layout (header, footer, loading screen)
│   ├── index.html           # Home page
│   ├── dashboard.html       # Scanner dashboard
│   ├── history.html         # Scan history
│   ├── about.html           # About / methodology / ethics
│   ├── contact.html         # Contact page
│   └── 404.html             # Custom error page
├── static/
│   ├── css/
│   │   ├── style.css         # Design tokens, layout, nav, footer, cards
│   │   ├── pages.css         # Page-specific components
│   │   └── animations.css    # Keyframes & motion
│   ├── js/
│   │   ├── main.js           # Toasts, nav, reveal-on-scroll, typing effect
│   │   ├── matrix.js          # Matrix rain canvas animation
│   │   ├── scanner.js         # Dashboard: validation, polling, results table
│   │   ├── history.js         # History page logic
│   │   └── charts.js          # Chart.js statistics
│   ├── images/
│   └── fonts/
├── database/                # SQLite database file lives here (gitignored)
├── exports/                 # Generated CSV exports (gitignored)
├── requirements.txt
├── Procfile                 # Render/Railway/Heroku-style start command
├── render.yaml               # Render deployment blueprint
├── railway.json               # Railway deployment config
└── README.md
```

---

## 🛠️ Technologies Used

**Backend:** Python 3, Flask, Flask-Limiter, SQLite, `socket`, `concurrent.futures`, Gunicorn
**Frontend:** HTML5, CSS3 (custom design system, no framework), Vanilla JavaScript, Chart.js, Font Awesome 6
**Fonts:** Orbitron (display), JetBrains Mono (terminal/data), Rajdhani (UI labels)

---

## 🚀 Installation

### Prerequisites
- Python 3.10 or newer
- `pip`

### Steps

```bash
# 1. Clone the repository
git clone https://github.com/yourusername/cyberport-scanner.git
cd cyberport-scanner

# 2. Create a virtual environment
python3 -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run the app
cd backend
python app.py
```

The app will be available at **http://127.0.0.1:5000**.

The SQLite database is created automatically on first run at `database/cyberport.db`.

---

## 📖 Usage

1. Open the **Scanner Dashboard** (`/dashboard`).
2. Enter a target IPv4 address or domain **that you own or are authorized to test** (e.g. `127.0.0.1`, your own LAN device, or a lab VM).
3. Set a start and end port (max 1024 ports per scan).
4. Click **Start Scan** and watch live progress.
5. Review results in the sortable/searchable table — filter to "Open Only", search by port/service, export to CSV, or copy to clipboard.
6. Visit **Scan History** to review, search, or delete past scans.

### Example API request

```bash
curl -X POST http://127.0.0.1:5000/api/scan/start \
  -H "Content-Type: application/json" \
  -d '{"target": "127.0.0.1", "start_port": 1, "end_port": 1024}'
```

---

## 🔐 Security Notes

- Rate limiting is applied to the scan API (default: 10 scans/minute per client) to prevent abuse.
- Port ranges are capped at 1024 ports per request.
- Input is validated server-side for both target format and port range before any socket is opened.
- Standard security headers (`X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`) are set on every response.
- This project performs **no exploitation, no authentication bypass, and no payload delivery** of any kind.

---

## ☁️ Deployment

### Render
1. Push this repo to GitHub.
2. Create a new **Web Service** on [Render](https://render.com), connect your repo — `render.yaml` is auto-detected.
3. Render will run `pip install -r requirements.txt` and start with the Gunicorn command in the Procfile.

### Railway
1. Push this repo to GitHub.
2. Create a new project on [Railway](https://railway.app) from your repo — `railway.json` is auto-detected.
3. Railway builds with Nixpacks and starts the app via the configured start command.

Both platforms provide a `PORT` environment variable automatically, which `app.py` and the Procfile already respect.

---

## 📄 License

This project is licensed under the **MIT License** — see the `LICENSE` file for details.

---

## 🙋 Disclaimer (again, because it matters)

CyberPort Scanner is an educational project. It is not a substitute for professional penetration-testing tools, and it should never be used against systems without proper authorization. If you're learning network security, always practice in a legal, isolated environment (your own lab, a VM, or a dedicated CTF platform).
