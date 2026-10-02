# CyberPort Scanner

<div align="center">

<img src="static/images/cyberport-logo.png" alt="CyberPort Scanner Logo" width="560">

<p>
A modern <b>Cyberpunk-Themed TCP Port Scanner</b> built with <b>Python, Flask, HTML, CSS &amp; JavaScript</b> for educational and authorized network security testing.
</p>

<p>

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-3.0-000000?style=for-the-badge&logo=flask&logoColor=white)
![SQLite](https://img.shields.io/badge/SQLite-003B57?style=for-the-badge&logo=sqlite&logoColor=white)
![MIT License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Live-success?style=for-the-badge)

</p>

### 🌐 Live Demo
## https://cyberport-scanner.onrender.com/

### 💻 GitHub Repository
## https://github.com/vipulbariya-code/CyberPort-Scanner

</div>

---

# 🚀 About

CyberPort Scanner is a professional **TCP Port Scanner** designed with a futuristic **Cyberpunk UI**. It allows users to scan ports on systems they own or are authorized to test while providing real-time scan progress, scan history, CSV export, statistics, and a premium hacker-style interface.

This project was built for learning **Cyber Security**, **Networking**, and **Python Flask Development**.

---

# ✨ Features

✅ Modern Cyberpunk UI

✅ Animated Matrix Background

✅ Multi-threaded TCP Port Scanner

✅ Scan IP Address or Domain

✅ Live Progress Bar

✅ Real-Time Results

✅ Common Service Detection

✅ CSV Export

✅ SQLite Database

✅ Scan History

✅ Search & Filter

✅ Responsive Design

✅ Flask Backend

✅ REST API

✅ Security Headers

✅ Rate Limiting

✅ Production Ready

---

## 🖼️ Screenshots

### 🏠 Home

![Home](https://raw.githubusercontent.com/vipulbariya-code/CyberPort-Scanner/main/img1.1.png)

### 🛰️ Port Scanner

![Dashboard](https://raw.githubusercontent.com/vipulbariya-code/CyberPort-Scanner/main/img2.png)

### 📜 History

![History](https://raw.githubusercontent.com/vipulbariya-code/CyberPort-Scanner/main/img3.png)



| Home | Dashboard | History |
|------|-----------|----------|
| Add Screenshot | Add Screenshot | Add Screenshot |

---

# ⚙ Tech Stack

## Backend

- Python
- Flask
- SQLite
- Socket Programming
- Flask-Limiter
- Gunicorn

## Frontend

- HTML5
- CSS3
- JavaScript
- Chart.js
- Font Awesome

---

# 📂 Folder Structure

```text
CyberPort-Scanner
│
├── backend
│   ├── app.py
│   ├── api_v1.py
│   ├── ports_data.py
│   ├── scanner.py
│   ├── routes.py
│   ├── models.py
│   └── config.py
│
├── static
│   ├── css
│   ├── js
│   ├── images
│   └── fonts
│
├── templates
│
├── database
│
├── exports
│
├── requirements.txt
├── render.yaml
├── railway.json
├── Procfile
├── LICENSE
└── README.md
```

---

# 🚀 Installation

Clone Repository

```bash
git clone https://github.com/vipulbariya-code/CyberPort-Scanner.git
```

Open Folder

```bash
cd CyberPort-Scanner
```

Install Dependencies

```bash
pip install -r requirements.txt
```

Run Application

```bash
cd backend

set FLASK_ENV=development
set SECRET_KEY=replace-with-a-random-local-secret
python app.py
```

Open Browser

```
http://127.0.0.1:5000
```

---

# 🌐 Live Website

## 🚀 https://cyberport-scanner.onrender.com/

---

# 📖 Usage

1. Open Dashboard
2. Enter IP Address or Domain
3. Select Port Range
4. Click Start Scan
5. View Live Results
6. Export CSV
7. View Scan History

---

# 🌐 CyberPort Scanner REST API

CyberPort Scanner provides a first-party, authenticated REST API under the versioned prefix `/api/v1`. The API allows programmatic access to port scanning, results retrieval, user history, stats, and educational port intelligence without depending on third-party scanning services.

- **Base URL**: `https://cyberport-scanner.onrender.com/api/v1`
- **Interactive Documentation**: `https://cyberport-scanner.onrender.com/api/docs`
- **OpenAPI Specification**: `https://cyberport-scanner.onrender.com/api/v1/openapi.json`

---

## 🔑 Authentication

Authenticate requests using standard HTTP Bearer token headers:

```http
Authorization: Bearer YOUR_API_KEY
```

> **API Key Safety Notice:**
> - Generate API keys in your dashboard under **Developer API** (`/developer`).
> - Keys start with `cps_live_` followed by cryptographically random entropy.
> - Plaintext keys are never stored in the database (only secure SHA-256 hashes are persisted).
> - The full key is displayed **only once** upon generation.

---

## 🛡️ Scanner Safety & Responsible Use

The REST API enforces the identical strict safety guardrails as the web interface:

1. **Authorized Testing Only:** Port scanning must only be performed on networks and hosts you own or have explicit written authorization to test.
2. **Private Targets Only (`PRIVATE_TARGETS_ONLY=true`):** Scans are restricted to private subnets (RFC 1918: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) and loopback (`127.0.0.1`). Public Internet targets are rejected with `400 Bad Request` (`TARGET_NOT_ALLOWED`).
3. **Port Range Cap:** Maximum **1024 ports** per request.
4. **Rate Limits & Concurrency:**
   - 60 API requests per minute per key
   - 10 scan starts per minute
   - Maximum **2 concurrent scans** per user account
   - Excess requests receive `429 Too Many Requests`

---

## 📡 API Endpoints

### 1. Health Check
```bash
curl -X GET https://cyberport-scanner.onrender.com/api/v1/health
```
**Response (200 OK):**
```json
{
  "success": true,
  "service": "CyberPort Scanner API",
  "version": "v1",
  "status": "healthy"
}
```

### 2. Start a Scan
```bash
curl -X POST https://cyberport-scanner.onrender.com/api/v1/scans \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "target": "192.168.1.10",
    "start_port": 1,
    "end_port": 100
  }'
```
**Response (201 Created):**
```json
{
  "success": true,
  "scan_id": 123,
  "status": "running",
  "target": "192.168.1.10",
  "resolved_ip": "192.168.1.10",
  "start_port": 1,
  "end_port": 100,
  "total_ports": 100,
  "created_at": "2026-09-29T00:15:00Z"
}
```

### 3. Get Scan Status & Results
```bash
curl -X GET https://cyberport-scanner.onrender.com/api/v1/scans/123 \
  -H "Authorization: Bearer YOUR_API_KEY"
```
**Response (200 OK):**
```json
{
  "success": true,
  "scan": {
    "id": 123,
    "target": "192.168.1.10",
    "resolved_ip": "192.168.1.10",
    "start_port": 1,
    "end_port": 100,
    "status": "completed",
    "open_ports": [
      {
        "port": 22,
        "service": "SSH",
        "state": "open"
      },
      {
        "port": 80,
        "service": "HTTP",
        "state": "open"
      }
    ],
    "total_ports_scanned": 100,
    "open_ports_count": 2,
    "closed_ports_count": 98,
    "duration_seconds": 0.45,
    "created_at": "2026-09-29T00:15:00Z"
  }
}
```

### 4. List Scan History (Paginated)
```bash
curl -X GET "https://cyberport-scanner.onrender.com/api/v1/scans?page=1&per_page=20" \
  -H "Authorization: Bearer YOUR_API_KEY"
```
**Response (200 OK):**
```json
{
  "success": true,
  "scans": [ ... ],
  "pagination": {
    "page": 1,
    "per_page": 20,
    "total_items": 15,
    "total_pages": 1,
    "has_next": false,
    "has_prev": false
  }
}
```

### 5. Delete a Scan (Strict IDOR Protected)
```bash
curl -X DELETE https://cyberport-scanner.onrender.com/api/v1/scans/123 \
  -H "Authorization: Bearer YOUR_API_KEY"
```
**Response (200 OK):**
```json
{
  "success": true,
  "message": "Scan deleted successfully."
}
```

### 6. User Statistics
```bash
curl -X GET https://cyberport-scanner.onrender.com/api/v1/stats \
  -H "Authorization: Bearer YOUR_API_KEY"
```
**Response (200 OK):**
```json
{
  "success": true,
  "stats": {
    "total_scans": 10,
    "open_ports": 25,
    "closed_ports": 450,
    "avg_duration": 1.2
  }
}
```

### 7. Educational Port Intelligence
```bash
curl -X GET https://cyberport-scanner.onrender.com/api/v1/ports/443 \
  -H "Authorization: Bearer YOUR_API_KEY"
```
**Response (200 OK):**
```json
{
  "success": true,
  "port": 443,
  "protocol": "TCP",
  "service": "HTTPS",
  "description": "Hypertext Transfer Protocol Secure (HTTPS) encrypts web traffic using TLS/SSL to protect data integrity and confidentiality."
}
```

---

## 🛑 Error Response Format

All API errors return consistent JSON:

```json
{
  "success": false,
  "error": {
    "code": "INVALID_TARGET",
    "message": "Target address is required."
  }
}
```

| HTTP Status | Error Code | Meaning |
|:---|:---|:---|
| `400 Bad Request` | `INVALID_TARGET` | Invalid host format or malformed IP |
| `400 Bad Request` | `TARGET_NOT_ALLOWED` | Public or non-private destination |
| `400 Bad Request` | `PORT_RANGE_TOO_LARGE` | Range exceeds 1024 ports limit |
| `401 Unauthorized` | `UNAUTHORIZED` | Missing or invalid Authorization header |
| `401 Unauthorized` | `INVALID_API_KEY` | Key does not exist or verification failed |
| `401 Unauthorized` | `REVOKED_API_KEY` | Key has been revoked |
| `404 Not Found` | `SCAN_NOT_FOUND` | Scan does not exist or belongs to another user |
| `429 Too Many Requests` | `RATE_LIMIT_EXCEEDED` | Request frequency limit exceeded |
| `429 Too Many Requests` | `CONCURRENT_SCAN_LIMIT` | Exceeded 2 concurrent scans |

# 🔐 Security

- TCP Connect Scan Only
- No Exploitation
- No Payload Delivery
- Rate Limited
- Private-network and localhost targets only in the public web UI
- Input Validation
- Educational Purpose Only

## Deployment configuration

- **SECRET_KEY**: Set `SECRET_KEY` to a cryptographically secure random string in production. When `FLASK_ENV=production`, the application strictly refuses to start if this is unset.
- **DATABASE_PATH**: Set `DATABASE_PATH` to a mounted persistent disk volume if you require scan history and user accounts to persist across container restarts. On Render's Free tier, the local container filesystem is **ephemeral** and resets on redeploy/spin-down; mounting a persistent disk is required for permanent data retention.
- **PRIVATE_TARGETS_ONLY**: Enabled by default (`true`). Restricts scans to localhost (`127.0.0.1`) and RFC 1918 private subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) to prevent the public deployment from being abused as an open proxy or internet port scanner.
- **MAX_PORT_RANGE**: Defaults to 1024 ports per single request to protect shared server resources.

---

# 📦 Deployment

### Render Deployment

- Connect your GitHub Repository to Render
- Create a new **Web Service**
- **Environment**: Python
- **Build Command**:
```bash
pip install -r requirements.txt
```
- **Start Command**:
```bash
gunicorn --chdir backend app:app --bind 0.0.0.0:$PORT --workers 1 --threads 4 --timeout 120
```
- **Environment Variables**:
  - `FLASK_ENV`: `production`
  - `SECRET_KEY`: *(Generate secure random string)*
  - `PYTHON_VERSION`: `3.11.9`
  - `PRIVATE_TARGETS_ONLY`: `true`
  - `DATABASE_URL`: *(Recommended for production persistence)* In the Render Dashboard, create a PostgreSQL database and attach or copy its database URL into `DATABASE_URL`. Without `DATABASE_URL`, CyberPort Scanner defaults to a local SQLite database (`database/cyberport.db`), which will be reset whenever Render spins down or redeploys ephemeral containers.


---

# 🧪 Running Tests

Automated testing is configured using `pytest`:

```bash
# Run complete test suite
pytest -v

# Run syntax and bytecode compilation verification
python -m compileall backend
```

---

# 📜 License

This project is licensed under the MIT License.

---

# 👨‍💻 Author

## Vipul Bariya

🌐 **Portfolio**: [https://vipulbariya.netlify.app/](https://vipulbariya.netlify.app/)  
💼 **LinkedIn**: [https://www.linkedin.com/in/vipulbariya/](https://www.linkedin.com/in/vipulbariya/)  
💻 **GitHub**: [https://github.com/vipulbariya-code](https://github.com/vipulbariya-code)  
🚀 **Live Project**: [https://cyberport-scanner.onrender.com/](https://cyberport-scanner.onrender.com/)

---

# ⭐ Support

If you like this project, please consider giving it a ⭐ Star on GitHub.

It motivates me to build more awesome Open Source Projects.

---

# ⚠ Disclaimer

CyberPort Scanner is developed strictly for educational purposes and authorized security testing.

Never scan systems, servers, or networks without proper permission.

The developer is not responsible for any misuse of this software.

---

<div align="center">

## ⭐ Thanks for Visiting ⭐

Made with ❤️ by **Vipul Bariya**

</div>
