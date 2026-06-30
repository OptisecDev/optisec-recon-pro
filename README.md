<div align="center">

```
╔══════════════════════════════════════════════════════════════════╗
║   ██████  ██████  ████████ ██  ██  ███████ ███████  ██████     ║
║  ██    ██ ██   ██    ██    ██ ██  ██      ██      ██           ║
║  ██    ██ ██████     ██    ████   ███████ █████   ██           ║
║  ██    ██ ██         ██    ██ ██       ██ ██      ██           ║
║   ██████  ██         ██    ██  ██ ███████ ███████  ██████      ║
╠══════════════════════════════════════════════════════════════════╣
║        R E C O N   P R O  ·  v 4 . 0  S I N G U L A R I T Y  ║
║           Enterprise Cybersecurity Intelligence Platform        ║
╚══════════════════════════════════════════════════════════════════╝
```

<p>
  <img src="https://img.shields.io/badge/Version-v4.0%20SINGULARITY-ff0055?style=for-the-badge&logo=rocket&logoColor=white" alt="Version" />
  <img src="https://img.shields.io/badge/Python-3.12%2B-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python" />
  <img src="https://img.shields.io/badge/FastAPI-Async-009688?style=for-the-badge&logo=fastapi&logoColor=white" alt="FastAPI" />
  <img src="https://img.shields.io/badge/AI-Groq%20LLaMA-ff6b35?style=for-the-badge&logo=meta&logoColor=white" alt="AI" />
  <img src="https://img.shields.io/badge/License-Proprietary-dc2626?style=for-the-badge" alt="License" />
  <img src="https://img.shields.io/badge/Status-Live-00ff88?style=for-the-badge&logo=statuspage&logoColor=white" alt="Status" />
</p>

<p>
  <img src="https://img.shields.io/badge/Scan%20Modules-13-06b6d4?style=for-the-badge" alt="Modules" />
  <img src="https://img.shields.io/badge/API%20Endpoints-149%2B-8b5cf6?style=for-the-badge" alt="Endpoints" />
  <img src="https://img.shields.io/badge/WebSocket-Live%20Progress-00ff88?style=for-the-badge" alt="WebSocket" />
  <img src="https://img.shields.io/badge/NLP-Arabic%20%2B%20English-fbbf24?style=for-the-badge" alt="NLP" />
</p>

### [🌐 Live Demo → optisec-recon-pro.onrender.com](https://optisec-recon-pro.onrender.com)

**Demo account:** `demo` / `Demo@optisec1`

</div>

---

<!-- ═══════════════════════════════════════════════════════════ -->
<!-- ENGLISH SECTION                                            -->
<!-- ═══════════════════════════════════════════════════════════ -->

# OPTISEC Recon Pro — Enterprise Cybersecurity Intelligence Platform

OPTISEC Recon Pro v4.0 SINGULARITY is a full-stack, AI-powered security intelligence platform built for professional penetration testers, bug bounty hunters, and enterprise SOC teams. It combines 13 active scan modules, Groq LLaMA AI analysis, real-time WebSocket progress, Arabic/English NLP command parsing, PDF report generation, and a role-based JWT authentication system — all delivered through a dark-themed web dashboard and a fully documented REST API.

## Screenshots

### Landing Page
![Landing Page](docs/screenshots/landing.png)

### Demo Account — Dashboard
![Dashboard](docs/screenshots/demo_dashboard.png)

### Demo Account — Scan Results
![Scan Results](docs/screenshots/demo_scan.png)

### API Documentation
![API Docs](docs/screenshots/api_docs.png)

### License Management
![License](docs/screenshots/license.png)

---

## Key Features

### 13 Scan Modules

| # | Module | Description |
|---|--------|-------------|
| 1 | **Subdomain Enumeration** | Discover subdomains via wordlist brute-force and DNS resolution |
| 2 | **DNS Lookup** | Query A, MX, NS, TXT, CNAME, SOA, and AAAA records |
| 3 | **WHOIS Lookup** | Registrar, registrant, creation/expiry dates, nameservers |
| 4 | **Nmap Port Scan** | Service version detection and default script scanning |
| 5 | **SSL/TLS Analysis** | Certificate validity, expiry, cipher suites, TLS version audit |
| 6 | **HTTP Security Headers** | CSP, HSTS, X-Frame-Options, Referrer-Policy, Permissions-Policy |
| 7 | **Port Scanner** | Fast TCP port sweep with service identification |
| 8 | **XSS Detection** | Reflected Cross-Site Scripting payload injection across URL parameters |
| 9 | **SQL Injection** | Error-based and boolean-blind SQLi detection |
| 10 | **SSRF Detection** | Server-Side Request Forgery via metadata endpoint probing |
| 11 | **LFI Detection** | Local File Inclusion path traversal attempts |
| 12 | **Open Redirect** | Unvalidated redirect parameter detection |
| 13 | **OSINT** | Email harvesting and social media profile discovery |

All 13 modules can run in parallel as a **full scan**, or selectively via the API or web UI.

### AI Analysis — Groq LLaMA
- Submit scan findings to **Groq LLaMA-3.3-70b** for deep threat analysis
- Outputs structured Markdown: threat assessment, CVE mapping, attack chain reconstruction, remediation priorities
- Supports Arabic and English output via the `lang` parameter

### WebSocket Live Progress
- Connect to `ws://host/ws/scan/{scan_id}` for push-based scan updates
- Each module reports its own progress step in real time
- No polling required — the UI updates automatically as results arrive

### PDF Security Reports
- Auto-generated professional PDF reports via ReportLab
- Includes: executive summary, vulnerability table, OSINT findings, remediation recommendations
- Downloadable from the Reports page or via `GET /reports/download/{filename}`

### Arabic NLP Command Interface
- Send natural-language commands in **Arabic or English** to `/api/nlp`
- Examples:
  - `افحص tesla.com عن ثغرات XSS` → launches XSS scan
  - `اجمع النطاقات الفرعية لـ google.com` → runs subdomain enumeration
  - `ابدأ فحص شامل وأنشئ تقرير` → full scan + report
- First tries Groq AI; falls back to local rule-based parser

### JWT Authentication & Role-Based Access
| Role | Capabilities |
|------|-------------|
| `admin` | Full access — user management, all scans, license control |
| `analyst` | Launch scans, view all findings, generate reports |
| `viewer` | Read-only access to own scans and findings |

- Session cookie + Bearer token support
- Rate limiting: 5 failed attempts → 15-minute lockout
- Sliding 30-minute session refresh
- API key generation and regeneration per user

### Additional Platform Modules
- **Bug Bounty Integration** — HackerOne, Bugcrowd, Intigriti program browser & report submission
- **Compliance Auditing** — ISO 27001, NIST, PCI-DSS, GDPR, HIPAA automated checks
- **AI Security (UEBA)** — Behavioral anomaly detection, Zero-Day prediction, AI Red Team
- **OSINT Engine** — Phone lookup, IP geolocation, national ID (Iraq), vehicle plates, username search, device fingerprinting, cell tower triangulation
- **MITRE ATT&CK Navigator** — Browse techniques, map detections, track APT profiles
- **Dark Web Intelligence** — Leaked credentials, threat actor mentions, IOC monitoring
- **Autonomous Red Team** — AI-driven attack sessions with automated reporting
- **NGFW** — ML-based DPI and anomaly detection engine
- **Threat Feed** — Global IOC and CVE intelligence feed
- **IOC Correlation Engine** — Cluster and link indicators across sources
- **WireGuard VPN** — Peer management and QR code key generation
- **Post-Quantum Cryptography** — Kyber-768 key encapsulation (PQC-ready)
- **Federated Scanning** — Coordinate scans across multiple OPTISEC nodes
- **License Management** — Tier-based feature gating (Free / Pro)

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| **Backend Framework** | FastAPI (async) + Uvicorn |
| **Database** | SQLite (dev) / PostgreSQL 16 (prod) via SQLAlchemy 2 async |
| **Authentication** | JWT (python-jose) + bcrypt password hashing |
| **AI Engine** | Groq API — LLaMA-3.3-70b-versatile |
| **WebSockets** | FastAPI WebSocket + custom connection manager |
| **Scanning** | Nmap, dnspython, python-whois, httpx, BeautifulSoup4 |
| **Reports** | ReportLab PDF generation |
| **NLP** | Groq LLaMA + local rule-based Arabic/English parser |
| **Task Queue** | FastAPI BackgroundTasks + APScheduler |
| **Cryptography** | PQC AES-GCM, python-cryptography |
| **VPN** | WireGuard-tools + QR code generation |
| **CLI** | Click + Rich |
| **Reverse Proxy** | Nginx (production) |
| **Containerization** | Docker + Docker Compose |
| **Deployment** | Render.com / Railway |

---

## Local Development Setup

### Prerequisites
- Python 3.12+
- `nmap` installed on the host (`apt install nmap` / `brew install nmap`)
- A Groq API key (free at [console.groq.com](https://console.groq.com)) — optional but enables AI features

### 1. Clone & create a virtual environment

```bash
git clone https://github.com/OptisecDev/optisec-recon-pro.git
cd optisec-recon-pro
python -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

### 3. Configure environment variables

```bash
cp .env.example .env   # or create .env manually
```

Edit `.env`:

```env
# Required
JWT_SECRET=change-this-to-a-random-secret

# Optional — enables AI analysis and NLP
GROQ_API_KEY=gsk_...

# Optional — enables AlienVault OTX threat intelligence
OTX_API_KEY=...

# Database (defaults to SQLite if not set)
# DATABASE_URL=postgresql+asyncpg://user:pass@localhost:5432/optisec

# First-run admin account (only used when DB is empty)
FIRST_ADMIN_USER=admin
FIRST_ADMIN_EMAIL=admin@example.com
FIRST_ADMIN_PASSWORD=StrongPass@1
```

### 4. Run the development server

```bash
python main.py web --reload
```

Open **http://localhost:8000** in your browser.

API documentation is available at **http://localhost:8000/docs**.

### 5. CLI usage (optional)

```bash
# Run a full scan
python main.py scan example.com --type full

# Run specific scan types
python main.py scan example.com --type xss
python main.py scan example.com --type subdomain

# Generate a PDF report
python main.py report example.com

# List saved targets
python main.py targets
```

---

## Docker Deployment

### Quick start (SQLite, single container)

```bash
docker build -t optisec-recon-pro .
docker run -d \
  -p 8000:8000 \
  -e JWT_SECRET=your-secret \
  -e GROQ_API_KEY=gsk_... \
  -v optisec_data:/app/data \
  -v optisec_reports:/app/reports \
  --name optisec \
  optisec-recon-pro
```

### Production stack (PostgreSQL + Redis + Nginx)

```bash
# 1. Copy and fill in environment variables
cp .env.example .env

# 2. Build and start all services
docker compose up -d --build

# 3. Check logs
docker compose logs -f app
```

Services started:

| Container | Role | Port |
|-----------|------|------|
| `optisec_app` | FastAPI application | internal |
| `optisec_db` | PostgreSQL 16 | internal |
| `optisec_redis` | Redis 7 (sessions/cache) | internal |
| `optisec_nginx` | Reverse proxy | 80, 443 |

The app will be available at **http://localhost** (port 80).

### Environment variables reference

| Variable | Default | Description |
|----------|---------|-------------|
| `JWT_SECRET` | *(must set)* | Secret key for JWT signing |
| `GROQ_API_KEY` | — | Groq API key for AI features |
| `OTX_API_KEY` | — | AlienVault OTX threat intel key |
| `DATABASE_URL` | SQLite | PostgreSQL connection string |
| `FIRST_ADMIN_USER` | `admin` | Initial admin username |
| `FIRST_ADMIN_EMAIL` | `admin@optisec.local` | Initial admin email |
| `FIRST_ADMIN_PASSWORD` | *(auto-generated)* | Initial admin password (printed to logs on first run) |
| `PORT` | `8000` | Bind port (used by Render/Railway) |

---

## API Overview

All endpoints require a valid JWT token (`Authorization: Bearer <token>` or `access_token` cookie).

```
POST /api/auth/login          — Obtain JWT token
POST /api/auth/register       — Register new account
POST /api/scan                — Launch a security scan
GET  /api/scan/{scan_id}      — Poll scan status / results
GET  /api/scans               — List recent scans
GET  /api/findings            — List vulnerability findings
POST /api/ai/analyze          — AI threat analysis (Groq)
POST /api/nlp                 — Parse Arabic/English command
POST /api/report              — Generate PDF report
POST /api/scan/ssl            — Quick SSL check
POST /api/scan/headers        — Quick headers check
POST /api/scan/ports          — Quick port scan
GET  /api/admin/users         — List users (admin)
GET  /api/admin/auth-log      — Auth audit log (admin)
```

Full interactive documentation: [https://optisec-recon-pro.onrender.com/docs](https://optisec-recon-pro.onrender.com/docs)

---

## License

**Proprietary Software — All Rights Reserved**

Copyright © 2024–2026 OPTISEC. All rights reserved.

This software and its source code are the exclusive property of OPTISEC. No part of this software may be copied, modified, distributed, sublicensed, or used in any form without the prior written permission of OPTISEC.

Contact: ahssanali84.syber@gmail.com

---

<!-- ═══════════════════════════════════════════════════════════ -->
<!-- ARABIC SECTION — القسم العربي                             -->
<!-- ═══════════════════════════════════════════════════════════ -->

<div dir="rtl">

---

# OPTISEC Recon Pro — منصة استخبارات الأمن السيبراني للمؤسسات

**OPTISEC Recon Pro v4.0 SINGULARITY** هي منصة أمنية متكاملة مدعومة بالذكاء الاصطناعي، مصممة لمختبري الاختراق المحترفين، وصائدي المكافآت الأمنية، وفرق مراكز العمليات الأمنية (SOC) في المؤسسات. تجمع المنصة بين 13 وحدة فحص نشطة، وتحليل ذكاء اصطناعي عبر Groq LLaMA، وتقدم تقارير تقدم الفحص في الوقت الفعلي عبر WebSocket، وتدعم تحليل الأوامر الطبيعية بالعربية والإنجليزية، مع توليد تقارير PDF احترافية، ونظام مصادقة JWT متكامل بصلاحيات متعددة المستويات — كل ذلك من خلال لوحة تحكم ويب أنيقة وواجهة برمجية REST موثقة بالكامل.

## 🔗 العرض التجريبي المباشر

**[optisec-recon-pro.onrender.com](https://optisec-recon-pro.onrender.com)**

بيانات الدخول التجريبية: اسم المستخدم `demo` / كلمة المرور `Demo@optisec1`

---

## الميزات الرئيسية

### وحدات الفحص الـ 13

| # | الوحدة | الوصف |
|---|--------|-------|
| 1 | **اكتشاف النطاقات الفرعية** | اكتشاف النطاقات الفرعية عبر القوائم والـ DNS |
| 2 | **بحث DNS** | استعلام سجلات A و MX و NS و TXT و CNAME و SOA |
| 3 | **بحث WHOIS** | معلومات المسجّل وتواريخ الإنشاء والانتهاء |
| 4 | **فحص المنافذ Nmap** | اكتشاف الخدمات والإصدارات |
| 5 | **تحليل SSL/TLS** | صحة الشهادة، انتهاء الصلاحية، مجموعات التشفير |
| 6 | **رؤوس HTTP الأمنية** | CSP و HSTS و X-Frame-Options وغيرها |
| 7 | **فحص المنافذ السريع** | مسح TCP سريع مع تحديد الخدمات |
| 8 | **كشف XSS** | حقن البرمجة عبر المواقع المنعكسة |
| 9 | **حقن SQL** | كشف SQLi القائم على الأخطاء والبوليان |
| 10 | **كشف SSRF** | طلبات المصدر من جانب الخادم |
| 11 | **كشف LFI** | تضمين الملفات المحلية عبر اجتياز المسار |
| 12 | **إعادة التوجيه المفتوح** | كشف معاملات إعادة التوجيه غير المُتحقق منها |
| 13 | **OSINT** | جمع البريد الإلكتروني والملفات الاجتماعية |

### الذكاء الاصطناعي عبر Groq
- إرسال نتائج الفحص إلى **Groq LLaMA-3.3-70b** للتحليل المعمّق
- تقرير منظم يشمل: تقييم التهديدات، ربط CVE، إعادة بناء سلسلة الهجوم، وأولويات الإصلاح
- يدعم الإخراج بالعربية والإنجليزية

### تقدم الفحص في الوقت الفعلي (WebSocket)
- الاتصال بـ `ws://host/ws/scan/{scan_id}` لاستقبال تحديثات الفحص الفورية
- كل وحدة ترسل تقدمها الخاص بشكل مستقل
- لا حاجة للاستطلاع (polling) — واجهة المستخدم تتحدث تلقائياً

### تقارير PDF الاحترافية
- تقارير PDF احترافية توليد تلقائي عبر ReportLab
- تشمل: ملخصاً تنفيذياً، جدول ثغرات، نتائج OSINT، توصيات الإصلاح
- قابلة للتحميل من صفحة التقارير أو عبر `GET /reports/download/{filename}`

### واجهة الأوامر الطبيعية بالعربية (NLP)
- إرسال أوامر بالعربية أو الإنجليزية إلى `/api/nlp`
- أمثلة:
  - `افحص tesla.com عن ثغرات XSS` ← يشغّل فحص XSS
  - `اجمع النطاقات الفرعية لـ google.com` ← يشغّل تعداد النطاقات
  - `ابدأ فحص شامل وأنشئ تقرير` ← فحص كامل وتقرير
- يستخدم Groq AI أولاً، ثم يرجع إلى المحلل المحلي عند الحاجة

### المصادقة JWT وإدارة الصلاحيات
| الدور | الصلاحيات |
|-------|-----------|
| `admin` | وصول كامل — إدارة المستخدمين، جميع الفحوصات، التحكم بالترخيص |
| `analyst` | تشغيل الفحوصات، عرض جميع النتائج، إنشاء التقارير |
| `viewer` | وصول للقراءة فقط لفحوصاته ونتائجه الخاصة |

---

## التقنيات المستخدمة

| الطبقة | التقنية |
|--------|---------|
| **الإطار الخلفي** | FastAPI (async) + Uvicorn |
| **قاعدة البيانات** | SQLite (تطوير) / PostgreSQL 16 (إنتاج) |
| **المصادقة** | JWT (python-jose) + تجزئة bcrypt |
| **الذكاء الاصطناعي** | Groq API — LLaMA-3.3-70b |
| **WebSocket** | FastAPI WebSocket + مدير اتصالات مخصص |
| **الفحص** | Nmap، dnspython، python-whois، httpx، BeautifulSoup4 |
| **التقارير** | ReportLab لتوليد PDF |
| **تحليل اللغة الطبيعية** | Groq LLaMA + محلل محلي عربي/إنجليزي |
| **التشفير** | AES-GCM ما بعد الكم (PQC) |
| **CLI** | Click + Rich |
| **الحاويات** | Docker + Docker Compose |
| **النشر** | Render.com / Railway |

---

## الإعداد المحلي

### المتطلبات الأساسية
- Python 3.12 أو أحدث
- `nmap` مثبت على النظام (`apt install nmap`)
- مفتاح Groq API (مجاني من [console.groq.com](https://console.groq.com)) — اختياري لتفعيل ميزات الذكاء الاصطناعي

### 1. استنساخ المشروع وإنشاء البيئة الافتراضية

```bash
git clone https://github.com/OptisecDev/optisec-recon-pro.git
cd optisec-recon-pro
python -m venv venv
source venv/bin/activate
```

### 2. تثبيت المتطلبات

```bash
pip install -r requirements.txt
```

### 3. إعداد متغيرات البيئة

```bash
cp .env.example .env
```

قم بتعديل ملف `.env`:

```env
JWT_SECRET=غيّر-هذا-لمفتاح-عشوائي
GROQ_API_KEY=gsk_...
FIRST_ADMIN_USER=admin
FIRST_ADMIN_PASSWORD=StrongPass@1
```

### 4. تشغيل خادم التطوير

```bash
python main.py web --reload
```

افتح **http://localhost:8000** في المتصفح.
توثيق API متاح على **http://localhost:8000/docs**.

---

## النشر عبر Docker

### تشغيل سريع (حاوية واحدة)

```bash
docker build -t optisec-recon-pro .
docker run -d \
  -p 8000:8000 \
  -e JWT_SECRET=your-secret \
  -e GROQ_API_KEY=gsk_... \
  -v optisec_data:/app/data \
  -v optisec_reports:/app/reports \
  --name optisec \
  optisec-recon-pro
```

### بيئة الإنتاج الكاملة (PostgreSQL + Redis + Nginx)

```bash
cp .env.example .env        # أضف كلمات المرور والمفاتيح
docker compose up -d --build
docker compose logs -f app
```

---

## الترخيص

**برنامج احتكاري — جميع الحقوق محفوظة**

حقوق النشر © 2024–2026 OPTISEC. جميع الحقوق محفوظة.

هذا البرنامج وكوده المصدري هما ملك حصري لـ OPTISEC. لا يجوز نسخ أي جزء من هذا البرنامج أو تعديله أو توزيعه أو الترخيص من الباطن له أو استخدامه بأي شكل من الأشكال دون الحصول على إذن مسبق وخطي من OPTISEC.

للتواصل: ahssanali84.syber@gmail.com

</div>
