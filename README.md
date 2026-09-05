# CloudNet ICES 🛡️
### Autonomous Integrated Cloud Email Security & Real-Time SOC Forensic Platform

[![Engine](https://img.shields.io/badge/AI_Engine-Gemini_3.6_Flash-9333ea?style=flat-square&logo=google)]()
[![Backend](https://img.shields.io/badge/Backend-FastAPI_AsyncPG-009688?style=flat-square&logo=fastapi)]()
[![Database](https://img.shields.io/badge/Database-Neon_PostgreSQL-00e599?style=flat-square&logo=postgresql)]()
[![Frontend](https://img.shields.io/badge/Frontend-React_18_TypeScript_Tailwind-38bdf8?style=flat-square&logo=react)]()
[![Remediation](https://img.shields.io/badge/Remediation-Google_Workspace_API-ea4335?style=flat-square&logo=gmail)]()

**CloudNet ICES** (Integrated Cloud Email Security) is an autonomous, zero-trust cloud email security platform built to intercept advanced Business Email Compromise (BEC), Executive Impersonation, QR-Code Phishing (Quishing), and Unencrypted Plaintext Communication before attackers compromise enterprise mailboxes.

---

## 🌟 Architecture & Core Capabilities

```
                  ┌────────────────────────────────────────────────────────┐
                  │          INCOMING CLOUD MAIL STREAM (GMAIL API)        │
                  └───────────────────────────┬────────────────────────────┘
                                              │
                                              ▼
                  ┌────────────────────────────────────────────────────────┐
                  │            MIME PARSER & ATTACHMENT SCANNER            │
                  │   • RFC-822 Extraction     • QR Code Optical Decoder   │
                  │   • SPF / DKIM / DMARC     • Inline Base64 OCR Stream  │
                  └───────────────────────────┬────────────────────────────┘
                                              │
                                              ▼
                  ┌────────────────────────────────────────────────────────┐
                  │             INTELLIGENCE & AI ANALYSIS LAYER           │
                  │   • Gemini 3.6 Flash Zero-Shot BEC Intent Engine       │
                  │   • VIP Homoglyph & Display Name Spoofing Detector     │
                  │   • Smtp Relay Hop GeoIP & Tor Exit Node Inspection    │
                  │   • Composite Threat Scoring (0 - 100 Scale)           │
                  └───────────────────────────┬────────────────────────────┘
                                              │
                         ┌────────────────────┴────────────────────┐
                         │                                         │
             [ Threat Score >= 80 ]                       [ Threat Score < 80 ]
                         │                                         │
                         ▼                                         ▼
        ┌──────────────────────────────────┐      ┌──────────────────────────────────┐
        │   AUTONOMOUS REMEDIATION ENGINE  │      │     INBOX PROTECTION ENGINE      │
        │ • Dynamic [SUSPICIOUS] Tagging   │      │ • Passive Telemetry Ingestion    │
        │ • Inline Security Warning Banner │      │ • Baseline Behavioral Profiling  │
        │ • 1-Click Cluster Quarantine     │      │ • Zero Latency Mailbox Access    │
        └──────────────────────────────────┘      └──────────────────────────────────┘
```

---

## 🚀 Key Features & Detections

### 1. Zero-Shot Gemini AI Threat Decomposition
* **LLM Engine**: Powered by Google **Gemini 3.6 Flash** with deep chain-of-thought intent reasoning.
* **BEC Classification**: Autonomous identification of Executive Impersonation, Urgent Wire Fraud, Payroll Diversion, and Supplier Invoice Alteration.
* **Entity Extraction**: Auto-extracts beneficiary names, bank routing numbers, accounts, and requested amounts ($USD).
* **Concurrency Semaphore & 429 Backoff**: Outbound request throttling with exponential retry guarantees zero dropped analyses.

### 2. QR Code Phishing (Quishing) & Insecure HTTP Interception
* **Optical QR Decoding**: Scans raw image attachments and inline base64 image streams to extract obfuscated destination URLs.
* **Unencrypted HTTP Interception**: Flags plaintext `http://` links (e.g. `httpforever.com`) susceptible to Man-in-the-Middle (MITM) credential interception, scoring threats at `90 (CRITICAL)` with instant quarantine.

### 3. Smtp Relay Traversal & GeoIP Telemetry
* **Hop-by-Hop Trace**: Parses `Received:` headers back to the originating IP address.
* **Autonomous Flagging**: Pinpoints Tor exit relays, unverified VPS hosting relays, and cross-border geographic anomalies.
* **RFC Authentication Matrix**: Granular status evaluation for `SPF`, `DKIM`, and `DMARC` alignment.

### 4. Non-Destructive Live Mailbox Remediation
* **Dynamic Gmail Label Provisioning**: Automatically generates and attaches the high-contrast `[SUSPICIOUS]` tag badge directly inside the user inbox.
* **Inline Threat Banners**: Generates executive HTML warning badges prepended to risky messages with an active `Report Phish to SOC` callback.
* **1-Click Cluster Quarantine (Search & Destroy)**: SOC analysts can purge matching threat clusters across all mailboxes in under 200ms.

### 5. Palantir-Grade Monolithic SOC Cockpit
* **Sub-50ms Response Time**: Instant database-first retrieval from Neon PostgreSQL with non-blocking background mailbox scanning.
* **Frame-0 Hydration**: Local storage caching ensures zero screen freezes on initial dashboard launch.
* **Keyboard-First Navigation**: Use `Up / Down` or `J / K` to cycle through alerts, `Q` to Quarantine, and `R` to Release.
* **Live Token Accounting**: Real-time telemetry monitoring Prompt Tokens, Output Tokens, and cumulative API costs ($USD).

---

## 🛠️ Technology Stack

### Backend
| Layer | Technology | Purpose |
| :--- | :--- | :--- |
| **Framework** | **FastAPI (Python 3.11)** | High-performance asynchronous REST API. |
| **Server** | **Uvicorn** | ASGI server with hot-reload and background worker tasks. |
| **Database** | **PostgreSQL (Neon Serverless)** / **AsyncPG** | Async relational persistence with connection pooling. |
| **ORM** | **SQLAlchemy 2.0 (Async)** | Non-blocking schema definitions and CRUD abstraction. |
| **Cloud Mail API** | **Google Workspace API / OAuth2** | Non-destructive label modification and raw EML retrieval. |
| **AI / LLM** | **Google Gemini 3.6 Flash** | Deep reasoning zero-shot intent and BEC decomposition. |
| **GeoIP / Network** | **MaxMind GeoIP2** | Originating IP ASN, ISP, and geographic geolocation. |

### Frontend
| Layer | Technology | Purpose |
| :--- | :--- | :--- |
| **Framework** | **React 18** + **TypeScript** | Type-safe declarative component architecture. |
| **Bundler** | **Vite** | Sub-second HMR and production bundle optimization. |
| **Styling** | **Tailwind CSS** | Industrial Cyber-Minimalism design system. |
| **Visual Forensics**| **@xyflow/react (ReactFlow)** | Node-graph visualizer for multi-hop SMTP relay tracing. |
| **Icons** | **Lucide React** | Clean, minimalist SVG iconography. |

---

## 📁 Repository Structure

```
ICES/
├── ICES-Backend/
│   ├── app/
│   │   ├── api/v1/endpoints/
│   │   │   ├── alerts.py            # Real-time alert ingestion, metrics & caching
│   │   │   ├── auth.py              # Google OAuth2 connect & callback flows
│   │   │   ├── remediation.py       # Quarantine, release, and cluster purge actions
│   │   │   ├── admin.py             # VIP directory & runtime configuration
│   │   │   └── forensics.py         # Raw EML & header analysis
│   │   ├── core/
│   │   │   └── config.py            # Pydantic v2 settings & environment variables
│   │   ├── db/
│   │   │   ├── base.py              # SQLAlchemy async engine & sessionmaker
│   │   │   ├── models.py            # EmailAlert, ForensicLog, NLPEvaluation models
│   │   │   └── crud.py              # High-performance async database operations
│   │   └── modules/
│   │       ├── ingestion/           # GmailClient & RFC-822 MIME parser
│   │       ├── intelligence/        # Gemini NLP, VIP Detector, Attachment Scanner
│   │       └── remediation/         # Warning Banner Engine & Remediation Actions
│   ├── requirements.txt             # Python dependencies
│   └── Procfile                     # Render production web service worker
│
└── ICES-Frontend/
    ├── src/
    │   ├── components/soc/
    │   │   ├── header.tsx           # SOC Cockpit header with live UTC clock & status
    │   │   ├── metrics-bar.tsx       # Palantir-style monolithic telemetry ribbon
    │   │   ├── alert-feed.tsx        # Dense threat stream with keyboard shortcuts
    │   │   ├── progressive-panel.tsx # Forensic Workbench & Attack Graph tabs
    │   │   └── webhook-simulator.tsx # BEC Attack Payload Simulation Matrix
    │   ├── types/ices.ts             # TypeScript definitions for alerts and tokens
    │   └── styles/globals.css        # Carbon Obsidian theme & active anchor blades
    ├── package.json
    └── vite.config.ts
```

---

## 🔌 Core API Endpoints

### 1. Alert Telemetry & Stream
- `GET /api/v1/alerts/`: Instantly returns persisted alerts (<50ms) and triggers background mailbox ingestion.
- `GET /api/v1/alerts/metrics`: Returns live SOC velocity, MTTR, threat breakdown, and Gemini AI Token Accounting stats.

### 2. Autonomous & Manual Remediation
- `POST /api/v1/remediation/execute`: Executes `QUARANTINE` (applies `[SUSPICIOUS]` tag) or `RELEASE` on live mailbox.
- `POST /api/v1/remediation/cluster-purge`: 1-Click Search & Destroy across all enterprise mailboxes.
- `GET /api/v1/remediation/report-phish`: User-facing callback confirmation portal for reported suspicious messages.

### 3. Google Workspace OAuth2 Lifecycle
- `GET /api/v1/auth/google/authorize`: Initiates Google OAuth2 consent flow with Gmail modify scopes.
- `GET /api/v1/auth/google/callback`: Exchanges authorization code and securely persists encrypted tokens in Neon PostgreSQL.

---

## ⚙️ Environment Variables

### Backend (`.env`)
```env
# Server
ENVIRONMENT=production
PROJECT_NAME="CloudNet ICES Forensic Engine"
PORT=8000

# Database
DATABASE_URL=postgresql+asyncpg://<user>:<password>@<host>/<dbname>?ssl=require

# Google Workspace OAuth & Gmail API
GOOGLE_CLIENT_ID=your-google-client-id.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=your-google-client-secret
GOOGLE_REDIRECT_URI=https://ices-backend.onrender.com/api/v1/auth/google/callback

# Gemini AI Engine
GEMINI_API_KEY=your-gemini-api-key
GEMINI_MODEL_NAME=gemini-3.6-flash

# Endpoints
FRONTEND_URL=https://ices-frontend.vercel.app
REPORT_CALLBACK_URL=https://ices-backend.onrender.com/api/v1/remediation/report-phish
```

### Frontend (`.env`)
```env
VITE_API_URL=https://ices-backend.onrender.com/api/v1
```

---

## 💻 Local Development Setup

### 1. Start Backend
```bash
cd ICES-Backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

### 2. Start Frontend
```bash
cd ICES-Frontend
npm install
npm run dev
```

Open `http://localhost:5173` in your browser.

---

## 🛡️ License & Compliance
Built under the **MIT License**. Compliant with zero-trust cloud email security standards, RFC-822 / RFC-5322 header formats, and Google Workspace security API policies.
