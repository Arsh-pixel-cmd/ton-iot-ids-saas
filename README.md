# ToN-IoT IDS  🛡️⚡

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![React](https://img.shields.io/badge/React-19.2-61dafb?logo=react&logoColor=black)](https://react.dev/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.9-3178c6?logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-Python-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![TailwindCSS](https://img.shields.io/badge/TailwindCSS-v4-38bdf8?logo=tailwindcss&logoColor=white)](https://tailwindcss.com/)
[![tRPC](https://img.shields.io/badge/tRPC-v11-25c2a0?logo=trpc&logoColor=white)](https://trpc.io/)
[![Drizzle ORM](https://img.shields.io/badge/Drizzle_ORM-MySQL-c5f74f?logo=drizzle&logoColor=black)](https://orm.drizzle.team/)
[![Vite](https://img.shields.io/badge/Vite-7.1-646cff?logo=vite&logoColor=white)](https://vitejs.dev/)

> **Next-Generation Cloud-Native Intrusion Detection System (NIDS) & Threat Intelligence Dashboard for IoT and Industry 4.0 Networks.**

ToN-IoT IDS SaaS is an end-to-end full-stack cybersecurity platform engineered to detect, classify, and mitigate cyber threats across heterogeneous Internet of Things (IoT) and Industrial IoT (IIoT) environments. Calibrated on the benchmark **ToN-IoT** dataset, the system pairs a high-throughput **FastAPI + Scikit-Learn** inference microservice with an enterprise-ready **React 19 + Node.js + tRPC** analytics workspace.

---

## 🌟 Key Highlights

- **🎯 Machine Learning Anomaly Detection**: Powered by a calibrated Multilayer Perceptron (MLP) pipeline (`ton-iot-mlp-deduplicated-v1`) processing 19 raw flow telemetry fields into 41 engineered features with an optimal decision threshold of `0.85`.
- **🔄 Dual-Mode High Availability**: If the Python inference microservice is offline or experiencing latency, the backend automatically fails over to an integrated, zero-downtime heuristic scoring adapter.
- **🛡️ Strict Telemetry Contract**: Validates all incoming traffic against 19 standard ToN-IoT flow attributes before scoring to eliminate garbage-in, garbage-out risks.
- **📊 Real-Time SOC Analyst Dashboard**: Modern dark-accented glassmorphic dashboard with live threat metrics, severity-stratified alerts (`Critical`, `High`, `Medium`, `Low`), and chronological run auditing.
- **🏢 Multi-Tenant Workspace Architecture**: Built from the ground up with organization-level scoping, user authentication, and role-based access control (`owner`, `analyst`, `viewer`).
- **⚡ End-to-End Type Safety**: Shared schema contracts and RPC endpoints via **tRPC v11** and **Zod**, backed by **Drizzle ORM** and MySQL.

---

## 🏗️ Architecture & Data Flow

```mermaid
flowchart TD
    subgraph Client ["Client (React 19 + Vite + Tailwind CSS v4)"]
        UI["SOC Dashboard UI"]
        Upload["CSV Telemetry Upload (Max 5MB)"]
        Validation["Client-Side Contract Validation"]
    end

    subgraph Backend ["Application Server (Node.js + Express + tRPC)"]
        Router["tRPC Router & Middleware"]
        Auth["OAuth & Multi-Tenant Context"]
        InferenceAdapter{"Inference Manager"}
        Fallback["Built-in Heuristic Engine (Fallback)"]
    end

    subgraph MLService ["Inference Microservice (Python FastAPI)"]
        FastAPI["FastAPI /predict Endpoint"]
        Bundle["Model Bundle (ton_iot_production_bundle.joblib)"]
        Pipeline["Preprocessor (41 Features) + MLP Classifier"]
    end

    subgraph Database ["Persistence Layer (MySQL / MariaDB)"]
        Drizzle["Drizzle ORM"]
        Orgs[("Organizations & Users")]
        Runs[("Analysis Runs")]
        Alerts[("Alerts & Threat Logs")]
    end

    UI --> Upload
    Upload --> Validation
    Validation --> Router
    Router --> Auth
    Auth --> InferenceAdapter

    InferenceAdapter -->|Primary (HTTP POST)| FastAPI
    FastAPI --> Bundle
    Bundle --> Pipeline
    Pipeline -->|Probabilities & Labels| InferenceAdapter

    InferenceAdapter -.->|On Timeout / Failure| Fallback

    InferenceAdapter --> Drizzle
    Drizzle --> Runs
    Drizzle --> Alerts
    Drizzle --> Orgs
    Drizzle -.->|Summary & Alerts| UI
```

---

## 📋 ToN-IoT Feature Contract

Every network flow analyzed requires the 19 core ToN-IoT telemetry attributes. Additional network headers (`src_ip`, `dst_ip`) are captured for attribution and alert enrichment:

| Feature Name | Type | Description |
|---|---|---|
| `src_port` | Integer | Source port number |
| `dst_port` | Integer | Destination port number (flagged for known service exploits) |
| `proto` | String | Transport protocol (`tcp`, `udp`, `icmp`) |
| `service` | String | Application layer protocol (`http`, `dns`, `ssl`, `ftp`, etc.) |
| `duration` | Float | Flow duration in seconds |
| `src_bytes` | Integer | Total bytes transferred from source to destination |
| `dst_bytes` | Integer | Total bytes transferred from destination to source |
| `conn_state` | String | Connection state (e.g., `SF`, `REJ`, `S0`, `RSTO`, `RSTR`) |
| `missed_bytes` | Integer | Number of missed/dropped bytes in transmission |
| `src_pkts` | Integer | Packet count from source |
| `src_ip_bytes` | Integer | IP payload bytes from source |
| `dst_pkts` | Integer | Packet count from destination |
| `dst_ip_bytes` | Integer | IP payload bytes from destination |
| `dns_qclass` | Integer | DNS query class identifier |
| `dns_qtype` | Integer | DNS query record type (A, AAAA, MX, TXT) |
| `dns_rcode` | Integer | DNS response return code |
| `http_request_body_len` | Integer | HTTP request payload length in bytes |
| `http_response_body_len` | Integer | HTTP response payload length in bytes |
| `http_status_code` | Integer | HTTP return status code (`200`, `404`, `500`, etc.) |

---

## 🧰 Tech Stack

### Frontend
- **React 19** & **Vite 7**
- **Tailwind CSS v4** & **Radix UI** primitives
- **tRPC React Query** (@tanstack/react-query v5)
- **Lucide Icons** & **Sonner** notifications
- **Recharts** & **Framer Motion** for analytics and animations

### Backend
- **Node.js** with **Express**
- **tRPC Server v11** with **Zod** schema validation
- **Drizzle ORM** connecting to **MySQL / MariaDB**
- Session cookies with **Jose** JWT authentication

### Machine Learning Microservice
- **Python 3.10+** & **FastAPI** / **Uvicorn**
- **Scikit-Learn**, **Pandas**, and **Joblib**
- Bundled preprocessor and calibrated MLP classifier (`ton-iot-mlp-deduplicated-v1`)

---

## 📂 Project Structure

```text
ton-iot-ids-saas/
├── client/                     # Frontend React application
│   ├── src/
│   │   ├── components/         # Dashboard layout, UI cards, dialogs
│   │   ├── hooks/              # Auth and workspace context hooks
│   │   ├── pages/              # Home (SOC dashboard) & 404 pages
│   │   ├── lib/                # tRPC and query client setup
│   │   └── App.tsx             # Root router and layout container
├── server/                     # Backend API & Business logic
│   ├── db.ts                   # Drizzle database client & helper queries
│   ├── inference.ts            # Dual-mode inference caller & fallback adapter
│   ├── routers.ts              # tRPC app router (auth, workspace, analysis)
│   ├── oauth.ts                # OAuth and authentication routes
│   └── index.ts                # Express server entry point & port resolver
├── inference-service/          # Python FastAPI ML microservice
│   ├── app.py                  # FastAPI /health and /predict endpoints
│   ├── requirements.txt        # Python dependencies
│   ├── ton_iot_input_schema.json # Schema contract specification
│   └── ton_iot_production_bundle.joblib # Serialized model & preprocessor
├── drizzle/                    # Database migrations & schemas
│   ├── schema.ts               # Users, Orgs, AnalysisRuns, Alerts tables
│   └── 0001_*.sql              # SQL migration snapshots
├── shared/                     # Shared types and constants across client/server
├── package.json                # Project scripts and dependencies
└── tsconfig.json               # TypeScript configuration
```

---

## 🚀 Getting Started

### Prerequisites

- **Node.js** (v20+ recommended)
- **pnpm** (v9+ or v10)
- **Python** (v3.10 or v3.11)
- **MySQL** or **MariaDB** database

---

### Step 1: Clone & Install Dependencies

```bash
git clone https://github.com/your-username/ton-iot-ids-saas.git
cd ton-iot-ids-saas

# Install Node dependencies
pnpm install
```

---

### Step 2: Start the Python ML Inference Service

In a separate terminal window:

```bash
cd inference-service

# Create and activate a virtual environment
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install requirements
pip install -r requirements.txt

# Launch FastAPI on port 8000
uvicorn app:app --host 127.0.0.1 --port 8000 --reload
```

Test that the service is running:
```bash
curl http://127.0.0.1:8000/health
# Returns: {"status":"ok","model_version":"ton-iot-mlp-deduplicated-v1",...}
```

---

### Step 3: Configure Environment Variables

Create a `.env` file in the root directory:

```env
NODE_ENV=development
PORT=3000

# Database Connection (MySQL / MariaDB)
DATABASE_URL=mysql://username:password@localhost:3306/ton_iot_ids

# Inference Microservice Endpoint
INFERENCE_SERVICE_URL=http://127.0.0.1:8000

# Authentication & Session Security
JWT_SECRET=super-secret-key-change-this-in-production
VITE_APP_ID=ton-iot-ids-saas
```

---

### Step 4: Run Database Migrations

Apply the Drizzle schemas to your MySQL database:

```bash
pnpm db:push
```

---

### Step 5: Start the Full-Stack Application

```bash
pnpm dev
```

The application will be live at `http://localhost:3000`.

---

## 🧪 Testing

Run unit and integration tests (including the dual-mode inference tests and fallback verification):

```bash
pnpm test
```

To run continuous test watching:
```bash
npx vitest
```

---

## 🛡️ Threat Severity Matrix

Alerts detected by the engine are categorized by confidence probability score:

| Severity Level | Attack Probability Range | Action Recommendation |
|---|---|---|
| **Critical** | $\ge 98.0\%$ | Immediate host isolation / firewall block rule creation |
| **High** | $92.0\% - 97.9\%$ | SOC analyst review and endpoint telemetry inspection |
| **Medium** | $85.0\% - 91.9\%$ | Connection throttling and rate-limit audit |
| **Low / Normal** | $< 85.0\%$ | Logged for baselining; no immediate alert triggered |

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).
