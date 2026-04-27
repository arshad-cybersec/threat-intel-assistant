# 🛡️ Threat Intelligence Assistant



AI-powered cybersecurity threat intelligence API built with **FastAPI** and **Claude (Anthropic)**. Analyze IOCs, CVEs, malware samples, and raw threat data with natural language intelligence.

---

## Features

- **IOC Analysis** — Analyze IPs, domains, URLs, file hashes, and emails
- **CVE Analysis** — Get severity, affected systems, and remediation for any CVE
- **Malware Analysis** — Classify samples, extract IOCs, map to MITRE ATT&CK
- **Threat Reports** — Transform raw logs and alerts into structured intelligence reports
- **Chat Interface** — Multi-turn conversational threat intelligence Q&A
- **MITRE ATT&CK Mapping** — Automatic technique identification (T####)

---

## Quick Start

### 1. Clone & install

```bash
git clone https://github.com/YOUR_USERNAME/threat-intel-assistant.git
cd threat-intel-assistant

python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

pip install -r requirements.txt
```

### 2. Configure environment

```bash
cp .env.example .env
# Edit .env and add your ANTHROPIC_API_KEY
```

Get your API key at: https://console.anthropic.com

### 3. Run the server

```bash
uvicorn app.main:app --reload
```

API available at: http://localhost:8000
Interactive docs: http://localhost:8000/docs

---

## API Endpoints

### Chat
```
POST /chat/
```
```json
{
  "message": "What are the most common phishing techniques in 2024?",
  "history": []
}
```

### Analyze IOC
```
POST /analyze/ioc
```
```json
{
  "indicator": "185.220.101.45",
  "ioc_type": "ip",
  "context": "Found in firewall logs attempting SSH brute force"
}
```

### Analyze CVE
```
POST /analyze/cve
```
```json
{
  "cve_id": "CVE-2024-1234",
  "context": "Running Apache 2.4.51 on Ubuntu 22.04"
}
```

### Analyze Malware
```
POST /analyze/malware
```
```json
{
  "sample_info": "d41d8cd98f00b204e9800998ecf8427e",
  "behavior": "Creates persistence via registry run key, beacons to C2 every 60 seconds"
}
```

### Generate Threat Report
```
POST /analyze/report
```
```json
{
  "raw_data": "2024-01-15 03:42:11 ALERT: Multiple failed SSH logins from 192.168.1.105...",
  "environment": "AWS cloud environment, Ubuntu servers"
}
```

---

## Project Structure

```
threat-intel-assistant/
├── app/
│   ├── main.py              # FastAPI app, CORS, router registration
│   ├── config.py            # Settings from environment variables
│   ├── routes/
│   │   ├── chat.py          # Conversational AI endpoint
│   │   └── analyze.py       # IOC, CVE, malware, report endpoints
│   ├── services/
│   │   └── claude_service.py  # All Claude API interactions
│   └── models/
│       └── schemas.py       # Pydantic request/response models
├── .env.example
├── .gitignore
├── requirements.txt
└── README.md
```

---

## Tech Stack

| Component | Technology |
|-----------|-----------|
| API Framework | FastAPI |
| AI Model | Claude (claude-sonnet-4-6) |
| Validation | Pydantic v2 |
| Server | Uvicorn |
| Language | Python 3.11+ |

---

## Contributing

PRs welcome! Open an issue first for major changes.

## License

MIT
