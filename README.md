# 🛡️ ARIA — Advanced Real-time Investigation Assistant

> **AI-powered SOC analyst that thinks like a top-tier threat hunter.** Built for the modern Security Operations Center — with full MITRE ATT&CK coverage and India DPDP Act 2023 compliance awareness.

[![Deploy with Vercel](https://vercel.com/button)](https://vercel.com/new/clone?repository-url=https://github.com/YOUR_USERNAME/aria-siem&env=ANTHROPIC_API_KEY&envDescription=Your%20Anthropic%20API%20key&envLink=https://console.anthropic.com/)

---

## 🚨 The Problem

Security Operations Centers are drowning. A mid-sized enterprise generates **10,000+ security alerts per day**. Analysts spend 70% of their time on manual triage — reading alerts, correlating events, writing detection queries — instead of actually stopping attacks.

**The average attacker dwell time in India is 89 days. ARIA cuts that to minutes.**

---

## 💡 What ARIA Does

ARIA is an AI-powered SIEM co-pilot that:

- **Streams live security alerts** and maps them to the full MITRE ATT&CK kill chain in real time
- **Answers natural language questions** about any active incident — no query language needed
- **Correlates across all alerts simultaneously** to reconstruct the attacker's full story
- **Generates ready-to-deploy KQL** for Microsoft Sentinel with syntax highlighting
- **Flags DPDP Act 2023 implications** automatically when PII exfiltration is detected
- **Builds an Investigation Notebook** — bookmarks every finding for handoff and reporting

---

## 🎯 Key Features

| Feature | Description |
|---|---|
| 🔴 Live Kill Chain Bar | Visual MITRE ATT&CK phase tracker — lights up as attack progresses |
| 🤖 ARIA AI Analyst | Claude-powered SOC analyst with full alert context |
| ⚡ Quick Actions | One-click investigation playbooks for common scenarios |
| 🔍 Entity Extraction | Auto-surfaces IPs, users, hosts from AI responses |
| 📋 Investigation Notebook | Persistent session log for analyst handoffs |
| 🇮🇳 DPDP Compliance | India Data Protection & Digital Privacy Act 2023 awareness |
| 📊 KQL Generation | Microsoft Sentinel queries with full syntax highlighting |

---

## 🚀 Deploy to Vercel (5 minutes)

### Option A — One-Click Deploy
Click the **Deploy with Vercel** button above. When prompted, set `ANTHROPIC_API_KEY` to your key from [console.anthropic.com](https://console.anthropic.com).

### Option B — Manual Deploy

**1. Clone & install**
```bash
git clone https://github.com/YOUR_USERNAME/aria-siem
cd aria-siem
npm install
```

**2. Set your API key locally**
```bash
cp .env.example .env.local
# Edit .env.local and add your ANTHROPIC_API_KEY
```

**3. Run locally**
```bash
npm run dev
# Open http://localhost:5173
```

**4. Deploy to Vercel**
```bash
npm install -g vercel
vercel
# Follow prompts — set ANTHROPIC_API_KEY as environment variable
```

---

## 🏗️ Architecture

```
aria-siem/
├── api/
│   └── aria.js          # Vercel serverless proxy (keeps API key secure)
├── src/
│   ├── ARIAApp.jsx      # Main React application
│   └── main.jsx         # Entry point
├── index.html           # App shell + design tokens
├── vercel.json          # Vercel routing config
└── vite.config.js       # Build config
```

**Why a backend proxy?**  
The Anthropic API key lives in Vercel's environment variables — never exposed to the browser. All AI calls go through `POST /api/aria`, which is a Vercel serverless function. This is production-grade security.

---

## 🎬 Demo Walkthrough (for judges)

**1. Watch the Kill Chain** — 20 alerts stream in over ~2 seconds, lighting up all 11 MITRE ATT&CK phases from Execution to Impact.

**2. ARIA auto-briefs** — Once loaded, ARIA immediately briefs you on the incident: APT group compromised `j.chen`'s laptop, pivoted to DC01, exfiltrated 4.7 GB of Finance/HR/Legal data, then deployed ransomware.

**3. Quick Action: "Trace the full attack chain"** — Shows every alert mapped to MITRE technique IDs (T1059, T1055, T1078, etc.)

**4. Quick Action: "What data was exfiltrated?"** — ARIA flags DPDP Act 2023 implications for the stolen HR/Finance data.

**5. Quick Action: "Generate C2 detection KQL"** — Live KQL query with syntax highlighting, ready to paste into Microsoft Sentinel.

**6. Click any alert** — ARIA deep-dives that specific event with forensic context.

---

## 🔒 Security & Compliance

- **API key never touches the browser** — serverless proxy pattern
- **India DPDP Act 2023** — ARIA automatically flags personal data breach obligations
- **No data persistence** — all analysis is in-memory, session-only

---

## 🛠️ Tech Stack

- **Frontend**: React 18 + Vite (zero dependencies beyond React)
- **AI**: Claude (claude-sonnet-4) via Anthropic API
- **Deployment**: Vercel (serverless functions + static hosting)
- **Styling**: Pure CSS-in-JS with design tokens — no UI library

---

## 🏆 Built for [Hackathon Name]

ARIA demonstrates how **generative AI transforms cybersecurity** — not by replacing analysts, but by giving them superhuman correlation speed. Every feature was designed around a real SOC analyst workflow.

**Team**: [Your Name]  
**Category**: AI for Security / Enterprise AI  
**Contact**: [your@email.com]
