import { useState, useEffect, useRef, useCallback } from "react";

// ═══════════════════════════════════════════════════════════════════════════════
//  ALERT DATASET — realistic 20-event APT → Ransomware kill chain
// ═══════════════════════════════════════════════════════════════════════════════
const ALERTS = [
  { id:"A001", ts:"14:02:33", sev:"medium",   cat:"execution",       rule:"Malicious Office Macro Executed",              host:"LAPTOP-CHEN",  user:"j.chen",         src:"10.2.1.55",   dst:null,           details:"Word doc 'Invoice_Q4_2024.docx' executed obfuscated PowerShell via WMI spawn" },
  { id:"A002", ts:"14:04:58", sev:"high",     cat:"c2",              rule:"PowerShell Downloads Remote Payload",          host:"LAPTOP-CHEN",  user:"j.chen",         src:"10.2.1.55",   dst:"185.220.101.47",details:"Encoded PS command: IEX(New-Object Net.WebClient).DownloadString — retrieved beacon.exe" },
  { id:"A003", ts:"14:07:12", sev:"high",     cat:"c2",              rule:"Outbound C2 Beacon — Cobalt Strike JA3",       host:"LAPTOP-CHEN",  user:"j.chen",         src:"10.2.1.55",   dst:"185.220.101.47",details:"Regular 60s TLS beacon to 185.220.101.47:443; JA3 hash matches Cobalt Strike profile" },
  { id:"A004", ts:"14:12:45", sev:"medium",   cat:"discovery",       rule:"Internal Network Enumeration",                 host:"LAPTOP-CHEN",  user:"j.chen",         src:"10.2.1.55",   dst:null,           details:"TCP SYN scan across 10.2.0.0/16 — 3,200 probes/min; ports 22,135,445,3389" },
  { id:"A005", ts:"14:23:11", sev:"critical", cat:"cred-access",     rule:"LSASS Memory Access — Credential Dumping",     host:"LAPTOP-CHEN",  user:"j.chen",         src:"10.2.1.55",   dst:null,           details:"Non-system process opened LSASS handle: C:\\Windows\\Temp\\.svcupdate.exe (PID 3847)" },
  { id:"A006", ts:"14:24:30", sev:"high",     cat:"cred-access",     rule:"Password Spray via SMB — 147 Failures",        host:"DC01",         user:"*",              src:"10.2.1.55",   dst:"10.2.0.1",     details:"147 SMB auth failures against DC01 in 90s from LAPTOP-CHEN; accounts: admin, svc_backup, svc_sql" },
  { id:"A007", ts:"14:31:04", sev:"critical", cat:"lateral",         rule:"Pass-the-Hash Authentication Detected",        host:"DC01",         user:"svc_backup",     src:"10.2.1.55",   dst:"10.2.0.1",     details:"NTLM type 3 with RC4 HMAC — stolen hash for svc_backup; origin workstation LAPTOP-CHEN" },
  { id:"A008", ts:"14:33:22", sev:"high",     cat:"lateral",         rule:"Remote Service Created on Domain Controller",  host:"DC01",         user:"svc_backup",     src:"10.2.1.55",   dst:"10.2.0.1",     details:"Service 'WinUpdateSvc' created on DC01 remotely via SCM; binary path: \\\\LAPTOP-CHEN\\IPC$" },
  { id:"A009", ts:"14:45:18", sev:"critical", cat:"privesc",         rule:"New Domain Admin Account Created",             host:"DC01",         user:"svc_backup",     src:null,          dst:null,           details:"Account 'adm_helpdesk01' created and added to 'Domain Admins' group by svc_backup" },
  { id:"A010", ts:"14:47:55", sev:"high",     cat:"privesc",         rule:"Default Domain Policy Modified",               host:"DC01",         user:"adm_helpdesk01", src:null,          dst:null,           details:"GPO edit: Defender real-time protection disabled; Windows audit logging reduced to minimal" },
  { id:"A011", ts:"14:50:02", sev:"critical", cat:"defense-evasion", rule:"AV Exclusions Pushed via GPO — All Endpoints", host:"DC01",         user:"adm_helpdesk01", src:null,          dst:null,           details:"Defender exclusion for C:\\Windows\\Temp\\* and C:\\ProgramData\\* applied domain-wide via GPO" },
  { id:"A012", ts:"14:52:40", sev:"medium",   cat:"defense-evasion", rule:"Security Event Logs Cleared on DC",            host:"DC01",         user:"adm_helpdesk01", src:null,          dst:null,           details:"Security and System event logs cleared on DC01; wevtutil cl Security && wevtutil cl System" },
  { id:"A013", ts:"14:58:33", sev:"high",     cat:"collection",      rule:"Mass File Enumeration on File Server",         host:"FILESVR-01",   user:"adm_helpdesk01", src:"10.2.5.20",   dst:null,           details:"Recursive enumeration: \\\\FILESVR-01\\Finance, \\HR, \\Legal, \\Executive — 2.3M files indexed" },
  { id:"A014", ts:"15:03:18", sev:"critical", cat:"collection",      rule:"4.7 GB Data Staged in Temp Directory",         host:"FILESVR-01",   user:"adm_helpdesk01", src:null,          dst:null,           details:"archive.zip (4.7 GB) created in C:\\Windows\\Temp\\ — contains Finance, HR and Legal documents" },
  { id:"A015", ts:"15:11:44", sev:"critical", cat:"exfil",           rule:"Large Outbound Transfer — Threat Intel Hit",   host:"FILESVR-01",   user:"adm_helpdesk01", src:"10.2.5.20",   dst:"45.33.32.156", details:"4.7 GB HTTPS upload to 45.33.32.156 (flagged: Mandiant, CrowdStrike, AlienVault OTX)" },
  { id:"A016", ts:"15:13:10", sev:"high",     cat:"exfil",           rule:"DNS Tunneling — Anomalous TXT Query Volume",   host:"LAPTOP-CHEN",  user:"j.chen",         src:"10.2.1.55",   dst:null,           details:"3,200 TXT queries to *.c2-relay.update-cdn.net; avg length 180 chars; encoding suspected" },
  { id:"A017", ts:"15:15:30", sev:"high",     cat:"persistence",     rule:"Malicious Scheduled Task — Mimics Edge",       host:"DC01",         user:"adm_helpdesk01", src:null,          dst:null,           details:"Task 'MicrosoftEdgeUpdateTaskMachineCore' created; runs C:\\Windows\\Temp\\.svcupdate.exe every 15 min" },
  { id:"A018", ts:"15:18:22", sev:"medium",   cat:"persistence",     rule:"Registry Run Key Modified for Persistence",    host:"LAPTOP-CHEN",  user:"j.chen",         src:null,          dst:null,           details:"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run → 'SvcHostHelper' = C:\\ProgramData\\svchost32.exe" },
  { id:"A019", ts:"15:24:05", sev:"critical", cat:"impact",          rule:"VSS Shadow Copies Deleted — Ransomware Prep",  host:"DC01",         user:"adm_helpdesk01", src:null,          dst:null,           details:"vssadmin delete shadows /all /quiet executed across domain via GPO; backup recovery destroyed" },
  { id:"A020", ts:"15:28:47", sev:"critical", cat:"impact",          rule:"RANSOMWARE CONFIRMED — Mass File Encryption",  host:"FILESVR-01",   user:"SYSTEM",         src:null,          dst:null,           details:"23,847 files renamed to *.locked in 90 seconds. EDR kernel sensor confirms encryption loop." },
];

const PHASE_MAP = {
  execution: "Execution", c2: "C2", discovery: "Discovery",
  "cred-access": "Cred Access", lateral: "Lateral Movement",
  privesc: "Privilege Esc", "defense-evasion": "Defense Evasion",
  collection: "Collection", exfil: "Exfiltration",
  persistence: "Persistence", impact: "Impact",
};

const KILL_CHAIN = [
  { id:"c2",              label:"Command & Control", color:"#EF9F27" },
  { id:"execution",       label:"Execution",         color:"#D85A30" },
  { id:"discovery",       label:"Discovery",         color:"#378ADD" },
  { id:"cred-access",     label:"Credential Access", color:"#D85A30" },
  { id:"lateral",         label:"Lateral Movement",  color:"#E24B4A" },
  { id:"privesc",         label:"Priv. Escalation",  color:"#E24B4A" },
  { id:"defense-evasion", label:"Defense Evasion",   color:"#A32D2D" },
  { id:"collection",      label:"Collection",        color:"#A32D2D" },
  { id:"exfil",           label:"Exfiltration",      color:"#A32D2D" },
  { id:"persistence",     label:"Persistence",       color:"#D85A30" },
  { id:"impact",          label:"Impact",            color:"#A32D2D" },
];

const QUICK_ACTIONS = [
  { label: "Trace the full attack chain",       q: "Walk me through the complete attack chain from initial access to ransomware. Map each event to MITRE ATT&CK techniques." },
  { label: "Hunt for persistence mechanisms",   q: "List all persistence mechanisms the attacker installed. Generate KQL to detect them." },
  { label: "What data was exfiltrated?",        q: "Summarize exactly what data was stolen, how much, and where it went. Was PII or sensitive data included?" },
  { label: "Identify threat actor TTPs",        q: "Based on the techniques and infrastructure, what threat actor group or profile does this match? Reference MITRE ATT&CK groups." },
  { label: "Generate C2 detection KQL",         q: "Generate KQL queries for Microsoft Sentinel to detect the C2 beaconing and DNS tunneling in these alerts." },
  { label: "Immediate response playbook",       q: "Give me an immediate incident response playbook — what to contain, eradicate and recover from this ransomware attack right now." },
];

// ═══════════════════════════════════════════════════════════════════════════════
//  UTILITIES
// ═══════════════════════════════════════════════════════════════════════════════
function buildSystemPrompt(alerts) {
  return `You are ARIA — Advanced Real-time Investigation Assistant, an elite AI-powered SOC analyst for a SIEM platform. You are sharp, precise, and think like a top-tier threat hunter and forensic investigator.

You have real-time access to the following ${alerts.length} security alerts from the last 2 hours:

${JSON.stringify(alerts, null, 2)}

INSTRUCTIONS:
1. Answer natural language security questions with authority — you are the expert
2. Always correlate across multiple alerts to find the full attack story
3. Use MITRE ATT&CK framework references (technique IDs) throughout
4. When generating queries, use Microsoft Sentinel KQL — wrap in triple backtick kql blocks
5. Structure complex answers with ## headers and bullet points
6. Use tables for timeline data, IP lists, and comparisons
7. Be concise but complete — prioritize actionable intelligence
8. Always end investigation answers with "**Next Steps:**" section
9. For any data exfiltration findings, note DPDP Act 2023 (India) implications if PII was involved
10. Sound like a real analyst: direct, confident, data-driven

Entity format conventions in your answers:
- Wrap IP addresses in backticks like \`10.2.1.55\`
- Wrap usernames in backticks like \`j.chen\` 
- Wrap hostnames in backticks like \`LAPTOP-CHEN\`
- Wrap file paths in backticks`;
}

async function callARIA(messages, alerts) {
  const res = await fetch("/api/aria", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      system: buildSystemPrompt(alerts),
      messages,
    }),
  });
  const data = await res.json();
  if (data.error) throw new Error(data.error.message || data.error);
  return data.content.map(b => b.text || "").join("");
}

function extractEntities(text) {
  const ips = [...(text.matchAll(/\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/g))].map(m => m[1]);
  const users = [...(text.matchAll(/\b(j\.chen|svc_backup|svc_sql|adm_helpdesk01|SYSTEM)\b/g))].map(m => m[1]);
  const hosts = [...(text.matchAll(/\b(LAPTOP-CHEN|DC01|FILESVR-01)\b/g))].map(m => m[1]);
  const ips_external = [...(text.matchAll(/\b(185\.220\.101\.47|45\.33\.32\.156)\b/g))].map(m => m[1]);
  return {
    ips: [...new Set(ips.filter(ip => !["0.0.0","255.255","127.0.0"].some(x => ip.startsWith(x))))],
    users: [...new Set(users)],
    hosts: [...new Set(hosts)],
    external: [...new Set(ips_external)],
  };
}

function fmt(s) { return s > 3600 ? `${Math.floor(s/3600)}h ${Math.floor((s%3600)/60)}m` : s > 60 ? `${Math.floor(s/60)}m ${s%60}s` : `${s}s`; }

// ═══════════════════════════════════════════════════════════════════════════════
//  INLINE TEXT RENDERER — bold, code, entity highlighting
// ═══════════════════════════════════════════════════════════════════════════════
function InlineText({ text }) {
  if (!text) return null;
  if (text.includes("**")) {
    const parts = text.split(/(\*\*[^*]+\*\*)/);
    return <>{parts.map((p, i) => p.startsWith("**") ? <strong key={i} style={{ fontWeight: 500 }}>{p.slice(2, -2)}</strong> : <InlineText key={i} text={p} />)}</>;
  }
  if (text.includes("`")) {
    const parts = text.split(/(`[^`]+`)/);
    return <>{parts.map((p, i) => {
      if (!p.startsWith("`")) return <InlineText key={i} text={p} />;
      const inner = p.slice(1, -1);
      const isIP = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(inner);
      const isUser = /^(j\.chen|svc_\w+|adm_\w+|SYSTEM)$/.test(inner);
      const isHost = /^(LAPTOP-\w+|DC\d+|FILESVR-\d+)$/.test(inner);
      const bg = isIP ? "#E6F1FB" : isUser ? "#FAEEDA" : isHost ? "#E1F5EE" : "var(--color-background-secondary)";
      const fg = isIP ? "#185FA5" : isUser ? "#854F0B" : isHost ? "#0F6E56" : "var(--color-text-primary)";
      return <code key={i} style={{ background: bg, color: fg, fontFamily: "var(--font-mono)", fontSize: "0.88em", padding: "1px 5px", borderRadius: 3 }}>{inner}</code>;
    })}</>;
  }
  return <>{text}</>;
}

// ═══════════════════════════════════════════════════════════════════════════════
//  KQL CODE BLOCK
// ═══════════════════════════════════════════════════════════════════════════════
const KQL_KW = /\b(SecurityEvent|SigninLogs|DeviceNetworkEvents|DeviceProcessEvents|OfficeActivity|AzureActivity|Heartbeat|let|where|project|summarize|extend|join|on|count|by|ago|bin|between|has|contains|startswith|endswith|dcount|makeset|render|union|search|distinct|top|sort|limit|order|make-series|evaluate|invoke|now|todatetime|tostring|toint|tolower|toupper|isempty|isnotempty|iff|case|coalesce|strcat|split|extract|parse|mv-expand|format_timespan|timespan|datetime|dynamic|print|datatable)\b/g;

function highlightKQL(line) {
  if (line.trim().startsWith("//")) return <span style={{ color: "var(--color-text-tertiary)", fontStyle: "italic" }}>{line}</span>;
  const tokens = [];
  let rest = line;
  let key = 0;
  while (rest.length > 0) {
    const pipeI = rest.indexOf("|");
    const strI = rest.search(/["']/);
    KQL_KW.lastIndex = 0;
    const kwM = KQL_KW.exec(rest);
    const candidates = [[pipeI >= 0 ? pipeI : Infinity, "pipe"], [strI >= 0 ? strI : Infinity, "str"], [kwM ? kwM.index : Infinity, "kw"]];
    candidates.sort((a, b) => a[0] - b[0]);
    const [pos, type] = candidates[0];
    if (pos === Infinity) { tokens.push(<span key={key++}>{rest}</span>); break; }
    if (pos > 0) tokens.push(<span key={key++}>{rest.slice(0, pos)}</span>);
    if (type === "pipe") { tokens.push(<span key={key++} style={{ color: "#BA7517", fontWeight: 600 }}>|</span>); rest = rest.slice(pos + 1); }
    else if (type === "str") {
      const q = rest[pos]; const end = rest.indexOf(q, pos + 1);
      const s = end >= 0 ? rest.slice(pos, end + 1) : rest.slice(pos);
      tokens.push(<span key={key++} style={{ color: "#3B6D11" }}>{s}</span>);
      rest = end >= 0 ? rest.slice(end + 1) : "";
    } else {
      KQL_KW.lastIndex = kwM.index;
      const m2 = KQL_KW.exec(rest);
      tokens.push(<span key={key++} style={{ color: "#185FA5", fontWeight: 500 }}>{m2[0]}</span>);
      rest = rest.slice(kwM.index + m2[0].length);
    }
  }
  return <>{tokens}</>;
}

function CodeBlock({ lang, code }) {
  const [copied, setCopied] = useState(false);
  const isKQL = ["kql", "kusto", "sql"].includes((lang || "").toLowerCase());
  const copy = () => { navigator.clipboard.writeText(code); setCopied(true); setTimeout(() => setCopied(false), 1500); };
  return (
    <div style={{ background: "var(--color-background-secondary)", border: `0.5px solid ${isKQL ? "var(--color-border-secondary)" : "var(--color-border-tertiary)"}`, borderRadius: "var(--border-radius-md)", margin: "8px 0", overflow: "hidden" }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "6px 12px", borderBottom: "0.5px solid var(--color-border-tertiary)" }}>
        <span style={{ fontSize: 10, fontWeight: 700, letterSpacing: ".1em", textTransform: "uppercase", color: isKQL ? "#185FA5" : "var(--color-text-tertiary)", fontFamily: "var(--font-mono)" }}>{lang || "code"}</span>
        <button onClick={copy} style={{ fontSize: 11, padding: "2px 8px", background: "transparent", border: "0.5px solid var(--color-border-tertiary)", borderRadius: 3, cursor: "pointer", color: "var(--color-text-secondary)" }}>{copied ? "copied" : "copy"}</button>
      </div>
      <pre style={{ margin: 0, padding: "10px 12px", fontFamily: "var(--font-mono)", fontSize: 12, lineHeight: 1.65, overflowX: "auto", whiteSpace: "pre" }}>
        {isKQL ? code.split("\n").map((ln, i) => <div key={i}>{highlightKQL(ln)}</div>) : code}
      </pre>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
//  MARKDOWN RENDERER
// ═══════════════════════════════════════════════════════════════════════════════
function MarkdownBlock({ content }) {
  const lines = content.split("\n");
  const out = [];
  let i = 0;
  while (i < lines.length) {
    const ln = lines[i];
    if (ln.startsWith("```")) {
      const lang = ln.slice(3).trim();
      const code = []; i++;
      while (i < lines.length && !lines[i].startsWith("```")) { code.push(lines[i]); i++; }
      out.push(<CodeBlock key={i} lang={lang} code={code.join("\n")} />);
    } else if (ln.startsWith("## ")) {
      out.push(<p key={i} style={{ margin: "14px 0 6px", fontSize: 13, fontWeight: 500, color: "var(--color-text-primary)" }}>{ln.slice(3)}</p>);
    } else if (ln.startsWith("### ")) {
      out.push(<p key={i} style={{ margin: "10px 0 4px", fontSize: 12, fontWeight: 500, color: "var(--color-text-secondary)", textTransform: "uppercase", letterSpacing: ".05em" }}>{ln.slice(4)}</p>);
    } else if (ln.trim() === "---") {
      out.push(<hr key={i} style={{ border: "none", borderTop: "0.5px solid var(--color-border-tertiary)", margin: "10px 0" }} />);
    } else if (ln.match(/^[-*] /)) {
      const items = [];
      while (i < lines.length && lines[i].match(/^[-*] /)) { items.push(lines[i].slice(2)); i++; }
      out.push(<ul key={`ul${i}`} style={{ margin: "5px 0", padding: 0, listStyle: "none" }}>
        {items.map((t, j) => <li key={j} style={{ display: "flex", gap: 6, marginBottom: 3, fontSize: 13, lineHeight: 1.55 }}><span style={{ color: "var(--color-text-tertiary)", flexShrink: 0, marginTop: 1 }}>›</span><span><InlineText text={t} /></span></li>)}
      </ul>);
      continue;
    } else if (ln.match(/^\d+\. /)) {
      const items = [];
      while (i < lines.length && lines[i].match(/^\d+\. /)) { items.push(lines[i].replace(/^\d+\. /, "")); i++; }
      out.push(<ol key={`ol${i}`} style={{ margin: "5px 0", paddingLeft: "1.3em" }}>
        {items.map((t, j) => <li key={j} style={{ marginBottom: 3, fontSize: 13, lineHeight: 1.55 }}><InlineText text={t} /></li>)}
      </ol>);
      continue;
    } else if (ln.includes("|") && ln.trim().startsWith("|")) {
      const rows = [];
      while (i < lines.length && lines[i].includes("|")) {
        if (!lines[i].includes("---")) rows.push(lines[i].split("|").map(c => c.trim()).filter(Boolean));
        i++;
      }
      if (rows.length) out.push(
        <div key={`tbl${i}`} style={{ overflowX: "auto", margin: "8px 0" }}>
          <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12 }}>
            <thead><tr>{rows[0].map((c, j) => <th key={j} style={{ padding: "5px 8px", textAlign: "left", borderBottom: "0.5px solid var(--color-border-secondary)", fontSize: 11, fontWeight: 600, textTransform: "uppercase", letterSpacing: ".05em", color: "var(--color-text-secondary)" }}>{c}</th>)}</tr></thead>
            <tbody>{rows.slice(1).map((row, r) => <tr key={r} style={{ background: r % 2 ? "var(--color-background-secondary)" : "transparent" }}>{row.map((c, j) => <td key={j} style={{ padding: "5px 8px", borderBottom: "0.5px solid var(--color-border-tertiary)", lineHeight: 1.5 }}><InlineText text={c} /></td>)}</tr>)}</tbody>
          </table>
        </div>
      );
      continue;
    } else if (ln.trim() === "") {
      out.push(<div key={i} style={{ height: 5 }} />);
    } else {
      out.push(<p key={i} style={{ margin: "2px 0", fontSize: 13, lineHeight: 1.6 }}><InlineText text={ln} /></p>);
    }
    i++;
  }
  return <div>{out}</div>;
}

// ═══════════════════════════════════════════════════════════════════════════════
//  SEVERITY BADGE
// ═══════════════════════════════════════════════════════════════════════════════
const SEV = {
  critical: { bg: "#FCEBEB", fg: "#A32D2D" },
  high:     { bg: "#FAECE7", fg: "#993C1D" },
  medium:   { bg: "#FAEEDA", fg: "#854F0B" },
  low:      { bg: "#EAF3DE", fg: "#3B6D11" },
  info:     { bg: "#E6F1FB", fg: "#185FA5" },
};
function SevBadge({ level, tiny }) {
  const s = SEV[level] || SEV.info;
  return <span style={{ background: s.bg, color: s.fg, fontSize: tiny ? 9 : 10, fontWeight: 700, padding: tiny ? "1px 4px" : "2px 6px", borderRadius: 3, textTransform: "uppercase", letterSpacing: ".07em", fontFamily: "var(--font-mono)", flexShrink: 0 }}>{level}</span>;
}

// ═══════════════════════════════════════════════════════════════════════════════
//  KILL CHAIN BAR
// ═══════════════════════════════════════════════════════════════════════════════
function KillChainBar({ detectedCats }) {
  return (
    <div style={{ display: "flex", gap: 3, flexWrap: "wrap", padding: "8px 12px", background: "var(--color-background-secondary)", borderBottom: "0.5px solid var(--color-border-tertiary)" }}>
      {KILL_CHAIN.map(phase => {
        const active = detectedCats.has(phase.id);
        return (
          <div key={phase.id} title={phase.label} style={{
            padding: "3px 7px", borderRadius: 4, fontSize: 10, fontWeight: active ? 700 : 400,
            fontFamily: "var(--font-mono)", letterSpacing: ".04em", cursor: "default",
            background: active ? phase.color + "22" : "transparent",
            color: active ? phase.color : "var(--color-text-tertiary)",
            border: `0.5px solid ${active ? phase.color + "66" : "var(--color-border-tertiary)"}`,
            transition: "all .2s",
          }}>{phase.label}</div>
        );
      })}
      <div style={{ marginLeft: "auto", fontSize: 11, color: "var(--color-text-tertiary)", display: "flex", alignItems: "center", gap: 4 }}>
        <span style={{ width: 6, height: 6, borderRadius: "50%", background: "#E24B4A", display: "inline-block" }} />
        {detectedCats.size} of {KILL_CHAIN.length} phases active
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
//  ALERT ROW
// ═══════════════════════════════════════════════════════════════════════════════
function AlertRow({ alert: a, highlighted, onClick }) {
  return (
    <div onClick={onClick} style={{
      padding: "8px 10px", borderBottom: "0.5px solid var(--color-border-tertiary)",
      cursor: "pointer", transition: "background .1s",
      background: highlighted ? (SEV[a.sev]?.bg || "var(--color-background-secondary)") : "transparent",
      borderLeft: highlighted ? `3px solid ${SEV[a.sev]?.fg || "#888"}` : "3px solid transparent",
    }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 3 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 5 }}>
          <SevBadge level={a.sev} tiny />
          <span style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--color-text-tertiary)" }}>{a.id}</span>
        </div>
        <span style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--color-text-tertiary)" }}>{a.ts}</span>
      </div>
      <p style={{ margin: "0 0 2px", fontSize: 12, fontWeight: 500, lineHeight: 1.3, color: "var(--color-text-primary)" }}>{a.rule}</p>
      <p style={{ margin: 0, fontSize: 11, color: "var(--color-text-secondary)", fontFamily: "var(--font-mono)" }}>{a.host} · {a.user}</p>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
//  ENTITY PANEL
// ═══════════════════════════════════════════════════════════════════════════════
function EntityPanel({ entities }) {
  const secs = [
    { label: "Internal IPs", items: entities.ips, bg: "#E6F1FB", fg: "#185FA5" },
    { label: "External IPs (IOC)", items: entities.external, bg: "#FCEBEB", fg: "#A32D2D" },
    { label: "Accounts", items: entities.users, bg: "#FAEEDA", fg: "#854F0B" },
    { label: "Hosts", items: entities.hosts, bg: "#E1F5EE", fg: "#0F6E56" },
  ].filter(s => s.items.length > 0);
  if (!secs.length) return (
    <div style={{ padding: "12px 10px", fontSize: 12, color: "var(--color-text-tertiary)", textAlign: "center" }}>Entities will appear as investigation progresses</div>
  );
  return (
    <div style={{ padding: "8px 10px" }}>
      <p style={{ margin: "0 0 8px", fontSize: 10, fontWeight: 600, textTransform: "uppercase", letterSpacing: ".08em", color: "var(--color-text-tertiary)" }}>Discovered Entities</p>
      {secs.map((s, i) => (
        <div key={i} style={{ marginBottom: 10 }}>
          <p style={{ margin: "0 0 4px", fontSize: 10, color: "var(--color-text-tertiary)" }}>{s.label}</p>
          <div style={{ display: "flex", flexWrap: "wrap", gap: 4 }}>
            {s.items.map((item, j) => <span key={j} style={{ background: s.bg, color: s.fg, fontSize: 10, fontFamily: "var(--font-mono)", padding: "2px 6px", borderRadius: 3 }}>{item}</span>)}
          </div>
        </div>
      ))}
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
//  NOTEBOOK ENTRY
// ═══════════════════════════════════════════════════════════════════════════════
function NotebookEntry({ entry, index }) {
  return (
    <div style={{ padding: "8px 10px", borderBottom: "0.5px solid var(--color-border-tertiary)", display: "flex", gap: 8, alignItems: "flex-start" }}>
      <span style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--color-text-tertiary)", minWidth: 24, marginTop: 1 }}>#{index + 1}</span>
      <div style={{ flex: 1 }}>
        <p style={{ margin: "0 0 2px", fontSize: 12, fontWeight: 500 }}>{entry.query}</p>
        <p style={{ margin: 0, fontSize: 11, color: "var(--color-text-secondary)", lineHeight: 1.4 }}>{entry.excerpt}</p>
        <p style={{ margin: "3px 0 0", fontSize: 10, color: "var(--color-text-tertiary)", fontFamily: "var(--font-mono)" }}>{entry.time}</p>
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
//  CHAT BUBBLE
// ═══════════════════════════════════════════════════════════════════════════════
function ChatBubble({ msg }) {
  const isARIA = msg.role === "assistant";
  const isSystem = msg.role === "system";
  if (isSystem) return (
    <div style={{ textAlign: "center", margin: "8px 0" }}>
      <span style={{ fontSize: 11, color: "var(--color-text-tertiary)", fontFamily: "var(--font-mono)", background: "var(--color-background-secondary)", padding: "3px 10px", borderRadius: "var(--border-radius-md)" }}>{msg.content}</span>
    </div>
  );
  return (
    <div style={{ display: "flex", gap: 8, marginBottom: 14, justifyContent: isARIA ? "flex-start" : "flex-end" }}>
      {isARIA && (
        <div style={{ width: 28, height: 28, borderRadius: "50%", background: "#FAEEDA", color: "#854F0B", display: "flex", alignItems: "center", justifyContent: "center", fontSize: 11, fontWeight: 700, flexShrink: 0, marginTop: 2 }}>A</div>
      )}
      <div style={{
        maxWidth: "84%", padding: "10px 13px",
        background: isARIA ? "var(--color-background-primary)" : "var(--color-background-secondary)",
        border: `0.5px solid ${isARIA ? "var(--color-border-secondary)" : "var(--color-border-tertiary)"}`,
        borderRadius: "var(--border-radius-lg)",
        borderTopLeftRadius: isARIA ? 4 : undefined,
        borderTopRightRadius: isARIA ? undefined : 4,
      }}>
        {isARIA && <div style={{ fontSize: 10, fontWeight: 700, color: "#854F0B", letterSpacing: ".08em", marginBottom: 6, fontFamily: "var(--font-mono)" }}>ARIA</div>}
        <MarkdownBlock content={msg.content} />
        <div style={{ fontSize: 10, color: "var(--color-text-tertiary)", marginTop: 5, fontFamily: "var(--font-mono)", textAlign: "right" }}>{msg.time}</div>
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
//  TYPING INDICATOR
// ═══════════════════════════════════════════════════════════════════════════════
function TypingIndicator() {
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 14 }}>
      <div style={{ width: 28, height: 28, borderRadius: "50%", background: "#FAEEDA", color: "#854F0B", display: "flex", alignItems: "center", justifyContent: "center", fontSize: 11, fontWeight: 700 }}>A</div>
      <div style={{ padding: "10px 14px", background: "var(--color-background-primary)", border: "0.5px solid var(--color-border-secondary)", borderRadius: "var(--border-radius-lg)", borderTopLeftRadius: 4, display: "flex", gap: 4, alignItems: "center" }}>
        {[0, 150, 300].map(delay => (
          <span key={delay} style={{ width: 6, height: 6, borderRadius: "50%", background: "#BA7517", display: "inline-block", animation: `aria-pulse 1.2s ease-in-out ${delay}ms infinite` }} />
        ))}
      </div>
      <style>{`@keyframes aria-pulse { 0%,80%,100%{opacity:.2;transform:scale(.8)} 40%{opacity:1;transform:scale(1)} }`}</style>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
//  MAIN APP — ARIA SIEM PLATFORM
// ═══════════════════════════════════════════════════════════════════════════════
export default function ARIAApp() {
  const [messages, setMessages] = useState([]);
  const [visibleAlerts, setVisibleAlerts] = useState([]);
  const [entities, setEntities] = useState({ ips: [], users: [], hosts: [], external: [] });
  const [notebook, setNotebook] = useState([]);
  const [loading, setLoading] = useState(false);
  const [input, setInput] = useState("");
  const [timer, setTimer] = useState(0);
  const [highlighted, setHighlighted] = useState(null);
  const [activeTab, setActiveTab] = useState("alerts");
  const [showNotebook, setShowNotebook] = useState(false);
  const [sevFilter, setSevFilter] = useState("all");
  const chatRef = useRef();
  const inputRef = useRef();
  const briefedRef = useRef(false);
  const startRef = useRef(Date.now());

  // Detected kill chain phases
  const detectedCats = new Set(visibleAlerts.filter(Boolean).map(a => a.cat));

  // Severity counts
  const sevCounts = ALERTS.reduce((a, x) => { a[x.sev] = (a[x.sev] || 0) + 1; return a; }, {});

  // Stream alerts in on mount
  useEffect(() => {
    let idx = 0;
    const iv = setInterval(() => {
      if (idx >= ALERTS.length) { clearInterval(iv); return; }
      setVisibleAlerts(prev => [...prev, ALERTS[idx]]);
      idx++;
    }, 120);
    return () => clearInterval(iv);
  }, []);

  // Timer
  useEffect(() => {
    const iv = setInterval(() => setTimer(Math.floor((Date.now() - startRef.current) / 1000)), 1000);
    return () => clearInterval(iv);
  }, []);

  // Auto-brief once all alerts loaded
  useEffect(() => {
    if (visibleAlerts.length === ALERTS.length && !briefedRef.current) {
      briefedRef.current = true;
      setTimeout(() => sendMessage("Brief me on this incident. What's happening right now, how severe is it, and what's the attacker's objective?", true), 800);
    }
  }, [visibleAlerts]);

  // Scroll chat to bottom
  useEffect(() => {
    if (chatRef.current) chatRef.current.scrollTop = chatRef.current.scrollHeight;
  }, [messages, loading]);

  const addEntities = useCallback((text) => {
    const extracted = extractEntities(text);
    setEntities(prev => ({
      ips: [...new Set([...prev.ips, ...extracted.ips])],
      users: [...new Set([...prev.users, ...extracted.users])],
      hosts: [...new Set([...prev.hosts, ...extracted.hosts])],
      external: [...new Set([...prev.external, ...extracted.external])],
    }));
  }, []);

  const sendMessage = useCallback(async (text, isAuto = false) => {
    if (!text.trim() || loading) return;
    setInput("");
    const now = new Date().toLocaleTimeString("en-IN", { hour12: false });
    const userMsg = { role: "user", content: text, time: now };
    setMessages(prev => [...prev, userMsg]);
    setLoading(true);

    const apiMessages = [
      ...messages.filter(m => m.role !== "system").map(m => ({ role: m.role, content: m.content })),
      { role: "user", content: text }
    ];

    try {
      const resp = await callARIA(apiMessages, ALERTS);
      const ariaMsg = { role: "assistant", content: resp, time: new Date().toLocaleTimeString("en-IN", { hour12: false }) };
      setMessages(prev => [...prev, ariaMsg]);
      addEntities(resp);
      // Add to notebook
      const firstLine = resp.split("\n").find(l => l.trim() && !l.startsWith("#") && !l.startsWith("`")) || resp.slice(0, 100);
      setNotebook(prev => [...prev, { query: text.slice(0, 60) + (text.length > 60 ? "…" : ""), excerpt: firstLine.replace(/\*\*/g, "").slice(0, 120) + "…", time: new Date().toLocaleTimeString("en-IN", { hour12: false }) }]);
    } catch (e) {
      setMessages(prev => [...prev, { role: "assistant", content: `**Error:** ${e.message}`, time: new Date().toLocaleTimeString() }]);
    }
    setLoading(false);
    inputRef.current?.focus();
  }, [messages, loading, addEntities]);

  const onKey = e => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); sendMessage(input); } };
  const filteredAlerts = (sevFilter === "all" ? visibleAlerts : visibleAlerts.filter(a => a.sev === sevFilter)).filter(Boolean);

  return (
    <div style={{ display: "flex", flexDirection: "column", height: "90vh", minHeight: 600, fontFamily: "var(--font-sans)" }}>

      {/* ── Header ────────────────────────────────────────────────── */}
      <div style={{ padding: "10px 14px", background: "var(--color-background-primary)", borderBottom: "0.5px solid var(--color-border-secondary)", display: "flex", justifyContent: "space-between", alignItems: "center", flexShrink: 0 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <div style={{ width: 32, height: 32, borderRadius: "50%", background: "#FAEEDA", color: "#854F0B", display: "flex", alignItems: "center", justifyContent: "center", fontSize: 12, fontWeight: 700 }}>A</div>
          <div>
            <div style={{ display: "flex", alignItems: "center", gap: 7 }}>
              <span style={{ fontSize: 14, fontWeight: 500 }}>ARIA</span>
              <span style={{ fontSize: 10, background: "#FCEBEB", color: "#A32D2D", padding: "1px 6px", borderRadius: 3, fontWeight: 700, fontFamily: "var(--font-mono)", letterSpacing: ".06em" }}>INCIDENT ACTIVE</span>
            </div>
            <p style={{ margin: 0, fontSize: 11, color: "var(--color-text-tertiary)" }}>Advanced Real-time Investigation Assistant · SIEM AI</p>
          </div>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
          {Object.entries(sevCounts).map(([s, n]) => (
            <div key={s} style={{ textAlign: "center", cursor: "pointer" }} onClick={() => setSevFilter(sevFilter === s ? "all" : s)}>
              <div style={{ fontSize: 16, fontWeight: 500, fontFamily: "var(--font-mono)", color: SEV[s]?.fg }}>{n}</div>
              <div style={{ fontSize: 9, textTransform: "uppercase", letterSpacing: ".07em", color: "var(--color-text-tertiary)" }}>{s}</div>
            </div>
          ))}
          <div style={{ width: 1, height: 30, background: "var(--color-border-tertiary)" }} />
          <div style={{ textAlign: "center" }}>
            <div style={{ fontSize: 14, fontWeight: 500, fontFamily: "var(--font-mono)", color: "var(--color-text-primary)" }}>{fmt(timer)}</div>
            <div style={{ fontSize: 9, textTransform: "uppercase", letterSpacing: ".07em", color: "var(--color-text-tertiary)" }}>elapsed</div>
          </div>
        </div>
      </div>

      {/* ── Kill Chain ────────────────────────────────────────────── */}
      <KillChainBar detectedCats={detectedCats} />

      {/* ── Main panels ───────────────────────────────────────────── */}
      <div style={{ display: "flex", flex: 1, overflow: "hidden" }}>

        {/* ── LEFT: Alert feed + entity panel ─────────────────────── */}
        <div style={{ width: 280, flexShrink: 0, borderRight: "0.5px solid var(--color-border-tertiary)", display: "flex", flexDirection: "column", overflow: "hidden" }}>
          {/* Left tabs */}
          <div style={{ display: "flex", borderBottom: "0.5px solid var(--color-border-tertiary)", flexShrink: 0 }}>
            {["alerts", "entities"].map(tab => (
              <button key={tab} onClick={() => setActiveTab(tab)} style={{
                flex: 1, padding: "7px 10px", fontSize: 11, border: "none", background: "transparent", cursor: "pointer",
                color: activeTab === tab ? "var(--color-text-primary)" : "var(--color-text-tertiary)",
                fontWeight: activeTab === tab ? 500 : 400,
                borderBottom: activeTab === tab ? "2px solid var(--color-text-primary)" : "2px solid transparent",
                textTransform: "uppercase", letterSpacing: ".06em",
              }}>{tab}</button>
            ))}
          </div>

          {/* Alerts tab */}
          {activeTab === "alerts" && (
            <div style={{ flex: 1, overflowY: "auto" }}>
              {/* Filter bar */}
              <div style={{ padding: "5px 8px", background: "var(--color-background-secondary)", borderBottom: "0.5px solid var(--color-border-tertiary)", display: "flex", gap: 4, flexWrap: "wrap" }}>
                {["all", "critical", "high", "medium"].map(f => (
                  <button key={f} onClick={() => setSevFilter(f)} style={{ fontSize: 10, padding: "2px 7px", borderRadius: 3, border: `0.5px solid ${sevFilter === f ? "var(--color-border-primary)" : "var(--color-border-tertiary)"}`, background: sevFilter === f ? "var(--color-background-tertiary)" : "transparent", cursor: "pointer", color: "var(--color-text-secondary)", textTransform: "uppercase", letterSpacing: ".05em" }}>{f}</button>
                ))}
              </div>
              {filteredAlerts.map(a => <AlertRow key={a.id} alert={a} highlighted={highlighted === a.id} onClick={() => { setHighlighted(a.id === highlighted ? null : a.id); sendMessage(`Tell me more about alert ${a.id}: ${a.rule}`); }} />)}
              {visibleAlerts.length < ALERTS.length && (
                <div style={{ padding: "8px 10px", fontSize: 11, color: "var(--color-text-tertiary)", textAlign: "center", fontFamily: "var(--font-mono)" }}>streaming {visibleAlerts.length}/{ALERTS.length} alerts…</div>
              )}
            </div>
          )}

          {/* Entities tab */}
          {activeTab === "entities" && (
            <div style={{ flex: 1, overflowY: "auto" }}>
              <EntityPanel entities={entities} />
            </div>
          )}
        </div>

        {/* ── RIGHT: Chat + input ──────────────────────────────────── */}
        <div style={{ flex: 1, display: "flex", flexDirection: "column", overflow: "hidden" }}>

          {/* Messages */}
          <div ref={chatRef} style={{ flex: 1, overflowY: "auto", padding: "14px 16px" }}>
            {messages.length === 0 && (
              <div style={{ textAlign: "center", padding: "2rem 1rem", color: "var(--color-text-tertiary)", fontSize: 13 }}>
                <div style={{ width: 40, height: 40, borderRadius: "50%", background: "#FAEEDA", color: "#854F0B", display: "flex", alignItems: "center", justifyContent: "center", fontSize: 14, fontWeight: 700, margin: "0 auto 1rem" }}>A</div>
                <p style={{ margin: 0 }}>ARIA is loading alert data…</p>
              </div>
            )}
            {messages.map((msg, i) => <ChatBubble key={i} msg={msg} />)}
            {loading && <TypingIndicator />}
          </div>

          {/* Investigation notebook (collapsible) */}
          {notebook.length > 0 && (
            <div style={{ flexShrink: 0, borderTop: "0.5px solid var(--color-border-tertiary)" }}>
              <button onClick={() => setShowNotebook(n => !n)} style={{ width: "100%", padding: "6px 12px", background: "var(--color-background-secondary)", border: "none", cursor: "pointer", textAlign: "left", fontSize: 11, color: "var(--color-text-secondary)", display: "flex", justifyContent: "space-between" }}>
                <span style={{ fontWeight: 600, textTransform: "uppercase", letterSpacing: ".06em" }}>Investigation Notebook ({notebook.length})</span>
                <span>{showNotebook ? "▲ hide" : "▼ show"}</span>
              </button>
              {showNotebook && (
                <div style={{ maxHeight: 180, overflowY: "auto" }}>
                  {notebook.map((e, i) => <NotebookEntry key={i} entry={e} index={i} />)}
                </div>
              )}
            </div>
          )}

          {/* Quick actions */}
          <div style={{ padding: "8px 12px", borderTop: "0.5px solid var(--color-border-tertiary)", background: "var(--color-background-secondary)", overflowX: "auto", flexShrink: 0 }}>
            <div style={{ display: "flex", gap: 5, minWidth: "max-content" }}>
              {QUICK_ACTIONS.map((qa, i) => (
                <button key={i} onClick={() => sendMessage(qa.q)} disabled={loading} style={{ padding: "5px 10px", fontSize: 11, background: loading ? "var(--color-background-tertiary)" : "var(--color-background-primary)", border: "0.5px solid var(--color-border-secondary)", borderRadius: "var(--border-radius-md)", cursor: loading ? "not-allowed" : "pointer", whiteSpace: "nowrap", color: loading ? "var(--color-text-tertiary)" : "var(--color-text-secondary)", transition: "background .1s" }}>
                  {qa.label}
                </button>
              ))}
            </div>
          </div>

          {/* Input bar */}
          <div style={{ padding: "10px 12px", borderTop: "0.5px solid var(--color-border-secondary)", display: "flex", gap: 8, flexShrink: 0 }}>
            <input
              ref={inputRef}
              value={input}
              onChange={e => setInput(e.target.value)}
              onKeyDown={onKey}
              disabled={loading}
              placeholder="Ask ARIA anything about this incident…"
              style={{ flex: 1, padding: "9px 12px", fontSize: 13, border: "0.5px solid var(--color-border-secondary)", borderRadius: "var(--border-radius-md)", background: "var(--color-background-primary)", color: "var(--color-text-primary)", outline: "none" }}
            />
            <button
              onClick={() => sendMessage(input)}
              disabled={!input.trim() || loading}
              style={{ padding: "9px 16px", background: input.trim() && !loading ? "#FAEEDA" : "var(--color-background-secondary)", color: input.trim() && !loading ? "#854F0B" : "var(--color-text-tertiary)", border: `0.5px solid ${input.trim() && !loading ? "#BA7517" : "var(--color-border-tertiary)"}`, borderRadius: "var(--border-radius-md)", cursor: input.trim() && !loading ? "pointer" : "not-allowed", fontSize: 13, fontWeight: 500, transition: "all .1s" }}>
              Investigate
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
