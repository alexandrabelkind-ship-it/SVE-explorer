import { useState } from "react";
import { SEVERITY_CONFIG, globalStyles, s } from "./styles.js";
import surfImg from "./assets/surff.png";


function getSeverity(score) {
  if (score >= 9.0) return "CRITICAL";
  if (score >= 7.0) return "HIGH";
  if (score >= 4.0) return "MEDIUM";
  return "LOW";
}

const MOCK_CVES = [
  { cve_id: "CVE-2024-1234", title: "Apache Log4j Remote Code Execution", description: "A critical vulnerability in Apache Log4j allows unauthenticated remote code execution via JNDI injection in log messages.", cvss_score: 9.8, severity: "CRITICAL", published_date: "2024-03-15" },
  { cve_id: "CVE-2024-5678", title: "OpenSSL Buffer Overflow in X.509", description: "A buffer overflow vulnerability in OpenSSL's X.509 certificate verification could allow attackers to crash or take over affected systems.", cvss_score: 7.5, severity: "HIGH", published_date: "2024-02-20" },
  { cve_id: "CVE-2024-9101", title: "WordPress Plugin XSS Injection", description: "Cross-site scripting vulnerability in a popular WordPress plugin allows attackers to inject malicious scripts into web pages.", cvss_score: 6.1, severity: "MEDIUM", published_date: "2024-01-10" },
  { cve_id: "CVE-2024-3344", title: "Linux Kernel Privilege Escalation", description: "A race condition in the Linux kernel's memory management allows local users to gain elevated privileges on the system.", cvss_score: 7.8, severity: "HIGH", published_date: "2024-03-01" },
  { cve_id: "CVE-2024-7890", title: "nginx Path Traversal Information Leak", description: "Improper input validation in nginx allows remote attackers to read arbitrary files from the server via path traversal sequences.", cvss_score: 5.3, severity: "MEDIUM", published_date: "2024-02-05" },
  { cve_id: "CVE-2024-2211", title: "curl Cookie Injection Low Risk", description: "A low-severity cookie injection issue in curl allows attackers under specific conditions to inject arbitrary cookies into requests.", cvss_score: 3.1, severity: "LOW", published_date: "2024-01-25" },
  { cve_id: "CVE-2024-4455", title: "Spring Framework Denial of Service", description: "Uncontrolled resource consumption in Spring Framework allows remote attackers to cause a denial of service via crafted HTTP requests.", cvss_score: 7.5, severity: "HIGH", published_date: "2024-03-10" },
  { cve_id: "CVE-2024-6677", title: "Python pickle Deserialization RCE", description: "Unsafe deserialization using Python's pickle module in a widely-used data processing library allows arbitrary code execution.", cvss_score: 9.1, severity: "CRITICAL", published_date: "2024-02-28" },
];

function SeverityBadge({ score, severity: rawSeverity, size = "md" }) {
  const key = rawSeverity ? rawSeverity.toUpperCase() : getSeverity(score);
  const cfg = SEVERITY_CONFIG[key] || SEVERITY_CONFIG.UNKNOWN;
  return (
    <span style={{
      background: cfg.bg, color: cfg.color, border: `1px solid ${cfg.border}`,
      borderRadius: 6, padding: size === "lg" ? "6px 14px" : "4px 10px",
      fontSize: size === "lg" ? 13 : 11,
      fontFamily: "monospace", fontWeight: 700, letterSpacing: "0.06em", whiteSpace: "nowrap",
    }}>
      {cfg.label}{score != null ? ` ${Number(score).toFixed(1)}` : ""}
    </span>
  );
}

function GPTButton({ cve }) {
  const prompt = `How do I fix and remediate ${cve.cve_id}: ${cve.title}? CVSS: ${cve.cvss_score}. ${cve.description}`;
  return (
    <button
      onClick={e => { e.stopPropagation(); window.open(`https://chat.openai.com/?q=${encodeURIComponent(prompt)}`, "_blank"); }}
      style={{ background: "#f5f5f7", border: "1px solid #e5e5ea", borderRadius: 8, padding: "5px 10px", fontSize: 11, fontWeight: 600, color: "#1d1d1f", cursor: "pointer", display: "flex", alignItems: "center", gap: 5 }}
    >
      💬 Ask GPT
    </button>
  );
}

function CveCard({ cve, onClick }) {
  const severity = (cve.severity || getSeverity(cve.cvss_score)).toUpperCase();
  const cfg = SEVERITY_CONFIG[severity] || SEVERITY_CONFIG.UNKNOWN;
  const [hovered, setHovered] = useState(false);
  return (
    <div
      onClick={() => onClick(cve)}
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
      style={{
        ...s.cardBase,
        background: hovered ? "#f9f9fb" : cfg.rowBg,
        borderLeft: `4px solid ${cfg.color}`,
        boxShadow: hovered ? "0 4px 16px rgba(0,0,0,0.08)" : "0 1px 3px rgba(0,0,0,0.05)",
        transform: hovered ? "translateY(-1px)" : "none",
      }}
    >
      <div style={s.cardInner}>
        <div style={s.cardLeft}>
          <div style={s.cardMeta}>
            <span style={s.cardId}>{cve.cve_id}</span>
            <span style={s.cardDate}>{new Date(cve.published_date).toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" })}</span>
          </div>
          <p style={s.cardTitle}>{cve.title}</p>
          <p style={s.cardDesc}>{cve.description}</p>
        </div>
        <div style={s.cardRight}>
          <SeverityBadge score={cve.cvss_score} severity={severity} />
          <GPTButton cve={cve} />
          <span style={{ color: "#0071e3", fontSize: 12, opacity: hovered ? 1 : 0, transition: "opacity 0.15s" }}>Details →</span>
        </div>
      </div>
    </div>
  );
}

function CveModal({ cve, onClose }) {
  const severity = (cve.severity || getSeverity(cve.cvss_score)).toUpperCase();
  const cfg = SEVERITY_CONFIG[severity] || SEVERITY_CONFIG.UNKNOWN;
  return (
    <div onClick={onClose} style={s.modalOverlay}>
      <div onClick={e => e.stopPropagation()} style={{ ...s.modalBox, border: `1px solid ${cfg.border}` }}>
        <div style={{ height: 4, background: cfg.color, borderRadius: "20px 20px 0 0" }} />
        <div style={s.modalBody}>
          <div style={s.modalHeader}>
            <div>
              <div style={s.modalIdRow}>
                <span style={s.modalId}>{cve.cve_id}</span>
                <SeverityBadge score={cve.cvss_score} severity={severity} size="lg" />
              </div>
              <h2 style={s.modalTitle}>{cve.title}</h2>
            </div>
            <button onClick={onClose} style={s.modalCloseBtn}>×</button>
          </div>
          <div style={{ marginTop: 20 }}>
            <p style={s.modalScoreLabel}>CVSS SCORE</p>
            <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
              <div style={s.scoreBarTrack}>
                <div style={{ width: `${(cve.cvss_score / 10) * 100}%`, height: "100%", background: cfg.color, borderRadius: 3 }} />
              </div>
              <span style={{ color: cfg.color, fontFamily: "monospace", fontSize: 13, fontWeight: 600 }}>{cve.cvss_score.toFixed(1)}</span>
            </div>
          </div>
          <div style={s.modalMetaGrid}>
            <div style={s.modalMetaBox}>
              <span style={s.modalMetaLabel}>PUBLISHED</span>
              <span style={s.modalMetaValue}>{new Date(cve.published_date).toLocaleDateString("en-US", { year: "numeric", month: "long", day: "numeric" })}</span>
            </div>
            <div style={s.modalMetaBox}>
              <span style={s.modalMetaLabel}>BASE SCORE</span>
              <span style={{ ...s.modalMetaValue, color: cfg.color }}>{cve.cvss_score.toFixed(1)} / 10.0</span>
            </div>
          </div>
          <div style={{ marginTop: 24 }}>
            <p style={s.modalDescLabel}>DESCRIPTION</p>
            <p style={s.modalDescBox}>{cve.description}</p>
          </div>
          <div style={{ marginTop: 20, background: "#f0f6ff", border: "1px solid #c9e0ff", borderRadius: 12, padding: "16px 20px" }}>
            <p style={{ color: "#0071e3", fontSize: 12, fontWeight: 700, marginBottom: 8 }}>✦ AI SUMMARY (MOCK)</p>
            <p style={{ color: "#1d1d1f", fontSize: 14, lineHeight: 1.75, margin: 0 }}>
              This is a mock AI summary. In production, clicking "Explain this CVE" will send the description to Claude and return a plain-English explanation of the vulnerability, its impact, and why the severity rating makes sense.
            </p>
          </div>
          <div style={{ ...s.modalFooter, display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <a href={`https://nvd.nist.gov/vuln/detail/${cve.cve_id}`} target="_blank" rel="noopener noreferrer" style={s.nvdLink}>View on NVD ↗</a>
            <GPTButton cve={cve} />
          </div>
        </div>
      </div>
    </div>
  );
}

export default function MockApp() {
  const [selected, setSelected] = useState(null);
  const [search, setSearch] = useState("");
  const [severity, setSeverity] = useState("ALL");
  const [sortBy, setSortBy] = useState("severity_desc");

  const SORT_OPTIONS = [
    { label: "⬆ Severity", value: "severity_desc" },
    { label: "A → Z", value: "alpha_asc" },
    { label: "Z → A", value: "alpha_desc" },
    { label: "Newest first", value: "date_desc" },
    { label: "Oldest first", value: "date_asc" },
  ];

  const SEVERITY_ORDER = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };

  const filtered = MOCK_CVES
    .filter(c => severity === "ALL" || c.severity === severity)
    .filter(c => !search || c.title.toLowerCase().includes(search.toLowerCase()) || c.cve_id.includes(search))
    .sort((a, b) => {
      if (sortBy === "severity_desc") return (SEVERITY_ORDER[a.severity] ?? 4) - (SEVERITY_ORDER[b.severity] ?? 4);
      if (sortBy === "alpha_asc") return a.title.localeCompare(b.title);
      if (sortBy === "alpha_desc") return b.title.localeCompare(a.title);
      if (sortBy === "date_desc") return new Date(b.published_date) - new Date(a.published_date);
      if (sortBy === "date_asc") return new Date(a.published_date) - new Date(b.published_date);
      return 0;
    });

  const stats = { CRITICAL: MOCK_CVES.filter(c => c.severity === "CRITICAL").length, HIGH: MOCK_CVES.filter(c => c.severity === "HIGH").length, MEDIUM: MOCK_CVES.filter(c => c.severity === "MEDIUM").length, LOW: MOCK_CVES.filter(c => c.severity === "LOW").length };

  return (
    <>
      <style>{globalStyles}</style>

        {/* Side images */}
        <div style={{ position: "fixed", left: 0, top: 0, height: "100vh", width: 180, display: "flex", alignItems: "center", justifyContent: "center", pointerEvents: "none", zIndex: 0 }}>
        <img src={surfImg} alt="" style={{ width: 150, opacity: 0.18, filter: "saturate(0.8)" }} />
        </div>
        <div style={{ position: "fixed", right: 0, top: 0, height: "100vh", width: 180, display: "flex", alignItems: "center", justifyContent: "center", pointerEvents: "none", zIndex: 0 }}>
        <img src={surfImg} alt="" style={{ width: 150, opacity: 0.18, filter: "saturate(0.8) scaleX(-1)", transform: "scaleX(-1)" }} />
        </div>

        <div style={{ ...s.page, position: "relative", zIndex: 1 }}>

        {/* MOCK banner */}
        <div style={{ background: "#fff8e6", border: "1px solid #ffd066", borderRadius: 10, padding: "10px 18px", marginBottom: 24, display: "flex", alignItems: "center", gap: 10 }}>
          <span>🧪</span>
          <span style={{ fontSize: 13, fontWeight: 600, color: "#996600" }}>MOCK MODE — No backend needed. All data is fake. Use this to test the UI.</span>
        </div>

        {/* Header */}
        <div style={{ marginBottom: 36, display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
          <div>
            <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 6 }}>
              <div style={s.liveIndicator} />
              <span style={s.liveLabel}>MOCK DATA — UI PREVIEW</span>
            </div>
            <div style={{ display: "flex", alignItems: "center", gap: 14 }}>
              <span style={{ fontSize: 38 }}>🏄</span>
              <h1 style={s.h1}>CVE Explorer</h1>
            </div>
            <p style={s.subtitle}>Showing {MOCK_CVES.length} sample vulnerabilities for UI testing.</p>
          </div>
          <button style={{ background: "#1d1d1f", color: "#ffffff", border: "none", borderRadius: 12, padding: "12px 22px", fontSize: 14, fontWeight: 600, cursor: "not-allowed", opacity: 0.5 }}>
            ↻ Refresh CVE Data
          </button>
        </div>

        {/* Dashboard */}
        <div style={s.dashboard}>
          {["CRITICAL", "HIGH", "MEDIUM", "LOW"].map(sev => {
            const cfg = SEVERITY_CONFIG[sev];
            return (
              <div key={sev} style={{ ...s.totalCard, borderTop: `3px solid ${cfg.color}` }}>
                <span style={{ color: cfg.color, fontSize: 34, fontWeight: 700, lineHeight: 1 }}>{stats[sev]}</span>
                <span style={{ color: cfg.color, opacity: 0.8, fontSize: 11, letterSpacing: "0.06em", fontWeight: 600 }}>{sev}</span>
              </div>
            );
          })}
          <div style={s.totalCard}>
            <span style={s.totalCount}>{MOCK_CVES.length}</span>
            <span style={s.totalLabel}>TOTAL</span>
          </div>
        </div>

        {/* Search */}
        <div style={s.searchRow}>
          <div style={s.searchBox}>
            <span style={s.searchIcon}>⌕</span>
            <input type="text" placeholder="Search by CVE ID, keyword, or technology…" value={search} onChange={e => setSearch(e.target.value)} style={s.searchInput} />
            {search && <button onClick={() => setSearch("")} style={s.searchClear}>×</button>}
          </div>
        </div>

        {/* Sort */}
        <div style={s.sortRow}>
          <span style={{ color: "#8e8e93", fontSize: 12, fontWeight: 600, letterSpacing: "0.04em" }}>SORT</span>
          {SORT_OPTIONS.map(opt => (
            <button key={opt.value} onClick={() => setSortBy(opt.value)} style={{
              background: sortBy === opt.value ? "#0071e3" : "#ffffff",
              color: sortBy === opt.value ? "#ffffff" : "#3a3a3c",
              border: `1px solid ${sortBy === opt.value ? "#0071e3" : "#e5e5ea"}`,
              borderRadius: 8, padding: "8px 14px", fontSize: 12, fontWeight: 600, cursor: "pointer",
            }}>{opt.label}</button>
          ))}
        </div>

        {/* Filter */}
        <div style={s.filterRow2}>
          <span style={{ color: "#8e8e93", fontSize: 12, fontWeight: 600, letterSpacing: "0.04em" }}>FILTER</span>
          {["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"].map(sev => {
            const cfg = sev === "ALL" ? null : SEVERITY_CONFIG[sev];
            const active = severity === sev;
            return (
              <button key={sev} onClick={() => setSeverity(sev)} style={{
                background: active ? (cfg?.color || "#0071e3") : "#ffffff",
                color: active ? "#ffffff" : (cfg?.color || "#3a3a3c"),
                border: `1px solid ${active ? (cfg?.color || "#0071e3") : "#e5e5ea"}`,
                borderRadius: 8, padding: "8px 14px", fontSize: 12, fontWeight: 600, cursor: "pointer",
              }}>{sev}</button>
            );
          })}
        </div>

        <p style={s.resultsCount}>{filtered.length} vulnerabilit{filtered.length === 1 ? "y" : "ies"}</p>

        {/* List */}
        <div style={s.cveList}>
          {filtered.map(cve => <CveCard key={cve.cve_id} cve={cve} onClick={setSelected} />)}
        </div>
      </div>

      {selected && <CveModal cve={selected} onClose={() => setSelected(null)} />}
    </>
  );
}