import { useState, useEffect, useCallback, useRef } from "react";
import { SEVERITY_CONFIG, globalStyles, s } from "./styles.js";
import surfImg from "./assets/surff.png";

function getSeverity(score) {
  if (score === null || score === undefined) return "UNKNOWN";
  if (score >= 9.0) return "CRITICAL";
  if (score >= 7.0) return "HIGH";
  if (score >= 4.0) return "MEDIUM";
  return "LOW";
}

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

function ScoreBar({ score }) {
  if (score == null) return null;
  const cfg = SEVERITY_CONFIG[getSeverity(score)];
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
      <div style={s.scoreBarTrack}>
        <div style={{ width: `${(score / 10) * 100}%`, height: "100%", background: cfg.color, borderRadius: 3 }} />
      </div>
      <span style={{ color: cfg.color, fontFamily: "monospace", fontSize: 13, minWidth: 28, fontWeight: 600 }}>
        {Number(score).toFixed(1)}
      </span>
    </div>
  );
}

function StatCard({ label, count, severity }) {
  const cfg = SEVERITY_CONFIG[severity];
  return (
    <div style={{ ...s.totalCard, borderTop: `3px solid ${cfg.color}` }}>
      <span style={{ color: cfg.color, fontSize: 34, fontWeight: 700, lineHeight: 1, letterSpacing: "-0.02em" }}>{count}</span>
      <span style={{ color: cfg.color, opacity: 0.8, fontSize: 11, letterSpacing: "0.06em", fontWeight: 600 }}>{label}</span>
    </div>
  );
}

function LoadingDots() {
  return (
    <span style={{ display: "inline-flex", gap: 3, alignItems: "center" }}>
      {[0, 1, 2].map(i => (
        <span key={i} style={{ width: 5, height: 5, borderRadius: "50%", background: "#0071e3", animation: `pulse 1.2s ease-in-out ${i * 0.2}s infinite` }} />
      ))}
    </span>
  );
}

function AISummary({ cveId }) {
  const [summary, setSummary] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const generate = async () => {
    setLoading(true); setError(null);
    try {
      const res = await fetch(`/cves/${cveId}/summary`);
      if (!res.ok) throw new Error();
      const data = await res.json();
      setSummary(data.summary);
    } catch {
      setError("Could not generate summary. Make sure the backend has an API key configured.");
    } finally { setLoading(false); }
  };

  if (summary) return (
    <div style={s.aiBox}>
      <div style={s.aiHeader}>
        <span style={{ fontSize: 14 }}>✦</span>
        <span style={s.aiLabel}>AI PLAIN-ENGLISH SUMMARY</span>
      </div>
      <p style={s.aiText}>{summary}</p>
    </div>
  );

  return (
    <div style={{ marginTop: 20 }}>
      {error && <p style={{ color: "#ff3b30", fontSize: 13, marginBottom: 10 }}>{error}</p>}
      <button onClick={generate} disabled={loading} style={{
        background: loading ? "#f5f5f7" : "#0071e3",
        color: loading ? "#aeaeb2" : "#ffffff",
        cursor: loading ? "not-allowed" : "pointer",
        border: "none", borderRadius: 10, padding: "11px 20px",
        fontSize: 14, fontWeight: 600, display: "flex", alignItems: "center", gap: 8,
      }}>
        {loading ? <><LoadingDots /> Generating…</> : <>✦ Explain this CVE in plain English</>}
      </button>
    </div>
  );
}

function ExploreSources({ cveId }) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let alive = true;
    setLoading(true);
    fetch(`/cves/${cveId}/explore`)
      .then(r => (r.ok ? r.json() : null))
      .then(d => { if (alive) { setData(d); setLoading(false); } })
      .catch(() => { if (alive) setLoading(false); });
    return () => { alive = false; };
  }, [cveId]);

  const linkStyle = {
    display: "inline-flex", alignItems: "center", gap: 5,
    background: "#f5f5f7", border: "1px solid #e5e5ea", borderRadius: 8,
    padding: "6px 12px", fontSize: 12, fontWeight: 600, color: "#1d1d1f",
    textDecoration: "none", whiteSpace: "nowrap",
  };

  return (
    <div style={{ marginTop: 24 }}>
      <p style={s.modalDescLabel}>CROSS-REFERENCES</p>
      {loading && <p style={{ color: "#8e8e93", fontSize: 13 }}>Looking up sources…</p>}
      {data && (
        <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
          <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
            {Object.entries(data.sources || {}).map(([name, url]) => (
              <a key={name} href={url} target="_blank" rel="noopener noreferrer" style={linkStyle}>
                🔗 {name.toUpperCase()} ↗
              </a>
            ))}
          </div>

          {data.ghsa && data.ghsa.length > 0 && (
            <div>
              <p style={{ color: "#8e8e93", fontSize: 11, fontWeight: 600, letterSpacing: "0.04em", margin: "0 0 8px" }}>
                GITHUB ADVISORIES · AFFECTED PACKAGES
              </p>
              <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                {data.ghsa.map(g => (
                  <a key={g.ghsa_id} href={g.url} target="_blank" rel="noopener noreferrer"
                     style={{ ...linkStyle, justifyContent: "space-between", padding: "10px 12px" }}>
                    <span style={{ display: "flex", flexDirection: "column", gap: 3, alignItems: "flex-start" }}>
                      <span style={{ fontFamily: "monospace", fontSize: 11, color: "#0071e3" }}>{g.ghsa_id}</span>
                      <span style={{ fontWeight: 500, color: "#3a3a3c", whiteSpace: "normal" }}>{g.summary}</span>
                      {g.packages?.length > 0 && (
                        <span style={{ display: "flex", gap: 5, flexWrap: "wrap", marginTop: 2 }}>
                          {g.packages.slice(0, 6).map(p => (
                            <span key={p} style={{ background: "#312e81", color: "#c7d2fe", borderRadius: 6, padding: "2px 7px", fontSize: 10, fontFamily: "monospace" }}>{p}</span>
                          ))}
                        </span>
                      )}
                    </span>
                  </a>
                ))}
              </div>
            </div>
          )}

          {data.web && data.web.length > 0 && (
            <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
              {data.web.map(w => (
                <a key={w.label} href={w.url} target="_blank" rel="noopener noreferrer" style={linkStyle}>
                  ⌕ {w.label} ↗
                </a>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function GPTButton({ cve }) {
  const severity = (cve.severity || getSeverity(cve.cvss_score)).toUpperCase();
  const prompt = `I need help understanding and remediating the following CVE vulnerability:

CVE ID: ${cve.cve_id}
Title: ${cve.title || cve.cve_id}
Severity: ${severity} (CVSS Score: ${cve.cvss_score ?? "N/A"})
Published: ${cve.published_date ? new Date(cve.published_date).toLocaleDateString() : "N/A"}
Description: ${cve.description || "No description available."}

Please explain:
1. What exactly is this vulnerability and what systems/software does it affect?
2. What can an attacker do if they exploit it?
3. Step-by-step remediation — what should I do to fix or mitigate this?
4. Any patches, workarounds, or configuration changes recommended?`;

  const openInChatGPT = (e) => {
    e.stopPropagation();
    const url = `https://chat.openai.com/?q=${encodeURIComponent(prompt)}`;
    window.open(url, "_blank");
  };

  return (
    <button
      onClick={openInChatGPT}
      title="Ask ChatGPT how to fix this CVE"
      style={{
        background: "#f5f5f7", border: "1px solid #e5e5ea",
        borderRadius: 8, padding: "5px 10px",
        fontSize: 11, fontWeight: 600, color: "#1d1d1f",
        cursor: "pointer", whiteSpace: "nowrap",
        display: "flex", alignItems: "center", gap: 5,
        transition: "all 0.15s",
      }}
      onMouseEnter={e => { e.currentTarget.style.background = "#e8f4ff"; e.currentTarget.style.color = "#0071e3"; e.currentTarget.style.borderColor = "#c9e0ff"; }}
      onMouseLeave={e => { e.currentTarget.style.background = "#f5f5f7"; e.currentTarget.style.color = "#1d1d1f"; e.currentTarget.style.borderColor = "#e5e5ea"; }}
    >
      <span>💬</span> Ask GPT
    </button>
  );
}

function SortButton({ label, value, current, onClick }) {
  const active = current === value;
  return (
    <button onClick={() => onClick(value)} style={{
      background: active ? "#0071e3" : "#ffffff",
      color: active ? "#ffffff" : "#3a3a3c",
      border: `1px solid ${active ? "#0071e3" : "#e5e5ea"}`,
      borderRadius: 8, padding: "8px 14px",
      fontSize: 12, fontWeight: 600, cursor: "pointer",
      transition: "all 0.15s", whiteSpace: "nowrap",
    }}>
      {label}
    </button>
  );
}

function FilterButton({ label, value, current, color, onClick }) {
  const active = current === value;
  return (
    <button onClick={() => onClick(value)} style={{
      background: active ? (color || "#0071e3") : "#ffffff",
      color: active ? "#ffffff" : (color || "#3a3a3c"),
      border: `1px solid ${active ? (color || "#0071e3") : "#e5e5ea"}`,
      borderRadius: 8, padding: "8px 14px",
      fontSize: 12, fontWeight: 600, cursor: "pointer",
      transition: "all 0.15s",
    }}>
      {label}
    </button>
  );
}

function CveModal({ cve, onClose }) {
  const severity = (cve.severity || getSeverity(cve.cvss_score)).toUpperCase();
  const cfg = SEVERITY_CONFIG[severity] || SEVERITY_CONFIG.UNKNOWN;

  useEffect(() => {
    const handler = (e) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [onClose]);

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
              <h2 style={s.modalTitle}>{cve.title || cve.cve_id}</h2>
            </div>
            <button onClick={onClose} style={s.modalCloseBtn}>×</button>
          </div>

          {cve.cvss_score != null && (
            <div style={{ marginTop: 20 }}>
              <p style={s.modalScoreLabel}>CVSS SCORE</p>
              <ScoreBar score={cve.cvss_score} />
            </div>
          )}

          <div style={s.modalMetaGrid}>
            {cve.published_date && (
              <div style={s.modalMetaBox}>
                <span style={s.modalMetaLabel}>PUBLISHED</span>
                <span style={s.modalMetaValue}>{new Date(cve.published_date).toLocaleDateString("en-US", { year: "numeric", month: "long", day: "numeric" })}</span>
              </div>
            )}
            {cve.cvss_score != null && (
              <div style={s.modalMetaBox}>
                <span style={s.modalMetaLabel}>BASE SCORE</span>
                <span style={{ ...s.modalMetaValue, color: cfg.color }}>{Number(cve.cvss_score).toFixed(1)} / 10.0</span>
              </div>
            )}
          </div>

          <div style={{ marginTop: 24 }}>
            <p style={s.modalDescLabel}>DESCRIPTION</p>
            <p style={s.modalDescBox}>{cve.description || "No description available."}</p>
          </div>

          <AISummary cveId={cve.cve_id} />

          <ExploreSources cveId={cve.cve_id} />

          <div style={{ ...s.modalFooter, display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <a href={`https://nvd.nist.gov/vuln/detail/${cve.cve_id}`} target="_blank" rel="noopener noreferrer" style={s.nvdLink}>
              View on NVD ↗
            </a>
            <GPTButton cve={cve} />
          </div>
        </div>
      </div>
    </div>
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
            {cve.published_date && (
              <span style={s.cardDate}>{new Date(cve.published_date).toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" })}</span>
            )}
          </div>
          <p style={s.cardTitle}>{cve.title || cve.cve_id}</p>
          <p style={s.cardDesc}>{cve.description || "No description available."}</p>
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

const SORT_OPTIONS = [
  { label: "⬆ Severity", value: "severity_desc" },
  { label: "A → Z", value: "alpha_asc" },
  { label: "Z → A", value: "alpha_desc" },
  { label: "Newest first", value: "date_desc" },
  { label: "Oldest first", value: "date_asc" },
];

const SEVERITY_ORDER = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, UNKNOWN: 4 };

function sortCves(list, sortBy) {
  const copy = [...list];
  switch (sortBy) {
    case "severity_desc": return copy.sort((a, b) => {
      const sa = SEVERITY_ORDER[(a.severity || getSeverity(a.cvss_score)).toUpperCase()] ?? 4;
      const sb = SEVERITY_ORDER[(b.severity || getSeverity(b.cvss_score)).toUpperCase()] ?? 4;
      return sa - sb;
    });
    case "alpha_asc": return copy.sort((a, b) => (a.title || a.cve_id).localeCompare(b.title || b.cve_id));
    case "alpha_desc": return copy.sort((a, b) => (b.title || b.cve_id).localeCompare(a.title || a.cve_id));
    case "date_desc": return copy.sort((a, b) => new Date(b.published_date) - new Date(a.published_date));
    case "date_asc": return copy.sort((a, b) => new Date(a.published_date) - new Date(b.published_date));
    default: return copy;
  }
}

export default function App() {
  const [cves, setCves] = useState([]);
  const [stats, setStats] = useState({ CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, total: 0 });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [search, setSearch] = useState("");
  const [severity, setSeverity] = useState("ALL");
  const [sortBy, setSortBy] = useState("severity_desc");
  const [selected, setSelected] = useState(null);
  const [scraping, setScraping] = useState(false);
  const debounceRef = useRef(null);

  const computeStats = (list) => {
    const st = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, total: list.length };
    list.forEach(c => {
      const sev = (c.severity || getSeverity(c.cvss_score)).toUpperCase();
      if (st[sev] !== undefined) st[sev]++;
    });
    setStats(st);
  };

  const fetchCves = useCallback(async (q, sev) => {
    setLoading(true); setError(null);
    try {
      const params = new URLSearchParams();
      if (q) params.set("search", q);
      if (sev && sev !== "ALL") params.set("severity", sev);
      const res = await fetch(`/cves?${params}`);
      if (!res.ok) throw new Error();
      const data = await res.json();
      const list = Array.isArray(data) ? data : data.cves || [];
      setCves(list);
      try {
        const sr = await fetch("/stats");
        if (sr.ok) setStats(await sr.json());
        else computeStats(list);
      } catch { computeStats(list); }
    } catch {
      setError("Cannot reach the API. Make sure the FastAPI backend is running on port 8000.");
      setCves([]);
    } finally { setLoading(false); }
  }, []);

  useEffect(() => { fetchCves("", "ALL"); }, [fetchCves]);

  const handleSearch = (val) => {
    setSearch(val);
    clearTimeout(debounceRef.current);
    debounceRef.current = setTimeout(() => fetchCves(val, severity), 350);
  };

  const handleSeverity = (sev) => { setSeverity(sev); fetchCves(search, sev); };

  const handleScrape = async () => {
    setScraping(true);
    try {
      const res = await fetch("/scrape", { method: "POST" });
      if (!res.ok) throw new Error();
      await fetchCves(search, severity);
    } catch {
      alert("Scraper failed. Make sure the backend exposes a POST /scrape endpoint.");
    } finally { setScraping(false); }
  };

  const displayed = sortCves(cves, sortBy);

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

        {/* Header */}
        <div style={{ marginBottom: 36, display: "flex", justifyContent: "space-between", alignItems: "flex-start", flexWrap: "wrap", gap: 16 }}>
          <div>
            <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 6 }}>
              <div style={s.liveIndicator} />
              <span style={s.liveLabel}>LIVE CVE INTELLIGENCE</span>
            </div>
            <div style={{ display: "flex", alignItems: "center", gap: 14 }}>
            <span style={{ fontSize: 38 }}>🏄</span>
            <h1 style={s.h1}>CVE Explorer</h1>
            </div>
            <p style={s.subtitle}>Real-time vulnerabilities from the National Vulnerability Database.</p>
          </div>
          <button
            onClick={handleScrape}
            disabled={scraping}
            style={{
              background: scraping ? "#f5f5f7" : "#1d1d1f",
              color: scraping ? "#aeaeb2" : "#ffffff",
              border: "none", borderRadius: 12,
              padding: "12px 22px", fontSize: 14, fontWeight: 600,
              cursor: scraping ? "not-allowed" : "pointer",
              display: "flex", alignItems: "center", gap: 8,
              boxShadow: scraping ? "none" : "0 2px 8px rgba(0,0,0,0.15)",
              transition: "all 0.15s",
            }}
          >
            {scraping ? <><LoadingDots /> Fetching new data…</> : <>↻ Refresh CVE Data</>}
          </button>
        </div>

        {/* Dashboard */}
        <div style={s.dashboard}>
          <StatCard label="CRITICAL" count={stats.CRITICAL} severity="CRITICAL" />
          <StatCard label="HIGH" count={stats.HIGH} severity="HIGH" />
          <StatCard label="MEDIUM" count={stats.MEDIUM} severity="MEDIUM" />
          <StatCard label="LOW" count={stats.LOW} severity="LOW" />
          <div style={s.totalCard}>
            <span style={s.totalCount}>{stats.total || cves.length}</span>
            <span style={s.totalLabel}>TOTAL</span>
          </div>
        </div>

        {/* Search */}
        <div style={s.searchRow}>
          <div style={s.searchBox}>
            <span style={s.searchIcon}>⌕</span>
            <input
              type="text"
              placeholder="Search by CVE ID, keyword, or technology…"
              value={search}
              onChange={e => handleSearch(e.target.value)}
              style={s.searchInput}
            />
            {search && <button onClick={() => handleSearch("")} style={s.searchClear}>×</button>}
          </div>
        </div>

        {/* Sort */}
        <div style={s.sortRow}>
        <span style={{ color: "#8e8e93", fontSize: 12, fontWeight: 600, letterSpacing: "0.04em" }}>SORT</span>
        {SORT_OPTIONS.map(opt => (
            <SortButton key={opt.value} label={opt.label} value={opt.value} current={sortBy} onClick={setSortBy} />
        ))}
        </div>

        {/* Filter */}
        <div style={s.filterRow2}>
        <span style={{ color: "#8e8e93", fontSize: 12, fontWeight: 600, letterSpacing: "0.04em" }}>FILTER</span>
        {["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"].map(sev => {
            const cfg = sev === "ALL" ? null : SEVERITY_CONFIG[sev];
            return (
            <FilterButton
                key={sev} label={sev} value={sev}
                current={severity} color={cfg?.color}
                onClick={handleSeverity}
            />
            );
        })}
        </div>

        {/* Count */}
        {!loading && !error && (
          <p style={s.resultsCount}>
            {displayed.length === 0 ? "No results" : `${displayed.length} vulnerabilit${displayed.length === 1 ? "y" : "ies"}${search ? ` matching "${search}"` : ""}${severity !== "ALL" ? ` · ${severity}` : ""}`}
          </p>
        )}

        {/* Error */}
        {error && (
          <div style={s.errorBox}>
            <p style={s.errorTitle}>⚠ Connection Error</p>
            <p style={s.errorMsg}>{error}</p>
            <button onClick={() => fetchCves(search, severity)} style={s.retryBtn}>Retry</button>
          </div>
        )}

        {/* Loading skeletons */}
        {loading && (
          <div style={s.cveList}>
            {[...Array(6)].map((_, i) => (
              <div key={i} style={{ background: "#ffffff", borderRadius: 14, height: 80, border: "1px solid #e5e5ea", borderLeft: "4px solid #e5e5ea", opacity: 1 - i * 0.12, animation: "pulse 1.5s ease-in-out infinite" }} />
            ))}
          </div>
        )}

        {/* Empty */}
        {!loading && !error && displayed.length === 0 && (
          <div style={s.emptyState}>
            <div style={s.emptyIcon}>🔍</div>
            <p style={s.emptyTitle}>No vulnerabilities found</p>
            <p style={s.emptyMsg}>{search ? `No results for "${search}"` : "No CVEs yet — click Refresh CVE Data to fetch from NVD"}</p>
          </div>
        )}

        {/* List */}
        {!loading && !error && displayed.length > 0 && (
          <div style={s.cveList}>
            {displayed.map(cve => <CveCard key={cve.cve_id} cve={cve} onClick={setSelected} />)}
          </div>
        )}
      </div>

      {selected && <CveModal cve={selected} onClose={() => setSelected(null)} />}
    </>
  );
}