export const SEVERITY_CONFIG = {
  CRITICAL: { color: "#ff3b30", bg: "#fff2f1", border: "#ffd0ce", label: "CRITICAL", rowBg: "rgba(255,59,48,0.06)" },
  HIGH:     { color: "#ff9500", bg: "#fff8f0", border: "#ffdea8", label: "HIGH",     rowBg: "rgba(255,149,0,0.06)" },
  MEDIUM:   { color: "#f5a623", bg: "#fffbf0", border: "#fdecc8", label: "MEDIUM",   rowBg: "rgba(245,166,35,0.05)" },
  LOW:      { color: "#34c759", bg: "#f1faf4", border: "#b8edc8", label: "LOW",      rowBg: "rgba(52,199,89,0.05)" },
  UNKNOWN:  { color: "#8e8e93", bg: "#f5f5f7", border: "#d1d1d6", label: "N/A",      rowBg: "rgba(142,142,147,0.04)" },
};

export const globalStyles = `
  @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: linear-gradient(180deg, #c8eaf5 0%, #d6eef7 35%, #e8d9b8 70%, #f0e4c8 100%); background-attachment: fixed; color: #1d1d1f; font-family: -apple-system, 'SF Pro Display', 'Inter', sans-serif; min-height: 100vh; }
  ::-webkit-scrollbar { width: 6px; }
  ::-webkit-scrollbar-track { background: #f5f5f7; }
  ::-webkit-scrollbar-thumb { background: #d1d1d6; border-radius: 3px; }
  @keyframes pulse { 0%, 100% { opacity: 0.4; transform: scale(0.85); } 50% { opacity: 1; transform: scale(1); } }
  @keyframes slideUp { from { opacity: 0; transform: translateY(12px); } to { opacity: 1; transform: translateY(0); } }
  ::placeholder { color: #aeaeb2; }
  input:focus { outline: none; }
  button:focus-visible { outline: 2px solid #0071e3; outline-offset: 2px; }
`;

export const s = {
  page: { maxWidth: 920, margin: "0 auto", padding: "48px 24px 100px" },

  liveIndicator: { width: 8, height: 8, borderRadius: "50%", background: "#ff3b30", boxShadow: "0 0 6px #ff3b30aa", animation: "pulse 2s ease-in-out infinite" },
  liveLabel: { color: "#8e8e93", fontSize: 12, letterSpacing: "0.08em", fontWeight: 600 },
  h1: { fontSize: 40, fontWeight: 700, color: "#1d1d1f", letterSpacing: "-0.03em", lineHeight: 1.05 },
  subtitle: { color: "#6e6e73", fontSize: 15, marginTop: 10, fontWeight: 400 },

  dashboard: { display: "flex", gap: 12, marginBottom: 32, flexWrap: "wrap" },
  totalCard: { background: "#ffffff", border: "1px solid #e5e5ea", borderRadius: 16, padding: "20px 24px", flex: 1, minWidth: 120, display: "flex", flexDirection: "column", gap: 6, boxShadow: "0 1px 3px rgba(0,0,0,0.06)" },
  totalCount: { color: "#1d1d1f", fontSize: 34, fontWeight: 700, lineHeight: 1, letterSpacing: "-0.02em" },
  totalLabel: { color: "#8e8e93", fontSize: 11, letterSpacing: "0.06em", fontWeight: 600 },

  searchRow: { display: "flex", gap: 10, marginBottom: 12, flexWrap: "wrap" },
  searchBox: { flex: 1, minWidth: 200, display: "flex", alignItems: "center", gap: 10, background: "#ffffff", border: "1px solid #e5e5ea", borderRadius: 12, padding: "0 16px", boxShadow: "0 1px 3px rgba(0,0,0,0.06)" },
  searchIcon: { color: "#aeaeb2", fontSize: 16 },
  searchInput: { flex: 1, background: "transparent", border: "none", color: "#1d1d1f", fontSize: 15, padding: "13px 0", fontFamily: "inherit" },
  searchClear: { background: "none", border: "none", color: "#aeaeb2", cursor: "pointer", fontSize: 18, padding: 0, lineHeight: 1 },

  sortRow: { display: "flex", gap: 10, marginBottom: 12, flexWrap: "wrap", alignItems: "center" },
  filterRow2: { display: "flex", gap: 10, marginBottom: 24, flexWrap: "wrap", alignItems: "center" },
  filterRow: { display: "flex", gap: 6, flexWrap: "wrap" },

  resultsCount: { color: "#aeaeb2", fontSize: 13, marginBottom: 14 },

  errorBox: { background: "#fff2f1", border: "1px solid #ffd0ce", borderRadius: 14, padding: "20px 24px", marginBottom: 20 },
  errorTitle: { color: "#ff3b30", fontWeight: 700, marginBottom: 6, fontSize: 15 },
  errorMsg: { color: "#c0392b", fontSize: 14 },
  retryBtn: { marginTop: 12, background: "white", border: "1px solid #ffd0ce", color: "#ff3b30", borderRadius: 8, padding: "8px 18px", fontSize: 13, fontWeight: 600, cursor: "pointer" },

  cveList: { display: "flex", flexDirection: "column", gap: 8 },

  cardBase: { borderRadius: 14, padding: "16px 20px", cursor: "pointer", transition: "all 0.15s ease", border: "1px solid #e5e5ea", boxShadow: "0 1px 3px rgba(0,0,0,0.05)" },
  cardInner: { display: "flex", justifyContent: "space-between", alignItems: "center", gap: 12 },
  cardLeft: { flex: 1, minWidth: 0 },
  cardMeta: { display: "flex", alignItems: "center", gap: 8, marginBottom: 4 },
  cardId: { color: "#0071e3", fontFamily: "monospace", fontSize: 12, fontWeight: 700, letterSpacing: "0.04em" },
  cardDate: { color: "#aeaeb2", fontSize: 11 },
  cardTitle: { color: "#1d1d1f", fontSize: 14, margin: 0, fontWeight: 600, lineHeight: 1.35, overflow: "hidden", display: "-webkit-box", WebkitLineClamp: 1, WebkitBoxOrient: "vertical" },
  cardDesc: { color: "#6e6e73", fontSize: 13, margin: "3px 0 0", lineHeight: 1.5, overflow: "hidden", display: "-webkit-box", WebkitLineClamp: 1, WebkitBoxOrient: "vertical" },
  cardRight: { flexShrink: 0, display: "flex", alignItems: "center", gap: 8 },

  modalOverlay: { position: "fixed", inset: 0, background: "rgba(0,0,0,0.35)", display: "flex", alignItems: "center", justifyContent: "center", zIndex: 1000, padding: 20, backdropFilter: "blur(8px)" },
  modalBox: { background: "#ffffff", borderRadius: 20, maxWidth: 680, width: "100%", maxHeight: "90vh", overflowY: "auto", animation: "slideUp 0.2s ease-out", boxShadow: "0 24px 80px rgba(0,0,0,0.18)" },
  modalBody: { padding: "32px 36px 36px" },
  modalHeader: { display: "flex", justifyContent: "space-between", alignItems: "flex-start", gap: 16 },
  modalIdRow: { display: "flex", alignItems: "center", gap: 10, marginBottom: 8 },
  modalId: { color: "#0071e3", fontFamily: "monospace", fontSize: 13, fontWeight: 700, letterSpacing: "0.06em" },
  modalTitle: { color: "#1d1d1f", fontSize: 22, fontWeight: 700, margin: 0, lineHeight: 1.25, letterSpacing: "-0.01em" },
  modalCloseBtn: { background: "#f5f5f7", border: "none", color: "#6e6e73", borderRadius: "50%", width: 32, height: 32, display: "flex", alignItems: "center", justifyContent: "center", cursor: "pointer", fontSize: 18, flexShrink: 0 },
  modalScoreLabel: { color: "#8e8e93", fontSize: 12, marginBottom: 8, letterSpacing: "0.06em", fontWeight: 600 },
  modalMetaGrid: { display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12, marginTop: 20 },
  modalMetaBox: { background: "#f5f5f7", borderRadius: 12, padding: "12px 16px" },
  modalMetaLabel: { color: "#8e8e93", fontSize: 11, letterSpacing: "0.06em", fontWeight: 600, display: "block", marginBottom: 4 },
  modalMetaValue: { color: "#1d1d1f", fontSize: 15, fontWeight: 600 },
  modalDescLabel: { color: "#8e8e93", fontSize: 12, marginBottom: 8, letterSpacing: "0.06em", fontWeight: 600 },
  modalDescBox: { color: "#3a3a3c", fontSize: 14, lineHeight: 1.75, margin: 0, background: "#f5f5f7", borderRadius: 12, padding: "16px 18px" },
  modalFooter: { marginTop: 24, paddingTop: 20, borderTop: "1px solid #f2f2f7" },
  nvdLink: { color: "#0071e3", fontSize: 13, textDecoration: "none", fontWeight: 500 },

  aiBox: { background: "#f0f6ff", border: "1px solid #c9e0ff", borderRadius: 12, padding: "16px 20px", marginTop: 20 },
  aiHeader: { display: "flex", alignItems: "center", gap: 8, marginBottom: 10 },
  aiLabel: { color: "#0071e3", fontWeight: 700, fontSize: 12, letterSpacing: "0.06em" },
  aiText: { color: "#1d1d1f", fontSize: 14, lineHeight: 1.75, margin: 0 },

  scoreBarTrack: { flex: 1, height: 5, background: "#e5e5ea", borderRadius: 3, overflow: "hidden" },

  emptyState: { textAlign: "center", padding: "70px 20px" },
  emptyIcon: { fontSize: 44, marginBottom: 16 },
  emptyTitle: { color: "#3a3a3c", fontSize: 17, fontWeight: 600, marginBottom: 8 },
  emptyMsg: { color: "#8e8e93", fontSize: 14 },
};