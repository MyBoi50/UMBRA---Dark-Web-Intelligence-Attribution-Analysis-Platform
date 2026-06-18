import { useState, useCallback, useRef } from "react";

const BACKEND = "http://localhost:8000";
const RISK_C = { CRITICAL: "#ff3c3c", HIGH: "#ff6b35", MEDIUM: "#ffcc00", LOW: "#00ff88" };
const C = { bg:"#03070f",border:"rgba(0,200,255,0.14)",text:"#b8ccd8",cyan:"#00c8ff",green:"#00ff88",yellow:"#ffcc00",orange:"#ff6b35",red:"#ff3c3c",purple:"#c084fc" };

const post = async (path, body) => {
  const r = await fetch(BACKEND + path, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
  if (!r.ok) throw new Error("Backend HTTP " + r.status + ". Is umbra_backend.py running on port 8000?");
  return r.json();
};
const getApi = async (path) => {
  const r = await fetch(BACKEND + path);
  if (!r.ok) throw new Error("HTTP " + r.status);
  return r.json();
};

function Panel({ title, color="#00c8ff", status, children }) {
  return (
    <div style={{ border:`1px solid ${color}28`, borderRadius:2, overflow:"hidden", marginBottom:14 }}>
      <div style={{ padding:"9px 14px", borderBottom:`1px solid ${color}20`, background:`${color}07`, display:"flex", justifyContent:"space-between", alignItems:"center" }}>
        <span style={{ color, fontSize:11, letterSpacing:"1.8px", fontWeight:"bold" }}>{title}</span>
        {status && <span style={{ color:"#b8ccd8", fontSize:10 }}>{status}</span>}
      </div>
      <div style={{ padding:14 }}>{children}</div>
    </div>
  );
}

function KV({ k, v, hi, mono }) {
  return (
    <div style={{ display:"flex", justifyContent:"space-between", padding:"4px 0", borderBottom:"1px solid rgba(255,255,255,0.04)", gap:12 }}>
      <span style={{ color:"#456070", fontSize:10, whiteSpace:"nowrap" }}>{k}</span>
      <span style={{ color:hi?"#fff":"#b8ccd8", fontSize:11, textAlign:"right", wordBreak:"break-all", fontFamily:mono?"Courier New, monospace":"inherit" }}>{String(v ?? "—")}</span>
    </div>
  );
}

function Badge({ risk }) {
  const c = RISK_C[risk] || "#4a7a9b";
  return <span style={{ fontSize:9, border:`1px solid ${c}`, color:c, padding:"2px 6px" }}>{risk}</span>;
}

function Pulse({ text }) {
  return <div style={{ display:"flex", alignItems:"center", gap:8, color:"#00c8ff", fontSize:11, padding:"6px 0" }}><span style={{ animation:"spin 1s linear infinite", display:"inline-block" }}>◎</span>{text}</div>;
}

export default function App() {
  const [tab, setTab] = useState("scan");
  const [onionUrl, setOnionUrl] = useState("");
  const [apiKey, setApiKey] = useState("");
  const [analyzeSubpages, setAnalyzeSubpages] = useState(false);
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(false);
  const [loadMsg, setLoadMsg] = useState("");
  const [error, setError] = useState("");
  const [torStatus, setTorStatus] = useState(null);
  const [torChecking, setTorChecking] = useState(false);
  const logRef = useRef(null);
  const [logs, setLogs] = useState([]);

  const addLog = (msg, type="info") => {
    const color = type==="ok"?"#00ff88":type==="err"?"#ff3c3c":type==="warn"?"#ffcc00":"#00c8ff";
    setLogs(p => [...p.slice(-80), { msg, color, t: new Date().toLocaleTimeString() }]);
    setTimeout(() => { if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight; }, 30);
  };

  const checkTor = async () => {
    setTorChecking(true);
    addLog("Checking Tor via backend...");
    try {
      const r = await getApi("/api/tor/check");
      setTorStatus(r);
      if (r.running && r.is_tor) addLog("Tor live. Exit IP: " + r.tor_ip, "ok");
      else addLog("Tor issue: " + (r.error || "not Tor exit"), "warn");
    } catch (e) {
      setTorStatus({ running:false, error:"Backend unreachable" });
      addLog("Backend unreachable. Run: python umbra_backend.py", "err");
    }
    setTorChecking(false);
  };

  const runAnalysis = useCallback(async () => {
    if (!onionUrl.trim()) return;
    setLoading(true); setError(""); setReport(null); setLogs([]);
    setTab("results");
    const steps = [
      "Establishing Tor circuit (3-hop)...",
      "Connecting via SOCKS5h to .onion...",
      "Fetching page source and headers...",
      "Running PII extraction (28 patterns)...",
      "Analyzing HTTP headers...",
      "Computing stylometric fingerprint...",
      "Querying Certificate Transparency logs...",
      "Querying blockchain (Blockchair)...",
      "Generating Claude OSINT brief...",
      "Compiling intelligence report...",
    ];
    let i = 0;
    const ticker = setInterval(() => {
      if (i < steps.length) { setLoadMsg(steps[i]); addLog(steps[i]); i++; }
    }, 1400);
    try {
      const result = await post("/api/analyze", {
        onion_url: onionUrl.trim(),
        anthropic_api_key: apiKey.trim(),
        analyze_subpages: analyzeSubpages,
        max_subpages: 3,
      });
      clearInterval(ticker);
      setReport(result);
      addLog("Done. PII: " + (result.pii?.length||0) + " artifacts, Headers: " + (result.headers?.length||0) + " findings", "ok");
      if (result.errors?.length) result.errors.forEach(e => addLog(e, "err"));
    } catch (e) {
      clearInterval(ticker);
      setError(e.message);
      addLog(e.message, "err");
    }
    setLoading(false);
  }, [onionUrl, apiKey, analyzeSubpages]);

  const TABS = [
    { id:"scan", label:"① SCAN" },
    { id:"results", label:"② RESULTS", disabled:!report && !loading },
    { id:"terminal", label:"⬡ LOG" },
  ];

  return (
    <div style={{ background:"#03070f", minHeight:"100vh", color:"#b8ccd8", fontFamily:"Courier New, monospace", fontSize:13 }}>
      <style>{`@keyframes spin{from{transform:rotate(0)}to{transform:rotate(360deg)}}*{box-sizing:border-box}::-webkit-scrollbar{width:4px}::-webkit-scrollbar-thumb{background:#1a3050}input,textarea,button{font-family:inherit}input::placeholder,textarea::placeholder{color:#2a4a6b}`}</style>

      <div style={{ padding:"11px 20px", borderBottom:"1px solid rgba(0,200,255,0.14)", display:"flex", justifyContent:"space-between", alignItems:"center", background:"rgba(0,0,0,0.6)" }}>
        <div style={{ display:"flex", alignItems:"center", gap:14 }}>
          <div style={{ width:32, height:32, border:"1px solid #00c8ff", display:"flex", alignItems:"center", justifyContent:"center", color:"#00c8ff", clipPath:"polygon(50% 0%,100% 25%,100% 75%,50% 100%,0% 75%,0% 25%)", background:"rgba(0,200,255,0.05)", fontSize:14 }}>◉</div>
          <div>
            <div style={{ color:"#00c8ff", fontSize:15, letterSpacing:5, fontWeight:"bold" }}>UMBRA</div>
            <div style={{ color:"#35607a", fontSize:9, letterSpacing:2 }}>DARK WEB INTELLIGENCE · TOR-CONNECTED · REAL ANALYSIS ENGINE</div>
          </div>
        </div>
        <div style={{ display:"flex", gap:20, alignItems:"center" }}>
          {torStatus && (
            <div style={{ fontSize:10 }}>
              <span style={{ display:"inline-block", width:7, height:7, borderRadius:"50%", background:torStatus.running&&torStatus.is_tor?"#00ff88":"#ff3c3c", marginRight:6, boxShadow:`0 0 6px ${torStatus.running&&torStatus.is_tor?"#00ff88":"#ff3c3c"}` }} />
              <span style={{ color:torStatus.running&&torStatus.is_tor?"#00ff88":"#ff3c3c" }}>
                {torStatus.running&&torStatus.is_tor?"TOR ACTIVE · "+torStatus.tor_ip:"TOR OFFLINE"}
              </span>
            </div>
          )}
          <button onClick={checkTor} disabled={torChecking} style={{ padding:"5px 14px", background:"transparent", border:"1px solid rgba(0,200,255,0.14)", color:"#b8ccd8", cursor:"pointer", fontSize:10, letterSpacing:1 }}>
            {torChecking?"CHECKING...":"CHECK TOR"}
          </button>
          <span style={{ color:"#ff6b35", fontSize:9, border:"1px solid rgba(255,107,53,0.3)", padding:"3px 10px" }}>LEA USE ONLY</span>
        </div>
      </div>

      <div style={{ display:"flex", borderBottom:"1px solid rgba(0,200,255,0.14)", background:"rgba(0,0,0,0.3)" }}>
        {TABS.map(t => (
          <button key={t.id} onClick={() => !t.disabled && setTab(t.id)} style={{ padding:"9px 22px", border:"none", background:"transparent", cursor:t.disabled?"not-allowed":"pointer", color:tab===t.id?"#00c8ff":t.disabled?"#1a3050":"#4a7a9b", borderBottom:tab===t.id?"2px solid #00c8ff":"2px solid transparent", fontSize:11, letterSpacing:1 }}>
            {t.label}
          </button>
        ))}
      </div>

      <div style={{ padding:20, maxWidth:1300, margin:"0 auto" }}>

        {tab === "scan" && (
          <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:16 }}>
            <div style={{ gridColumn:"1/-1", padding:"10px 16px", border:"1px solid rgba(255,204,0,0.2)", background:"rgba(255,204,0,0.03)", fontSize:11, color:"#ffcc00", lineHeight:1.7 }}>
              ⚠ PREREQUISITES — (1) Tor Browser open OR tor daemon running at 127.0.0.1:9050  (2) python umbra_backend.py running at localhost:8000  (3) Click CHECK TOR above to verify
            </div>

            <Panel title="TARGET .ONION URL" color="#00c8ff">
              <div style={{ marginBottom:10, color:"#4a7a9b", fontSize:10, lineHeight:1.6 }}>
                Paste any .onion v2 or v3 URL. Backend connects through Tor SOCKS5h, fetches real page source and HTTP headers, then all 9 analysis modules run automatically.
              </div>
              <input value={onionUrl} onChange={e => setOnionUrl(e.target.value)} onKeyDown={e => e.key==="Enter" && runAnalysis()} placeholder="http://3g2upl4pq6kufc4m.onion  or just  3g2upl4pq6kufc4m.onion" style={{ width:"100%", background:"rgba(0,0,0,0.7)", border:"1px solid rgba(0,200,255,0.3)", color:"#00c8ff", padding:"10px 12px", fontSize:13, outline:"none" }} />
              <div style={{ marginTop:12, display:"flex", gap:8, alignItems:"center" }}>
                <input type="checkbox" id="sub" checked={analyzeSubpages} onChange={e => setAnalyzeSubpages(e.target.checked)} style={{ accentColor:"#00c8ff" }} />
                <label htmlFor="sub" style={{ color:"#4a7a9b", fontSize:11, cursor:"pointer" }}>Also fetch internal subpages (up to 3) for wider intelligence surface</label>
              </div>
            </Panel>

            <Panel title="ANTHROPIC API KEY — AI OSINT Brief" color="#c084fc">
              <div style={{ marginBottom:10, color:"#4a7a9b", fontSize:10, lineHeight:1.6 }}>
                Needed for Claude OSINT brief. Get at console.anthropic.com. Skip if ANTHROPIC_API_KEY is set as env var on backend machine.
              </div>
              <input value={apiKey} onChange={e => setApiKey(e.target.value)} type="password" placeholder="sk-ant-api03-..." style={{ width:"100%", background:"rgba(0,0,0,0.7)", border:"1px solid rgba(192,132,252,0.3)", color:"#b8ccd8", padding:"10px 12px", fontSize:12, outline:"none" }} />
              <div style={{ marginTop:8, color:"#4a7a9b", fontSize:10 }}>Sent to your local backend only — never stored.</div>
            </Panel>

            <div style={{ gridColumn:"1/-1" }}>
              <div style={{ display:"grid", gridTemplateColumns:"repeat(3,1fr)", gap:10, marginBottom:16 }}>
                {[
                  ["TOR FETCH","#00c8ff","Real SOCKS5h through Tor daemon. Fetches page source + full headers. Follows redirects."],
                  ["PII EXTRACTION","#c084fc","28 regex patterns: emails, BTC/ETH/XMR/LTC, IPs, Telegram, Signal, Jabber, AWS S3, GA IDs, FB Pixel."],
                  ["HEADER ANALYSIS","#00ff88","X-Forwarded-For real IP leak detection, server fingerprint, timezone, CDN misconfiguration."],
                  ["STYLOMETRY","#ff6b35","Burrows Delta: TTR, Hapax/Dis Legomena, Yule K, Honore R, function words, trigrams, language detection."],
                  ["PAGE INTEL","#00c8ff","Platform (WordPress/Flask/Django), market categories (drugs/weapons/carding), clearnet links, analytics IDs."],
                  ["CERT TRANSPARENCY","#ffcc00","Live crt.sh for all clearnet domains found. Full cert history + SAN domains + Shodan query string."],
                  ["BLOCKCHAIN","#ff3c3c","Live Blockchair for every BTC address. Real balance, tx count, timestamps. Links to OXT.me/Chainalysis."],
                  ["CLAUDE OSINT","#00c8ff","All artifacts → Claude Opus. Returns operator profile, top 5 leads, opsec failures, exact tool queries."],
                  ["SUBPAGE CRAWL","#c084fc","Optional Tor-crawl of internal pages. Rate-limited to avoid detection signatures."],
                ].map(([name, color, desc]) => (
                  <div key={name} style={{ padding:10, border:`1px solid ${color}20`, background:`${color}05` }}>
                    <div style={{ color, fontSize:10, letterSpacing:1, marginBottom:5, fontWeight:"bold" }}>✓ {name}</div>
                    <div style={{ color:"#5a8090", fontSize:10, lineHeight:1.5 }}>{desc}</div>
                  </div>
                ))}
              </div>
              <button onClick={runAnalysis} disabled={loading || !onionUrl.trim()} style={{ width:"100%", padding:14, background:loading?"rgba(0,200,255,0.1)":"transparent", border:"1px solid #00c8ff", color:"#00c8ff", cursor:loading||!onionUrl.trim()?"not-allowed":"pointer", fontSize:13, letterSpacing:3, opacity:!onionUrl.trim()?0.3:1 }}>
                {loading ? "◎  " + loadMsg : "▶  CONNECT VIA TOR → FETCH → FULL ANALYSIS"}
              </button>
              {error && <div style={{ marginTop:8, padding:"10px 14px", border:"1px solid rgba(255,60,60,0.4)", background:"rgba(255,60,60,0.08)", color:"#ff3c3c", fontSize:11 }}>✖ {error}</div>}
            </div>
          </div>
        )}

        {tab === "results" && (
          <div>
            {loading && <div style={{ padding:"40px 0", textAlign:"center" }}><Pulse text={loadMsg} /><div style={{ color:"#4a7a9b", fontSize:11, marginTop:8 }}>Fetching via Tor — typically 30–90s</div></div>}
            {report && !loading && (
              <div>
                <div style={{ padding:"12px 16px", border:`1px solid ${report.fetch?.success?"rgba(0,255,136,0.4)":"rgba(255,60,60,0.4)"}`, background:`${report.fetch?.success?"rgba(0,255,136,0.06)":"rgba(255,60,60,0.06)"}`, display:"grid", gridTemplateColumns:"repeat(5,1fr)", gap:12, marginBottom:14 }}>
                  {[["TARGET",report.target_url],["STATUS",report.fetch?.status_code||(report.fetch?.success?"OK":"FAILED")],["SIZE",report.fetch?.content_length?((report.fetch.content_length/1024).toFixed(1)+" KB"):"—"],["TOR RESPONSE",report.fetch?.elapsed_seconds?(report.fetch.elapsed_seconds+"s"):"—"],["SERVER",report.fetch?.server||"—"]].map(([k,v]) => (
                    <div key={k}><div style={{ color:"#4a7a9b", fontSize:9, letterSpacing:1 }}>{k}</div><div style={{ color:"#fff", fontSize:11, wordBreak:"break-all" }}>{String(v)}</div></div>
                  ))}
                </div>

                {report.page_intel && (
                  <Panel title="⬡ PAGE INTELLIGENCE" color="#00c8ff" status={(report.page_intel.category_signals?.length||0)+" categories"}>
                    <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr 1fr", gap:16 }}>
                      <div>
                        <KV k="Title" v={report.page_intel.title||"—"} hi />
                        <KV k="Total Links" v={report.page_intel.all_links_count} />
                        <KV k="Clearnet Links" v={report.page_intel.clearnet_links?.length} hi />
                        <KV k="Other .onion Links" v={report.page_intel.onion_links?.length} />
                        <KV k="Has JavaScript" v={report.page_intel.has_js?"YES":"no"} />
                      </div>
                      <div>
                        <div style={{ color:"#4a7a9b", fontSize:9, letterSpacing:1, marginBottom:6 }}>MARKET CATEGORIES</div>
                        {report.page_intel.category_signals?.length>0?report.page_intel.category_signals.map(s=><div key={s} style={{ color:"#ff3c3c", fontSize:11, padding:"2px 0" }}>⚠ {s}</div>):<div style={{ color:"#4a7a9b", fontSize:11 }}>None detected</div>}
                        <div style={{ marginTop:10, color:"#4a7a9b", fontSize:9, letterSpacing:1, marginBottom:6 }}>PLATFORM</div>
                        {report.page_intel.platform_signals?.length>0?report.page_intel.platform_signals.map(s=><div key={s} style={{ color:"#ffcc00", fontSize:11 }}>◉ {s}</div>):<div style={{ color:"#4a7a9b", fontSize:11 }}>Custom/unknown</div>}
                      </div>
                      <div>
                        <div style={{ color:"#4a7a9b", fontSize:9, letterSpacing:1, marginBottom:6 }}>CLEARNET LINKS FOUND</div>
                        {report.page_intel.clearnet_links?.slice(0,5).map((l,i)=><div key={i} style={{ color:"#ff3c3c", fontSize:10, padding:"2px 0", wordBreak:"break-all" }}>→ {l.href?.slice(0,60)}</div>)}
                        {report.page_intel.analytics_ids?.length>0&&<><div style={{ marginTop:10, color:"#4a7a9b", fontSize:9, letterSpacing:1 }}>ANALYTICS IDs (CRITICAL)</div>{report.page_intel.analytics_ids.map((id,i)=><div key={i} style={{ color:"#ff3c3c", fontSize:11, fontFamily:"monospace" }}>⚠ {id}</div>)}</>}
                      </div>
                    </div>
                  </Panel>
                )}

                <Panel title="⬡ AI OSINT INTELLIGENCE BRIEF" color="#00c8ff">
                  {report.ai_brief?<pre style={{ color:"#b8ccd8", fontSize:12, lineHeight:1.8, whiteSpace:"pre-wrap", margin:0 }}>{report.ai_brief}</pre>:<span style={{ color:"#4a7a9b", fontSize:11 }}>No brief — check API key</span>}
                </Panel>

                <Panel title={"⬡ PII EXTRACTION — "+(report.pii?.length||0)+" ARTIFACTS"} color="#c084fc">
                  {report.pii?.length>0?(
                    <div style={{ display:"grid", gridTemplateColumns:"repeat(auto-fill, minmax(240px,1fr))", gap:8 }}>
                      {report.pii.map((p,i)=>(
                        <div key={i} style={{ padding:"9px 11px", border:`1px solid ${RISK_C[p.risk]||"#4a7a9b"}22`, background:`${RISK_C[p.risk]||"#4a7a9b"}06` }}>
                          <div style={{ display:"flex", justifyContent:"space-between", marginBottom:4 }}>
                            <span style={{ color:"#c084fc", fontSize:10 }}>{p.type}</span>
                            <Badge risk={p.risk} />
                          </div>
                          <div style={{ color:"#fff", fontSize:11, wordBreak:"break-all", fontFamily:"Courier New, monospace", marginBottom:p.context?3:0 }}>{p.value}</div>
                          {p.context&&<div style={{ color:"#4a7a9b", fontSize:9, fontStyle:"italic" }}>…{p.context.slice(0,80)}…</div>}
                        </div>
                      ))}
                    </div>
                  ):<span style={{ color:"#4a7a9b", fontSize:11 }}>No PII found in fetched content.</span>}
                </Panel>

                {report.headers?.length>0&&(
                  <Panel title="⬡ HTTP HEADER ANALYSIS" color="#00ff88" status={report.headers.length+" findings"}>
                    <div style={{ display:"flex", flexDirection:"column", gap:6 }}>
                      {report.headers.map((h,i)=>(
                        <div key={i} style={{ padding:"10px 12px", border:`1px solid ${RISK_C[h.risk]||"#4a7a9b"}20`, background:`${RISK_C[h.risk]||"#4a7a9b"}05`, display:"grid", gridTemplateColumns:"180px 220px 1fr", gap:12, alignItems:"start" }}>
                          <div><div style={{ color:"#00ff88", fontSize:11 }}>{h.field}</div><Badge risk={h.risk} /></div>
                          <div style={{ color:"#fff", fontSize:11, fontFamily:"Courier New, monospace", wordBreak:"break-all" }}>{h.value}</div>
                          <div>
                            <div style={{ color:"#b8ccd8", fontSize:11 }}>{h.note}</div>
                            {h.action&&<div style={{ color:"#00c8ff", fontSize:10, marginTop:3, fontFamily:"monospace" }}>⬡ {h.action}</div>}
                          </div>
                        </div>
                      ))}
                    </div>
                  </Panel>
                )}

                {report.stylometry&&(
                  <Panel title="⬡ STYLOMETRIC AUTHORSHIP FINGERPRINT" color="#ff6b35" status="Burrows Delta + Yule K + Honore R">
                    <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr 1fr", gap:16 }}>
                      <div>
                        <div style={{ color:"#ff6b35", fontSize:9, letterSpacing:1, marginBottom:8 }}>CORPUS STATS</div>
                        <KV k="Words" v={report.stylometry.word_count?.toLocaleString()} />
                        <KV k="Unique" v={report.stylometry.unique_words?.toLocaleString()} />
                        <KV k="Type-Token Ratio" v={report.stylometry.ttr} hi />
                        <KV k="Avg Sentence Len" v={report.stylometry.avg_sentence_length+" words"} hi />
                        <KV k="Avg Word Len" v={report.stylometry.avg_word_length+" chars"} />
                        <KV k="Hapax Legomena" v={report.stylometry.hapax_legomena+" ("+((report.stylometry.hapax_ratio||0)*100).toFixed(1)+"%)"} hi />
                        <KV k="Yule's K" v={report.stylometry.yules_k} />
                        <KV k="Honore's R" v={report.stylometry.honores_r} />
                        <div style={{ marginTop:8, padding:8, background:"rgba(255,107,53,0.08)", border:"1px solid rgba(255,107,53,0.15)", fontSize:10, color:"#5a8090", lineHeight:1.5 }}>{report.stylometry.vocabulary_richness}</div>
                      </div>
                      <div>
                        <div style={{ color:"#ff6b35", fontSize:9, letterSpacing:1, marginBottom:8 }}>LANGUAGE SIGNALS</div>
                        <KV k="Likely Speaker" v={report.stylometry.language?.likely_native_language} hi />
                        <KV k="Hindi/Hinglish" v={report.stylometry.language?.hindi_romanized?"✓ DETECTED":"—"} hi={report.stylometry.language?.hindi_romanized} />
                        <KV k="Russian patterns" v={report.stylometry.language?.russian_patterns?"✓ DETECTED":"—"} hi={report.stylometry.language?.russian_patterns} />
                        <KV k="British English" v={report.stylometry.language?.british_spelling?"✓":"—"} />
                        <KV k="American English" v={report.stylometry.language?.american_spelling?"✓":"—"} />
                        <div style={{ marginTop:12, color:"#ff6b35", fontSize:9, letterSpacing:1, marginBottom:6 }}>PUNCTUATION PROFILE</div>
                        {Object.entries(report.stylometry.punctuation||{}).map(([k,v])=><KV key={k} k={k} v={v} />)}
                      </div>
                      <div>
                        <div style={{ color:"#ff6b35", fontSize:9, letterSpacing:1, marginBottom:8 }}>FUNCTION WORDS (per 1000)</div>
                        {report.stylometry.top_function_words?.map(([w,f],i)=>(
                          <div key={i} style={{ display:"flex", justifyContent:"space-between", padding:"3px 0", borderBottom:"1px solid rgba(255,107,53,0.08)" }}>
                            <span style={{ color:"#b8ccd8", fontSize:11, fontFamily:"monospace" }}>{w}</span>
                            <span style={{ color:"#ff6b35", fontSize:11 }}>{f}</span>
                          </div>
                        ))}
                        <div style={{ marginTop:12, color:"#ff6b35", fontSize:9, letterSpacing:1, marginBottom:6 }}>CHAR TRIGRAMS</div>
                        {report.stylometry.top_trigrams?.map(([tg,cnt],i)=>(
                          <div key={i} style={{ display:"flex", justifyContent:"space-between", padding:"2px 0" }}>
                            <span style={{ color:"#b8ccd8", fontSize:11, fontFamily:"monospace" }}>"{tg}"</span>
                            <span style={{ color:"#4a7a9b", fontSize:11 }}>{cnt}</span>
                          </div>
                        ))}
                        <div style={{ marginTop:10, padding:8, background:"rgba(255,107,53,0.05)", border:"1px solid rgba(255,107,53,0.12)", fontSize:10, color:"#5a8090", lineHeight:1.5 }}>Feed into JGAAP or stylo (R) for cross-document authorship matching.</div>
                      </div>
                    </div>
                  </Panel>
                )}

                {report.cert_transparency?.length>0&&(
                  <Panel title="⬡ CERTIFICATE TRANSPARENCY — crt.sh Live" color="#ffcc00">
                    {report.cert_transparency.map((ct,i)=>(
                      <div key={i} style={{ marginBottom:12 }}>
                        <div style={{ color:"#ffcc00", fontSize:11, marginBottom:6 }}>Domain: <strong>{ct.domain}</strong> — {ct.result?.total_certs} certs</div>
                        {ct.result?.error?<div style={{ color:"#ff6b35", fontSize:11 }}>{ct.result.error}</div>:<>
                          <div style={{ maxHeight:180, overflowY:"auto", display:"flex", flexDirection:"column", gap:4 }}>
                            {ct.result?.results?.slice(0,10).map((c,j)=>(
                              <div key={j} style={{ padding:"6px 10px", border:"1px solid rgba(255,204,0,0.12)", background:"rgba(255,204,0,0.02)", display:"grid", gridTemplateColumns:"1fr 1fr auto", gap:8 }}>
                                <div style={{ color:"#ffcc00", fontSize:11 }}>{c.common_name}</div>
                                <div style={{ color:"#4a7a9b", fontSize:10 }}>{c.issuer?.slice(0,40)}</div>
                                <div style={{ color:"#b8ccd8", fontSize:10 }}>{c.not_before?.slice(0,10)}</div>
                              </div>
                            ))}
                          </div>
                          {ct.result?.investigation_note&&<div style={{ marginTop:8, padding:"8px 10px", background:"rgba(255,204,0,0.05)", border:"1px solid rgba(255,204,0,0.18)", color:"#ffcc00", fontSize:10 }}>⬡ {ct.result.investigation_note}</div>}
                        </>}
                      </div>
                    ))}
                  </Panel>
                )}

                {report.blockchain?.length>0&&(
                  <Panel title="⬡ BITCOIN BLOCKCHAIN — Blockchair Live" color="#ff3c3c">
                    {report.blockchain.map((b,i)=>(
                      <div key={i} style={{ marginBottom:12, padding:12, border:"1px solid rgba(255,60,60,0.2)", background:"rgba(255,60,60,0.04)" }}>
                        {b.result?.error?<div style={{ color:"#ff6b35", fontSize:11 }}>{b.result.error}</div>:b.result?(
                          <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:16 }}>
                            <div>
                              <KV k="Address" v={b.address} mono />
                              <KV k="Balance" v={b.result.balance_btc+" BTC"} hi />
                              <KV k="Total Received" v={b.result.total_received_btc+" BTC"} hi />
                              <KV k="Total Spent" v={b.result.total_spent_btc+" BTC"} />
                            </div>
                            <div>
                              <KV k="Transactions" v={b.result.transaction_count} hi />
                              <KV k="First Seen" v={b.result.first_seen} />
                              <KV k="Last Seen" v={b.result.last_seen} />
                              <KV k="Unspent Outputs" v={b.result.unspent_outputs} />
                            </div>
                            <div style={{ gridColumn:"1/-1", display:"flex", gap:8, flexWrap:"wrap" }}>
                              {Object.entries(b.result.investigation_links||{}).map(([label,url])=>(
                                <a key={label} href={url} target="_blank" rel="noreferrer" style={{ color:"#00c8ff", fontSize:10, border:"1px solid rgba(0,200,255,0.3)", padding:"4px 10px", textDecoration:"none" }}>⬡ {label.replace(/_/g," ").toUpperCase()}</a>
                              ))}
                            </div>
                            {b.result.investigation_note&&<div style={{ gridColumn:"1/-1", padding:8, background:"rgba(255,60,60,0.05)", border:"1px solid rgba(255,60,60,0.15)", color:"#b8ccd8", fontSize:10, lineHeight:1.6 }}>⬡ {b.result.investigation_note}</div>}
                          </div>
                        ):null}
                      </div>
                    ))}
                  </Panel>
                )}
              </div>
            )}
          </div>
        )}

        {tab === "terminal" && (
          <div>
            <div style={{ color:"#00c8ff", fontSize:11, letterSpacing:2, marginBottom:10 }}>⬡ OPERATION LOG</div>
            <div ref={logRef} style={{ background:"rgba(0,0,0,0.85)", border:"1px solid rgba(0,200,255,0.14)", padding:14, height:"65vh", overflowY:"auto", fontFamily:"Courier New, monospace", fontSize:12 }}>
              {logs.length===0&&<div style={{ color:"#2a4a6b" }}>[UMBRA] Ready. Run a scan to see operation log.</div>}
              {logs.map((l,i)=><div key={i} style={{ color:l.color, padding:"2px 0", lineHeight:1.5 }}><span style={{ color:"#1a3050", marginRight:10 }}>{l.t}</span>{l.msg}</div>)}
              <div style={{ color:"#00c8ff" }}>█</div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
