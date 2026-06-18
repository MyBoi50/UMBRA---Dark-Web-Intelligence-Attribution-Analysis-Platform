import { useState, useCallback, useRef, useEffect } from "react";
import * as d3 from "d3";

// ─── Design Tokens ───────────────────────────────────────────────────────────
const T = {
  // Backgrounds
  bg:       "#0d1117",
  surface:  "#161b22",
  surface2: "#21262d",
  surface3: "#2d333b",
  border:   "#30363d",
  borderFocus: "#58a6ff",

  // Text
  text:     "#e6edf3",
  textMuted:"#8b949e",
  textDim:  "#484f58",

  // Semantic
  blue:     "#58a6ff",
  green:    "#3fb950",
  yellow:   "#d29922",
  orange:   "#f0883e",
  red:      "#f85149",
  purple:   "#a371f7",
  teal:     "#39d353",
  cyan:     "#79c0ff",

  // Status colors mapped to risk
  risk: { CRITICAL:"#f85149", HIGH:"#f0883e", MEDIUM:"#d29922", LOW:"#3fb950" },
};

const BACKEND = "http://localhost:8000";

// ─── Utilities ───────────────────────────────────────────────────────────────
const api = async (path, body) => {
  const opts = body
    ? { method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify(body) }
    : {};
  const r = await fetch(BACKEND + path, opts);
  if (!r.ok) throw new Error(`Backend HTTP ${r.status} — is umbra_v3_backend.py running?`);
  return r.json();
};

const isHeaderLeak = (src="") => {
  const s = src.toLowerCase();
  return ["forwarded","x-real","cf-connecting","true-client","cluster","originating","fastly","header leak","rfc"].some(k=>s.includes(k));
};

const riskColor = (r) => T.risk[r] || T.textMuted;

const fmt = {
  pct: (n) => `${Math.round(n || 0)}%`,
  ip:  (g) => g?.ip || "—",
  loc: (g) => [g?.city, g?.country].filter(Boolean).join(", ") || "Unknown",
};

// ─── Small Components ─────────────────────────────────────────────────────────
function Chip({ label, color=T.blue, small }) {
  return (
    <span style={{
      display:"inline-block", padding: small ? "1px 7px" : "3px 10px",
      borderRadius:20, fontSize: small ? 10 : 11, fontWeight:500,
      background:`${color}18`, color, border:`1px solid ${color}40`,
    }}>{label}</span>
  );
}

function RiskChip({ risk }) {
  return <Chip label={risk} color={riskColor(risk)} small />;
}

function Card({ children, style={} }) {
  return (
    <div style={{
      background: T.surface, border:`1px solid ${T.border}`,
      borderRadius:8, overflow:"hidden", ...style
    }}>{children}</div>
  );
}

function CardHeader({ title, subtitle, right, color=T.blue, icon }) {
  return (
    <div style={{
      padding:"12px 16px", borderBottom:`1px solid ${T.border}`,
      display:"flex", justifyContent:"space-between", alignItems:"center",
    }}>
      <div style={{display:"flex",alignItems:"center",gap:8}}>
        {icon && <span style={{color,fontSize:14}}>{icon}</span>}
        <div>
          <div style={{color:T.text, fontWeight:600, fontSize:13}}>{title}</div>
          {subtitle && <div style={{color:T.textMuted, fontSize:11, marginTop:1}}>{subtitle}</div>}
        </div>
      </div>
      {right && <div style={{color:T.textMuted, fontSize:11}}>{right}</div>}
    </div>
  );
}

function Row({ label, value, highlight, mono, valueColor }) {
  return (
    <div style={{
      display:"flex", justifyContent:"space-between", alignItems:"flex-start",
      padding:"6px 0", borderBottom:`1px solid ${T.surface3}`, gap:16,
    }}>
      <span style={{color:T.textMuted, fontSize:12, whiteSpace:"nowrap", flexShrink:0}}>{label}</span>
      <span style={{
        color: valueColor || (highlight ? T.text : T.textMuted),
        fontSize:12, textAlign:"right", wordBreak:"break-all",
        fontFamily: mono ? "monospace" : "inherit", fontWeight: highlight ? 500 : 400,
      }}>{String(value ?? "—")}</span>
    </div>
  );
}

function Stat({ label, value, color=T.blue, sub }) {
  return (
    <div style={{
      padding:"14px 16px", background:T.surface2, borderRadius:8,
      border:`1px solid ${T.border}`,
    }}>
      <div style={{color:T.textMuted, fontSize:11, marginBottom:4}}>{label}</div>
      <div style={{color, fontSize:24, fontWeight:700, lineHeight:1}}>{value}</div>
      {sub && <div style={{color:T.textMuted, fontSize:10, marginTop:4}}>{sub}</div>}
    </div>
  );
}

function Bar({ value, max=100, color=T.blue, height=6 }) {
  const pct = Math.min(100, Math.max(0, (value/max)*100));
  return (
    <div style={{height, background:T.surface3, borderRadius:3, overflow:"hidden"}}>
      <div style={{height:"100%", width:`${pct}%`, background:color, borderRadius:3, transition:"width 0.6s ease"}}/>
    </div>
  );
}

function Alert({ type="info", children }) {
  const cfg = {
    info:    { color:T.blue,   icon:"ℹ" },
    warning: { color:T.yellow, icon:"⚠" },
    danger:  { color:T.red,    icon:"✕" },
    success: { color:T.green,  icon:"✓" },
  }[type] || { color:T.blue, icon:"ℹ" };
  return (
    <div style={{
      padding:"10px 14px", borderRadius:6,
      background:`${cfg.color}12`, border:`1px solid ${cfg.color}30`,
      display:"flex", gap:8, alignItems:"flex-start",
    }}>
      <span style={{color:cfg.color, fontSize:13, flexShrink:0}}>{cfg.icon}</span>
      <div style={{color:T.text, fontSize:12, lineHeight:1.6}}>{children}</div>
    </div>
  );
}

function Spinner() {
  return <span style={{display:"inline-block", animation:"spin 1s linear infinite", fontSize:14}}>◌</span>;
}

function EmptyState({ icon="◉", message }) {
  return (
    <div style={{padding:"48px 24px", textAlign:"center"}}>
      <div style={{color:T.textDim, fontSize:28, marginBottom:8}}>{icon}</div>
      <div style={{color:T.textMuted, fontSize:13}}>{message}</div>
    </div>
  );
}

// ─── D3 Attribution Graph ─────────────────────────────────────────────────────
const NODE_COLORS = {
  onion_site:"#58a6ff", email:"#f85149", telegram:"#29b6f6",
  btc_address:"#f0883e", eth_address:"#a371f7", xmr_address:"#f0883e",
  domain:"#d29922", pgp_key:"#3fb950", github_profile:"#e6edf3",
  reddit_profile:"#f85149", ip_address:"#f85149", analytics_id:"#ff0080",
  exchange:"#3fb950", location:"#79c0ff", isp:"#8b949e",
  server_software:"#58a6ff",
};

function AttributionGraph({ data }) {
  const ref = useRef(null);
  useEffect(() => {
    if (!data?.nodes?.length || !ref.current) return;
    const el = ref.current;
    d3.select(el).selectAll("*").remove();
    const W = el.clientWidth || 900, H = 580;
    const svg = d3.select(el).attr("width",W).attr("height",H).style("background",T.bg);
    const defs = svg.append("defs");
    ["glow"].forEach(id => {
      const f = defs.append("filter").attr("id",id);
      f.append("feGaussianBlur").attr("stdDeviation","2.5").attr("result","cb");
      const m = f.append("feMerge");
      m.append("feMergeNode").attr("in","cb");
      m.append("feMergeNode").attr("in","SourceGraphic");
    });
    Object.entries(NODE_COLORS).forEach(([t,c]) => {
      defs.append("marker").attr("id","arr-"+t).attr("viewBox","0 -4 8 8")
        .attr("refX",18).attr("refY",0).attr("markerWidth",5).attr("markerHeight",5)
        .attr("orient","auto").append("path").attr("d","M0,-4L8,0L0,4").attr("fill",c).attr("opacity",0.6);
    });
    const nodeById = {};
    data.nodes.forEach(n => { nodeById[n.id] = n; });
    const g = svg.append("g");
    svg.call(d3.zoom().scaleExtent([0.1,6]).on("zoom",ev => g.attr("transform",ev.transform)));
    const sim = d3.forceSimulation(data.nodes)
      .force("link", d3.forceLink(data.edges).id(d=>d.id).distance(d=>d.confidence==="CRITICAL"?80:130).strength(0.4))
      .force("charge", d3.forceManyBody().strength(-380))
      .force("center", d3.forceCenter(W/2,H/2))
      .force("collision", d3.forceCollide(30));

    const link = g.append("g").selectAll("line").data(data.edges).enter().append("line")
      .attr("stroke",d=>{ const s=typeof d.source==="object"?d.source:nodeById[d.source]; return NODE_COLORS[s?.type]||T.border; })
      .attr("stroke-opacity",0.4).attr("stroke-width",d=>d.confidence==="CRITICAL"?2:1)
      .attr("stroke-dasharray",d=>d.confidence==="LOW"?"4,3":null)
      .attr("marker-end",d=>{ const s=typeof d.source==="object"?d.source:nodeById[d.source]; return `url(#arr-${s?.type||"onion_site"})`; });

    const edgeLbl = g.append("g").selectAll("text").data(data.edges.filter(e=>e.confidence==="CRITICAL")).enter()
      .append("text").attr("fill",`${T.yellow}70`).attr("font-size","8px")
      .attr("font-family","monospace").attr("text-anchor","middle").text(d=>d.relation);

    const ICONS = { onion_site:"◉",email:"@",telegram:"✈",btc_address:"₿",eth_address:"Ξ",
      xmr_address:"ɱ",domain:"⬡",pgp_key:"⚿",github_profile:"⌬",reddit_profile:"R",
      ip_address:"⊕",analytics_id:"★",exchange:"$",location:"◎",isp:"⊞",server_software:"⚙" };

    const nodeG = g.append("g").selectAll("g").data(data.nodes).enter().append("g")
      .call(d3.drag()
        .on("start",(ev,d)=>{ if(!ev.active)sim.alphaTarget(0.3).restart(); d.fx=d.x; d.fy=d.y; })
        .on("drag",(ev,d)=>{ d.fx=ev.x; d.fy=ev.y; })
        .on("end",(ev,d)=>{ if(!ev.active)sim.alphaTarget(0); d.fx=null; d.fy=null; }));

    nodeG.each(function(d) {
      const el2 = d3.select(this), c = NODE_COLORS[d.type]||T.blue, root = d.type==="onion_site";
      if (root) {
        const pts = Array.from({length:6},(_,i)=>{ const a=Math.PI/180*(60*i-30); return `${20*Math.cos(a)},${20*Math.sin(a)}`; }).join(" ");
        el2.append("polygon").attr("points",pts).attr("fill",`${c}18`).attr("stroke",c).attr("stroke-width",2).attr("filter","url(#glow)");
      } else {
        el2.append("circle").attr("r",d.risk==="CRITICAL"?13:d.risk==="HIGH"?10:8)
          .attr("fill",`${c}12`).attr("stroke",c).attr("stroke-width",d.risk==="CRITICAL"?2:1)
          .attr("filter",d.risk==="CRITICAL"?"url(#glow)":null);
      }
      el2.append("text").attr("dy","0.35em").attr("text-anchor","middle").attr("font-size",root?"11px":"9px")
        .attr("fill",c).attr("pointer-events","none").text(ICONS[d.type]||"◆");
    });

    nodeG.append("text").attr("dx",16).attr("dy","0.35em").attr("font-size","10px")
      .attr("font-family","monospace").attr("fill",T.textMuted).attr("pointer-events","none")
      .text(d => d.label?.length>22 ? d.label.slice(0,22)+"…" : d.label);

    const tip = d3.select("body").append("div")
      .style("position","fixed").style("background",T.surface)
      .style("border",`1px solid ${T.border}`).style("color",T.text)
      .style("padding","10px 14px").style("font-family","monospace")
      .style("font-size","11px").style("pointer-events","none")
      .style("opacity",0).style("z-index","9999").style("max-width","300px")
      .style("line-height","1.7").style("border-radius","6px");

    nodeG.on("mouseover",(ev,d)=>{
      const c = NODE_COLORS[d.type]||T.blue;
      let h = `<div style="color:${c};font-weight:600;margin-bottom:5px">${d.type.replace(/_/g," ").toUpperCase()}</div>`;
      h += `<div style="color:#fff;margin-bottom:4px;word-break:break-all">${d.label}</div>`;
      if (d.data) Object.entries(d.data).forEach(([k,v])=>{ if(v&&k!=="full"&&k!=="maps") h+=`<div><span style="color:${T.textMuted}">${k}: </span>${String(v).slice(0,80)}</div>`; });
      if (d.data?.maps) h += `<div style="margin-top:4px"><a href="${d.data.maps}" target="_blank" style="color:${T.blue}">→ Maps</a></div>`;
      h += `<div style="margin-top:4px;color:${T.textMuted}">Risk: <span style="color:${riskColor(d.risk)}">${d.risk}</span></div>`;
      tip.html(h).style("opacity",1).style("left",(ev.clientX+12)+"px").style("top",(ev.clientY-8)+"px");
    }).on("mousemove",ev=>tip.style("left",(ev.clientX+12)+"px").style("top",(ev.clientY-8)+"px"))
      .on("mouseout",()=>tip.style("opacity",0));

    sim.on("tick",()=>{
      link.attr("x1",d=>d.source.x).attr("y1",d=>d.source.y).attr("x2",d=>d.target.x).attr("y2",d=>d.target.y);
      edgeLbl.attr("x",d=>(d.source.x+d.target.x)/2).attr("y",d=>(d.source.y+d.target.y)/2);
      nodeG.attr("transform",d=>`translate(${d.x},${d.y})`);
    });
    return () => { tip.remove(); sim.stop(); };
  }, [data]);
  return <svg ref={ref} style={{width:"100%",height:580,display:"block"}} />;
}

// ─── IP Card ──────────────────────────────────────────────────────────────────
function IPCard({ g, defaultOpen=false }) {
  const [open, setOpen] = useState(defaultOpen);
  if (!g) return null;
  const leak = isHeaderLeak(g.source||"");
  const residential = g.success && !g.is_proxy && !g.is_hosting;
  const accentColor = leak ? T.red : residential ? T.green : T.orange;

  return (
    <div style={{ borderRadius:8, overflow:"hidden", marginBottom:8, border:`1px solid ${accentColor}35` }}>
      <div onClick={()=>setOpen(o=>!o)} style={{
        padding:"10px 14px", cursor:"pointer", background:`${accentColor}0a`,
        display:"flex", justifyContent:"space-between", alignItems:"center",
      }}>
        <div style={{display:"flex", alignItems:"center", gap:10}}>
          {leak && <Chip label="HEADER LEAK" color={T.red} small/>}
          {g.chain_position===0 && <Chip label="CLIENT IP" color={T.red} small/>}
          {!leak && g.discovery_method && <Chip label={g.discovery_method.replace(/_/g," ")} color={T.cyan} small/>}
          <span style={{fontFamily:"monospace", fontWeight:600, color:T.text, fontSize:13}}>{g.ip || "N/A"}</span>
          {g.ip_version===6 && <Chip label="IPv6" color={T.purple} small/>}
        </div>
        <div style={{display:"flex", alignItems:"center", gap:8}}>
          <span style={{color:T.textMuted, fontSize:12}}>{fmt.loc(g)}</span>
          {residential && <Chip label="RESIDENTIAL" color={T.green} small/>}
          {g.is_proxy && <Chip label="VPN/PROXY" color={T.red} small/>}
          {g.is_hosting && <Chip label="DATACENTER" color={T.orange} small/>}
          <span style={{color:T.textMuted, fontSize:12}}>{open?"▲":"▼"}</span>
        </div>
      </div>
      {open && g.success && (
        <div style={{padding:"14px 16px", display:"grid", gridTemplateColumns:"1fr 1fr 1fr", gap:20, background:T.surface}}>
          <div>
            <div style={{color:T.textMuted, fontSize:10, fontWeight:600, letterSpacing:"0.08em", marginBottom:8}}>GEOLOCATION</div>
            <Row label="Country" value={`${g.country||"?"} (${g.country_code||"?"})`} highlight/>
            <Row label="City / Region" value={`${g.city||"?"}, ${g.region||"?"}`} highlight/>
            <Row label="Coordinates" value={g.lat && g.lon ? `${g.lat}, ${g.lon}` : "—"} mono/>
            <Row label="Timezone" value={g.timezone}/>
          </div>
          <div>
            <div style={{color:T.textMuted, fontSize:10, fontWeight:600, letterSpacing:"0.08em", marginBottom:8}}>NETWORK</div>
            <Row label="ISP" value={g.isp} highlight/>
            <Row label="Organization" value={g.org}/>
            <Row label="ASN" value={g.asn} mono/>
            {g.hostname && <Row label="Hostname" value={g.hostname} mono highlight/>}
            {g.open_ports?.length>0 && <Row label="Open Ports" value={g.open_ports.join(", ")} mono/>}
          </div>
          <div>
            <div style={{color:T.textMuted, fontSize:10, fontWeight:600, letterSpacing:"0.08em", marginBottom:8}}>INVESTIGATION</div>
            {g.investigation_notes?.map((n,i)=>(
              <div key={i} style={{color:T.textMuted, fontSize:11, lineHeight:1.5, marginBottom:4, paddingLeft:6, borderLeft:`2px solid ${T.orange}40`}}>{n}</div>
            ))}
            <div style={{marginTop:10, padding:"8px 10px", background:T.surface2, borderRadius:6, fontSize:11, color:T.textMuted, lineHeight:1.5}}>{g.legal_action}</div>
            <div style={{display:"flex", gap:6, flexWrap:"wrap", marginTop:8}}>
              {g.google_maps_url && <a href={g.google_maps_url} target="_blank" rel="noreferrer" style={{color:T.blue, fontSize:11}}>Maps ↗</a>}
              <a href={`https://www.shodan.io/host/${g.ip}`} target="_blank" rel="noreferrer" style={{color:T.blue, fontSize:11}}>Shodan ↗</a>
              <a href={`https://internetdb.shodan.io/${g.ip}`} target="_blank" rel="noreferrer" style={{color:T.blue, fontSize:11}}>InternetDB ↗</a>
            </div>
          </div>
        </div>
      )}
      {open && !g.success && (
        <div style={{padding:"12px 16px", background:T.surface, color:T.textMuted, fontSize:12}}>
          Geolocation failed: {g.error || "Unknown error"} — Source: {g.source}
        </div>
      )}
    </div>
  );
}

// ─── Main App ─────────────────────────────────────────────────────────────────
export default function App() {
  const [tab, setTab]       = useState("scan");
  const [onion, setOnion]   = useState("");
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(false);
  const [loadStep, setStep] = useState("");
  const [error, setError]   = useState("");
  const [torOk, setTorOk]   = useState(null);
  const logRef = useRef(null);
  const [logs, setLogs]     = useState([]);

  const log = (msg, type="info") => {
    setLogs(p => [...p.slice(-150), {msg, type, t: new Date().toLocaleTimeString()}]);
    setTimeout(()=>{ if(logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight; }, 20);
  };

  const checkTor = async () => {
    log("Checking Tor connection...");
    try {
      const r = await api("/api/tor/check");
      setTorOk(r.is_tor);
      log(r.is_tor ? `Tor active — exit IP: ${r.tor_ip}` : "Tor not active", r.is_tor ? "ok" : "warn");
    } catch { setTorOk(false); log("Backend unreachable. Run: python umbra_v3_backend.py", "error"); }
  };

  const STEPS = [
    "Connecting to Tor network...", "Fetching .onion page...",
    "Extracting page intelligence...", "Running PII extraction (30 patterns)...",
    "Analysing HTTP headers (RFC 7239, X-Real-IP)...",
    "Geolocating IPs — proxy chain + page source...",
    "Stylometric fingerprint analysis...", "Certificate transparency lookup...",
    "Blockchain forensics...", "Identity correlation (GitHub, Reddit, PGP)...",
    "Infrastructure fingerprinting...", "Active IP discovery (DNS + urlscan.io)...",
    "Building attribution graph...", "OPSEC failure detection...",
    "Behavioral timeline analysis...", "Computing intelligence score...",
  ];

  const run = useCallback(async () => {
    if (!onion.trim() || loading) return;
    setLoading(true); setError(""); setReport(null); setLogs([]);
    setTab("intel");
    let i = 0;
    const t = setInterval(()=>{ if(i<STEPS.length){ setStep(STEPS[i]); log(STEPS[i]); i++; } }, 1800);
    try {
      const r = await api("/api/analyze", { onion_url: onion.trim(), anthropic_api_key: "" });
      clearInterval(t);
      setReport(r);
      const g = r.attribution_graph?.stats;
      const conf = r.intelligence?.attribution_confidence_pct || 0;
      log(`Analysis complete — Confidence: ${conf}% | IPs: ${r.ip_intelligence?.length||0} | PII: ${r.pii?.length||0} | Graph: ${g?.total_nodes||0}N/${g?.total_edges||0}E`, "ok");
      if (r.errors?.length) r.errors.forEach(e => log(e, "error"));
    } catch(e) { clearInterval(t); setError(e.message); log(e.message, "error"); }
    setLoading(false);
  }, [onion, loading]);

  const TABS = [
    { id:"scan",      label:"Scan",             icon:"◉" },
    { id:"intel",     label:"Intelligence",     icon:"★",  disabled:!report&&!loading },
    { id:"opsec",     label:"OPSEC Analysis",   icon:"⚠",  disabled:!report },
    { id:"ip",        label:"IP Intelligence",  icon:"⊕",  disabled:!report },
    { id:"discover",  label:"Active Discovery", icon:"◎",  disabled:!report },
    { id:"graph",     label:"Attribution Graph",icon:"⬡",  disabled:!report },
    { id:"identity",  label:"Identity",         icon:"⌬",  disabled:!report },
    { id:"behavior",  label:"Behavioral",       icon:"◷",  disabled:!report },
    { id:"infra",     label:"Infrastructure",   icon:"⊞",  disabled:!report },
    { id:"log",       label:"Log",              icon:"≡" },
  ];

  const ips = report?.ip_intelligence || [];
  const headerLeaks = ips.filter(g => isHeaderLeak(g.source||""));
  const residential = ips.filter(g => g.success && !g.is_proxy && !g.is_hosting);
  const intel = report?.intelligence;
  const opsec = report?.opsec_analysis;
  const beh   = report?.behavioral;
  const leads = report?.correlation?.high_confidence_leads || [];

  const confColor = !intel ? T.blue :
    intel.attribution_confidence_pct >= 75 ? T.green :
    intel.attribution_confidence_pct >= 50 ? T.yellow :
    intel.attribution_confidence_pct >= 25 ? T.orange : T.red;

  return (
    <div style={{ background:T.bg, minHeight:"100vh", color:T.text, fontFamily:"-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif", fontSize:13 }}>
      <style>{`
        @keyframes spin { from{transform:rotate(0)} to{transform:rotate(360deg)} }
        @keyframes fadeIn { from{opacity:0;transform:translateY(4px)} to{opacity:1;transform:translateY(0)} }
        * { box-sizing:border-box; }
        ::-webkit-scrollbar { width:5px; height:5px; }
        ::-webkit-scrollbar-track { background:${T.surface}; }
        ::-webkit-scrollbar-thumb { background:${T.surface3}; border-radius:3px; }
        a { color:${T.blue}; text-decoration:none; }
        a:hover { text-decoration:underline; }
        button { cursor:pointer; font-family:inherit; }
        input { font-family:inherit; }
        input::placeholder { color:${T.textDim}; }
        .tab-btn:hover { color:${T.text} !important; background:${T.surface2} !important; }
      `}</style>

      {/* ── Top Navigation ── */}
      <div style={{ background:T.surface, borderBottom:`1px solid ${T.border}`, position:"sticky", top:0, zIndex:100 }}>
        <div style={{ maxWidth:1400, margin:"0 auto", padding:"0 20px", display:"flex", alignItems:"stretch", gap:0 }}>
          {/* Logo */}
          <div style={{ padding:"12px 20px 12px 0", marginRight:12, borderRight:`1px solid ${T.border}`, display:"flex", alignItems:"center", gap:10 }}>
            <div style={{ width:28, height:28, background:`${T.blue}18`, border:`1px solid ${T.blue}40`, borderRadius:6, display:"flex", alignItems:"center", justifyContent:"center", color:T.blue, fontSize:14 }}>◉</div>
            <div>
              <div style={{ fontWeight:700, fontSize:14, color:T.text, letterSpacing:"0.05em" }}>UMBRA</div>
              <div style={{ fontSize:9, color:T.textMuted, letterSpacing:"0.12em" }}>V3.2 · NIA LEA</div>
            </div>
          </div>

          {/* Tabs */}
          <div style={{ display:"flex", alignItems:"stretch", flex:1, gap:0, overflowX:"auto" }}>
            {TABS.map(t => (
              <button key={t.id} className="tab-btn"
                onClick={() => !t.disabled && setTab(t.id)}
                disabled={t.disabled}
                style={{
                  padding:"0 14px", border:"none", background:"transparent",
                  color: tab===t.id ? T.blue : t.disabled ? T.textDim : T.textMuted,
                  borderBottom: tab===t.id ? `2px solid ${T.blue}` : "2px solid transparent",
                  fontSize:12, fontWeight: tab===t.id ? 600 : 400,
                  display:"flex", alignItems:"center", gap:5, whiteSpace:"nowrap",
                  cursor: t.disabled ? "not-allowed" : "pointer",
                  transition:"color 0.15s, border-color 0.15s",
                }}>
                <span style={{ fontSize:11 }}>{t.icon}</span>
                {t.label}
              </button>
            ))}
          </div>

          {/* Status bar */}
          <div style={{ padding:"0 16px", display:"flex", alignItems:"center", gap:12, borderLeft:`1px solid ${T.border}` }}>
            {torOk !== null && (
              <span style={{ display:"flex", alignItems:"center", gap:5, fontSize:11 }}>
                <span style={{ width:7, height:7, borderRadius:"50%", background:torOk?T.green:T.red, display:"inline-block" }}/>
                <span style={{ color:torOk?T.green:T.red }}>{torOk?"TOR ACTIVE":"TOR DOWN"}</span>
              </span>
            )}
            <button onClick={checkTor} style={{
              padding:"4px 10px", background:T.surface2, border:`1px solid ${T.border}`,
              color:T.textMuted, borderRadius:5, fontSize:11,
            }}>Check Tor</button>
          </div>
        </div>
      </div>

      {/* ── Content ── */}
      <div style={{ maxWidth:1400, margin:"0 auto", padding:"20px" }}>

        {/* ══ SCAN ══════════════════════════════════════════════════════════ */}
        {tab==="scan" && (
          <div style={{ maxWidth:800, margin:"0 auto", animation:"fadeIn 0.2s ease" }}>
            <div style={{ marginBottom:24 }}>
              <h1 style={{ color:T.text, fontWeight:700, fontSize:20, margin:"0 0 6px" }}>Dark Web Intelligence Analysis</h1>
              <p style={{ color:T.textMuted, margin:0, lineHeight:1.6 }}>
                Enter a .onion URL to run 16-module analysis — IP correlation, identity attribution, OPSEC scoring, and behavioral profiling.
              </p>
            </div>

            <Card style={{ marginBottom:16 }}>
              <CardHeader title="Target" subtitle="Enter a Tor v2 or v3 hidden service address" icon="◉"/>
              <div style={{ padding:16 }}>
                <div style={{ display:"flex", gap:10 }}>
                  <input value={onion} onChange={e=>setOnion(e.target.value)}
                    onKeyDown={e=>e.key==="Enter"&&run()}
                    placeholder="http://example3g2uuu7j5d5kpppux6grnlg5s2ybi5gypdg5qvg.onion"
                    style={{
                      flex:1, padding:"10px 12px", background:T.surface2,
                      border:`1px solid ${T.border}`, borderRadius:6,
                      color:T.text, fontSize:13, outline:"none",
                    }}/>
                  <button onClick={run} disabled={loading||!onion.trim()} style={{
                    padding:"10px 20px", background: loading||!onion.trim() ? T.surface2 : T.blue,
                    border:"none", borderRadius:6, color: loading||!onion.trim() ? T.textDim : "#fff",
                    fontWeight:600, fontSize:13, display:"flex", alignItems:"center", gap:6,
                  }}>
                    {loading ? <><Spinner/> Analysing...</> : "▶ Analyse"}
                  </button>
                </div>
                {error && <Alert type="danger" style={{marginTop:10}}>{error}</Alert>}
                {loading && (
                  <div style={{ marginTop:12, padding:"10px 14px", background:T.surface2, borderRadius:6, color:T.blue, fontSize:12, display:"flex", alignItems:"center", gap:8 }}>
                    <Spinner/> {loadStep}
                  </div>
                )}
              </div>
            </Card>

            <div style={{ display:"grid", gridTemplateColumns:"repeat(3,1fr)", gap:10, marginBottom:16 }}>
              {[
                ["IP Intelligence","Header leak detection, RFC 7239, IPv4/IPv6, full proxy chain"],
                ["Active IP Discovery","DNS + urlscan.io + Shodan InternetDB correlation"],
                ["Identity Correlation","PGP keyserver, GitHub, Reddit, email cross-matching"],
                ["OPSEC Failure Detector","Automated detection of every security mistake"],
                ["Behavioral Analysis","Timezone, language, activity pattern profiling"],
                ["Attribution Scoring","Weighted confidence percentage with evidence breakdown"],
                ["Stylometry","Burrows Delta, Yule K, Honore R authorship fingerprint"],
                ["Blockchain Forensics","BTC/ETH/XMR wallet analysis, exchange identification"],
                ["Certificate Transparency","crt.sh historical domain and IP lookup"],
              ].map(([n,d])=>(
                <div key={n} style={{ padding:"10px 12px", background:T.surface, border:`1px solid ${T.border}`, borderRadius:8 }}>
                  <div style={{ color:T.text, fontWeight:600, fontSize:12, marginBottom:3 }}>✓ {n}</div>
                  <div style={{ color:T.textMuted, fontSize:11, lineHeight:1.4 }}>{d}</div>
                </div>
              ))}
            </div>

            <Alert type="warning">
              Prerequisites: Tor daemon on 127.0.0.1:9050 · Backend running: <code>python umbra_v3_backend.py</code> · NIA / LEA use only
            </Alert>
          </div>
        )}

        {/* ══ INTELLIGENCE DASHBOARD ════════════════════════════════════════ */}
        {tab==="intel" && (
          <div style={{ animation:"fadeIn 0.2s ease" }}>
            {loading && (
              <div style={{ textAlign:"center", padding:"60px 20px" }}>
                <div style={{ color:T.blue, fontSize:18, marginBottom:12 }}><Spinner/></div>
                <div style={{ color:T.text, fontSize:14, marginBottom:6 }}>{loadStep}</div>
                <div style={{ color:T.textMuted, fontSize:12 }}>Running 16-module analysis via Tor — typically 60–120 seconds</div>
              </div>
            )}
            {!report && !loading && <EmptyState message="Run an analysis from the Scan tab to see intelligence results."/>}
            {report && !loading && (
              <div>
                {/* Attribution confidence header */}
                <div style={{ padding:"20px", background:T.surface, border:`1px solid ${T.border}`, borderRadius:8, marginBottom:16 }}>
                  <div style={{ display:"flex", justifyContent:"space-between", alignItems:"flex-start", marginBottom:14 }}>
                    <div>
                      <div style={{ color:T.textMuted, fontSize:11, letterSpacing:"0.08em", marginBottom:4 }}>ATTRIBUTION CONFIDENCE</div>
                      <div style={{ display:"flex", alignItems:"baseline", gap:10 }}>
                        <span style={{ color:confColor, fontSize:40, fontWeight:800, lineHeight:1 }}>{fmt.pct(intel?.attribution_confidence_pct)}</span>
                        <span style={{ color:confColor, fontSize:16, fontWeight:600 }}>{intel?.attribution_strength}</span>
                      </div>
                      <div style={{ color:T.textMuted, fontSize:12, marginTop:6, maxWidth:500 }}>{intel?.attribution_strength_note}</div>
                    </div>
                    <div style={{ textAlign:"right" }}>
                      <div style={{ color:T.textMuted, fontSize:11 }}>Target</div>
                      <div style={{ color:T.text, fontSize:12, fontFamily:"monospace", wordBreak:"break-all", maxWidth:340 }}>{report.target_url}</div>
                      <div style={{ color:T.textMuted, fontSize:11, marginTop:4 }}>{report.timestamp?.slice(0,16)} UTC</div>
                    </div>
                  </div>
                  <Bar value={intel?.attribution_confidence_pct||0} color={confColor} height={8}/>
                  <div style={{ display:"flex", justifyContent:"space-between", marginTop:4, fontSize:10, color:T.textDim }}>
                    <span>0% Minimal</span><span>20% Weak</span><span>40% Moderate</span><span>60% Strong</span><span>80%+ Definitive</span>
                  </div>
                </div>

                {/* KPI grid */}
                <div style={{ display:"grid", gridTemplateColumns:"repeat(5,1fr)", gap:10, marginBottom:16 }}>
                  <Stat label="Threat Level"    value={intel?.threat_level||"—"}
                    color={{CRITICAL:T.red,HIGH:T.orange,MEDIUM:T.yellow,LOW:T.green}[intel?.threat_level]||T.blue}
                    sub={intel?.threat_note}/>
                  <Stat label="OPSEC Score"     value={`${opsec?.opsec_score||0}/100`}
                    color={opsec?.opsec_score>=60?T.yellow:T.red} sub={opsec?.opsec_rating}/>
                  <Stat label="Sophistication"  value={intel?.operator_sophistication||"—"} color={T.purple}/>
                  <Stat label="Probable Region" value={intel?.probable_region||"Unknown"} color={T.cyan} sub="from IPs + language"/>
                  <Stat label="PII Artifacts"   value={report.pii?.length||0} color={T.blue} sub={`${leads.length} high-confidence leads`}/>
                </div>

                {/* Critical IP leaks banner */}
                {headerLeaks.length > 0 && (
                  <Alert type="danger" style={{marginBottom:16}}>
                    <strong>Critical: {headerLeaks.length} real IP leak(s) in HTTP headers.</strong>{" "}
                    {headerLeaks.map(g=>`${g.ip} (${g.city||"?"}, ${g.country||"?"})`).join(" · ")}
                    {" — "}
                    <button onClick={()=>setTab("ip")} style={{background:"none",border:"none",color:T.blue,padding:0,cursor:"pointer",fontSize:12}}>View IP Intelligence →</button>
                  </Alert>
                )}

                {/* Priority Actions */}
                {intel?.priority_actions?.length > 0 && (
                  <Card style={{ marginBottom:16 }}>
                    <CardHeader title="Priority Actions" subtitle="Ranked by attribution value" icon="★" color={T.yellow}
                      right={`${intel.priority_actions.length} actions`}/>
                    <div style={{ padding:"8px 0" }}>
                      {intel.priority_actions.map((a,i) => (
                        <div key={i} style={{ padding:"10px 16px", borderBottom:`1px solid ${T.border}`, display:"flex", gap:12, alignItems:"flex-start" }}>
                          <span style={{ paddingTop:1, flexShrink:0 }}><RiskChip risk={a.priority}/></span>
                          <div>
                            <div style={{ color:T.text, fontWeight:600, fontSize:12, marginBottom:2 }}>{a.action}</div>
                            <div style={{ color:T.textMuted, fontSize:11 }}>{a.detail}</div>
                          </div>
                        </div>
                      ))}
                    </div>
                  </Card>
                )}

                <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:16 }}>
                  {/* Evidence breakdown */}
                  <Card>
                    <CardHeader title="Evidence Breakdown" icon="◈" color={T.green}
                      right={`${intel?.evidence_found_count||0}/${intel?.evidence_total||0} found`}/>
                    <div style={{ padding:"4px 0" }}>
                      {intel?.evidence_breakdown?.map((e,i) => (
                        <div key={i} style={{ padding:"7px 16px", borderBottom:`1px solid ${T.surface3}`, display:"flex", alignItems:"center", gap:10 }}>
                          <span style={{ color:e.present?T.green:T.red, fontSize:13, flexShrink:0 }}>{e.present?"✓":"✗"}</span>
                          <span style={{ flex:1, color:e.present?T.text:T.textMuted, fontSize:12 }}>{e.name}</span>
                          <span style={{ color:T.textDim, fontSize:10, minWidth:32, textAlign:"right" }}>w:{e.weight}</span>
                        </div>
                      ))}
                    </div>
                  </Card>

                  {/* Operator profile */}
                  <Card>
                    <CardHeader title="Operator Profile" icon="⌬" color={T.cyan}/>
                    <div style={{ padding:"4px 0 4px 16px" }}>
                      <Row label="Probable Region"  value={intel?.probable_region} highlight/>
                      <Row label="Sophistication"   value={intel?.operator_sophistication}/>
                      <Row label="Language"         value={beh?.language_profile?.likely_language} highlight/>
                      <Row label="Threat Category"  value={intel?.threat_note} highlight/>
                      {beh?.behavioral_summary?.map((s,i)=>(
                        <div key={i} style={{ padding:"5px 0", borderBottom:`1px solid ${T.surface3}`, color:T.textMuted, fontSize:11 }}>{s}</div>
                      ))}
                    </div>
                    {leads.length > 0 && (
                      <div style={{ padding:"12px 16px", borderTop:`1px solid ${T.border}` }}>
                        <div style={{ color:T.textMuted, fontSize:10, fontWeight:600, marginBottom:8 }}>HIGH-CONFIDENCE LEADS</div>
                        {leads.slice(0,4).map((l,i)=>(
                          <div key={i} style={{ marginBottom:6, display:"flex", gap:8, alignItems:"flex-start" }}>
                            <RiskChip risk={l.confidence}/>
                            <div>
                              <div style={{ color:T.text, fontSize:11, fontWeight:500 }}>{l.type}</div>
                              <div style={{ color:T.textMuted, fontSize:10 }}>{l.finding}</div>
                            </div>
                          </div>
                        ))}
                      </div>
                    )}
                  </Card>
                </div>

                {/* OSINT Brief */}
                {report.ai_brief && (
                  <Card style={{ marginTop:16 }}>
                    <CardHeader title="OSINT Intelligence Brief" subtitle="NIA / CERT-In format — rule-based analysis" icon="≡"/>
                    <pre style={{ padding:"16px", color:T.textMuted, fontSize:11, lineHeight:1.8, whiteSpace:"pre-wrap", margin:0, maxHeight:400, overflowY:"auto" }}>
                      {report.ai_brief}
                    </pre>
                  </Card>
                )}
              </div>
            )}
          </div>
        )}

        {/* ══ OPSEC ANALYSIS ════════════════════════════════════════════════ */}
        {tab==="opsec" && (
          <div style={{ animation:"fadeIn 0.2s ease" }}>
            {!opsec ? <EmptyState message="Run analysis to see OPSEC assessment."/> : (
              <div>
                {/* Score display */}
                <Card style={{ marginBottom:16 }}>
                  <div style={{ padding:"24px", display:"grid", gridTemplateColumns:"auto 1fr", gap:32, alignItems:"center" }}>
                    <div style={{ textAlign:"center" }}>
                      <div style={{ fontSize:60, fontWeight:800, lineHeight:1, color:opsec.opsec_score>=60?T.yellow:T.red }}>{opsec.opsec_score}</div>
                      <div style={{ color:T.textMuted, fontSize:12, marginTop:4 }}>out of 100</div>
                      <div style={{ marginTop:6 }}><Chip label={opsec.opsec_rating} color={opsec.opsec_score>=60?T.yellow:T.red}/></div>
                    </div>
                    <div>
                      <Bar value={opsec.opsec_score} color={opsec.opsec_score>=60?T.yellow:T.red} height={10}/>
                      <div style={{ display:"flex", gap:20, marginTop:14 }}>
                        {Object.entries(opsec.by_severity||{}).filter(([,v])=>v>0).map(([sev,cnt])=>(
                          <div key={sev} style={{ textAlign:"center" }}>
                            <div style={{ color:riskColor(sev), fontSize:22, fontWeight:700 }}>{cnt}</div>
                            <div style={{ color:T.textMuted, fontSize:10 }}>{sev}</div>
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>
                </Card>

                {/* Failures by severity */}
                {["CRITICAL","HIGH","MEDIUM","LOW"].map(sev => {
                  const list = opsec.failures?.filter(f=>f.severity===sev)||[];
                  if (!list.length) return null;
                  return (
                    <div key={sev} style={{ marginBottom:12 }}>
                      <div style={{ color:riskColor(sev), fontSize:11, fontWeight:700, marginBottom:6, display:"flex", alignItems:"center", gap:6 }}>
                        <span style={{ width:8, height:8, borderRadius:"50%", background:riskColor(sev), display:"inline-block" }}/>
                        {sev} — {list.length} failure(s)
                      </div>
                      {list.map((f,i) => (
                        <Card key={i} style={{ marginBottom:8 }}>
                          <div style={{ padding:"12px 16px" }}>
                            <div style={{ display:"flex", justifyContent:"space-between", marginBottom:6 }}>
                              <div style={{ fontWeight:600, color:T.text, fontSize:13 }}>{f.title}</div>
                              <Chip label={f.category} color={T.blue} small/>
                            </div>
                            <div style={{ color:T.textMuted, fontSize:12, lineHeight:1.6, marginBottom:8 }}>{f.detail}</div>
                            {f.evidence && <div style={{ fontFamily:"monospace", fontSize:11, color:T.text, padding:"6px 10px", background:T.surface2, borderRadius:5, marginBottom:8, wordBreak:"break-all" }}>{f.evidence}</div>}
                            <div style={{ padding:"6px 10px", background:`${T.blue}10`, border:`1px solid ${T.blue}25`, borderRadius:5, color:T.blue, fontSize:11 }}>
                              → {f.action}
                            </div>
                          </div>
                        </Card>
                      ))}
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        )}

        {/* ══ IP INTELLIGENCE ═══════════════════════════════════════════════ */}
        {tab==="ip" && (
          <div style={{ animation:"fadeIn 0.2s ease" }}>
            {!ips.length ? <EmptyState message="No IPs extracted. Run analysis first."/> : (
              <div>
                <div style={{ display:"grid", gridTemplateColumns:"repeat(5,1fr)", gap:10, marginBottom:16 }}>
                  <Stat label="Total IPs"     value={ips.length}                                                     color={T.blue}/>
                  <Stat label="Header Leaks"  value={headerLeaks.length}                                            color={T.red}/>
                  <Stat label="Residential"   value={residential.length}                                            color={T.green}/>
                  <Stat label="VPN / Proxy"   value={ips.filter(g=>g.is_proxy).length}                              color={T.yellow}/>
                  <Stat label="Datacenter"    value={ips.filter(g=>g.is_hosting).length}                            color={T.orange}/>
                </div>
                {headerLeaks.length > 0 && (
                  <Alert type="danger" style={{marginBottom:12}}>
                    Real IP leaks detected in HTTP headers — these are operator OPSEC failures. Click each card to see full geolocation.
                  </Alert>
                )}
                {headerLeaks.map((g,i) => <IPCard key={i} g={g} defaultOpen={true}/>)}
                {ips.filter(g=>!isHeaderLeak(g.source||"")).map((g,i) => <IPCard key={i} g={g}/>)}
              </div>
            )}
          </div>
        )}

        {/* ══ ACTIVE IP DISCOVERY ═══════════════════════════════════════════ */}
        {tab==="discover" && (() => {
          const disc = report?.active_ip_discovery;
          if (!disc) return <EmptyState message="Run analysis to see active IP discovery results."/>;
          const discIPs = (disc.discovered_ips||[]).filter(g=>g.success||g.country);
          const domains = disc.all_candidate_domains||[];
          const shodan  = disc.shodan_queries||[];
          const urls    = disc.urlscan_matches||[];
          const fp      = disc.fingerprints||{};

          return (
            <div style={{ animation:"fadeIn 0.2s ease" }}>
              <div style={{ display:"grid", gridTemplateColumns:"repeat(5,1fr)", gap:10, marginBottom:16 }}>
                <Stat label="Domains Found"   value={domains.length}                    color={T.blue}/>
                <Stat label="IPs Resolved"    value={discIPs.length}                    color={T.green}/>
                <Stat label="urlscan Matches" value={urls.filter(u=>u.ip).length}       color={T.yellow}/>
                <Stat label="Fingerprints"    value={(fp.searches||[]).length}          color={T.purple}/>
                <Stat label="Shodan Queries"  value={shodan.length}                     color={T.orange}/>
              </div>

              <Alert type="info" style={{marginBottom:16}}>
                Correlation-based discovery: Tor v3 never exposes the server IP directly. UMBRA resolves clearnet domains linked in the page, searches urlscan.io for pages with matching fingerprints (title, build hash, analytics ID), and generates Shodan queries for manual follow-up.
              </Alert>

              {discIPs.length > 0 && (
                <Card style={{marginBottom:16}}>
                  <CardHeader title={`Resolved IPs — ${discIPs.length}`} icon="◎" color={T.green} subtitle="From clearnet DNS resolution"/>
                  <div style={{padding:"8px 16px"}}>
                    {discIPs.map((g,i) => <IPCard key={i} g={g} defaultOpen={i===0}/>)}
                  </div>
                </Card>
              )}

              {!discIPs.length && (
                <Alert type="warning" style={{marginBottom:16}}>
                  No IPs resolved — site has no clearnet domains or all are behind a CDN. Use the Shodan queries below — paste them at shodan.io while logged in.
                </Alert>
              )}

              {urls.filter(u=>u.ip).length > 0 && (
                <Card style={{marginBottom:16}}>
                  <CardHeader title={`urlscan.io Matches — ${urls.filter(u=>u.ip).length}`} icon="★" color={T.yellow} subtitle="Same fingerprint found on clearnet"/>
                  <div style={{padding:16}}>
                    {urls.filter(u=>u.ip).map((u,i) => (
                      <div key={i} style={{marginBottom:10, padding:"10px 14px", background:T.surface2, borderRadius:8, display:"grid", gridTemplateColumns:"1fr 1fr", gap:12}}>
                        <div>
                          <div style={{fontFamily:"monospace", fontWeight:700, fontSize:14, marginBottom:4, color:T.text}}>{u.ip}</div>
                          <Row label="Domain" value={u.domain} highlight mono/>
                          <Row label="Country" value={u.country} highlight/>
                          <Row label="ASN" value={u.asn} mono/>
                        </div>
                        <div style={{display:"flex",gap:8,flexWrap:"wrap",alignItems:"flex-start",paddingTop:4}}>
                          {u.scan_url && <a href={u.scan_url} target="_blank" rel="noreferrer" style={{fontSize:11}}>View Scan ↗</a>}
                          {u.screenshot && <a href={u.screenshot} target="_blank" rel="noreferrer" style={{fontSize:11}}>Screenshot ↗</a>}
                          <a href={`https://www.shodan.io/host/${u.ip}`} target="_blank" rel="noreferrer" style={{fontSize:11}}>Shodan ↗</a>
                        </div>
                      </div>
                    ))}
                  </div>
                </Card>
              )}

              {shodan.length > 0 && (
                <Card style={{marginBottom:16}}>
                  <CardHeader title="Shodan Queries" subtitle="Paste these at shodan.io (requires account)" icon="⊕" color={T.orange}/>
                  <div style={{padding:"8px 0"}}>
                    {shodan.map((q,i) => (
                      <div key={i} style={{padding:"10px 16px", borderBottom:`1px solid ${T.border}`, display:"grid", gridTemplateColumns:"100px 1fr auto", gap:12, alignItems:"center"}}>
                        <RiskChip risk={q.confidence}/>
                        <div>
                          <div style={{fontFamily:"monospace", color:T.text, fontSize:12, userSelect:"all", padding:"4px 8px", background:T.surface2, borderRadius:4, marginBottom:3}}>{q.query}</div>
                          <div style={{color:T.textMuted, fontSize:11}}>{q.method}</div>
                        </div>
                        <a href={q.url} target="_blank" rel="noreferrer" style={{fontSize:11, whiteSpace:"nowrap"}}>Open ↗</a>
                      </div>
                    ))}
                  </div>
                </Card>
              )}

              {(fp.searches||[]).length > 0 && (
                <Card style={{marginBottom:16}}>
                  <CardHeader title="Page Fingerprints" subtitle="Unique identifiers for cross-site matching" icon="◈" color={T.purple} right={`${fp.searches.length} found`}/>
                  <div style={{padding:"8px 0"}}>
                    {fp.searches.map((s,i) => (
                      <div key={i} style={{padding:"8px 16px", borderBottom:`1px solid ${T.border}`, display:"grid", gridTemplateColumns:"140px 1fr auto", gap:12, alignItems:"center"}}>
                        <Chip label={s.type.replace(/_/g," ")} color={T.purple} small/>
                        <div style={{fontFamily:"monospace", fontSize:12, color:T.text, wordBreak:"break-all"}}>{s.value}</div>
                        <div style={{display:"flex",gap:8}}>
                          <RiskChip risk={s.confidence}/>
                          {s.shodan_url && <a href={s.shodan_url} target="_blank" rel="noreferrer" style={{fontSize:11}}>Shodan ↗</a>}
                        </div>
                      </div>
                    ))}
                  </div>
                </Card>
              )}

              {domains.length > 0 && (
                <Card>
                  <CardHeader title={`Clearnet Domains — ${domains.length}`} subtitle="CDN/shared infrastructure filtered out" icon="⬡" color={T.cyan}/>
                  <div style={{padding:"8px 0"}}>
                    {domains.map((d,i) => {
                      const res = (disc.domain_resolutions||[]).find(r=>r.domain===d);
                      return (
                        <div key={i} style={{padding:"8px 16px", borderBottom:`1px solid ${T.border}`, display:"flex", justifyContent:"space-between", alignItems:"center"}}>
                          <span style={{fontFamily:"monospace", color:T.text, fontSize:12}}>{d}</span>
                          <div style={{display:"flex", gap:8, alignItems:"center"}}>
                            {res?.ips?.length ? <span style={{color:T.green, fontSize:11}}>✓ {res.ips.join(", ")}</span> : <span style={{color:T.textDim, fontSize:11}}>Behind CDN</span>}
                            <a href={`https://securitytrails.com/domain/${d}/history/a`} target="_blank" rel="noreferrer" style={{fontSize:11}}>History ↗</a>
                            <a href={`https://crt.sh/?q=${d}`} target="_blank" rel="noreferrer" style={{fontSize:11}}>CT Log ↗</a>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </Card>
              )}
            </div>
          );
        })()}

        {/* ══ ATTRIBUTION GRAPH ═════════════════════════════════════════════ */}
        {tab==="graph" && (
          <div style={{ animation:"fadeIn 0.2s ease" }}>
            {!report?.attribution_graph ? <EmptyState message="Run analysis to generate attribution graph."/> : (
              <div>
                <div style={{ display:"grid", gridTemplateColumns:"repeat(4,1fr)", gap:10, marginBottom:16 }}>
                  <Stat label="Nodes"           value={report.attribution_graph.stats?.total_nodes}  color={T.blue}/>
                  <Stat label="Edges"           value={report.attribution_graph.stats?.total_edges}  color={T.green}/>
                  <Stat label="Critical Nodes"  value={report.attribution_graph.stats?.critical_nodes} color={T.red}/>
                  <Stat label="High-Value Paths" value={report.attribution_graph.high_value_paths?.length} color={T.orange}/>
                </div>
                <div style={{ marginBottom:8, display:"flex", flexWrap:"wrap", gap:8 }}>
                  {Object.entries(NODE_COLORS).map(([type,color]) => (
                    <span key={type} style={{ display:"flex", alignItems:"center", gap:4, fontSize:10, color:T.textMuted }}>
                      <span style={{ width:8, height:8, borderRadius:"50%", background:color, display:"inline-block" }}/>
                      {type.replace(/_/g," ")}
                    </span>
                  ))}
                  <span style={{ color:T.textDim, fontSize:10 }}>· Drag · Scroll=zoom · Hover=details</span>
                </div>
                <Card>
                  <AttributionGraph data={report.attribution_graph}/>
                </Card>
                {report.attribution_graph.high_value_paths?.length > 0 && (
                  <Card style={{marginTop:12}}>
                    <CardHeader title="High-Value Evidence Chains" color={T.red}/>
                    <div style={{padding:"4px 0"}}>
                      {report.attribution_graph.high_value_paths.map((e,i) => (
                        <div key={i} style={{padding:"7px 16px", borderBottom:`1px solid ${T.border}`, fontSize:12, display:"flex", gap:8, alignItems:"center"}}>
                          <span style={{color:T.red,fontFamily:"monospace"}}>{typeof e.source==="object"?e.source.label:e.source}</span>
                          <span style={{color:T.textMuted}}>→[{e.relation}]→</span>
                          <span style={{color:T.orange,fontFamily:"monospace"}}>{typeof e.target==="object"?e.target.label:e.target}</span>
                          <span style={{marginLeft:"auto"}}><RiskChip risk={e.confidence}/></span>
                        </div>
                      ))}
                    </div>
                  </Card>
                )}
              </div>
            )}
          </div>
        )}

        {/* ══ IDENTITY CORRELATION ══════════════════════════════════════════ */}
        {tab==="identity" && (
          <div style={{ animation:"fadeIn 0.2s ease" }}>
            {!report?.correlation ? <EmptyState message="Run analysis to see identity correlation."/> : (
              <div style={{ display:"flex", flexDirection:"column", gap:12 }}>
                {/* PII artifacts */}
                <Card>
                  <CardHeader title={`PII Artifacts — ${report.pii?.length||0}`} icon="◈" color={T.purple}/>
                  <div style={{ padding:16, display:"grid", gridTemplateColumns:"repeat(auto-fill,minmax(200px,1fr))", gap:8 }}>
                    {report.pii?.map((p,i) => (
                      <div key={i} style={{ padding:"8px 10px", background:T.surface2, borderRadius:7, border:`1px solid ${riskColor(p.risk)}22` }}>
                        <div style={{ display:"flex", justifyContent:"space-between", marginBottom:4 }}>
                          <span style={{ color:T.textMuted, fontSize:10 }}>{p.type}</span>
                          <RiskChip risk={p.risk}/>
                        </div>
                        <div style={{ color:T.text, fontSize:11, fontFamily:"monospace", wordBreak:"break-all" }}>{p.value}</div>
                      </div>
                    ))}
                  </div>
                </Card>

                {/* GitHub */}
                {report.correlation.github?.length > 0 && (
                  <Card>
                    <CardHeader title={`GitHub — ${report.correlation.github.length} profile(s)`} icon="⌬" color={T.text}/>
                    <div style={{padding:"4px 0"}}>
                      {report.correlation.github.map((g,i) => (
                        <div key={i} style={{padding:"12px 16px", borderBottom:`1px solid ${T.border}`, display:"grid", gridTemplateColumns:"1fr 1fr", gap:16}}>
                          <div>
                            <div style={{fontWeight:700, fontSize:14, color:T.text, marginBottom:8}}>{g.username||g.matches?.[0]?.login}</div>
                            <Row label="Source" value={g.source_artifact} mono/>
                            <Row label="Name" value={g.display_name} highlight/>
                            <Row label="Email" value={g.email} highlight/>
                            <Row label="Location" value={g.location} highlight/>
                            <Row label="Repos" value={g.public_repos}/>
                            <Row label="Created" value={g.created_at}/>
                          </div>
                          <div>
                            {g.pii_found?.length>0 && <Alert type="danger" style={{marginBottom:8}}><strong>Real PII:</strong> {g.pii_found.join(" · ")}</Alert>}
                            {g.bio && <div style={{color:T.textMuted,fontSize:11,lineHeight:1.6,marginBottom:8,padding:"8px",background:T.surface2,borderRadius:6}}>{g.bio}</div>}
                            <a href={g.profile_url} target="_blank" rel="noreferrer" style={{fontSize:12}}>View Profile ↗</a>
                            <div style={{marginTop:6,color:T.textMuted,fontSize:11}}>Confidence: <span style={{color:T.green}}>{g.confidence}</span></div>
                          </div>
                        </div>
                      ))}
                    </div>
                  </Card>
                )}

                {/* PGP */}
                {report.correlation.pgp_keyserver?.length > 0 && (
                  <Card>
                    <CardHeader title={`PGP Keys — ${report.correlation.pgp_keyserver.length}`} icon="⚿" color={T.green}/>
                    <div style={{padding:"4px 0"}}>
                      {report.correlation.pgp_keyserver.map((pgp,i) => (
                        <div key={i} style={{padding:"12px 16px", borderBottom:`1px solid ${T.border}`}}>
                          <Row label="Source" value={pgp.source_artifact} mono highlight/>
                          <Row label="Keys Found" value={pgp.keys_found} highlight/>
                          {pgp.keys?.map((k,j) => (
                            <div key={j} style={{marginTop:8, padding:"8px 10px", background:T.surface2, borderRadius:6}}>
                              <Row label="Fingerprint" value={k.fingerprint} mono/>
                              <Row label="Identity" value={k.identity} highlight={!!k.email_in_key}/>
                              {k.email_in_key && <Alert type="danger" style={{marginTop:6}}>Real email in key: {k.email_in_key}</Alert>}
                            </div>
                          ))}
                        </div>
                      ))}
                    </div>
                  </Card>
                )}

                {/* Google Dorks */}
                {report.correlation.google_dorks?.length > 0 && (
                  <Card>
                    <CardHeader title="Google Dorks" subtitle="Run these manually" icon="◉" color={T.yellow}/>
                    <div style={{padding:"4px 0"}}>
                      {report.correlation.google_dorks.map((dg,i) => (
                        <div key={i} style={{padding:"10px 16px", borderBottom:`1px solid ${T.border}`}}>
                          <div style={{color:T.text, fontWeight:600, fontSize:12, marginBottom:6}}>{dg.type}: <span style={{fontFamily:"monospace"}}>{dg.artifact}</span></div>
                          {dg.queries?.map((q,j) => (
                            <div key={j} style={{display:"flex", justifyContent:"space-between", padding:"3px 0", borderBottom:`1px solid ${T.surface3}`}}>
                              <span style={{fontFamily:"monospace", fontSize:11, color:T.textMuted, wordBreak:"break-all", flex:1}}>{q.query}</span>
                              <a href={q.url} target="_blank" rel="noreferrer" style={{fontSize:11, marginLeft:8, flexShrink:0}}>Search ↗</a>
                            </div>
                          ))}
                        </div>
                      ))}
                    </div>
                  </Card>
                )}
              </div>
            )}
          </div>
        )}

        {/* ══ BEHAVIORAL ════════════════════════════════════════════════════ */}
        {tab==="behavior" && (
          <div style={{ animation:"fadeIn 0.2s ease" }}>
            {!beh ? <EmptyState message="Run analysis to see behavioral profiling."/> : (
              <div>
                {beh.behavioral_summary?.length > 0 && (
                  <Card style={{marginBottom:12}}>
                    <CardHeader title="Behavioral Summary" icon="◷" color={T.orange}/>
                    <div style={{padding:"4px 0"}}>
                      {beh.behavioral_summary.map((s,i) => (
                        <div key={i} style={{padding:"8px 16px", borderBottom:`1px solid ${T.border}`, color:T.text, fontSize:12}}>{s}</div>
                      ))}
                    </div>
                  </Card>
                )}
                <div style={{display:"grid", gridTemplateColumns:"1fr 1fr", gap:12, marginBottom:12}}>
                  <Card>
                    <CardHeader title="Language Profile" icon="◈" color={T.orange}/>
                    <div style={{padding:"4px 16px"}}>
                      {Object.entries(beh.language_profile||{}).map(([k,v]) => (
                        <Row key={k} label={k.replace(/_/g," ")} value={String(v)} highlight={k==="likely_language"}/>
                      ))}
                    </div>
                  </Card>
                  <Card>
                    <CardHeader title="Timezone Signals" icon="◷" color={T.yellow}/>
                    <div style={{padding:"4px 16px"}}>
                      {beh.timezone_signals?.length > 0 ? beh.timezone_signals.map((t,i) => (
                        <Row key={i} label={t.signal} value={t.value} highlight/>
                      )) : <div style={{padding:"16px 0", color:T.textMuted, fontSize:12}}>No timezone signals detected</div>}
                      {beh.activity_window?.observed_hours_utc?.length > 0 && (
                        <div style={{marginTop:12}}>
                          <div style={{color:T.textMuted, fontSize:10, fontWeight:600, marginBottom:8}}>ACTIVITY HOURS UTC</div>
                          <div style={{display:"flex", gap:3, flexWrap:"wrap"}}>
                            {Array.from({length:24},(_,h) => (
                              <div key={h} style={{
                                width:20, height:20, borderRadius:4,
                                background: beh.activity_window.observed_hours_utc.includes(h) ? `${T.yellow}60` : T.surface3,
                                border: `1px solid ${beh.activity_window.peak_hour_utc===h?T.yellow:T.surface3}`,
                                fontSize:8, display:"flex", alignItems:"center", justifyContent:"center", color:T.textMuted,
                              }}>{h}</div>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  </Card>
                </div>
                {beh.timeline?.length > 0 && (
                  <Card>
                    <CardHeader title="Temporal Evidence" subtitle="All timestamps extracted from page and headers" icon="◷" color={T.cyan} right={`${beh.timeline.length} entry/entries`}/>
                    <div style={{padding:"4px 0"}}>
                      {beh.timeline.map((t,i) => (
                        <div key={i} style={{padding:"8px 16px", borderBottom:`1px solid ${T.border}`, display:"grid", gridTemplateColumns:"160px 200px 1fr", gap:12}}>
                          <span style={{color:T.textMuted, fontSize:11}}>{t.source}</span>
                          <span style={{fontFamily:"monospace", color:T.text, fontSize:11}}>{t.value}</span>
                          <span style={{color:T.textMuted, fontSize:11}}>{t.note}</span>
                        </div>
                      ))}
                    </div>
                  </Card>
                )}
              </div>
            )}
          </div>
        )}

        {/* ══ INFRASTRUCTURE ════════════════════════════════════════════════ */}
        {tab==="infra" && (
          <div style={{ animation:"fadeIn 0.2s ease" }}>
            {!report?.infra_fingerprint ? <EmptyState message="Run analysis to see infrastructure data."/> : (() => {
              const inf = report.infra_fingerprint;
              return (
                <div style={{display:"flex", flexDirection:"column", gap:12}}>
                  {Object.keys(inf.analytics_ids||{}).length > 0 && (
                    <Card>
                      <CardHeader title="Analytics / Tracker IDs" subtitle="Critical cross-site linking opportunities" icon="★" color={T.red}/>
                      <div style={{padding:"4px 0"}}>
                        {Object.entries(inf.analytics_ids||{}).flatMap(([cat,items]) =>
                          items.map((item,i) => (
                            <div key={`${cat}-${i}`} style={{padding:"12px 16px", borderBottom:`1px solid ${T.border}`}}>
                              <div style={{display:"flex", justifyContent:"space-between", marginBottom:6}}>
                                <span style={{fontFamily:"monospace", fontWeight:700, color:T.text, fontSize:13}}>{item.id}</span>
                                <div style={{display:"flex", gap:6}}><Chip label={cat.replace(/_/g," ")} color={T.red} small/><RiskChip risk="CRITICAL"/></div>
                              </div>
                              <div style={{color:T.textMuted, fontSize:12, marginBottom:8}}>{item.note}</div>
                              {item.shodan && <div style={{fontFamily:"monospace", fontSize:11, padding:"4px 8px", background:T.surface2, borderRadius:4, color:T.cyan, marginBottom:4}}>Shodan: {item.shodan}</div>}
                            </div>
                          ))
                        )}
                      </div>
                    </Card>
                  )}

                  {inf.favicon?.found && (
                    <Card>
                      <CardHeader title="Favicon Hash" subtitle="Cross-server fingerprint via Shodan" icon="◈" color={T.yellow}/>
                      <div style={{padding:"4px 16px"}}>
                        <Row label="MurmurHash3" value={inf.favicon.hash} mono highlight/>
                        <Row label="MD5" value={inf.favicon.md5} mono/>
                        <Row label="Size" value={`${inf.favicon.size_bytes} bytes`}/>
                        <div style={{marginTop:8}}>
                          <div style={{fontFamily:"monospace", fontSize:11, padding:"6px 10px", background:T.surface2, borderRadius:5, color:T.yellow, marginBottom:6}}>{inf.favicon.shodan_query}</div>
                          <a href={inf.favicon.shodan_url} target="_blank" rel="noreferrer" style={{fontSize:12}}>Open on Shodan ↗</a>
                        </div>
                      </div>
                    </Card>
                  )}

                  {inf.cdn_detection?.length > 0 && (
                    <Card>
                      <CardHeader title="CDN / Proxy Detection" icon="⊞" color={T.orange}/>
                      <div style={{padding:"4px 0"}}>
                        {inf.cdn_detection.map((c,i) => (
                          <div key={i} style={{padding:"8px 16px", borderBottom:`1px solid ${T.border}`, display:"flex", justifyContent:"space-between"}}>
                            <span style={{color:T.text, fontWeight:600, fontSize:12}}>{c.cdn}</span>
                            <span style={{color:T.textMuted, fontSize:11}}>{c.note}</span>
                          </div>
                        ))}
                      </div>
                    </Card>
                  )}

                  {inf.cross_site_indicators?.length > 0 && (
                    <Card>
                      <CardHeader title="Cross-Site Correlation" icon="⬡" color={T.cyan}/>
                      <div style={{padding:"4px 0"}}>
                        {inf.cross_site_indicators.map((ind,i) => (
                          <div key={i} style={{padding:"10px 16px", borderBottom:`1px solid ${T.border}`}}>
                            <div style={{fontWeight:600, color:T.text, fontSize:12, marginBottom:4}}>{ind.type}: {ind.value}</div>
                            <div style={{color:T.textMuted, fontSize:11, marginBottom:4}}>{ind.action}</div>
                            {ind.shodan && <div style={{fontFamily:"monospace", fontSize:11, color:T.yellow}}>{ind.shodan}</div>}
                          </div>
                        ))}
                      </div>
                    </Card>
                  )}
                </div>
              );
            })()}
          </div>
        )}

        {/* ══ LOG ═══════════════════════════════════════════════════════════ */}
        {tab==="log" && (
          <div style={{ animation:"fadeIn 0.2s ease" }}>
            <div style={{ display:"flex", justifyContent:"space-between", marginBottom:10 }}>
              <span style={{ color:T.textMuted, fontSize:12 }}>Operation log — {logs.length} entries</span>
              <button onClick={()=>setLogs([])} style={{ padding:"3px 10px", background:T.surface2, border:`1px solid ${T.border}`, color:T.textMuted, borderRadius:5, fontSize:11 }}>Clear</button>
            </div>
            <Card>
              <div ref={logRef} style={{ padding:14, height:"70vh", overflowY:"auto", fontFamily:"monospace", fontSize:12, lineHeight:1.6 }}>
                {logs.length===0 && <span style={{color:T.textDim}}>No log entries. Run an analysis to see operation logs.</span>}
                {logs.map((l,i) => (
                  <div key={i} style={{ color: l.type==="ok"?T.green:l.type==="error"?T.red:l.type==="warn"?T.yellow:T.textMuted }}>
                    <span style={{color:T.textDim, marginRight:10}}>{l.t}</span>{l.msg}
                  </div>
                ))}
                <div style={{color:T.blue}}>▌</div>
              </div>
            </Card>
          </div>
        )}

      </div>
    </div>
  );
}
