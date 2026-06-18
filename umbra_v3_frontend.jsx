import { useState, useCallback, useRef, useEffect } from "react";
import * as d3 from "d3";

const BACKEND = "http://localhost:8000";
const RISK_C = { CRITICAL:"#ff3c3c", HIGH:"#ff6b35", MEDIUM:"#ffcc00", LOW:"#00ff88" };
const NODE_C = {
  onion_site:"#00c8ff", email:"#ff3c3c", telegram:"#29b6f6", btc_address:"#f7931a",
  eth_address:"#627eea", xmr_address:"#ff6600", domain:"#ffcc00", pgp_key:"#00ff88",
  github_profile:"#e0e0e0", reddit_profile:"#ff4500", ip_address:"#ff3c3c",
  analytics_id:"#ff0080", exchange:"#00ff88", location:"#80deea", isp:"#b0bec5",
  server_software:"#78909c", twitter_profile:"#1da1f2",
};
const C = {
  bg:"#02050c", border:"rgba(0,200,255,0.14)", text:"#b8ccd8",
  cyan:"#00c8ff", green:"#00ff88", yellow:"#ffcc00",
  orange:"#ff6b35", red:"#ff3c3c", purple:"#c084fc",
};

const post = async (path, body) => {
  const r = await fetch(BACKEND + path, {method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)});
  if (!r.ok) throw new Error("Backend HTTP "+r.status+". Is umbra_v3_backend.py running?");
  return r.json();
};
const getApi = async (path) => {
  const r = await fetch(BACKEND + path);
  if (!r.ok) throw new Error("HTTP "+r.status);
  return r.json();
};

// ─── D3 ATTRIBUTION GRAPH ──────────────────────────────────────────────────
function AttributionGraph({ graphData }) {
  const svgRef = useRef(null);
  useEffect(() => {
    if (!graphData?.nodes?.length || !svgRef.current) return;
    const el = svgRef.current;
    d3.select(el).selectAll("*").remove();
    const W = el.clientWidth || 960, H = 620;
    const svg = d3.select(el).attr("width",W).attr("height",H).style("background","#02050c");
    const defs = svg.append("defs");
    const filter = defs.append("filter").attr("id","glow");
    filter.append("feGaussianBlur").attr("stdDeviation","3").attr("result","coloredBlur");
    const fm = filter.append("feMerge");
    fm.append("feMergeNode").attr("in","coloredBlur");
    fm.append("feMergeNode").attr("in","SourceGraphic");
    Object.entries(NODE_C).forEach(([type,color])=>{
      defs.append("marker").attr("id","arrow-"+type).attr("viewBox","0 -5 10 10")
        .attr("refX",20).attr("refY",0).attr("markerWidth",5).attr("markerHeight",5)
        .attr("orient","auto").append("path").attr("d","M0,-5L10,0L0,5")
        .attr("fill",color).attr("opacity",0.5);
    });
    const nodeById = {};
    graphData.nodes.forEach(n=>{nodeById[n.id]=n;});
    const g = svg.append("g");
    svg.call(d3.zoom().scaleExtent([0.15,5]).on("zoom",ev=>g.attr("transform",ev.transform)));
    const sim = d3.forceSimulation(graphData.nodes)
      .force("link",d3.forceLink(graphData.edges).id(d=>d.id).distance(d=>d.confidence==="CRITICAL"?90:140).strength(0.4))
      .force("charge",d3.forceManyBody().strength(-400))
      .force("center",d3.forceCenter(W/2,H/2))
      .force("collision",d3.forceCollide(30));
    const link = g.append("g").selectAll("line").data(graphData.edges).enter().append("line")
      .attr("stroke",d=>{const s=typeof d.source==="object"?d.source:nodeById[d.source]; return NODE_C[s?.type]||"#4a7a9b";})
      .attr("stroke-opacity",0.45)
      .attr("stroke-width",d=>d.confidence==="CRITICAL"?2.5:d.confidence==="HIGH"?1.5:1)
      .attr("stroke-dasharray",d=>d.confidence==="LOW"?"4,4":null)
      .attr("marker-end",d=>{const s=typeof d.source==="object"?d.source:nodeById[d.source]; return "url(#arrow-"+(s?.type||"onion_site")+")";});
    const edgeLbl = g.append("g").selectAll("text")
      .data(graphData.edges.filter(e=>e.confidence==="CRITICAL")).enter()
      .append("text").attr("fill","#ffcc0080").attr("font-size","8px")
      .attr("font-family","Courier New,monospace").attr("text-anchor","middle")
      .text(d=>d.relation);
    const nodeG = g.append("g").selectAll("g").data(graphData.nodes).enter().append("g")
      .call(d3.drag()
        .on("start",(ev,d)=>{if(!ev.active)sim.alphaTarget(0.3).restart();d.fx=d.x;d.fy=d.y;})
        .on("drag",(ev,d)=>{d.fx=ev.x;d.fy=ev.y;})
        .on("end",(ev,d)=>{if(!ev.active)sim.alphaTarget(0);d.fx=null;d.fy=null;}));
    nodeG.each(function(d){
      const el2=d3.select(this), color=NODE_C[d.type]||"#4a7a9b", isRoot=d.type==="onion_site";
      if(isRoot){
        const pts=Array.from({length:6},(_,i)=>{const a=Math.PI/180*(60*i-30);return `${20*Math.cos(a)},${20*Math.sin(a)}`;}).join(" ");
        el2.append("polygon").attr("points",pts).attr("fill",color+"18").attr("stroke",color).attr("stroke-width",2).attr("filter","url(#glow)");
      } else {
        el2.append("circle").attr("r",d.risk==="CRITICAL"?14:d.risk==="HIGH"?11:9)
          .attr("fill",color+"15").attr("stroke",color)
          .attr("stroke-width",d.risk==="CRITICAL"?2:1)
          .attr("filter",d.risk==="CRITICAL"?"url(#glow)":null);
      }
      const icons={onion_site:"◉",email:"@",telegram:"✈",btc_address:"₿",eth_address:"Ξ",xmr_address:"ɱ",domain:"⬡",pgp_key:"⚿",github_profile:"⌬",reddit_profile:"R",ip_address:"⊕",analytics_id:"★",exchange:"$",location:"◎",isp:"⊞",server_software:"⚙"};
      el2.append("text").attr("dy","0.35em").attr("text-anchor","middle").attr("font-size",isRoot?"11px":"9px").attr("fill",color).attr("pointer-events","none").text(icons[d.type]||"◆");
    });
    nodeG.append("text").attr("dx",17).attr("dy","0.35em").attr("font-size","9px").attr("font-family","Courier New,monospace").attr("fill","#b8ccd8").attr("pointer-events","none")
      .text(d=>d.label?.length>24?d.label.slice(0,24)+"…":d.label);
    const tooltip = d3.select("body").append("div")
      .style("position","fixed").style("background","rgba(2,5,12,0.98)").style("border","1px solid rgba(0,200,255,0.3)")
      .style("color","#b8ccd8").style("padding","10px 14px").style("font-family","Courier New,monospace")
      .style("font-size","11px").style("pointer-events","none").style("opacity",0)
      .style("z-index","9999").style("max-width","320px").style("line-height","1.7");
    nodeG.on("mouseover",(ev,d)=>{
      const color=NODE_C[d.type]||"#4a7a9b";
      let html=`<div style="color:${color};font-weight:bold;margin-bottom:6px">${d.type.replace(/_/g," ").toUpperCase()}</div><div style="color:#fff;margin-bottom:4px;word-break:break-all">${d.label}</div>`;
      if(d.data)Object.entries(d.data).forEach(([k,v])=>{if(v&&k!=="full"&&k!=="maps")html+=`<div><span style="color:#456070">${k}:</span> ${String(v).slice(0,80)}</div>`;});
      if(d.data?.maps)html+=`<div style="margin-top:4px"><a href="${d.data.maps}" target="_blank" style="color:#00c8ff;font-size:10px">→ Google Maps</a></div>`;
      html+=`<div style="margin-top:5px;color:#456070">Risk: <span style="color:${RISK_C[d.risk]||"#4a7a9b"}">${d.risk}</span></div>`;
      tooltip.html(html).style("opacity",1).style("left",(ev.clientX+14)+"px").style("top",(ev.clientY-10)+"px");
    }).on("mousemove",ev=>tooltip.style("left",(ev.clientX+14)+"px").style("top",(ev.clientY-10)+"px"))
      .on("mouseout",()=>tooltip.style("opacity",0));
    sim.on("tick",()=>{
      link.attr("x1",d=>d.source.x).attr("y1",d=>d.source.y).attr("x2",d=>d.target.x).attr("y2",d=>d.target.y);
      edgeLbl.attr("x",d=>(d.source.x+d.target.x)/2).attr("y",d=>(d.source.y+d.target.y)/2);
      nodeG.attr("transform",d=>`translate(${d.x},${d.y})`);
    });
    return ()=>{tooltip.remove();sim.stop();};
  }, [graphData]);
  return <svg ref={svgRef} style={{width:"100%",height:"620px",display:"block"}} />;
}

// ─── UI ATOMS ──────────────────────────────────────────────────────────────
function Panel({title,color="#00c8ff",status,children}){
  return(
    <div style={{border:`1px solid ${color}28`,borderRadius:2,overflow:"hidden",marginBottom:14}}>
      <div style={{padding:"9px 14px",borderBottom:`1px solid ${color}20`,background:`${color}07`,display:"flex",justifyContent:"space-between",alignItems:"center"}}>
        <span style={{color,fontSize:11,letterSpacing:"1.8px",fontWeight:"bold"}}>{title}</span>
        {status&&<span style={{color:C.text,fontSize:10}}>{status}</span>}
      </div>
      <div style={{padding:14}}>{children}</div>
    </div>
  );
}
function KV({k,v,hi,mono}){
  return(
    <div style={{display:"flex",justifyContent:"space-between",padding:"4px 0",borderBottom:"1px solid rgba(255,255,255,0.04)",gap:12}}>
      <span style={{color:"#456070",fontSize:10,whiteSpace:"nowrap",flexShrink:0}}>{k}</span>
      <span style={{color:hi?"#fff":C.text,fontSize:11,textAlign:"right",wordBreak:"break-all",fontFamily:mono?"Courier New,monospace":"inherit"}}>{String(v??"-")}</span>
    </div>
  );
}
function Badge({risk}){const c=RISK_C[risk]||"#4a7a9b";return<span style={{fontSize:9,border:`1px solid ${c}`,color:c,padding:"2px 6px"}}>{risk}</span>;}
function Pulse({text}){return<div style={{display:"flex",alignItems:"center",gap:8,color:C.cyan,fontSize:11,padding:"6px 0"}}><span style={{animation:"spin 1s linear infinite",display:"inline-block"}}>◎</span>{text}</div>;}

// ─── MAIN APP ──────────────────────────────────────────────────────────────
export default function App(){
  const [tab,setTab]=useState("scan");
  const [onionUrl,setOnionUrl]=useState("");
  const [apiKey,setApiKey]=useState("");
  const [report,setReport]=useState(null);
  const [loading,setLoading]=useState(false);
  const [loadMsg,setLoadMsg]=useState("");
  const [error,setError]=useState("");
  const [torStatus,setTorStatus]=useState(null);
  const logRef=useRef(null);
  const [logs,setLogs]=useState([]);

  const addLog=(msg,type="info")=>{
    const color=type==="ok"?C.green:type==="err"?C.red:type==="warn"?C.yellow:C.cyan;
    setLogs(p=>[...p.slice(-100),{msg,color,t:new Date().toLocaleTimeString()}]);
    setTimeout(()=>{if(logRef.current)logRef.current.scrollTop=logRef.current.scrollHeight;},30);
  };

  const checkTor=async()=>{
    addLog("Checking Tor via backend...");
    try{
      const r=await getApi("/api/tor/check");
      setTorStatus(r);
      addLog(r.is_tor?`Tor ACTIVE. Exit IP: ${r.tor_ip}`:"Tor OFFLINE: "+(r.error||"not Tor exit"),r.is_tor?"ok":"warn");
    }catch(e){setTorStatus({running:false,error:"Backend unreachable"});addLog("Backend unreachable. Start: python umbra_v3_backend.py","err");}
  };

  const STEPS=[
    "Establishing Tor circuit (3-hop)...","Fetching .onion via SOCKS5h...",
    "Parsing HTML / page intelligence...","PII extraction (28 patterns)...",
    "Analyzing HTTP headers...","IP geolocation + VPN detection...",
    "Stylometric fingerprint (Burrows Delta)...","Certificate Transparency (crt.sh)...",
    "Blockchain forensics (Blockchair)...","Identity correlation (GitHub, Reddit, PGP)...",
    "Infrastructure fingerprinting (favicon, analytics, CDN)...",
    "Building attribution graph...","Claude OSINT brief (NIA format)...",
  ];

  const runAnalysis=useCallback(async()=>{
    if(!onionUrl.trim())return;
    setLoading(true);setError("");setReport(null);setLogs([]);
    setTab("results");
    let i=0;
    const ticker=setInterval(()=>{
      if(i<STEPS.length){setLoadMsg(STEPS[i]);addLog(STEPS[i]);i++;}
    },1700);
    try{
      const result=await post("/api/analyze",{onion_url:onionUrl.trim(),anthropic_api_key:apiKey.trim()});
      clearInterval(ticker);
      setReport(result);
      const g=result.attribution_graph?.stats;
      addLog(`DONE. PII:${result.pii?.length||0} | IPs:${result.ip_intelligence?.length||0} | Leads:${result.correlation?.high_confidence_leads?.length||0} | Graph:${g?.total_nodes||0}N/${g?.total_edges||0}E`,"ok");
      if(result.errors?.length)result.errors.forEach(e=>addLog(e,"err"));
    }catch(e){clearInterval(ticker);setError(e.message);addLog(e.message,"err");}
    setLoading(false);
  },[onionUrl,apiKey]);

  const TABS=[
    {id:"scan",label:"① SCAN"},
    {id:"results",label:"② RESULTS",disabled:!report&&!loading},
    {id:"ip",label:"⊕ IP INTELLIGENCE",disabled:!report},
    {id:"graph",label:"⬡ ATTRIBUTION GRAPH",disabled:!report},
    {id:"correlation",label:"⬡ IDENTITY CORRELATION",disabled:!report},
    {id:"infra",label:"⬡ INFRASTRUCTURE",disabled:!report},
    {id:"terminal",label:"⬡ LOG"},
  ];

  const leads=report?.correlation?.high_confidence_leads||[];
  const ips=report?.ip_intelligence||[];

  return(
    <div style={{background:C.bg,minHeight:"100vh",color:C.text,fontFamily:"Courier New,monospace",fontSize:13}}>
      <style>{`@keyframes spin{from{transform:rotate(0)}to{transform:rotate(360deg)}}*{box-sizing:border-box}::-webkit-scrollbar{width:4px}::-webkit-scrollbar-thumb{background:#1a3050}input,textarea,button{font-family:inherit}input::placeholder{color:#2a4a6b}a{text-decoration:none}`}</style>

      {/* HEADER */}
      <div style={{padding:"10px 20px",borderBottom:`1px solid ${C.border}`,display:"flex",justifyContent:"space-between",alignItems:"center",background:"rgba(0,0,0,0.7)"}}>
        <div style={{display:"flex",alignItems:"center",gap:14}}>
          <div style={{width:30,height:30,border:`1px solid ${C.cyan}`,display:"flex",alignItems:"center",justifyContent:"center",color:C.cyan,clipPath:"polygon(50% 0%,100% 25%,100% 75%,50% 100%,0% 75%,0% 25%)",background:`${C.cyan}0a`,fontSize:13}}>◉</div>
          <div>
            <div style={{color:C.cyan,fontSize:15,letterSpacing:5,fontWeight:"bold"}}>UMBRA  V3</div>
            <div style={{color:"#35607a",fontSize:9,letterSpacing:2}}>DARK WEB INTELLIGENCE · TOR-CONNECTED · NIA / LAW ENFORCEMENT</div>
          </div>
        </div>
        <div style={{display:"flex",gap:16,alignItems:"center"}}>
          {torStatus&&(
            <span style={{fontSize:10}}>
              <span style={{display:"inline-block",width:7,height:7,borderRadius:"50%",background:torStatus.is_tor?C.green:C.red,marginRight:5,boxShadow:`0 0 7px ${torStatus.is_tor?C.green:C.red}`}}/>
              <span style={{color:torStatus.is_tor?C.green:C.red}}>{torStatus.is_tor?`TOR ACTIVE · ${torStatus.tor_ip}`:"TOR OFFLINE"}</span>
            </span>
          )}
          <button onClick={checkTor} style={{padding:"4px 12px",background:"transparent",border:`1px solid ${C.border}`,color:C.text,cursor:"pointer",fontSize:10}}>CHECK TOR</button>
          <button onClick={()=>getApi("/api/tor/newcircuit").then(()=>addLog("New Tor circuit requested","ok")).catch(()=>{})} style={{padding:"4px 12px",background:"transparent",border:`1px solid ${C.border}`,color:"#4a7a9b",cursor:"pointer",fontSize:10}}>NEW CIRCUIT</button>
          <span style={{color:C.orange,fontSize:9,border:"1px solid rgba(255,107,53,0.3)",padding:"3px 8px"}}>NIA / LEA ONLY</span>
        </div>
      </div>

      {/* TABS */}
      <div style={{display:"flex",borderBottom:`1px solid ${C.border}`,background:"rgba(0,0,0,0.3)",overflowX:"auto"}}>
        {TABS.map(t=>(
          <button key={t.id} onClick={()=>!t.disabled&&setTab(t.id)} style={{padding:"8px 16px",border:"none",background:"transparent",cursor:t.disabled?"not-allowed":"pointer",color:tab===t.id?C.cyan:t.disabled?"#1a3050":"#4a7a9b",borderBottom:tab===t.id?`2px solid ${C.cyan}`:"2px solid transparent",fontSize:11,letterSpacing:1,whiteSpace:"nowrap"}}>
            {t.label}
          </button>
        ))}
      </div>

      <div style={{padding:20,maxWidth:1400,margin:"0 auto"}}>

        {/* ── SCAN ── */}
        {tab==="scan"&&(
          <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:16}}>
            <div style={{gridColumn:"1/-1",padding:"10px 16px",border:"1px solid rgba(255,204,0,0.2)",background:"rgba(255,204,0,0.03)",fontSize:11,color:C.yellow,lineHeight:1.7}}>
              ⚠ PREREQUISITES — (1) Tor daemon at 127.0.0.1:9050 &nbsp;·&nbsp; (2) <code>python umbra_v3_backend.py</code> at localhost:8000 &nbsp;·&nbsp; (3) Click CHECK TOR to verify &nbsp;·&nbsp; (4) Set Anthropic API key for AI brief
            </div>
            <Panel title="TARGET .ONION URL" color={C.cyan}>
              <div style={{marginBottom:10,color:"#4a7a9b",fontSize:10,lineHeight:1.6}}>Enter v2 or v3 .onion address. Backend fetches via real Tor connection, then runs all 12 modules automatically.</div>
              <input value={onionUrl} onChange={e=>setOnionUrl(e.target.value)} onKeyDown={e=>e.key==="Enter"&&runAnalysis()} placeholder="http://exampleonion56ixjvkiew7ed.onion" style={{width:"100%",background:"rgba(0,0,0,0.8)",border:`1px solid ${C.cyan}30`,color:C.cyan,padding:"10px 12px",fontSize:13,outline:"none"}}/>
            </Panel>
            <Panel title="ANTHROPIC API KEY — Claude OSINT Brief" color={C.purple}>
              <div style={{marginBottom:10,color:"#4a7a9b",fontSize:10,lineHeight:1.6}}>Required for NIA-format intelligence brief. Get at console.anthropic.com. Can also set as ANTHROPIC_API_KEY env var on backend.</div>
              <input value={apiKey} onChange={e=>setApiKey(e.target.value)} type="password" placeholder="sk-ant-api03-..." style={{width:"100%",background:"rgba(0,0,0,0.8)",border:`1px solid ${C.purple}30`,color:C.text,padding:"10px 12px",fontSize:12,outline:"none"}}/>
            </Panel>
            <div style={{gridColumn:"1/-1"}}>
              <div style={{display:"grid",gridTemplateColumns:"repeat(4,1fr)",gap:10,marginBottom:16}}>
                {[
                  ["TOR FETCH",C.cyan,"Real SOCKS5h. Fetches full page + headers through Tor daemon."],
                  ["PII EXTRACTION",C.purple,"28 patterns: email, BTC/ETH/XMR, IPs, Telegram, Jabber, GA IDs, Stripe, S3, SimpleX."],
                  ["IP GEOLOCATION",C.red,"ip-api.com: country, city, ISP, ASN, lat/lon, VPN/proxy/datacenter detection."],
                  ["HEADER ANALYSIS",C.green,"X-Forwarded-For real IP leak, server fingerprint, timezone, CDN detection."],
                  ["STYLOMETRY",C.orange,"Burrows Delta: TTR, Hapax/Dis, Yule K, Honore R, function words, trigrams, language."],
                  ["CERT TRANSPARENCY",C.yellow,"Live crt.sh for all clearnet domains found. Full cert history + SAN domains."],
                  ["BLOCKCHAIN",C.red,"Blockchair real balance/tx. WalletExplorer exchange label for legal process."],
                  ["IDENTITY CORRELATION",C.cyan,"GitHub API, Reddit API, OpenPGP keyserver for usernames/emails/PGP keys."],
                  ["INFRA FINGERPRINTING",C.purple,"Favicon MurmurHash3 (Shodan), analytics ID reuse, CDN, JS fingerprint."],
                  ["ATTRIBUTION GRAPH",C.green,"D3 force graph: all artifacts as nodes, evidence chains as edges."],
                  ["GOOGLE DORKS",C.yellow,"Auto-generated exact search queries per artifact for manual investigation."],
                  ["CLAUDE OSINT BRIEF",C.cyan,"All data → Claude Opus: operator profile, top 5 leads, NIA legal recommendations."],
                ].map(([n,c,d])=>(
                  <div key={n} style={{padding:10,border:`1px solid ${c}20`,background:`${c}05`}}>
                    <div style={{color:c,fontSize:10,letterSpacing:1,marginBottom:4,fontWeight:"bold"}}>✓ {n}</div>
                    <div style={{color:"#5a8090",fontSize:10,lineHeight:1.4}}>{d}</div>
                  </div>
                ))}
              </div>
              <button onClick={runAnalysis} disabled={loading||!onionUrl.trim()} style={{width:"100%",padding:14,background:loading?`${C.cyan}10`:"transparent",border:`1px solid ${C.cyan}`,color:C.cyan,cursor:loading||!onionUrl.trim()?"not-allowed":"pointer",fontSize:13,letterSpacing:3,opacity:!onionUrl.trim()?0.3:1}}>
                {loading?`◎  ${loadMsg}`:"▶  CONNECT TOR → FETCH → 12-MODULE ANALYSIS"}
              </button>
              {error&&<div style={{marginTop:8,padding:"10px 14px",border:`1px solid ${C.red}40`,background:`${C.red}08`,color:C.red,fontSize:11}}>✖ {error}</div>}
            </div>
          </div>
        )}

        {/* ── RESULTS ── */}
        {tab==="results"&&(
          <div>
            {loading&&<div style={{padding:"40px 0",textAlign:"center"}}><Pulse text={loadMsg}/><div style={{color:"#4a7a9b",fontSize:11,marginTop:8}}>Running 12-module analysis via Tor — typically 45–120 seconds</div></div>}
            {report&&!loading&&(
              <div>
                {/* Fetch banner */}
                <div style={{padding:"12px 16px",border:`1px solid ${report.fetch?.success?C.green:C.red}40`,background:`${report.fetch?.success?C.green:C.red}05`,display:"grid",gridTemplateColumns:"repeat(5,1fr)",gap:12,marginBottom:14}}>
                  {[["TARGET",report.target_url],["HTTP STATUS",report.fetch?.status_code||"FAILED"],["PAGE SIZE",report.fetch?.content_length?((report.fetch.content_length/1024).toFixed(1)+" KB"):"—"],["TOR LATENCY",report.fetch?.elapsed_seconds?(report.fetch.elapsed_seconds+"s"):"—"],["SERVER",report.fetch?.server||"—"]].map(([k,v])=>(
                    <div key={k}><div style={{color:"#4a7a9b",fontSize:9,letterSpacing:1}}>{k}</div><div style={{color:"#fff",fontSize:11,wordBreak:"break-all"}}>{String(v)}</div></div>
                  ))}
                </div>

                {/* High confidence leads */}
                {leads.length>0&&(
                  <Panel title={`⚠ HIGH-CONFIDENCE LEADS — ${leads.length} DE-ANONYMIZATION PATHS`} color={C.red}>
                    {leads.map((l,i)=>(
                      <div key={i} style={{marginBottom:8,padding:"10px 12px",border:`1px solid ${RISK_C[l.confidence]||"#4a7a9b"}30`,background:`${RISK_C[l.confidence]||"#4a7a9b"}05`,display:"grid",gridTemplateColumns:"200px 1fr auto",gap:12,alignItems:"center"}}>
                        <div style={{color:C.orange,fontSize:11,fontWeight:"bold"}}>{l.type}</div>
                        <div>
                          <div style={{color:"#fff",fontSize:12}}>{l.finding}</div>
                          {l.url&&<a href={l.url} target="_blank" rel="noreferrer" style={{color:C.cyan,fontSize:10}}>→ {l.url.slice(0,60)}</a>}
                        </div>
                        <Badge risk={l.confidence}/>
                      </div>
                    ))}
                  </Panel>
                )}

                {/* IP summary inline */}
                {ips.filter(g=>g.success).length>0&&(
                  <Panel title={`⊕ IP INTELLIGENCE SUMMARY — ${ips.filter(g=>g.success).length} IPs`} color={C.red}>
                    <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fill,minmax(280px,1fr))",gap:10}}>
                      {ips.filter(g=>g.success).map((g,i)=>(
                        <div key={i} style={{padding:10,border:`1px solid ${g.source?.includes("HEADER")?C.red:C.orange}30`,background:`${g.source?.includes("HEADER")?C.red:C.orange}05`}}>
                          {g.source?.includes("HEADER")&&<div style={{color:C.red,fontSize:9,fontWeight:"bold",marginBottom:4}}>⚠ REAL IP LEAK</div>}
                          <div style={{color:"#fff",fontSize:12,fontFamily:"monospace",marginBottom:4}}>{g.ip}</div>
                          <div style={{color:C.text,fontSize:11}}>{g.city}, {g.region}, {g.country}</div>
                          <div style={{color:"#4a7a9b",fontSize:10}}>{g.isp}</div>
                          <div style={{display:"flex",gap:4,marginTop:6,flexWrap:"wrap"}}>
                            {g.is_proxy&&<span style={{color:C.red,fontSize:9,border:`1px solid ${C.red}40`,padding:"1px 6px"}}>VPN/PROXY</span>}
                            {g.is_hosting&&<span style={{color:C.orange,fontSize:9,border:`1px solid ${C.orange}40`,padding:"1px 6px"}}>DATACENTER</span>}
                            {!g.is_proxy&&!g.is_hosting&&<span style={{color:C.green,fontSize:9,border:`1px solid ${C.green}40`,padding:"1px 6px"}}>RESIDENTIAL</span>}
                            <a href={g.google_maps_url} target="_blank" rel="noreferrer" style={{color:C.cyan,fontSize:9,border:`1px solid ${C.cyan}30`,padding:"1px 6px"}}>MAP</a>
                          </div>
                        </div>
                      ))}
                    </div>
                  </Panel>
                )}

                {/* AI Brief */}
                <Panel title="⬡ AI OSINT BRIEF — NIA Intelligence Analysis" color={C.cyan}>
                  {report.ai_brief?<pre style={{color:C.text,fontSize:12,lineHeight:1.8,whiteSpace:"pre-wrap",margin:0}}>{report.ai_brief}</pre>:<span style={{color:"#4a7a9b",fontSize:11}}>No brief — check Anthropic API key</span>}
                </Panel>

                {/* PII */}
                <Panel title={`⬡ PII EXTRACTION — ${report.pii?.length||0} ARTIFACTS`} color={C.purple}>
                  {report.pii?.length>0?(
                    <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fill,minmax(240px,1fr))",gap:8}}>
                      {report.pii.map((p,i)=>(
                        <div key={i} style={{padding:"9px 11px",border:`1px solid ${RISK_C[p.risk]}22`,background:`${RISK_C[p.risk]}06`}}>
                          <div style={{display:"flex",justifyContent:"space-between",marginBottom:4}}>
                            <span style={{color:C.purple,fontSize:10}}>{p.type}</span>
                            <Badge risk={p.risk}/>
                          </div>
                          <div style={{color:"#fff",fontSize:11,wordBreak:"break-all",fontFamily:"Courier New,monospace",marginBottom:p.context?3:0}}>{p.value}</div>
                          {p.context&&<div style={{color:"#4a7a9b",fontSize:9,fontStyle:"italic"}}>…{p.context.slice(0,80)}…</div>}
                        </div>
                      ))}
                    </div>
                  ):<span style={{color:"#4a7a9b",fontSize:11}}>No PII artifacts found in fetched content.</span>}
                </Panel>

                {/* Headers */}
                {report.headers?.length>0&&(
                  <Panel title="⬡ HTTP HEADER ANALYSIS" color={C.green} status={`${report.headers.length} findings`}>
                    {report.headers.map((h,i)=>(
                      <div key={i} style={{padding:"9px 12px",border:`1px solid ${RISK_C[h.risk]}20`,background:`${RISK_C[h.risk]}04`,display:"grid",gridTemplateColumns:"170px 220px 1fr",gap:12,marginBottom:4,alignItems:"start"}}>
                        <div><div style={{color:C.green,fontSize:11}}>{h.field}</div><Badge risk={h.risk}/></div>
                        <div style={{color:"#fff",fontSize:11,fontFamily:"monospace",wordBreak:"break-all"}}>{h.value}</div>
                        <div>
                          <div style={{color:C.text,fontSize:11}}>{h.note}</div>
                          {h.action&&<div style={{color:C.cyan,fontSize:10,marginTop:2,fontFamily:"monospace"}}>⬡ {h.action}</div>}
                        </div>
                      </div>
                    ))}
                  </Panel>
                )}

                {/* Stylometry */}
                {report.stylometry&&(
                  <Panel title="⬡ STYLOMETRIC AUTHORSHIP FINGERPRINT" color={C.orange} status="Burrows Delta + Yule K + Honore R">
                    <div style={{display:"grid",gridTemplateColumns:"1fr 1fr 1fr",gap:16}}>
                      <div>
                        <div style={{color:C.orange,fontSize:9,letterSpacing:1,marginBottom:8}}>CORPUS STATISTICS</div>
                        <KV k="Words" v={report.stylometry.word_count?.toLocaleString()}/>
                        <KV k="Unique" v={report.stylometry.unique_words?.toLocaleString()}/>
                        <KV k="Type-Token Ratio" v={report.stylometry.ttr} hi/>
                        <KV k="Avg Sentence Length" v={report.stylometry.avg_sentence_length+" words"} hi/>
                        <KV k="Avg Word Length" v={report.stylometry.avg_word_length+" chars"}/>
                        <KV k="Hapax Legomena" v={report.stylometry.hapax_legomena+" ("+((report.stylometry.hapax_ratio||0)*100).toFixed(1)+"%)"} hi/>
                        <KV k="Yule's K" v={report.stylometry.yules_k}/>
                        <KV k="Honore's R" v={report.stylometry.honores_r}/>
                        <div style={{marginTop:8,padding:8,background:`${C.orange}08`,border:`1px solid ${C.orange}15`,fontSize:10,color:"#5a8090",lineHeight:1.5}}>{report.stylometry.vocabulary_richness}</div>
                      </div>
                      <div>
                        <div style={{color:C.orange,fontSize:9,letterSpacing:1,marginBottom:8}}>LANGUAGE SIGNALS</div>
                        <KV k="Likely Speaker" v={report.stylometry.language?.likely_native_language} hi/>
                        <KV k="Hindi/Hinglish" v={report.stylometry.language?.hindi_romanized?"✓ DETECTED":"—"} hi={report.stylometry.language?.hindi_romanized}/>
                        <KV k="Russian patterns" v={report.stylometry.language?.russian_patterns?"✓ DETECTED":"—"} hi={report.stylometry.language?.russian_patterns}/>
                        <KV k="British English" v={report.stylometry.language?.british_spelling?"✓":"—"}/>
                        <KV k="American English" v={report.stylometry.language?.american_spelling?"✓":"—"}/>
                        <div style={{marginTop:12,color:C.orange,fontSize:9,letterSpacing:1,marginBottom:6}}>PUNCTUATION PROFILE</div>
                        {Object.entries(report.stylometry.punctuation||{}).map(([k,v])=><KV key={k} k={k} v={v}/>)}
                      </div>
                      <div>
                        <div style={{color:C.orange,fontSize:9,letterSpacing:1,marginBottom:8}}>FUNCTION WORDS (per 1000)</div>
                        {report.stylometry.top_function_words?.map(([w,f],i)=>(
                          <div key={i} style={{display:"flex",justifyContent:"space-between",padding:"3px 0",borderBottom:"1px solid rgba(255,107,53,0.08)"}}>
                            <span style={{color:C.text,fontSize:11,fontFamily:"monospace"}}>{w}</span>
                            <span style={{color:C.orange,fontSize:11}}>{f}</span>
                          </div>
                        ))}
                        <div style={{marginTop:10,color:C.orange,fontSize:9,letterSpacing:1,marginBottom:6}}>CHAR TRIGRAMS</div>
                        {report.stylometry.top_trigrams?.map(([tg,cnt],i)=>(
                          <div key={i} style={{display:"flex",justifyContent:"space-between",padding:"2px 0"}}>
                            <span style={{color:C.text,fontSize:11,fontFamily:"monospace"}}>"{tg}"</span>
                            <span style={{color:"#4a7a9b",fontSize:11}}>{cnt}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  </Panel>
                )}

                {/* CT + Blockchain */}
                <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:14}}>
                  {report.cert_transparency?.length>0&&(
                    <Panel title="⬡ CERT TRANSPARENCY" color={C.yellow}>
                      {report.cert_transparency.slice(0,1).map((ct,i)=>(
                        <div key={i}>
                          <div style={{color:C.yellow,fontSize:11,marginBottom:6}}>{ct.domain} — {ct.result?.total_certs} certs found</div>
                          {ct.result?.results?.slice(0,5).map((c,j)=>(
                            <div key={j} style={{color:C.text,fontSize:10,padding:"2px 0",borderBottom:"1px solid rgba(255,204,0,0.08)"}}>{c.common_name} <span style={{color:"#4a7a9b"}}>({c.not_before?.slice(0,10)})</span></div>
                          ))}
                          {ct.result?.shodan_query&&<div style={{marginTop:8,fontFamily:"monospace",fontSize:10,color:C.cyan}}>Shodan: {ct.result.shodan_query}</div>}
                        </div>
                      ))}
                    </Panel>
                  )}
                  {report.blockchain?.length>0&&(
                    <Panel title="⬡ BLOCKCHAIN" color={C.orange}>
                      {report.blockchain.slice(0,1).map((b,i)=>(
                        <div key={i}>
                          {b.result?.error?<div style={{color:C.orange,fontSize:11}}>{b.result.error}</div>:b.result&&<>
                            <KV k="Balance" v={b.result.balance_btc+" BTC"} hi/>
                            <KV k="Transactions" v={b.result.transaction_count}/>
                            <KV k="First Seen" v={b.result.first_seen}/>
                            <KV k="Last Seen" v={b.result.last_seen}/>
                            <div style={{marginTop:8,display:"flex",gap:6,flexWrap:"wrap"}}>
                              {Object.entries(b.result.links||{}).map(([label,url])=>(
                                <a key={label} href={url} target="_blank" rel="noreferrer" style={{color:C.cyan,fontSize:9,border:`1px solid ${C.cyan}30`,padding:"3px 8px"}}>{label.toUpperCase()}</a>
                              ))}
                            </div>
                          </>}
                        </div>
                      ))}
                    </Panel>
                  )}
                </div>
              </div>
            )}
          </div>
        )}

        {/* ── IP INTELLIGENCE ── */}
        {tab==="ip"&&(
          <div>
            {ips.length>0?(
              <div>
                <div style={{display:"grid",gridTemplateColumns:"repeat(4,1fr)",gap:12,marginBottom:14}}>
                  {[
                    ["IPs FOUND",ips.length,C.cyan],
                    ["RESIDENTIAL",ips.filter(g=>g.success&&!g.is_proxy&&!g.is_hosting).length,C.green],
                    ["VPN / PROXY",ips.filter(g=>g.success&&g.is_proxy).length,C.red],
                    ["DATACENTER",ips.filter(g=>g.success&&g.is_hosting).length,C.orange],
                  ].map(([label,val,color])=>(
                    <div key={label} style={{padding:"12px 16px",border:`1px solid ${color}30`,background:`${color}06`}}>
                      <div style={{color:"#4a7a9b",fontSize:9,letterSpacing:1,marginBottom:4}}>{label}</div>
                      <div style={{color,fontSize:30,fontWeight:"bold",lineHeight:1}}>{val}</div>
                    </div>
                  ))}
                </div>
                {ips.map((g,i)=>(
                  <div key={i} style={{marginBottom:14,padding:16,border:`1px solid ${g.source?.includes("HEADER")?C.red:C.orange}30`,background:`${g.source?.includes("HEADER")?C.red:C.orange}05`}}>
                    {g.source?.includes("HEADER")&&<div style={{color:C.red,fontSize:10,fontWeight:"bold",marginBottom:8,padding:"4px 8px",background:`${C.red}15`,border:`1px solid ${C.red}30`}}>⚠ CRITICAL: REAL IP LEAK VIA X-Forwarded-For HEADER</div>}
                    {g.success?(
                      <div style={{display:"grid",gridTemplateColumns:"1fr 1fr 1fr",gap:16}}>
                        <div>
                          <div style={{color:"#fff",fontSize:16,fontFamily:"monospace",fontWeight:"bold",marginBottom:8}}>{g.ip}</div>
                          <KV k="Country" v={`${g.country} (${g.country_code})`} hi/>
                          <KV k="Region / State" v={g.region} hi/>
                          <KV k="City" v={g.city} hi/>
                          <KV k="Postal Code" v={g.postal}/>
                          <KV k="Timezone" v={g.timezone}/>
                          <KV k="Coordinates" v={`${g.lat}, ${g.lon}`} hi mono/>
                        </div>
                        <div>
                          <KV k="ISP" v={g.isp} hi/>
                          <KV k="Organization" v={g.org}/>
                          <KV k="ASN" v={g.asn} mono/>
                          <KV k="ASN Name" v={g.asn_name}/>
                          <div style={{marginTop:10}}>
                            {g.is_proxy&&<div style={{color:C.red,fontSize:11,padding:"4px 8px",background:`${C.red}10`,border:`1px solid ${C.red}30`,marginBottom:4}}>⚠ VPN / PROXY DETECTED — this is a known proxy/VPN exit node</div>}
                            {g.is_hosting&&<div style={{color:C.orange,fontSize:11,padding:"4px 8px",background:`${C.orange}10`,border:`1px solid ${C.orange}30`,marginBottom:4}}>⚠ HOSTING / DATACENTER — VPS or cloud server, not residential</div>}
                            {!g.is_proxy&&!g.is_hosting&&<div style={{color:C.green,fontSize:11,padding:"4px 8px",background:`${C.green}10`,border:`1px solid ${C.green}30`}}>✓ RESIDENTIAL ISP — direct subscriber identity request</div>}
                          </div>
                        </div>
                        <div>
                          <div style={{color:"#4a7a9b",fontSize:9,letterSpacing:1,marginBottom:8}}>INVESTIGATION NOTES</div>
                          {g.investigation_notes?.map((note,j)=>(
                            <div key={j} style={{color:C.text,fontSize:11,padding:"5px 8px",borderBottom:"1px solid rgba(255,255,255,0.04)",lineHeight:1.5}}>{note}</div>
                          ))}
                          <div style={{marginTop:12,display:"flex",gap:8,flexWrap:"wrap"}}>
                            <a href={g.google_maps_url} target="_blank" rel="noreferrer" style={{color:C.cyan,fontSize:10,border:`1px solid ${C.cyan}30`,padding:"4px 10px"}}>⊕ Google Maps</a>
                            <a href={`https://www.shodan.io/host/${g.ip}`} target="_blank" rel="noreferrer" style={{color:C.cyan,fontSize:10,border:`1px solid ${C.cyan}30`,padding:"4px 10px"}}>⊕ Shodan</a>
                            <a href={`https://viz.greynoise.io/ip/${g.ip}`} target="_blank" rel="noreferrer" style={{color:C.cyan,fontSize:10,border:`1px solid ${C.cyan}30`,padding:"4px 10px"}}>⊕ GreyNoise</a>
                            <a href={`https://www.abuseipdb.com/check/${g.ip}`} target="_blank" rel="noreferrer" style={{color:C.cyan,fontSize:10,border:`1px solid ${C.cyan}30`,padding:"4px 10px"}}>⊕ AbuseIPDB</a>
                          </div>
                          <div style={{marginTop:10,padding:8,background:"rgba(0,200,255,0.05)",border:`1px solid ${C.cyan}15`,color:"#4a7a9b",fontSize:10,lineHeight:1.6}}>Source: {g.source}</div>
                        </div>
                      </div>
                    ):<div style={{color:C.red,fontSize:11}}>Geolocation failed: {g.error}</div>}
                  </div>
                ))}
              </div>
            ):<div style={{padding:"40px 0",textAlign:"center",color:"#4a7a9b"}}>No IP addresses extracted. Run a scan first.</div>}
          </div>
        )}

        {/* ── ATTRIBUTION GRAPH ── */}
        {tab==="graph"&&(
          <div>
            {report?.attribution_graph?(
              <div>
                <div style={{display:"grid",gridTemplateColumns:"repeat(4,1fr)",gap:12,marginBottom:14}}>
                  {[["NODES",report.attribution_graph.stats?.total_nodes,C.cyan],["EDGES",report.attribution_graph.stats?.total_edges,C.green],["CRITICAL",report.attribution_graph.stats?.critical_nodes,C.red],["HIGH-VALUE PATHS",report.attribution_graph.high_value_paths?.length,C.orange]].map(([l,v,c])=>(
                    <div key={l} style={{padding:"12px 16px",border:`1px solid ${c}30`,background:`${c}06`}}>
                      <div style={{color:"#4a7a9b",fontSize:9,letterSpacing:1,marginBottom:4}}>{l}</div>
                      <div style={{color:c,fontSize:28,fontWeight:"bold",lineHeight:1}}>{v||0}</div>
                    </div>
                  ))}
                </div>
                <div style={{marginBottom:12,display:"flex",gap:8,flexWrap:"wrap",alignItems:"center"}}>
                  {Object.entries(NODE_C).slice(0,12).map(([type,color])=>(
                    <div key={type} style={{display:"flex",alignItems:"center",gap:4,fontSize:9,color:C.text}}>
                      <span style={{display:"inline-block",width:9,height:9,borderRadius:"50%",background:color,border:`1px solid ${color}`}}/>
                      {type.replace(/_/g," ")}
                    </div>
                  ))}
                  <span style={{color:"#4a7a9b",fontSize:9,marginLeft:8}}>· Drag · Scroll=zoom · Hover=details</span>
                </div>
                <div style={{border:`1px solid ${C.border}`,borderRadius:2,overflow:"hidden"}}>
                  <AttributionGraph graphData={report.attribution_graph}/>
                </div>
                {report.attribution_graph.high_value_paths?.length>0&&(
                  <Panel title="⬡ HIGH-VALUE EVIDENCE CHAINS" color={C.red} status="direct attribution paths">
                    {report.attribution_graph.high_value_paths.map((e,i)=>(
                      <div key={i} style={{padding:"8px 12px",border:`1px solid ${C.red}18`,background:`${C.red}03`,marginBottom:5,fontSize:11}}>
                        <span style={{color:C.red}}>{typeof e.source==="object"?e.source.label:e.source}</span>
                        <span style={{color:"#4a7a9b"}}> →[{e.relation}]→ </span>
                        <span style={{color:C.orange}}>{typeof e.target==="object"?e.target.label:e.target}</span>
                        <Badge risk={e.confidence}/>
                      </div>
                    ))}
                  </Panel>
                )}
              </div>
            ):<div style={{padding:"40px 0",textAlign:"center",color:"#4a7a9b"}}>Run a scan to generate the attribution graph.</div>}
          </div>
        )}

        {/* ── IDENTITY CORRELATION ── */}
        {tab==="correlation"&&(
          <div>
            {report?.correlation?(
              <div style={{display:"flex",flexDirection:"column",gap:14}}>
                {report.correlation.github?.length>0&&(
                  <Panel title={`⬡ GITHUB — ${report.correlation.github.length} PROFILE(S) FOUND`} color={C.text}>
                    {report.correlation.github.map((gh,i)=>(
                      <div key={i} style={{marginBottom:12,padding:12,border:"1px solid rgba(224,224,224,0.15)",background:"rgba(224,224,224,0.03)"}}>
                        <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:16}}>
                          <div>
                            <div style={{color:"#fff",fontSize:13,fontWeight:"bold",marginBottom:8}}>{gh.username||gh.matches?.[0]?.login}</div>
                            <KV k="Source Artifact" v={gh.source_artifact} mono hi/>
                            <KV k="Display Name" v={gh.display_name||"—"} hi={!!gh.display_name}/>
                            <KV k="Email (public)" v={gh.email||"—"} hi={!!gh.email}/>
                            <KV k="Location" v={gh.location||"—"} hi={!!gh.location}/>
                            <KV k="Company" v={gh.company||"—"}/>
                            <KV k="Public Repos" v={gh.public_repos}/>
                            <KV k="Account Created" v={gh.created_at}/>
                          </div>
                          <div>
                            {gh.bio&&<div style={{color:C.text,fontSize:11,padding:8,background:"rgba(255,255,255,0.03)",border:"1px solid rgba(255,255,255,0.06)",marginBottom:10,lineHeight:1.6}}>{gh.bio}</div>}
                            {gh.pii_found?.length>0&&<div style={{padding:8,background:`${C.red}08`,border:`1px solid ${C.red}25`,color:C.red,fontSize:10,marginBottom:8}}>⚠ REAL PII FOUND: {gh.pii_found.join(" | ")}</div>}
                            <div style={{display:"flex",gap:6,flexWrap:"wrap"}}>
                              <a href={gh.profile_url} target="_blank" rel="noreferrer" style={{color:C.cyan,fontSize:10,border:`1px solid ${C.cyan}30`,padding:"4px 10px"}}>⬡ GitHub Profile</a>
                            </div>
                            <div style={{marginTop:8,padding:6,background:"rgba(0,200,255,0.05)",border:`1px solid ${C.cyan}10`,color:"#4a7a9b",fontSize:10}}>Confidence: <span style={{color:C.green}}>{gh.confidence}</span></div>
                          </div>
                        </div>
                      </div>
                    ))}
                  </Panel>
                )}
                {report.correlation.reddit?.length>0&&(
                  <Panel title={`⬡ REDDIT — ${report.correlation.reddit.length} PROFILE(S) FOUND`} color="#ff4500">
                    {report.correlation.reddit.map((rd,i)=>(
                      <div key={i} style={{marginBottom:8,padding:12,border:"1px solid rgba(255,69,0,0.2)",background:"rgba(255,69,0,0.04)"}}>
                        <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:12}}>
                          <div>
                            <KV k="Username" v={rd.username} mono hi/>
                            <KV k="Source Artifact" v={rd.source_artifact} mono/>
                            <KV k="Total Karma" v={rd.karma} hi/>
                            <KV k="Comment Karma" v={rd.comment_karma}/>
                            <KV k="Account Created" v={rd.created_at} hi/>
                            <KV k="Moderator" v={rd.is_mod?"YES — check moderated subs":"No"}/>
                          </div>
                          <div>
                            <a href={rd.profile_url} target="_blank" rel="noreferrer" style={{display:"inline-block",color:"#ff4500",fontSize:10,border:"1px solid rgba(255,69,0,0.3)",padding:"4px 10px",marginBottom:8}}>⬡ Reddit Profile</a>
                            <div style={{color:"#4a7a9b",fontSize:10,lineHeight:1.5}}>Review post/comment history for location clues, writing patterns, other usernames, timestamps</div>
                          </div>
                        </div>
                      </div>
                    ))}
                  </Panel>
                )}
                {report.correlation.pgp_keyserver?.length>0&&(
                  <Panel title={`⬡ PGP KEYSERVER — ${report.correlation.pgp_keyserver.length} KEY(S) FOUND`} color={C.green}>
                    {report.correlation.pgp_keyserver.map((pgp,i)=>(
                      <div key={i} style={{marginBottom:10,padding:12,border:`1px solid ${C.green}20`,background:`${C.green}04`}}>
                        <KV k="Source" v={pgp.source_artifact} mono hi/>
                        <KV k="Keys Found" v={pgp.keys_found} hi/>
                        {pgp.keys?.map((k,j)=>(
                          <div key={j} style={{marginTop:8,padding:8,background:`${C.green}04`,border:`1px solid ${C.green}12`}}>
                            <KV k="Fingerprint" v={k.fingerprint} mono/>
                            <KV k="Identity String" v={k.identity} hi={!!k.email_in_key}/>
                            {k.email_in_key&&<div style={{marginTop:6,padding:6,background:`${C.red}10`,border:`1px solid ${C.red}30`,color:C.red,fontSize:11}}>⚠ REAL EMAIL IN KEY: {k.email_in_key}</div>}
                            <KV k="Created" v={k.created}/>
                            <KV k="Algorithm" v={k.algorithm}/>
                          </div>
                        ))}
                      </div>
                    ))}
                  </Panel>
                )}
                {report.correlation.wallet_labels?.filter(w=>w.found).length>0&&(
                  <Panel title="⬡ BITCOIN WALLET LABELS — Exchange Identification" color={C.orange}>
                    {report.correlation.wallet_labels.filter(w=>w.found).map((w,i)=>(
                      <div key={i} style={{marginBottom:8,padding:12,border:`1px solid ${C.orange}20`,background:`${C.orange}04`}}>
                        <KV k="Address" v={w.address} mono/>
                        <KV k="Exchange / Label" v={w.label} hi={!!w.label}/>
                        <KV k="Is Known Exchange" v={w.is_exchange?"YES — submit legal process for KYC records":"No known exchange label"} hi={w.is_exchange}/>
                        {w.is_exchange&&<div style={{marginTop:8,padding:8,background:`${C.red}08`,border:`1px solid ${C.red}20`,color:C.red,fontSize:10}}>{w.legal_note}</div>}
                      </div>
                    ))}
                  </Panel>
                )}
                {report.correlation.google_dorks?.length>0&&(
                  <Panel title="⬡ GOOGLE DORKS — Copy & Run Manually" color={C.yellow} status={`${report.correlation.google_dorks.length} artifact(s)`}>
                    {report.correlation.google_dorks.map((dg,i)=>(
                      <div key={i} style={{marginBottom:14}}>
                        <div style={{color:C.yellow,fontSize:11,marginBottom:6}}>{dg.type.toUpperCase()}: <span style={{fontFamily:"monospace",color:"#fff"}}>{dg.artifact}</span></div>
                        {dg.queries?.map((q,j)=>(
                          <div key={j} style={{display:"flex",justifyContent:"space-between",padding:"4px 8px",borderBottom:"1px solid rgba(255,204,0,0.08)",gap:12}}>
                            <span style={{fontFamily:"Courier New,monospace",fontSize:10,color:C.text,wordBreak:"break-all"}}>{q.query}</span>
                            <a href={q.url} target="_blank" rel="noreferrer" style={{color:C.cyan,fontSize:9,whiteSpace:"nowrap"}}>SEARCH →</a>
                          </div>
                        ))}
                      </div>
                    ))}
                  </Panel>
                )}
              </div>
            ):<div style={{padding:"40px 0",textAlign:"center",color:"#4a7a9b"}}>Run a scan to see identity correlation.</div>}
          </div>
        )}

        {/* ── INFRASTRUCTURE ── */}
        {tab==="infra"&&(
          <div>
            {report?.infra_fingerprint?(
              <div style={{display:"flex",flexDirection:"column",gap:14}}>
                {Object.keys(report.infra_fingerprint.analytics_ids||{}).length>0&&(
                  <Panel title="⚠ ANALYTICS / TRACKING IDs — CRITICAL LEADS" color={C.red}>
                    {Object.entries(report.infra_fingerprint.analytics_ids).map(([cat,items])=>
                      items.map((item,i)=>(
                        <div key={`${cat}-${i}`} style={{marginBottom:10,padding:12,border:`1px solid ${C.red}30`,background:`${C.red}06`}}>
                          <div style={{display:"flex",justifyContent:"space-between",marginBottom:6}}>
                            <span style={{color:C.red,fontSize:12,fontWeight:"bold"}}>{cat.replace(/_/g," ").toUpperCase()}: {item.id}</span>
                            <Badge risk="CRITICAL"/>
                          </div>
                          <div style={{color:C.text,fontSize:11,marginBottom:6}}>{item.note}</div>
                          {item.shodan&&<div style={{fontFamily:"monospace",fontSize:10,color:C.cyan,padding:"4px 8px",background:"rgba(0,200,255,0.05)",border:"1px solid rgba(0,200,255,0.15)",marginBottom:4}}>Shodan: {item.shodan}</div>}
                          {item.dork&&<div style={{fontFamily:"monospace",fontSize:10,color:C.yellow,padding:"4px 8px",background:"rgba(255,204,0,0.05)",border:"1px solid rgba(255,204,0,0.15)",marginBottom:4}}>Google: "{item.dork}"</div>}
                          {item.fb_ads&&<a href={item.fb_ads} target="_blank" rel="noreferrer" style={{display:"block",color:C.cyan,fontSize:10,marginTop:4}}>→ Facebook Ads Library</a>}
                        </div>
                      ))
                    )}
                  </Panel>
                )}
                {report.infra_fingerprint.favicon?.found&&(
                  <Panel title="⬡ FAVICON HASH — Shodan Correlation" color={C.yellow}>
                    <KV k="MurmurHash3" v={report.infra_fingerprint.favicon.hash} mono hi/>
                    <KV k="MD5" v={report.infra_fingerprint.favicon.md5} mono/>
                    <KV k="Size" v={report.infra_fingerprint.favicon.size_bytes+" bytes"}/>
                    <div style={{marginTop:10,padding:8,background:"rgba(255,204,0,0.05)",border:`1px solid ${C.yellow}18`}}>
                      <div style={{color:C.yellow,fontFamily:"monospace",fontSize:11,marginBottom:4}}>{report.infra_fingerprint.favicon.shodan_query}</div>
                      <a href={report.infra_fingerprint.favicon.shodan_url} target="_blank" rel="noreferrer" style={{color:C.cyan,fontSize:10}}>→ Open in Shodan</a>
                    </div>
                    <div style={{marginTop:8,color:"#4a7a9b",fontSize:10,lineHeight:1.5}}>{report.infra_fingerprint.favicon.note}</div>
                  </Panel>
                )}
                {report.infra_fingerprint.cdn_detection?.length>0&&(
                  <Panel title="⬡ CDN / PROXY DETECTION" color={C.orange}>
                    {report.infra_fingerprint.cdn_detection.map((cdn,i)=>(
                      <div key={i} style={{padding:"8px 12px",border:`1px solid ${C.orange}20`,marginBottom:6}}>
                        <div style={{color:C.orange,fontSize:12,marginBottom:3}}>{cdn.cdn}</div>
                        <div style={{color:C.text,fontSize:11}}>{cdn.note}</div>
                      </div>
                    ))}
                  </Panel>
                )}
                {report.infra_fingerprint.js_libraries&&(
                  <Panel title="⬡ JAVASCRIPT FINGERPRINT — Cross-Site Matching" color={C.purple}>
                    <KV k="Script Fingerprint" v={report.infra_fingerprint.js_libraries.fingerprint} mono hi/>
                    <div style={{color:"#4a7a9b",fontSize:10,marginTop:4,marginBottom:10}}>Same hash across multiple onion sites = same operator / template</div>
                    {report.infra_fingerprint.js_libraries.detected?.length>0&&(
                      <>
                        <div style={{color:"#4a7a9b",fontSize:9,letterSpacing:1,marginBottom:6}}>LIBRARIES DETECTED</div>
                        {report.infra_fingerprint.js_libraries.detected.map((lib,i)=>(
                          <div key={i} style={{color:C.text,fontSize:11,padding:"2px 0",borderBottom:"1px solid rgba(255,255,255,0.04)"}}>{lib.library} <span style={{color:C.purple}}>v{lib.version}</span></div>
                        ))}
                      </>
                    )}
                    {report.infra_fingerprint.js_libraries.external_scripts?.length>0&&(
                      <>
                        <div style={{color:"#4a7a9b",fontSize:9,letterSpacing:1,marginBottom:4,marginTop:10}}>EXTERNAL SCRIPT SOURCES (CRITICAL)</div>
                        {report.infra_fingerprint.js_libraries.external_scripts.map((src,i)=>(
                          <div key={i} style={{color:C.red,fontSize:10,padding:"2px 0",fontFamily:"monospace",wordBreak:"break-all"}}>→ {src}</div>
                        ))}
                      </>
                    )}
                  </Panel>
                )}
                {report.infra_fingerprint.cross_site_indicators?.length>0&&(
                  <Panel title="⬡ CROSS-SITE CORRELATION INDICATORS" color={C.cyan}>
                    {report.infra_fingerprint.cross_site_indicators.map((ind,i)=>(
                      <div key={i} style={{marginBottom:10,padding:12,border:`1px solid ${C.cyan}20`,background:`${C.cyan}04`}}>
                        <div style={{color:C.cyan,fontSize:11,fontWeight:"bold",marginBottom:6}}>{ind.type}: {ind.value}</div>
                        <div style={{color:C.text,fontSize:11,marginBottom:6}}>{ind.action}</div>
                        {ind.shodan&&<div style={{fontFamily:"monospace",fontSize:10,color:C.yellow,padding:"3px 8px",background:"rgba(255,204,0,0.04)"}}>{ind.shodan}</div>}
                        {ind.shodan_url&&<a href={ind.shodan_url} target="_blank" rel="noreferrer" style={{display:"block",color:C.cyan,fontSize:10,marginTop:4}}>→ Search on Shodan</a>}
                      </div>
                    ))}
                  </Panel>
                )}
              </div>
            ):<div style={{padding:"40px 0",textAlign:"center",color:"#4a7a9b"}}>Run a scan to see infrastructure fingerprinting.</div>}
          </div>
        )}

        {/* ── LOG ── */}
        {tab==="terminal"&&(
          <div>
            <div style={{color:C.cyan,fontSize:11,letterSpacing:2,marginBottom:10}}>⬡ OPERATION LOG — UMBRA V3</div>
            <div ref={logRef} style={{background:"rgba(0,0,0,0.9)",border:`1px solid ${C.border}`,padding:14,height:"68vh",overflowY:"auto",fontFamily:"Courier New,monospace",fontSize:12}}>
              {logs.length===0&&<div style={{color:"#2a4a6b"}}>[UMBRA V3] Initialized. Run a scan to see operation log.</div>}
              {logs.map((l,i)=><div key={i} style={{color:l.color,padding:"2px 0",lineHeight:1.5}}><span style={{color:"#1a3050",marginRight:10}}>{l.t}</span>{l.msg}</div>)}
              <div style={{color:C.cyan}}>█</div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}