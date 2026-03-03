import { useState, useMemo, useRef, useEffect } from "react";

const DICTIONARY = new Set([
  "password","password1","password123","123456","12345678","1234567890","qwerty","qwerty123",
  "abc123","letmein","monkey","1234567","111111","dragon","master","sunshine","princess",
  "welcome","shadow","superman","michael","football","baseball","iloveyou","trustno1",
  "hello","charlie","donald","password2","qwertyuiop","123456789","696969","starwars",
  "123123","login","admin","admin123","root","toor","pass","test","guest","user",
  "default","changeme","secret","1q2w3e4r","zxcvbnm","asdfghjkl","passw0rd","p@ssword",
  "p@ssw0rd","pass123","pass1234","welcome1","welcome123","letmein1","qwerty1","abc1234",
  "baseball1","basketball","jordan23","ranger","hockey","soccer","golfer","harley",
  "butter","cheese","milk","coffee","cookie","batman","superman1","spiderman","pokemon",
  "pikachu","naruto","iphone","samsung","google","facebook","twitter","instagram","amazon",
  "spring","summer","winter","autumn","january","february","march","april","monday","friday",
  "london","paris","india","china","japan","korea","russia","brazil","mexico","canada",
  "matrix","killer","hunter","silver","thunder","rainbow","flower","love123","angel","devil",
  "fire","water","storm","ocean","mountain","forest","happy","sad","angry","bored",
  "asdf","zxcv","qwer","1111","2222","3333","4444","5555","6666","7777","8888","9999","0000",
  "11111","22222","55555","99999","112233","123321","654321","321321","000000","999999",
  "aaaaaa","bbbbbb","abcabc","abcdef","qazwsx","edcrfv","tgbyhn","pass@123","Pass@123",
]);

const FACTS = [
  { icon: "🏆", stat: "Most common password", value: '"123456"', sub: "used by 23 million accounts" },
  { icon: "📏", stat: "Average password length", value: "8 chars", sub: "experts recommend 16+" },
  { icon: "💥", stat: "Passwords exposed in 2023", value: "8.2 billion", sub: "across data breaches" },
  { icon: "⚡", stat: "Brute-force speed (GPU)", value: "10 billion/sec", sub: "for simple hashes" },
  { icon: "♻️", stat: "People reuse passwords", value: "65%", sub: "across multiple sites" },
  { icon: "🎯", stat: "Attacks use dictionary first", value: "91%", sub: "of all credential attacks" },
  { icon: "🔐", stat: "MFA blocks attacks", value: "99.9%", sub: "of automated attacks" },
  { icon: "🕒", stat: "8-char lowercase cracked", value: "< 1 sec", sub: "with modern hardware" },
  { icon: "🌍", stat: "Data breaches in 2023", value: "3,205", sub: "publicly disclosed" },
  { icon: "🧠", stat: "People use pet names", value: "1 in 3", sub: "in their passwords" },
  { icon: "📧", stat: "Credentials on dark web", value: "24 billion+", sub: "username/password pairs" },
  { icon: "🛡️", stat: "Strong password survives", value: "Centuries", sub: "16+ char random passwords" },
];

const PATTERNS = [
  { test: p => /(.)\1{2,}/.test(p), label: "Repeated chars" },
  { test: p => /012|123|234|345|456|567|678|789|890|abc|bcd|cde/i.test(p), label: "Sequential pattern" },
  { test: p => /^[a-z]+$/i.test(p), label: "Letters only" },
  { test: p => /^\d+$/.test(p), label: "Numbers only" },
  { test: p => /^[A-Z][a-z]+\d{1,4}$/.test(p), label: "Word + number" },
];

// Line colors for each password in history
const LINE_COLORS = ["#818cf8","#f472b6","#34d399","#fbbf24","#60a5fa","#a78bfa","#fb923c","#4ade80","#e879f9","#38bdf8","#f87171","#facc15"];

function analyze(pwd) {
  if (!pwd) return null;
  const lower = pwd.toLowerCase();
  const inDict = DICTIONARY.has(lower);
  const len = pwd.length;
  const hasL = /[a-z]/.test(pwd), hasU = /[A-Z]/.test(pwd);
  const hasD = /\d/.test(pwd), hasS = /[^a-zA-Z0-9]/.test(pwd);
  let charset = 0;
  if (hasL) charset += 26; if (hasU) charset += 26;
  if (hasD) charset += 10; if (hasS) charset += 32;
  const entropy = charset > 0 ? len * Math.log2(charset) : 0;
  const detected = PATTERNS.filter(p => p.test(pwd)).map(p => p.label);
  if (inDict) detected.unshift("Found in dictionary");

  let score = 0;
  score += Math.min(len * 3, 30);
  if (hasL) score += 10; if (hasU) score += 10;
  if (hasD) score += 10; if (hasS) score += 20;
  if (len >= 12) score += 10; if (len >= 16) score += 10;
  score -= detected.length * 10;
  if (inDict) score -= 50;
  score = Math.max(0, Math.min(100, score));

  const strength = inDict ? "Very Weak" : score >= 70 ? "Strong" : score >= 40 ? "Medium" : "Weak";

  const gps = 1e10, combos = Math.pow(Math.max(charset,1), len), secs = combos / (2 * gps);
  const crackTime = inDict || secs < 1 ? "Instantly"
    : secs < 60 ? `${Math.round(secs)}s`
    : secs < 3600 ? `${Math.round(secs/60)} min`
    : secs < 86400 ? `${Math.round(secs/3600)} hrs`
    : secs < 31536000 ? `${Math.round(secs/86400)} days`
    : secs < 3.154e9 ? `${Math.round(secs/31536000)} yrs`
    : secs < 3.154e12 ? `${Math.round(secs/3.154e9)}K yrs`
    : "Centuries+";

  const bruteForce = secs < 1 ? { label:"Vulnerable", color:"#ef4444", icon:"🔴" }
    : secs < 86400 ? { label:"At Risk", color:"#f97316", icon:"🟠" }
    : secs < 3.154e9 ? { label:"Moderate", color:"#facc15", icon:"🟡" }
    : { label:"Resistant", color:"#34d399", icon:"🟢" };
  const dictionary = inDict ? { label:"Vulnerable", color:"#ef4444", icon:"🔴" }
    : detected.length >= 2 ? { label:"Possible", color:"#f97316", icon:"🟠" }
    : detected.length === 1 ? { label:"Low Risk", color:"#facc15", icon:"🟡" }
    : { label:"Safe", color:"#34d399", icon:"🟢" };
  const hybrid = (inDict || detected.length >= 2) ? { label:"Vulnerable", color:"#ef4444", icon:"🔴" }
    : (!hasS || !hasU || len < 10) ? { label:"Possible", color:"#f97316", icon:"🟠" }
    : len < 14 ? { label:"Low Risk", color:"#facc15", icon:"🟡" }
    : { label:"Safe", color:"#34d399", icon:"🟢" };
  const rainbow = (!hasS && !hasU) ? { label:"Vulnerable", color:"#ef4444", icon:"🔴" }
    : (!hasS || !hasU) ? { label:"Possible", color:"#f97316", icon:"🟠" }
    : entropy < 40 ? { label:"Low Risk", color:"#facc15", icon:"🟡" }
    : { label:"Safe", color:"#34d399", icon:"🟢" };

  const charTypes = [hasL,hasU,hasD,hasS].filter(Boolean).length;
  const radar = {
    Complexity: Math.min(100, charTypes * 22 + (hasS ? 12 : 0)),
    Length: Math.min(100, Math.round((len / 20) * 100)),
    Entropy: Math.min(100, Math.round((entropy / 80) * 100)),
    Predictability: Math.max(0, 100 - (detected.length * 25) - (inDict ? 60 : 0)),
    "Dict Safety": inDict ? 0 : Math.max(0, 100 - detected.length * 20),
  };

  const suggestions = [];
  if (inDict) suggestions.push("Remove — it's in every attacker's wordlist");
  if (len < 12) suggestions.push("Use at least 12 characters");
  if (!hasU) suggestions.push("Add uppercase letters (A–Z)");
  if (!hasL) suggestions.push("Add lowercase letters (a–z)");
  if (!hasD) suggestions.push("Include numbers (0–9)");
  if (!hasS) suggestions.push("Add special characters (!@#$%...)");
  if (detected.some(d => d.includes("Repeated"))) suggestions.push("Avoid repeated characters");
  if (detected.some(d => d.includes("Sequential"))) suggestions.push("Avoid sequential patterns");
  if (suggestions.length === 0) suggestions.push("Excellent — store it in a password manager!");

  return { score, strength, crackTime, entropy: Math.round(entropy), detected,
    suggestions, inDict, hasL, hasU, hasD, hasS, radar,
    attacks: { bruteForce, dictionary, hybrid, rainbow } };
}

const SC = {
  "Very Weak": { fill:"#ef4444", text:"#fca5a5", border:"rgba(239,68,68,0.4)", bg:"rgba(239,68,68,0.08)" },
  Weak:        { fill:"#f97316", text:"#fdba74", border:"rgba(249,115,22,0.4)", bg:"rgba(249,115,22,0.08)" },
  Medium:      { fill:"#facc15", text:"#fde047", border:"rgba(250,204,21,0.4)", bg:"rgba(250,204,21,0.08)" },
  Strong:      { fill:"#34d399", text:"#6ee7b7", border:"rgba(52,211,153,0.4)", bg:"rgba(52,211,153,0.08)" },
};

// ── Radar Chart ──────────────────────────────────────────────────────────────
function RadarChart({ data, color }) {
  const canvasRef = useRef();
  useEffect(() => {
    const canvas = canvasRef.current; if (!canvas) return;
    const ctx = canvas.getContext("2d");
    const W = canvas.width, H = canvas.height;
    ctx.clearRect(0, 0, W, H);
    const cx = W/2, cy = H/2, R = Math.min(W,H)/2 - 36;
    const keys = Object.keys(data), vals = Object.values(data), N = keys.length;
    const angle = i => (Math.PI*2*i)/N - Math.PI/2;
    [0.25,0.5,0.75,1].forEach(t => {
      ctx.beginPath();
      keys.forEach((_,i) => { const a=angle(i),x=cx+R*t*Math.cos(a),y=cy+R*t*Math.sin(a); i===0?ctx.moveTo(x,y):ctx.lineTo(x,y); });
      ctx.closePath(); ctx.strokeStyle=t===1?"rgba(255,255,255,0.12)":"rgba(255,255,255,0.05)"; ctx.lineWidth=1; ctx.stroke();
    });
    keys.forEach((_,i) => { const a=angle(i); ctx.beginPath(); ctx.moveTo(cx,cy); ctx.lineTo(cx+R*Math.cos(a),cy+R*Math.sin(a)); ctx.strokeStyle="rgba(255,255,255,0.08)"; ctx.lineWidth=1; ctx.stroke(); });
    ctx.beginPath();
    vals.forEach((v,i) => { const a=angle(i),r=(v/100)*R,x=cx+r*Math.cos(a),y=cy+r*Math.sin(a); i===0?ctx.moveTo(x,y):ctx.lineTo(x,y); });
    ctx.closePath();
    const grad=ctx.createRadialGradient(cx,cy,0,cx,cy,R);
    grad.addColorStop(0,color+"55"); grad.addColorStop(1,color+"22");
    ctx.fillStyle=grad; ctx.fill(); ctx.strokeStyle=color; ctx.lineWidth=2; ctx.stroke();
    vals.forEach((v,i) => { const a=angle(i),r=(v/100)*R,x=cx+r*Math.cos(a),y=cy+r*Math.sin(a); ctx.beginPath(); ctx.arc(x,y,4,0,Math.PI*2); ctx.fillStyle=color; ctx.fill(); ctx.strokeStyle="#030712"; ctx.lineWidth=2; ctx.stroke(); });
    keys.forEach((k,i) => { const a=angle(i),lx=cx+(R+22)*Math.cos(a),ly=cy+(R+22)*Math.sin(a); ctx.fillStyle="#9ca3af"; ctx.font="bold 10px system-ui"; ctx.textAlign=Math.abs(Math.cos(a))<0.1?"center":Math.cos(a)>0?"left":"right"; ctx.textBaseline=Math.abs(Math.sin(a))<0.1?"middle":Math.sin(a)>0?"top":"bottom"; ctx.fillText(k,lx,ly); const r2=(vals[i]/100)*R,vx=cx+r2*Math.cos(a),vy=cy+r2*Math.sin(a); ctx.fillStyle=color; ctx.font="bold 9px system-ui"; ctx.textAlign="center"; ctx.textBaseline="middle"; ctx.fillText(vals[i],vx+Math.cos(a)*14,vy+Math.sin(a)*14); });
  }, [data, color]);
  return <canvas ref={canvasRef} width={260} height={260} style={{ width:"100%", maxWidth:260, display:"block", margin:"0 auto" }} />;
}

// ── Multi-line comparison chart ──────────────────────────────────────────────
function ComparisonChart({ history, metrics, selectedMetric }) {
  const canvasRef = useRef();
  useEffect(() => {
    const canvas = canvasRef.current; if (!canvas || history.length === 0) return;
    const ctx = canvas.getContext("2d");
    const W = canvas.width, H = canvas.height;
    ctx.clearRect(0, 0, W, H);
    const padL=44, padR=16, padT=16, padB=52;
    const chartW = W-padL-padR, chartH = H-padT-padB;

    // Background grid
    const gridLines = [0,25,50,75,100];
    gridLines.forEach(v => {
      const y = padT + chartH - (v/100)*chartH;
      ctx.strokeStyle = v===0||v===100 ? "rgba(255,255,255,0.1)" : "rgba(255,255,255,0.04)";
      ctx.lineWidth=1; ctx.setLineDash([4,4]);
      ctx.beginPath(); ctx.moveTo(padL,y); ctx.lineTo(padL+chartW,y); ctx.stroke();
      ctx.setLineDash([]);
      ctx.fillStyle="#4b5563"; ctx.font="10px system-ui"; ctx.textAlign="right"; ctx.textBaseline="middle";
      ctx.fillText(v, padL-6, y);
    });

    // X axis line
    ctx.strokeStyle="rgba(255,255,255,0.1)"; ctx.lineWidth=1;
    ctx.beginPath(); ctx.moveTo(padL,padT+chartH); ctx.lineTo(padL+chartW,padT+chartH); ctx.stroke();

    // Vertical gridlines
    const N = history.length;
    if (N > 1) {
      for (let i=0;i<N;i++) {
        const x = padL + (i/(N-1))*chartW;
        ctx.strokeStyle="rgba(255,255,255,0.03)"; ctx.lineWidth=1;
        ctx.beginPath(); ctx.moveTo(x,padT); ctx.lineTo(x,padT+chartH); ctx.stroke();
      }
    }

    // Get metric values per password
    const getVal = (h, m) => {
      if (m==="Score") return h.score;
      if (m==="Entropy") return Math.min(100, Math.round((h.entropy/80)*100));
      if (m==="Length") return Math.min(100, Math.round((h.pwd.length/20)*100));
      if (m==="Complexity") return h.radar?.Complexity||0;
      if (m==="Predictability") return h.radar?.Predictability||0;
      return h.score;
    };

   
    // Drawing handled below in the N===1 / else branches
    // ── Mode: x-axis = passwords, y = selected metric value ──
    if (N === 1) {
      // Single dot
      const val = getVal(history[0], selectedMetric);
      const x = padL + chartW/2;
      const y = padT + chartH - (val/100)*chartH;
      const col = LINE_COLORS[0];
      ctx.beginPath(); ctx.arc(x,y,6,0,Math.PI*2); ctx.fillStyle=col; ctx.fill();
      ctx.strokeStyle="#030712"; ctx.lineWidth=2; ctx.stroke();
      ctx.fillStyle=col; ctx.font="bold 11px system-ui"; ctx.textAlign="center"; ctx.textBaseline="bottom";
      ctx.fillText(val, x, y-8);
    } else {
      // Each password = a line across all metrics
      // x-axis = metric index, draw one line per password
      const M = metrics.length;
      history.forEach((h, hi) => {
        const color = LINE_COLORS[hi % LINE_COLORS.length];
        const pts = metrics.map((m,mi) => ({
          x: padL + (mi/(M-1))*chartW,
          y: padT + chartH - (getVal(h,m)/100)*chartH,
          val: getVal(h,m)
        }));

        // Gradient line
        const grad = ctx.createLinearGradient(pts[0].x, 0, pts[M-1].x, 0);
        grad.addColorStop(0, color+"cc"); grad.addColorStop(1, color);

        // Draw filled area
        ctx.beginPath();
        pts.forEach((p,i) => i===0?ctx.moveTo(p.x,p.y):ctx.lineTo(p.x,p.y));
        ctx.lineTo(pts[M-1].x, padT+chartH); ctx.lineTo(pts[0].x, padT+chartH);
        ctx.closePath();
        ctx.fillStyle=color+"18"; ctx.fill();

        // Draw line
        ctx.beginPath();
        pts.forEach((p,i) => i===0?ctx.moveTo(p.x,p.y):ctx.lineTo(p.x,p.y));
        ctx.strokeStyle=color; ctx.lineWidth=2.5; ctx.lineJoin="round"; ctx.stroke();

        // Dots + values
        pts.forEach(p => {
          ctx.beginPath(); ctx.arc(p.x,p.y,4,0,Math.PI*2); ctx.fillStyle=color; ctx.fill();
          ctx.strokeStyle="#030712"; ctx.lineWidth=2; ctx.stroke();
          ctx.fillStyle=color; ctx.font="bold 9px system-ui"; ctx.textAlign="center"; ctx.textBaseline="bottom";
          ctx.fillText(p.val, p.x, p.y-7);
        });
      });

      // X-axis metric labels
      metrics.forEach((m,mi) => {
        const x = padL + (mi/(M-1))*chartW;
        ctx.fillStyle="#6b7280"; ctx.font="bold 10px system-ui"; ctx.textAlign="center"; ctx.textBaseline="top";
        ctx.fillText(m, x, padT+chartH+8);
      });
    }

    // X-axis password labels (below metric labels)
    if (N === 1) {
      const h = history[0];
      const label = h.pwd.length>10?h.pwd.slice(0,9)+"…":h.pwd;
      ctx.fillStyle=LINE_COLORS[0]; ctx.font="10px system-ui"; ctx.textAlign="center"; ctx.textBaseline="top";
      ctx.fillText(label, padL+chartW/2, padT+chartH+22);
    }

  }, [history, metrics, selectedMetric]);

  return <canvas ref={canvasRef} width={480} height={240} style={{ width:"100%", height:"auto", display:"block" }} />;
}

// ── Bar comparison chart (score per password) ────────────────────────────────
function BarChart({ history }) {
  const canvasRef = useRef();
  useEffect(() => {
    const canvas = canvasRef.current; if (!canvas||history.length===0) return;
    const ctx = canvas.getContext("2d");
    const W=canvas.width, H=canvas.height;
    ctx.clearRect(0,0,W,H);
    const padL=44,padR=16,padT=16,padB=56;
    const chartW=W-padL-padR, chartH=H-padT-padB;
    const N=history.length, barW=Math.min(48,(chartW/N)*0.55), gap=chartW/N;

    // Grid
    [0,25,50,75,100].forEach(v=>{
      const y=padT+chartH-(v/100)*chartH;
      ctx.strokeStyle=v===0?"rgba(255,255,255,0.1)":"rgba(255,255,255,0.05)"; ctx.lineWidth=1;
      ctx.setLineDash(v>0?[3,4]:[]); ctx.beginPath(); ctx.moveTo(padL,y); ctx.lineTo(padL+chartW,y); ctx.stroke();
      ctx.setLineDash([]);
      ctx.fillStyle="#4b5563"; ctx.font="10px system-ui"; ctx.textAlign="right"; ctx.textBaseline="middle";
      ctx.fillText(v, padL-6, y);
    });

    history.forEach((h,i) => {
      const color = LINE_COLORS[i%LINE_COLORS.length];
      const x = padL + i*gap + gap/2 - barW/2;
      const barH = (h.score/100)*chartH;
      const y = padT+chartH-barH;

      // Bar gradient
      const grad=ctx.createLinearGradient(0,y,0,y+barH);
      grad.addColorStop(0,color); grad.addColorStop(1,color+"44");
      ctx.fillStyle=grad;
      ctx.beginPath();
      ctx.roundRect?ctx.roundRect(x,y,barW,barH,4):ctx.rect(x,y,barW,barH);
      ctx.fill();

      // Glow
      ctx.shadowColor=color; ctx.shadowBlur=8;
      ctx.strokeStyle=color+"88"; ctx.lineWidth=1;
      ctx.beginPath();
      ctx.roundRect?ctx.roundRect(x,y,barW,barH,4):ctx.rect(x,y,barW,barH);
      ctx.stroke();
      ctx.shadowBlur=0;

      // Score label
      ctx.fillStyle=color; ctx.font="bold 11px system-ui"; ctx.textAlign="center"; ctx.textBaseline="bottom";
      ctx.fillText(h.score, x+barW/2, y-4);

      // Password label
      const label=h.pwd.length>8?h.pwd.slice(0,7)+"…":h.pwd;
      ctx.fillStyle=color; ctx.font="9px monospace"; ctx.textAlign="center"; ctx.textBaseline="top";
      ctx.fillText(label, x+barW/2, padT+chartH+6);

      // Strength badge
      const sc=SC[h.strength];
      ctx.fillStyle=sc.fill+"33";
      const bw=44,bh=14,bx=x+barW/2-bw/2,by=padT+chartH+22;
      ctx.beginPath(); ctx.roundRect?ctx.roundRect(bx,by,bw,bh,3):ctx.rect(bx,by,bw,bh); ctx.fill();
      ctx.fillStyle=sc.fill; ctx.font="bold 8px system-ui"; ctx.textAlign="center"; ctx.textBaseline="middle";
      ctx.fillText(h.strength, x+barW/2, by+bh/2);
    });
  }, [history]);
  return <canvas ref={canvasRef} width={480} height={220} style={{ width:"100%", height:"auto", display:"block" }} />;
}

// ── Fact Ticker ──────────────────────────────────────────────────────────────
function FactTicker() {
  const [idx,setIdx]=useState(0),[fade,setFade]=useState(true);
  useEffect(()=>{
    const t=setInterval(()=>{ setFade(false); setTimeout(()=>{setIdx(i=>(i+1)%FACTS.length);setFade(true);},400); },4000);
    return ()=>clearInterval(t);
  },[]);
  const f=FACTS[idx];
  return (
    <div style={{ background:"#0c1120", border:"1px solid #1e293b", borderRadius:12, padding:"12px 16px", display:"flex", alignItems:"center", gap:14, opacity:fade?1:0, transition:"opacity 0.4s", marginBottom:16 }}>
      <span style={{ fontSize:26, flexShrink:0 }}>{f.icon}</span>
      <div style={{ flex:1 }}>
        <div style={{ color:"#6b7280", fontSize:10, textTransform:"uppercase", letterSpacing:"0.06em" }}>{f.stat}</div>
        <div style={{ color:"white", fontWeight:800, fontSize:16 }}>{f.value}</div>
        <div style={{ color:"#4b5563", fontSize:11, marginTop:1 }}>{f.sub}</div>
      </div>
      <div style={{ display:"flex", gap:3 }}>
        {FACTS.map((_,i)=><div key={i} style={{ width:5,height:5,borderRadius:"50%",background:i===idx?"#6366f1":"#1f2937",transition:"background 0.3s" }}/>)}
      </div>
    </div>
  );
}

const METRICS = ["Score","Entropy","Length","Complexity","Predictability"];

export default function App() {
  const [password,setPassword]=useState("");
  const [show,setShow]=useState(false);
  const [history,setHistory]=useState([]);
  const [tab,setTab]=useState("analyzer");
  const [chartMode,setChartMode]=useState("bar"); // bar | multiline
  const [_hoveredIdx,_setHoveredIdx]=useState(null);
  const result=useMemo(()=>analyze(password),[password]);
  const c=result?SC[result.strength]:SC.Weak;

  const addToHistory=()=>{
    if(!password||!result)return;
    setHistory(prev=>[...prev.slice(-11),{pwd:password,...result}]);
    setPassword(""); setTab("history");
  };

  const avgScore=history.length?Math.round(history.reduce((a,h)=>a+h.score,0)/history.length):0;
  const best=history.length?history.reduce((a,b)=>a.score>b.score?a:b):null;
  const worst=history.length?history.reduce((a,b)=>a.score<b.score?a:b):null;
  const trend=history.length>=2?history[history.length-1].score-history[history.length-2].score:0;

  return (
    <div style={{ minHeight:"100vh", background:"#030712", color:"white", display:"flex", alignItems:"center", justifyContent:"center", padding:"16px 12px", fontFamily:"system-ui,-apple-system,sans-serif" }}>
      <div style={{ width:"100%", maxWidth:560 }}>
        {/* Header */}
        <div style={{ textAlign:"center", marginBottom:20 }}>
          <div style={{ display:"inline-flex", alignItems:"center", justifyContent:"center", width:52,height:52,borderRadius:14,background:"rgba(99,102,241,0.15)",border:"1px solid rgba(99,102,241,0.3)",marginBottom:10 }}>
            <svg width="26" height="26" fill="none" stroke="#818cf8" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/></svg>
          </div>
          <h1 style={{ fontSize:24,fontWeight:900,background:"linear-gradient(135deg,#818cf8,#c084fc,#f472b6)",WebkitBackgroundClip:"text",WebkitTextFillColor:"transparent",margin:0 }}>Password Fortress</h1>
          <p style={{ color:"#4b5563",fontSize:12,marginTop:4 }}>Advanced security · Attack simulation · Comparison charts</p>
        </div>

        <FactTicker/>

        {/* Tabs */}
        <div style={{ display:"flex",background:"#0f172a",borderRadius:12,padding:4,marginBottom:18,border:"1px solid #1e293b" }}>
          {[["analyzer","🔍 Analyzer"],["history",`📊 History (${history.length})`]].map(([k,l])=>(
            <button key={k} onClick={()=>setTab(k)} style={{ flex:1,padding:"8px 0",borderRadius:9,border:"none",cursor:"pointer",fontSize:12,fontWeight:700,transition:"all 0.2s",background:tab===k?"#6366f1":"transparent",color:tab===k?"white":"#4b5563" }}>{l}</button>
          ))}
        </div>

        {/* ── ANALYZER TAB ── */}
        {tab==="analyzer" && (
          <>
            <div style={{ position:"relative",marginBottom:14 }}>
              <input type={show?"text":"password"} value={password} onChange={e=>setPassword(e.target.value)} onKeyDown={e=>e.key==="Enter"&&addToHistory()} placeholder="Enter password to analyze..."
                style={{ width:"100%",background:"#0f172a",border:"1px solid #334155",borderRadius:12,padding:"14px 48px 14px 16px",color:"white",fontSize:15,outline:"none",boxSizing:"border-box" }}/>
              <button onClick={()=>setShow(s=>!s)} style={{ position:"absolute",right:14,top:"50%",transform:"translateY(-50%)",background:"none",border:"none",color:"#6b7280",cursor:"pointer" }}>
                <svg width="18" height="18" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"/><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z"/></svg>
              </button>
            </div>

            {result&&password?(
              <div style={{ display:"flex",flexDirection:"column",gap:10 }}>
                {result.inDict&&(
                  <div style={{ background:"rgba(239,68,68,0.1)",border:"1px solid rgba(239,68,68,0.5)",borderRadius:12,padding:"12px 16px",display:"flex",alignItems:"center",gap:10 }}>
                    <span style={{ fontSize:22 }}>🚨</span>
                    <div><div style={{ color:"#f87171",fontWeight:700,fontSize:13 }}>Dictionary Attack Vulnerable!</div><div style={{ color:"#fca5a5",fontSize:11,marginTop:2 }}>Found in common wordlists — will be cracked instantly.</div></div>
                  </div>
                )}
                <div style={{ borderRadius:12,border:`1px solid ${c.border}`,background:c.bg,padding:14 }}>
                  <div style={{ display:"flex",justifyContent:"space-between",marginBottom:10 }}>
                    <div><div style={{ color:"#9ca3af",fontSize:10 }}>Strength</div><div style={{ fontSize:22,fontWeight:800,color:c.text }}>{result.strength}</div></div>
                    <div style={{ textAlign:"right" }}><div style={{ color:"#9ca3af",fontSize:10 }}>Score</div><div style={{ fontSize:22,fontWeight:800,color:c.text }}>{result.score}<span style={{ fontSize:11,color:"#6b7280" }}>/100</span></div></div>
                  </div>
                  <div style={{ background:"#1e293b",borderRadius:999,height:7 }}><div style={{ height:"100%",borderRadius:999,background:c.fill,width:`${result.score}%`,transition:"width 0.5s" }}/></div>
                </div>
                <div style={{ background:"#0f172a",border:"1px solid #1e293b",borderRadius:12,padding:14 }}>
                  <div style={{ color:"#818cf8",fontSize:10,fontWeight:700,textTransform:"uppercase",letterSpacing:"0.06em",marginBottom:12 }}>🛡️ Attack Resistance</div>
                  <div style={{ display:"grid",gridTemplateColumns:"1fr 1fr",gap:8 }}>
                    {[["💪 Brute Force",result.attacks.bruteForce],["📖 Dictionary",result.attacks.dictionary],["🧬 Hybrid Attack",result.attacks.hybrid],["🌈 Rainbow Table",result.attacks.rainbow]].map(([label,verdict])=>(
                      <div key={label} style={{ background:"#0c1120",border:`1px solid ${verdict.color}33`,borderRadius:10,padding:"10px 12px",display:"flex",alignItems:"center",justifyContent:"space-between" }}>
                        <div style={{ fontSize:11,color:"#9ca3af" }}>{label}</div>
                        <div style={{ display:"flex",alignItems:"center",gap:5 }}><span style={{ fontSize:11 }}>{verdict.icon}</span><span style={{ fontSize:11,fontWeight:700,color:verdict.color }}>{verdict.label}</span></div>
                      </div>
                    ))}
                  </div>
                </div>
                <div style={{ background:"#0f172a",border:"1px solid #1e293b",borderRadius:12,padding:16 }}>
                  <div style={{ color:"#818cf8",fontSize:10,fontWeight:700,textTransform:"uppercase",letterSpacing:"0.06em",marginBottom:4 }}>🕸️ Security Radar</div>
                  <RadarChart data={result.radar} color={c.fill}/>
                  <div style={{ display:"flex",flexWrap:"wrap",justifyContent:"center",gap:8,marginTop:8 }}>
                    {Object.entries(result.radar).map(([k,v])=>(
                      <div key={k} style={{ display:"flex",alignItems:"center",gap:5,fontSize:10,color:"#6b7280" }}>
                        <div style={{ width:7,height:7,borderRadius:"50%",background:c.fill }}/>
                        {k}: <span style={{ color:c.text,fontWeight:700 }}>{v}</span>
                      </div>
                    ))}
                  </div>
                </div>
                <div style={{ display:"grid",gridTemplateColumns:"1fr 1fr 1fr",gap:8 }}>
                  {[["⏱","Crack Time",result.crackTime],["🔢","Entropy",`${result.entropy} bits`],["📏","Length",`${password.length} chars`]].map(([ic,lb,vl])=>(
                    <div key={lb} style={{ background:"#0f172a",border:"1px solid #1e293b",borderRadius:10,padding:"10px 12px" }}>
                      <div style={{ color:"#6b7280",fontSize:10,marginBottom:3 }}>{ic} {lb}</div>
                      <div style={{ color:"white",fontWeight:700,fontSize:12 }}>{vl}</div>
                    </div>
                  ))}
                </div>
                <div style={{ display:"grid",gridTemplateColumns:"repeat(4,1fr)",gap:6 }}>
                  {[["Aa","Lower",result.hasL],["AB","Upper",result.hasU],["09","Digits",result.hasD],["!@","Symbols",result.hasS]].map(([ic,lb,ok])=>(
                    <div key={lb} style={{ textAlign:"center",padding:"8px 4px",borderRadius:10,border:`1px solid ${ok?"rgba(52,211,153,0.35)":"#334155"}`,background:ok?"rgba(52,211,153,0.07)":"#0f172a",color:ok?"#6ee7b7":"#334155",fontSize:10 }}>
                      <div style={{ fontWeight:700,fontSize:14,marginBottom:2 }}>{ok?"✓":"✗"}</div>{lb}
                    </div>
                  ))}
                </div>
                {result.detected.length>0&&(
                  <div style={{ background:"#0f172a",border:"1px solid rgba(249,115,22,0.3)",borderRadius:10,padding:12 }}>
                    <div style={{ color:"#fb923c",fontSize:10,fontWeight:700,textTransform:"uppercase",letterSpacing:"0.05em",marginBottom:8 }}>⚠ Patterns Detected</div>
                    <div style={{ display:"flex",flexWrap:"wrap",gap:6 }}>
                      {result.detected.map(d=><span key={d} style={{ padding:"3px 9px",background:"rgba(249,115,22,0.12)",color:"#fdba74",fontSize:11,borderRadius:8,border:"1px solid rgba(249,115,22,0.25)" }}>{d}</span>)}
                    </div>
                  </div>
                )}
                <div style={{ background:"#0f172a",border:"1px solid #1e293b",borderRadius:10,padding:12 }}>
                  <div style={{ color:"#818cf8",fontSize:10,fontWeight:700,textTransform:"uppercase",letterSpacing:"0.05em",marginBottom:8 }}>💡 Suggestions</div>
                  {result.suggestions.map(s=>(
                    <div key={s} style={{ display:"flex",gap:7,marginBottom:5,fontSize:12,color:"#d1d5db" }}><span style={{ color:"#818cf8",flexShrink:0 }}>→</span>{s}</div>
                  ))}
                </div>
                <button onClick={addToHistory} style={{ padding:"12px",borderRadius:12,border:"none",background:"linear-gradient(135deg,#6366f1,#8b5cf6)",color:"white",fontWeight:700,fontSize:13,cursor:"pointer" }}>+ Save to History</button>
              </div>
            ):(
              <div style={{ textAlign:"center",color:"#1e293b",padding:"36px 0" }}>
                <div style={{ fontSize:44,marginBottom:10 }}>🔒</div>
                <p style={{ fontSize:13,color:"#334155" }}>Type a password to see full analysis</p>
              </div>
            )}
          </>
        )}

        {/* ── HISTORY TAB ── */}
        {tab==="history" && (
          <>
            {history.length===0?(
              <div style={{ textAlign:"center",color:"#334155",padding:"48px 0" }}>
                <div style={{ fontSize:44,marginBottom:12 }}>📊</div>
                <p style={{ fontSize:14 }}>No history yet</p>
                <button onClick={()=>setTab("analyzer")} style={{ marginTop:14,padding:"9px 20px",borderRadius:10,border:"1px solid #6366f1",background:"transparent",color:"#818cf8",cursor:"pointer",fontSize:12 }}>← Go to Analyzer</button>
              </div>
            ):(
              <div style={{ display:"flex",flexDirection:"column",gap:12 }}>
                {/* Summary cards */}
                <div style={{ display:"grid",gridTemplateColumns:"repeat(4,1fr)",gap:8 }}>
                  {[["📈","Avg",`${avgScore}`],["🏆","Best",`${best?.score}`],["💀","Worst",`${worst?.score}`],["📉","Trend",trend===0?"—":trend>0?`+${trend}↑`:`${trend}↓`]].map(([ic,lb,vl])=>(
                    <div key={lb} style={{ background:"#0f172a",border:"1px solid #1e293b",borderRadius:10,padding:"10px 8px",textAlign:"center" }}>
                      <div style={{ fontSize:16,marginBottom:3 }}>{ic}</div>
                      <div style={{ color:"#6b7280",fontSize:9,marginBottom:2,textTransform:"uppercase",letterSpacing:"0.05em" }}>{lb}</div>
                      <div style={{ color:"white",fontWeight:800,fontSize:14 }}>{vl}</div>
                    </div>
                  ))}
                </div>

                {trend<0&&<div style={{ background:"rgba(239,68,68,0.07)",border:"1px solid rgba(239,68,68,0.3)",borderRadius:10,padding:10,fontSize:12,color:"#fca5a5" }}>⬇ Score dropped. Add symbols, uppercase, and more length.</div>}
                {trend>10&&<div style={{ background:"rgba(52,211,153,0.07)",border:"1px solid rgba(52,211,153,0.3)",borderRadius:10,padding:10,fontSize:12,color:"#6ee7b7" }}>⬆ Nice improvement! Push for 70+ to reach Strong.</div>}

                {/* ── CHART SECTION ── */}
                <div style={{ background:"#0f172a",border:"1px solid #1e293b",borderRadius:14,padding:16 }}>
                  {/* Chart mode toggle */}
                  <div style={{ display:"flex",alignItems:"center",justifyContent:"space-between",marginBottom:14 }}>
                    <div>
                      <div style={{ color:"#9ca3af",fontSize:11,fontWeight:700,textTransform:"uppercase",letterSpacing:"0.06em" }}>
                        {chartMode==="bar"?"📊 Score Comparison":"📈 Multi-Metric Lines"}
                      </div>
                      <div style={{ color:"#4b5563",fontSize:10,marginTop:2 }}>
                        {chartMode==="bar"?"Side-by-side score for each password":"All metrics across passwords"}
                      </div>
                    </div>
                    <div style={{ display:"flex",gap:4 }}>
                      {[["bar","▊▊"],["multiline","〰"]].map(([m,ic])=>(
                        <button key={m} onClick={()=>setChartMode(m)} style={{ padding:"6px 10px",borderRadius:8,border:`1px solid ${chartMode===m?"#6366f1":"#334155"}`,background:chartMode===m?"rgba(99,102,241,0.2)":"transparent",color:chartMode===m?"#818cf8":"#6b7280",cursor:"pointer",fontSize:13,fontWeight:700,transition:"all 0.2s" }}>{ic}</button>
                      ))}
                    </div>
                  </div>

                  {chartMode==="bar"?(
                    <BarChart history={history}/>
                  ):(
                    <>
                      <ComparisonChart history={history} metrics={METRICS} selectedMetric="Score"/>
                      {/* Legend */}
                      <div style={{ display:"flex",flexWrap:"wrap",gap:8,marginTop:12,justifyContent:"center" }}>
                        {history.map((h,i)=>(
                          <div key={i} style={{ display:"flex",alignItems:"center",gap:5,fontSize:10 }}>
                            <div style={{ width:24,height:3,borderRadius:99,background:LINE_COLORS[i%LINE_COLORS.length] }}/>
                            <span style={{ color:LINE_COLORS[i%LINE_COLORS.length],fontFamily:"monospace" }}>{h.pwd.length>10?h.pwd.slice(0,9)+"…":h.pwd}</span>
                          </div>
                        ))}
                      </div>
                      <div style={{ display:"flex",flexWrap:"wrap",gap:6,marginTop:10,justifyContent:"center" }}>
                        {METRICS.map(m=>(
                          <span key={m} style={{ padding:"2px 8px",background:"#1e293b",borderRadius:6,fontSize:10,color:"#6b7280" }}>{m}</span>
                        ))}
                      </div>
                    </>
                  )}
                </div>

                {/* Password list */}
                <div style={{ background:"#0f172a",border:"1px solid #1e293b",borderRadius:12,padding:14 }}>
                  <div style={{ color:"#9ca3af",fontSize:10,fontWeight:700,textTransform:"uppercase",letterSpacing:"0.05em",marginBottom:10 }}>Password Log</div>
                  {[...history].reverse().map((h,i)=>{
                    const hc=SC[h.strength];
                    const realIdx=history.length-1-i;
                    const lineColor=LINE_COLORS[realIdx%LINE_COLORS.length];
                    return (
                      <div key={i} style={{ display:"flex",alignItems:"center",justifyContent:"space-between",padding:"8px 0",borderBottom:i<history.length-1?"1px solid #1e293b":"none" }}>
                        <div style={{ display:"flex",alignItems:"center",gap:10 }}>
                          <div style={{ width:10,height:10,borderRadius:"50%",background:lineColor,flexShrink:0,boxShadow:`0 0 6px ${lineColor}` }}/>
                          <div style={{ fontSize:12,color:"#e5e7eb",fontFamily:"monospace" }}>{h.pwd.length>16?h.pwd.slice(0,14)+"…":h.pwd}</div>
                        </div>
                        <div style={{ display:"flex",alignItems:"center",gap:8 }}>
                          <span style={{ fontSize:10,color:hc.text,background:hc.bg,padding:"2px 8px",borderRadius:6,border:`1px solid ${hc.border}` }}>{h.strength}</span>
                          <span style={{ fontSize:12,color:"#6b7280",minWidth:36,textAlign:"right" }}>{h.score}/100</span>
                        </div>
                      </div>
                    );
                  })}
                </div>

                <button onClick={()=>setHistory([])} style={{ padding:"10px",borderRadius:10,border:"1px solid #334155",background:"transparent",color:"#6b7280",cursor:"pointer",fontSize:12 }}>Clear History</button>
              </div>
            )}
          </>
        )}

        <p style={{ textAlign:"center",color:"#1e293b",fontSize:10,marginTop:16 }}>All analysis is local — nothing is ever transmitted.</p>
      </div>
    </div>
  );
}
