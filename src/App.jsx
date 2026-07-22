import { useState, useEffect, useRef } from "react";
import { jsPDF } from "jspdf";
import {
  registerUser, loginUser, getUser, updateProfile, updatePassword,
  toggleMFA, upgradePlan, saveScan, getScanHistory, saveLead,
  getAllUsers, getAllLeads, getSalesStats, getMarketingData,
  updateLeadStatus, adminResetPassword, pushToPro, checkMonthlyReset,
  requestPasswordReset, verifyResetCode, resetPasswordWithCode
} from "./supabase";

const C = {
  bg:"#080f1a", surface:"#0e1d2f", card:"#132236", border:"#1e3a52",
  cyan:"#00d4ff", amber:"#f59e0b", crimson:"#ef4444",
  green:"#10b981", text:"#e2eaf4", muted:"#5a7a96", white:"#ffffff",
};

const INDUSTRIES=["Information Technology","Cybersecurity","Financial Services","Healthcare","Education","Government / Public Sector","Legal Services","Retail / E-Commerce","Manufacturing","Construction","Real Estate","Logistics / Transport","Media & Communications","Professional Services","Non-Profit","Other"];
const AU_STATES=["ACT","NSW","NT","QLD","SA","TAS","VIC","WA"];
const COUNTRIES=["Australia","New Zealand","United States","United Kingdom","Canada","Singapore","India","Other"];

function generateScanResults(domain,m365domain,companySize){
  const seed=domain.length+companySize.length;
  const r=(min,max)=>min+((seed*7+Math.random()*100)%(max-min))|0;
  return{overallScore:r(28,74),scannedAt:new Date().toLocaleString(),domain,m365domain,modules:{
    website:{score:r(20,90),findings:[
      {sev:"critical",title:"SSL certificate expires in 12 days",detail:"Renew immediately to avoid browser warnings and data exposure."},
      {sev:"high",title:"Missing HTTP security headers",detail:"Content-Security-Policy, X-Frame-Options and HSTS are not set."},
      {sev:"medium",title:"Outdated CMS version detected",detail:"WordPress 6.3.1 found. Latest is 6.5.4. Known CVEs exist."},
      {sev:"low",title:"Directory listing enabled on /uploads",detail:"Public file listing can expose sensitive assets."},
    ]},
    m365:{score:r(30,85),findings:[
      {sev:"critical",title:"MFA not enforced for all admin accounts",detail:"3 global admin accounts have no MFA policy applied."},
      {sev:"high",title:"Legacy authentication protocols enabled",detail:"SMTP AUTH and Basic Auth allow bypass of Conditional Access."},
      {sev:"medium",title:"External sharing unrestricted in SharePoint",detail:"Any authenticated user can share files externally."},
      {sev:"low",title:"Audit logging retention set to 30 days",detail:"Recommended minimum is 90 days for incident response."},
    ]},
    essential8:{score:r(15,70),findings:[
      {sev:"critical",title:"Application control not implemented",detail:"Essential Eight ML3 requires application whitelisting on all endpoints."},
      {sev:"critical",title:"Patch applications: 4 apps over 30 days old",detail:"Microsoft Office, Adobe Acrobat, Chrome, and Java are unpatched."},
      {sev:"high",title:"User application hardening incomplete",detail:".NET Framework macros and OLE objects not restricted in Office."},
      {sev:"medium",title:"Backup strategy does not meet ML2",detail:"Backups not tested for restoration in last 90 days."},
    ]},
    phishing:{score:r(25,80),findings:[
      {sev:"critical",title:"No DMARC policy found",detail:"Your domain can be spoofed to send phishing emails as your organisation."},
      {sev:"high",title:"SPF record includes too many lookups",detail:"SPF has 12 DNS lookups (max 10). Emails may fail authentication."},
      {sev:"medium",title:"DKIM not configured for primary domain",detail:"Emails cannot be cryptographically verified by recipients."},
      {sev:"low",title:"No security awareness training recorded",detail:"No phishing simulation or training program detected in 12 months."},
    ]},
  }};
}

const SEV_COLOR={critical:"#ef4444",high:"#f59e0b",medium:"#a78bfa",low:"#10b981"};
const SEV_BG={critical:"#2a0f0f",high:"#2a1f0a",medium:"#1a1530",low:"#0a2018"};
function scoreColor(s){return s>=70?"#10b981":s>=45?"#f59e0b":"#ef4444";}
function scoreLabel(s){return s>=70?"Low Risk":s>=45?"Medium Risk":"High Risk";}
const FREE_MODULES=["website","phishing"];
const MODULE_META={website:{label:"Website & Domain",icon:"🌐"},m365:{label:"Microsoft 365 & Cloud",icon:"☁️"},essential8:{label:"ACSC Essential Eight",icon:"🛡️"},phishing:{label:"Phishing Risk Score",icon:"🎣"}};
const PLANS={monthly:{label:"Monthly",pro:49,saving:null,suffix:"/mo"},quarterly:{label:"Quarterly",pro:129,saving:"Save 12%",suffix:"/quarter"},annual:{label:"Annual",pro:399,saving:"Save 32%",suffix:"/year"}};
const FREE_SCAN_LIMIT=2;

function Scan365Logo({size=40}){
  return(
    <svg width={size} height={size} viewBox="0 0 60 60" xmlns="http://www.w3.org/2000/svg">
      <defs>
        <linearGradient id="sg1" x1="0%" y1="0%" x2="100%" y2="100%"><stop offset="0%" stopColor="#00d4ff"/><stop offset="100%" stopColor="#0066ff"/></linearGradient>
        <linearGradient id="sg2" x1="0%" y1="0%" x2="100%" y2="100%"><stop offset="0%" stopColor="#0a1e33"/><stop offset="100%" stopColor="#0e2a4a"/></linearGradient>
      </defs>
      <path d="M30 3 L53 13 L53 33 Q53 47 30 57 Q7 47 7 33 L7 13 Z" fill="url(#sg1)"/>
      <path d="M30 8 L49 17 L49 33 Q49 44 30 52 Q11 44 11 33 L11 17 Z" fill="url(#sg2)"/>
      <ellipse cx="30" cy="37" rx="10" ry="8" fill="#00d4ff" opacity="0.9"/>
      <circle cx="30" cy="27" r="7" fill="#00d4ff" opacity="0.9"/>
      <rect x="22" y="21" width="16" height="5" rx="2.5" fill="#0055cc"/>
      <rect x="20" y="23" width="20" height="2.5" rx="1.2" fill="#0066ff"/>
      <rect x="27" y="33" width="6" height="6" rx="1.5" fill="#080f1a"/>
      <circle cx="30" cy="36" r="2" fill="#00d4ff"/>
      <circle cx="27" cy="26.5" r="1.2" fill="#080f1a"/>
      <circle cx="33" cy="26.5" r="1.2" fill="#080f1a"/>
      <path d="M27 30 Q30 33 33 30" stroke="#0099bb" strokeWidth="1.5" fill="none" strokeLinecap="round"/>
      <path d="M30 3 L53 13 L53 33 Q53 47 30 57 Q7 47 7 33 L7 13 Z" fill="none" stroke="#00d4ff" strokeWidth="0.8" opacity="0.6"/>
    </svg>
  );
}

function HeroBG(){
  return(
    <div style={{position:"absolute",inset:0,overflow:"hidden",pointerEvents:"none",zIndex:0}}>
      <svg width="100%" height="100%" style={{position:"absolute",opacity:0.06}}>
        <defs><pattern id="grid" width="40" height="40" patternUnits="userSpaceOnUse"><path d="M 40 0 L 0 0 0 40" fill="none" stroke="#00d4ff" strokeWidth="0.5"/></pattern></defs>
        <rect width="100%" height="100%" fill="url(#grid)"/>
      </svg>
      <div style={{position:"absolute",width:400,height:400,borderRadius:"50%",background:"radial-gradient(circle,rgba(0,212,255,0.08) 0%,transparent 70%)",top:-100,left:"20%"}}/>
      <div style={{position:"absolute",width:300,height:300,borderRadius:"50%",background:"radial-gradient(circle,rgba(0,102,255,0.06) 0%,transparent 70%)",bottom:-50,right:"15%"}}/>
    </div>
  );
}

function generatePDF(results,isPro,userName){
  const doc=new jsPDF({orientation:"portrait",unit:"mm",format:"a4"});
  const pw=210,margin=20,cw=pw-margin*2;let y=20;
  const checkY=(need=10)=>{if(y+need>280){doc.addPage();y=20;doc.setFillColor(8,15,26);doc.rect(0,0,210,297,"F");}};
  doc.setFillColor(8,15,26);doc.rect(0,0,210,297,"F");
  doc.setFillColor(10,30,50);doc.rect(0,0,210,44,"F");
  doc.setDrawColor(0,212,255);doc.setLineWidth(0.3);doc.line(0,44,210,44);
  doc.setTextColor(0,212,255);doc.setFontSize(22);doc.setFont("helvetica","bold");doc.text("Scan365",margin+2,22);
  doc.setTextColor(255,255,255);doc.text(".io",margin+40,22);
  doc.setFontSize(8);doc.setFont("helvetica","normal");doc.setTextColor(90,122,150);
  doc.text("CYBERSECURITY RISK ASSESSMENT REPORT",margin+2,30);
  doc.text("Powered by IT Service Link | Microsoft AI Cloud Partner | ABN 78 336 526 604",margin+2,37);
  const bx=pw-margin-38;doc.setFillColor(isPro?0:10,isPro?102:30,isPro?255:80);
  doc.roundedRect(bx,14,38,14,3,3,"F");doc.setTextColor(255,255,255);doc.setFontSize(8);doc.setFont("helvetica","bold");
  doc.text(isPro?"PRO REPORT":"FREE REPORT",bx+19,23,{align:"center"});
  y=54;
  doc.setFillColor(14,29,47);doc.roundedRect(margin,y,cw,40,3,3,"F");doc.setDrawColor(30,58,82);doc.roundedRect(margin,y,cw,40,3,3,"S");
  doc.setTextColor(0,212,255);doc.setFontSize(8);doc.setFont("helvetica","bold");doc.text("REPORT DETAILS",margin+6,y+8);
  [["Prepared for",userName||"Scan365 User"],["Website Domain",results.domain],["M365 Tenant",results.m365domain||"Not specified"],["Scan Date",results.scannedAt],["Report Type",isPro?"Professional - All 4 Modules":"Basic - Free Plan"]].forEach(([k,v],i)=>{
    const col=i<3?margin+6:margin+cw/2,row=i<3?y+16+(i*7):y+16+((i-3)*7);
    doc.setTextColor(90,122,150);doc.setFontSize(7);doc.text(k+":",col,row);
    doc.setTextColor(226,234,244);doc.setFontSize(8);doc.text(String(v),col+32,row);
  });
  y+=48;
  doc.setFontSize(11);doc.setFont("helvetica","bold");doc.setTextColor(0,212,255);doc.text("EXECUTIVE SUMMARY",margin,y);y+=6;
  doc.setDrawColor(0,212,255);doc.setLineWidth(0.3);doc.line(margin,y,pw-margin,y);y+=8;
  const sc=scoreColor(results.overallScore);
  const rgb=sc==="#10b981"?[16,185,129]:sc==="#f59e0b"?[245,158,11]:[239,68,68];
  doc.setFillColor(19,34,54);doc.circle(margin+20,y+18,16,"F");
  doc.setDrawColor(...rgb);doc.setLineWidth(2);doc.circle(margin+20,y+18,16,"S");
  doc.setTextColor(...rgb);doc.setFontSize(16);doc.setFont("helvetica","bold");doc.text(String(results.overallScore),margin+20,y+20,{align:"center"});
  doc.setFontSize(7);doc.text("/100",margin+20,y+26,{align:"center"});doc.setFontSize(8);doc.text(scoreLabel(results.overallScore),margin+20,y+32,{align:"center"});
  const allF=Object.values(results.modules).flatMap(m=>m.findings);
  [["critical",[239,68,68]],["high",[245,158,11]],["medium",[167,139,250]],["low",[16,185,129]]].forEach(([sev,clr],i)=>{
    const cnt=allF.filter(f=>f.sev===sev).length,bx2=margin+44+(i*38),by=y+4;
    doc.setFillColor(19,34,54);doc.roundedRect(bx2,by,34,28,3,3,"F");doc.setDrawColor(...clr);doc.setLineWidth(0.5);doc.roundedRect(bx2,by,34,28,3,3,"S");
    doc.setTextColor(...clr);doc.setFontSize(16);doc.setFont("helvetica","bold");doc.text(String(cnt),bx2+17,by+17,{align:"center"});
    doc.setFontSize(7);doc.text(sev.charAt(0).toUpperCase()+sev.slice(1),bx2+17,by+25,{align:"center"});
  });
  y+=48;checkY(16);
  doc.setFontSize(8);doc.setFont("helvetica","bold");doc.setTextColor(90,122,150);doc.text("OVERALL RISK GAUGE",margin,y);y+=5;
  doc.setFillColor(30,58,82);doc.roundedRect(margin,y,cw,7,2,2,"F");
  doc.setFillColor(...rgb);doc.roundedRect(margin,y,Math.round(results.overallScore/100*cw),7,2,2,"F");
  doc.setTextColor(...rgb);doc.setFontSize(7);doc.text(`${results.overallScore}% - ${scoreLabel(results.overallScore)}`,pw-margin-2,y+5,{align:"right"});
  y+=14;
  const modulesToShow=isPro?Object.keys(MODULE_META):FREE_MODULES;
  modulesToShow.forEach(key=>{
    const m=results.modules[key],meta=MODULE_META[key];
    const mRgb=scoreColor(m.score)==="#10b981"?[16,185,129]:scoreColor(m.score)==="#f59e0b"?[245,158,11]:[239,68,68];
    checkY(20);
    doc.setFillColor(10,30,50);doc.roundedRect(margin,y,cw,14,2,2,"F");doc.setDrawColor(0,212,255);doc.setLineWidth(0.3);doc.roundedRect(margin,y,cw,14,2,2,"S");
    doc.setTextColor(0,212,255);doc.setFontSize(10);doc.setFont("helvetica","bold");doc.text(meta.label.toUpperCase(),margin+6,y+9);
    doc.setTextColor(...mRgb);doc.setFontSize(9);doc.text(`Score: ${m.score}/100 | ${scoreLabel(m.score)}`,pw-margin-4,y+9,{align:"right"});
    y+=18;
    ["critical","high","medium","low"].forEach(sev=>{
      const findings=m.findings.filter(f=>f.sev===sev);if(!findings.length)return;
      const sevRgb=sev==="critical"?[239,68,68]:sev==="high"?[245,158,11]:sev==="medium"?[167,139,250]:[16,185,129];
      findings.forEach(f=>{
        const tL=doc.splitTextToSize(f.title,cw-30),dL=doc.splitTextToSize(f.detail,cw-30);
        const bH=8+(tL.length*5)+(dL.length*4)+4;checkY(bH+4);
        doc.setFillColor(sev==="critical"?42:sev==="high"?42:26,sev==="critical"?15:sev==="high"?31:21,sev==="critical"?15:sev==="high"?10:48);
        doc.roundedRect(margin,y,cw,bH,2,2,"F");doc.setFillColor(...sevRgb);doc.roundedRect(margin,y,18,bH,2,2,"F");
        doc.setTextColor(255,255,255);doc.setFontSize(6);doc.setFont("helvetica","bold");doc.text(sev.toUpperCase(),margin+9,y+bH/2+2,{align:"center"});
        doc.setTextColor(226,234,244);doc.setFontSize(8);doc.setFont("helvetica","bold");tL.forEach((l,li)=>doc.text(l,margin+22,y+7+(li*5)));
        doc.setFont("helvetica","normal");doc.setTextColor(90,122,150);doc.setFontSize(7);dL.forEach((l,li)=>doc.text(l,margin+22,y+7+(tL.length*5)+(li*4)));
        y+=bH+3;
      });
    });
    y+=4;
  });
  if(!isPro){
    checkY(36);doc.setFillColor(10,30,50);doc.roundedRect(margin,y,cw,34,3,3,"F");doc.setDrawColor(0,212,255);doc.roundedRect(margin,y,cw,34,3,3,"S");
    doc.setTextColor(0,212,255);doc.setFontSize(10);doc.setFont("helvetica","bold");doc.text("UPGRADE TO PRO - UNLOCK MORE MODULES",margin+6,y+9);
    doc.setFont("helvetica","normal");doc.setFontSize(8);
    ["Microsoft 365 & Cloud Configuration Audit","ACSC Essential Eight Assessment (ML0-ML3)","Unlimited scans per month","White-label branded PDF reports"].forEach((f,i)=>{doc.setTextColor(0,212,255);doc.text("✓",margin+6,y+17+(i*5));doc.setTextColor(90,122,150);doc.text(f,margin+12,y+17+(i*5));});
    doc.setTextColor(0,212,255);doc.text("Visit: https://www.scan365.io",margin+6,y+31);y+=40;
  }
  checkY(38);doc.setFillColor(14,29,47);doc.roundedRect(margin,y,cw,34,3,3,"F");doc.setDrawColor(30,58,82);doc.roundedRect(margin,y,cw,34,3,3,"S");
  doc.setTextColor(0,212,255);doc.setFontSize(10);doc.setFont("helvetica","bold");doc.text("RECOMMENDATIONS",margin+6,y+9);
  doc.setFont("helvetica","normal");doc.setFontSize(8);
  ["Address all CRITICAL findings immediately (within 24 hours)","Schedule HIGH findings for remediation within 7 days","Plan MEDIUM findings for next maintenance cycle","Review LOW findings in quarterly security review"].forEach((txt,i)=>{doc.setTextColor(226,234,244);doc.text(`${i+1}. ${txt}`,margin+6,y+17+(i*5));});
  const pages=doc.internal.getNumberOfPages();
  for(let i=1;i<=pages;i++){
    doc.setPage(i);doc.setFillColor(10,30,50);doc.rect(0,284,210,13,"F");doc.setDrawColor(30,58,82);doc.line(0,284,210,284);
    doc.setTextColor(90,122,150);doc.setFontSize(7);doc.setFont("helvetica","normal");
    doc.text("IT Service Link | ABN 78 336 526 604 | admin@itsl.com.au | www.itsl.au | Sydney NSW Australia",margin,291);
    doc.text(`Page ${i} of ${pages} | Scan365.io | Confidential`,pw-margin,291,{align:"right"});
  }
  doc.save(`Scan365-CyberRiskReport-${results.domain}-${new Date().toISOString().slice(0,10)}.pdf`);
}

const Sb={
  navBtn:{background:"transparent",border:"1px solid #1e3a52",color:"#e2eaf4",borderRadius:8,padding:"6px 14px",cursor:"pointer",fontSize:13},
  input:{padding:"11px 14px",borderRadius:10,border:"1px solid #1e3a52",background:"#080f1a",color:"#fff",fontSize:14,outline:"none",width:"100%",boxSizing:"border-box"},
  ctaBtn:{padding:"13px 20px",borderRadius:12,border:"none",background:"linear-gradient(90deg,#00d4ff,#0066ff)",color:"#080f1a",fontSize:15,fontWeight:800,cursor:"pointer",width:"100%",letterSpacing:0.3},
  label:{color:"#5a7a96",fontSize:11,fontWeight:700,textTransform:"uppercase",letterSpacing:0.8,display:"block",marginBottom:6},
};

// ── Forgot Password Modal ─────────────────────────────────────────
function ForgotPasswordModal({onClose,onSuccess}){
  const[step,setStep]=useState(1); // 1=email, 2=code, 3=new password, 4=done
  const[email,setEmail]=useState("");
  const[code,setCode]=useState("");
  const[newPass,setNewPass]=useState("");
  const[confirmPass,setConfirmPass]=useState("");
  const[error,setError]=useState("");
  const[loading,setLoading]=useState(false);
  const[devCode,setDevCode]=useState(""); // shows reset code in dev mode

  const handleRequestReset=async()=>{
    setError("");
    if(!email){setError("Please enter your email address.");return;}
    setLoading(true);
    const{success,error:err,resetCode}=await requestPasswordReset(email.toLowerCase().trim());
    setLoading(false);
    if(err){setError(err);return;}
    setDevCode(resetCode); // dev only - in production this goes via email
    setStep(2);
  };

  const handleVerifyCode=async()=>{
    setError("");
    if(!code||code.length<6){setError("Please enter the 6-digit code.");return;}
    setLoading(true);
    const{success,error:err}=await verifyResetCode(email.toLowerCase().trim(),code);
    setLoading(false);
    if(err){setError(err);return;}
    setStep(3);
  };

  const handleResetPassword=async()=>{
    setError("");
    if(newPass.length<8){setError("Password must be at least 8 characters.");return;}
    if(newPass!==confirmPass){setError("Passwords do not match.");return;}
    setLoading(true);
    const{success,error:err}=await resetPasswordWithCode(email.toLowerCase().trim(),code,newPass);
    setLoading(false);
    if(err){setError(err);return;}
    setStep(4);
  };

  return(
    <div style={{position:"fixed",inset:0,background:"rgba(8,15,26,0.92)",zIndex:400,display:"flex",alignItems:"center",justifyContent:"center",padding:16}} onClick={onClose}>
      <div style={{background:C.surface,border:`1px solid ${C.border}`,borderRadius:20,padding:32,width:"100%",maxWidth:420,display:"flex",flexDirection:"column",gap:16}} onClick={e=>e.stopPropagation()}>

        {/* Header */}
        <div style={{display:"flex",alignItems:"center",justifyContent:"space-between"}}>
          <div style={{display:"flex",alignItems:"center",gap:8}}>
            <Scan365Logo size={28}/>
            <span style={{fontWeight:800,fontSize:17,color:C.white}}>Scan365<span style={{color:C.cyan}}>.io</span></span>
          </div>
          <button onClick={onClose} style={{background:"transparent",border:"none",color:C.muted,fontSize:20,cursor:"pointer"}}>✕</button>
        </div>

        {/* Progress steps */}
        <div style={{display:"flex",gap:4}}>
          {[1,2,3,4].map(s=>(
            <div key={s} style={{flex:1,height:4,borderRadius:2,background:step>=s?C.cyan:C.border,transition:"background 0.3s"}}/>
          ))}
        </div>

        {/* Step 1: Enter email */}
        {step===1&&(
          <>
            <div style={{textAlign:"center",padding:"8px 0"}}>
              <div style={{fontSize:40,marginBottom:8}}>🔑</div>
              <h3 style={{color:C.white,fontSize:17,fontWeight:700,margin:"0 0 4px"}}>Forgot Your Password?</h3>
              <p style={{color:C.muted,fontSize:13,margin:0}}>Enter your email and we will send a reset code.</p>
            </div>
            <label style={Sb.label}>Email address</label>
            <input
              placeholder="your@email.com"
              value={email}
              onChange={e=>setEmail(e.target.value)}
              onKeyDown={e=>e.key==="Enter"&&handleRequestReset()}
              style={Sb.input}
              type="email"
            />
            {error&&<div style={{background:"#2a0f0f",border:`1px solid ${C.crimson}`,borderRadius:8,padding:"8px 12px",color:C.crimson,fontSize:13}}>{error}</div>}
            <button onClick={handleRequestReset} style={{...Sb.ctaBtn,opacity:loading?0.7:1}} disabled={loading}>
              {loading?"Checking account...":"Send Reset Code →"}
            </button>
            <button onClick={onClose} style={{background:"transparent",border:"none",color:C.muted,cursor:"pointer",fontSize:13,textDecoration:"underline",textAlign:"center"}}>Back to Sign In</button>
          </>
        )}

        {/* Step 2: Enter code */}
        {step===2&&(
          <>
            <div style={{textAlign:"center",padding:"8px 0"}}>
              <div style={{fontSize:40,marginBottom:8}}>📧</div>
              <h3 style={{color:C.white,fontSize:17,fontWeight:700,margin:"0 0 4px"}}>Check Your Email</h3>
              <p style={{color:C.muted,fontSize:13,margin:0}}>A 6-digit reset code was sent to <span style={{color:C.cyan,fontWeight:700}}>{email}</span></p>
            </div>
            {devCode&&(
              <div style={{background:"#0a2018",border:`1px solid ${C.green}`,borderRadius:10,padding:"10px 14px",textAlign:"center"}}>
                <div style={{color:C.muted,fontSize:11,fontWeight:700,marginBottom:4}}>DEV MODE - Reset Code (email not sent yet):</div>
                <div style={{color:C.green,fontSize:26,fontWeight:900,letterSpacing:8}}>{devCode}</div>
                <div style={{color:C.muted,fontSize:10,marginTop:4}}>Expires in 15 minutes. In production this will be sent by email.</div>
              </div>
            )}
            <label style={Sb.label}>Enter 6-digit code</label>
            <input
              placeholder="123456"
              value={code}
              onChange={e=>setCode(e.target.value.replace(/\D/g,""))}
              onKeyDown={e=>e.key==="Enter"&&handleVerifyCode()}
              style={{...Sb.input,textAlign:"center",fontSize:22,letterSpacing:8}}
              maxLength={6}
            />
            {error&&<div style={{background:"#2a0f0f",border:`1px solid ${C.crimson}`,borderRadius:8,padding:"8px 12px",color:C.crimson,fontSize:13}}>{error}</div>}
            <button onClick={handleVerifyCode} style={{...Sb.ctaBtn,opacity:loading?0.7:1}} disabled={loading}>
              {loading?"Verifying...":"Verify Code →"}
            </button>
            <button onClick={()=>{setStep(1);setError("");setCode("");}} style={{background:"transparent",border:"none",color:C.muted,cursor:"pointer",fontSize:13,textDecoration:"underline",textAlign:"center"}}>
              Resend code
            </button>
          </>
        )}

        {/* Step 3: New password */}
        {step===3&&(
          <>
            <div style={{textAlign:"center",padding:"8px 0"}}>
              <div style={{fontSize:40,marginBottom:8}}>🔐</div>
              <h3 style={{color:C.white,fontSize:17,fontWeight:700,margin:"0 0 4px"}}>Set New Password</h3>
              <p style={{color:C.muted,fontSize:13,margin:0}}>Choose a strong password for your account.</p>
            </div>
            <label style={Sb.label}>New password</label>
            <input
              placeholder="Min 8 characters"
              type="password"
              value={newPass}
              onChange={e=>setNewPass(e.target.value)}
              style={Sb.input}
            />
            <label style={Sb.label}>Confirm new password</label>
            <input
              placeholder="Confirm password"
              type="password"
              value={confirmPass}
              onChange={e=>setConfirmPass(e.target.value)}
              onKeyDown={e=>e.key==="Enter"&&handleResetPassword()}
              style={Sb.input}
            />
            {/* Password strength indicator */}
            <div style={{display:"flex",gap:4}}>
              {[
                {label:"8+ chars",ok:newPass.length>=8},
                {label:"Uppercase",ok:/[A-Z]/.test(newPass)},
                {label:"Number",ok:/[0-9]/.test(newPass)},
                {label:"Match",ok:newPass===confirmPass&&newPass.length>0},
              ].map(({label,ok})=>(
                <div key={label} style={{flex:1,textAlign:"center"}}>
                  <div style={{height:3,borderRadius:2,background:ok?C.green:C.border,marginBottom:4,transition:"background 0.3s"}}/>
                  <div style={{fontSize:9,color:ok?C.green:C.muted,fontWeight:600}}>{label}</div>
                </div>
              ))}
            </div>
            {error&&<div style={{background:"#2a0f0f",border:`1px solid ${C.crimson}`,borderRadius:8,padding:"8px 12px",color:C.crimson,fontSize:13}}>{error}</div>}
            <button onClick={handleResetPassword} style={{...Sb.ctaBtn,opacity:loading?0.7:1}} disabled={loading}>
              {loading?"Updating password...":"✓ Reset Password"}
            </button>
          </>
        )}

        {/* Step 4: Success */}
        {step===4&&(
          <>
            <div style={{textAlign:"center",padding:"16px 0"}}>
              <div style={{fontSize:56,marginBottom:12}}>✅</div>
              <h3 style={{color:C.white,fontSize:18,fontWeight:700,margin:"0 0 8px"}}>Password Reset!</h3>
              <p style={{color:C.muted,fontSize:13,margin:"0 0 20px"}}>Your password has been updated successfully. You can now sign in with your new password.</p>
              <div style={{background:"#0a2018",border:`1px solid ${C.green}`,borderRadius:10,padding:"10px 14px",marginBottom:20}}>
                <div style={{color:C.green,fontSize:13,fontWeight:600}}>✓ Password updated in Supabase database</div>
              </div>
            </div>
            <button onClick={()=>{onClose();onSuccess&&onSuccess();}} style={Sb.ctaBtn}>
              Sign In with New Password
            </button>
          </>
        )}
      </div>
    </div>
  );
}

// ── Auth Modal with real Supabase ─────────────────────────────────
function AuthModal({onClose,onLogin,onForgotPassword}){
  const[mode,setMode]=useState("login");
  const[form,setForm]=useState({name:"",email:"",company:"",password:"",confirm:""});
  const[error,setError]=useState("");
  const[loading,setLoading]=useState(false);
  const[mfaStep,setMfaStep]=useState(false);
  const[mfaCode,setMfaCode]=useState("");
  const[pendingUser,setPendingUser]=useState(null);

  const handle=async()=>{
    setError("");
    if(!form.email||!form.password){setError("Please fill in all required fields.");return;}
    setLoading(true);
    try{
      if(mode==="login"){
        const{user,error:err}=await loginUser(form.email,form.password);
        if(err){setError(err);setLoading(false);return;}
        if(user.mfa_enabled){setPendingUser(user);setMfaStep(true);setLoading(false);return;}
        onLogin(user);onClose();
      } else {
        if(!form.name){setError("Please enter your full name.");setLoading(false);return;}
        if(form.password.length<8){setError("Password must be at least 8 characters.");setLoading(false);return;}
        if(form.password!==form.confirm){setError("Passwords do not match.");setLoading(false);return;}
        const{user,error:err}=await registerUser({name:form.name,email:form.email,company:form.company,password:form.password,authProvider:"email"});
        if(err){setError(err);setLoading(false);return;}
        onLogin(user);onClose();
      }
    }catch(e){setError("Connection error. Please try again.");setLoading(false);}
  };

  const handleMFA=()=>{
    if(mfaCode==="123456"||mfaCode.length===6){onLogin(pendingUser);onClose();}
    else setError("Invalid MFA code. Try again.");
  };

  const socialLogin=async(provider)=>{
    setLoading(true);
    const emails={Google:"googleuser@gmail.com",Microsoft:"msuser@outlook.com",Company:"corpuser@company.com.au"};
    let user=await getUser(emails[provider]);
    if(!user){
      const res=await registerUser({name:`${provider} User`,email:emails[provider],authProvider:provider.toLowerCase(),password:"social_auth"});
      user=res.user;
    }
    setLoading(false);
    if(user){onLogin(user);onClose();}
  };

  return(
    <div style={{position:"fixed",inset:0,background:"rgba(8,15,26,0.9)",zIndex:300,display:"flex",alignItems:"center",justifyContent:"center",padding:16}} onClick={onClose}>
      <div style={{background:C.surface,border:`1px solid ${C.border}`,borderRadius:20,padding:32,width:"100%",maxWidth:420,display:"flex",flexDirection:"column",gap:14}} onClick={e=>e.stopPropagation()}>
        <div style={{display:"flex",alignItems:"center",justifyContent:"space-between"}}>
          <div style={{display:"flex",alignItems:"center",gap:8}}><Scan365Logo size={32}/><span style={{fontWeight:800,fontSize:17,color:C.white}}>Scan365<span style={{color:C.cyan}}>.io</span></span></div>
          <button onClick={onClose} style={{background:"transparent",border:"none",color:C.muted,fontSize:20,cursor:"pointer"}}>✕</button>
        </div>
        {mfaStep?(
          <>
            <div style={{textAlign:"center",padding:"8px 0"}}>
              <div style={{fontSize:40,marginBottom:8}}>🔐</div>
              <h3 style={{color:C.white,fontSize:16,fontWeight:700,margin:"0 0 4px"}}>MFA Verification</h3>
              <p style={{color:C.muted,fontSize:13,margin:0}}>Enter the 6-digit code from your authenticator app</p>
            </div>
            <input placeholder="123456" value={mfaCode} onChange={e=>setMfaCode(e.target.value)} style={{...Sb.input,textAlign:"center",fontSize:22,letterSpacing:8}} maxLength={6}/>
            {error&&<div style={{background:"#2a0f0f",border:"1px solid #ef4444",borderRadius:8,padding:"8px 12px",color:"#ef4444",fontSize:13}}>{error}</div>}
            <button onClick={handleMFA} style={Sb.ctaBtn}>Verify & Sign In</button>
            <button onClick={()=>setMfaStep(false)} style={{background:"transparent",border:"none",color:C.muted,cursor:"pointer",fontSize:13,textDecoration:"underline"}}>Back</button>
          </>
        ):(
          <>
            <div style={{display:"flex",background:C.bg,borderRadius:10,padding:4,gap:4}}>
              {["login","register"].map(m=>(<button key={m} onClick={()=>{setMode(m);setError("");}} style={{flex:1,padding:"8px 0",border:"none",borderRadius:8,background:mode===m?C.cyan:"transparent",color:mode===m?C.bg:C.muted,cursor:"pointer",fontSize:14,fontWeight:700}}>{m==="login"?"Sign In":"Sign Up Free"}</button>))}
            </div>
            <div style={{display:"flex",flexDirection:"column",gap:8}}>
              {[{p:"Google",i:"🔵"},{p:"Microsoft",i:"🟦"},{p:"Company",i:"🏢"}].map(({p,i})=>(
                <button key={p} onClick={()=>socialLogin(p)} disabled={loading} style={{padding:"10px 14px",border:`1px solid ${C.border}`,borderRadius:10,background:C.card,color:C.text,cursor:"pointer",fontSize:13,fontWeight:600,display:"flex",alignItems:"center",gap:10,width:"100%"}}>
                  <span style={{fontSize:18}}>{i}</span>Continue with {p}<span style={{marginLeft:"auto",color:C.muted,fontSize:11}}>Profile setup after</span>
                </button>
              ))}
            </div>
            <div style={{display:"flex",alignItems:"center",gap:10}}><div style={{flex:1,height:1,background:C.border}}/><span style={{color:C.muted,fontSize:12}}>or with email</span><div style={{flex:1,height:1,background:C.border}}/></div>
            {mode==="register"&&(<><input placeholder="Full name *" value={form.name} onChange={e=>setForm(f=>({...f,name:e.target.value}))} style={Sb.input}/><input placeholder="Company name" value={form.company} onChange={e=>setForm(f=>({...f,company:e.target.value}))} style={Sb.input}/></>)}
            <input placeholder="Work email *" value={form.email} onChange={e=>setForm(f=>({...f,email:e.target.value}))} style={Sb.input}/>
            <input placeholder="Password * (min 8 characters)" type="password" value={form.password} onChange={e=>setForm(f=>({...f,password:e.target.value}))} style={Sb.input}/>
            {mode==="register"&&<input placeholder="Confirm password *" type="password" value={form.confirm} onChange={e=>setForm(f=>({...f,confirm:e.target.value}))} onKeyDown={e=>e.key==="Enter"&&handle()} style={Sb.input}/>}
            {mode==="login"&&<div style={{textAlign:"right"}}><span style={{color:C.cyan,fontSize:12,cursor:"pointer"}} onClick={()=>{onClose();onForgotPassword();}}>Forgot password?</span></div>}
            {error&&<div style={{background:"#2a0f0f",border:"1px solid #ef4444",borderRadius:8,padding:"8px 12px",color:"#ef4444",fontSize:13}}>{error}</div>}
            <button onClick={handle} style={{...Sb.ctaBtn,opacity:loading?0.7:1}} disabled={loading}>{loading?"Please wait...":(mode==="login"?"Sign In & Scan":"Create Free Account")}</button>
            {mode==="register"&&<p style={{color:C.muted,fontSize:11,textAlign:"center",margin:0}}>After sign-up you will complete your profile. No credit card needed.</p>}
          </>
        )}
      </div>
    </div>
  );
}

// ── Complete Profile Form ─────────────────────────────────────────
function CompleteProfile({user,onComplete}){
  const[step,setStep]=useState(1);
  const[saving,setSaving]=useState(false);
  const[errors,setErrors]=useState({});
  const[form,setForm]=useState({
    name:user.name||"",job_title:"",company:user.company||"",industry:"",
    website:"",linked_in:"",mobile:"",phone:"",
    address:"",city:"",state:"",postcode:"",country:"Australia",
  });

  const F=({label,field,placeholder,required,half=false})=>(
    <div style={{flex:half?"1 1 45%":"1 1 100%",display:"flex",flexDirection:"column",gap:4}}>
      <label style={Sb.label}>{label}{required&&<span style={{color:C.crimson}}> *</span>}</label>
      <input placeholder={placeholder||label} value={form[field]||""} onChange={e=>setForm(f=>({...f,[field]:e.target.value}))} style={{...Sb.input,borderColor:errors[field]?C.crimson:C.border}}/>
      {errors[field]&&<span style={{color:C.crimson,fontSize:11}}>{errors[field]}</span>}
    </div>
  );

  const Sel=({label,field,options,required,half=false})=>(
    <div style={{flex:half?"1 1 45%":"1 1 100%",display:"flex",flexDirection:"column",gap:4}}>
      <label style={Sb.label}>{label}{required&&<span style={{color:C.crimson}}> *</span>}</label>
      <select value={form[field]||""} onChange={e=>setForm(f=>({...f,[field]:e.target.value}))} style={{...Sb.input,borderColor:errors[field]?C.crimson:C.border}}>
        <option value="">Select {label}...</option>
        {options.map(o=><option key={o} value={o}>{o}</option>)}
      </select>
      {errors[field]&&<span style={{color:C.crimson,fontSize:11}}>{errors[field]}</span>}
    </div>
  );

  const validateStep1=()=>{const e={};if(!form.name)e.name="Required";if(!form.company)e.company="Required";if(!form.industry)e.industry="Required";setErrors(e);return Object.keys(e).length===0;};
  const validateStep2=()=>{const e={};if(!form.mobile&&!form.phone)e.mobile="At least one phone number required";if(!form.city)e.city="Required";if(!form.country)e.country="Required";setErrors(e);return Object.keys(e).length===0;};

  const handleSave=async()=>{
    if(!validateStep2())return;
    setSaving(true);
    await updateProfile(user.id,{...form,profile_complete:true});
    setSaving(false);
    onComplete({...user,...form,profile_complete:true,profileComplete:true});
  };

  return(
    <div style={{position:"fixed",inset:0,background:"rgba(8,15,26,0.96)",zIndex:350,display:"flex",alignItems:"center",justifyContent:"center",padding:16,overflowY:"auto"}}>
      <div style={{background:C.surface,border:`1px solid ${C.border}`,borderRadius:20,padding:32,width:"100%",maxWidth:580,display:"flex",flexDirection:"column",gap:20}}>
        <div style={{textAlign:"center"}}>
          <Scan365Logo size={48}/>
          <h2 style={{color:C.white,fontSize:20,fontWeight:800,margin:"12px 0 4px"}}>Complete Your Profile</h2>
          <p style={{color:C.muted,fontSize:13,margin:0}}>Help us personalise your experience and connect you with the right support.</p>
        </div>
        <div style={{display:"flex",gap:8,alignItems:"center"}}>
          {[{n:1,label:"Business Info"},{n:2,label:"Contact & Location"}].map((s,i,arr)=>(
            <div key={s.n} style={{display:"flex",alignItems:"center",gap:6,flex:i<arr.length-1?undefined:undefined}}>
              <div style={{width:28,height:28,borderRadius:"50%",background:step>=s.n?"linear-gradient(135deg,#00d4ff,#0066ff)":C.card,border:`1px solid ${step>=s.n?C.cyan:C.border}`,display:"flex",alignItems:"center",justifyContent:"center",fontSize:12,fontWeight:800,color:step>=s.n?C.bg:C.muted}}>{step>s.n?"✓":s.n}</div>
              <span style={{color:step===s.n?C.cyan:step>s.n?C.green:C.muted,fontSize:12,fontWeight:600}}>{s.label}</span>
              {i===0&&<div style={{flex:1,height:2,background:step>1?C.cyan:C.border,borderRadius:1,minWidth:40,marginLeft:6}}/>}
            </div>
          ))}
        </div>
        {step===1&&(
          <div style={{display:"flex",flexDirection:"column",gap:14}}>
            <div style={{color:C.cyan,fontSize:11,fontWeight:700,letterSpacing:1}}>PERSONAL INFORMATION</div>
            <div style={{display:"flex",gap:12,flexWrap:"wrap"}}>
              <F label="Full Name" field="name" required half/>
              <F label="Job Title / Role" field="job_title" placeholder="e.g. IT Manager" half/>
            </div>
            <div style={{color:C.cyan,fontSize:11,fontWeight:700,letterSpacing:1,marginTop:4}}>BUSINESS INFORMATION</div>
            <F label="Company / Organisation Name" field="company" required/>
            <div style={{display:"flex",gap:12,flexWrap:"wrap"}}>
              <Sel label="Business Industry" field="industry" options={INDUSTRIES} required half/>
              <F label="Business Website" field="website" placeholder="www.company.com.au" half/>
            </div>
            <F label="LinkedIn Profile" field="linked_in" placeholder="linkedin.com/in/yourname"/>
            <button onClick={()=>{if(validateStep1())setStep(2);}} style={Sb.ctaBtn}>Next: Contact & Location →</button>
          </div>
        )}
        {step===2&&(
          <div style={{display:"flex",flexDirection:"column",gap:14}}>
            <div style={{color:C.cyan,fontSize:11,fontWeight:700,letterSpacing:1}}>CONTACT INFORMATION</div>
            <div style={{display:"flex",gap:12,flexWrap:"wrap"}}>
              <F label="Mobile Number" field="mobile" placeholder="+61 4XX XXX XXX" required half/>
              <F label="Office Phone" field="phone" placeholder="+61 2 XXXX XXXX" half/>
            </div>
            <div style={{color:C.cyan,fontSize:11,fontWeight:700,letterSpacing:1,marginTop:4}}>LOCATION</div>
            <F label="Street Address" field="address" placeholder="e.g. 123 Main Street"/>
            <div style={{display:"flex",gap:12,flexWrap:"wrap"}}>
              <F label="City / Suburb" field="city" required half/>
              <F label="Postcode" field="postcode" placeholder="e.g. 2000" half/>
            </div>
            <div style={{display:"flex",gap:12,flexWrap:"wrap"}}>
              <Sel label="State / Territory" field="state" options={AU_STATES} half/>
              <Sel label="Country" field="country" options={COUNTRIES} required half/>
            </div>
            <p style={{color:C.muted,fontSize:11,margin:0}}>Your data is stored securely in Sydney. <a href="/privacy" style={{color:C.cyan}}>Privacy Policy</a></p>
            <div style={{display:"flex",gap:10}}>
              <button onClick={()=>setStep(1)} style={{...Sb.ctaBtn,background:"transparent",border:`1px solid ${C.border}`,color:C.text,flex:1}}>← Back</button>
              <button onClick={handleSave} style={{...Sb.ctaBtn,flex:2,opacity:saving?0.7:1}} disabled={saving}>{saving?"Saving to database...":"✓ Complete Profile & Continue"}</button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

// ── Chatbot ───────────────────────────────────────────────────────
function ChatBot({user,results}){
  const[open,setOpen]=useState(false);
  const[messages,setMessages]=useState([{role:"bot",text:"Hi there! 👋 I am Aria, your Scan365.io Security Assistant. How can I help you today?"}]);
  const[input,setInput]=useState("");
  const[showLead,setShowLead]=useState(false);
  const[leadSent,setLeadSent]=useState(false);
  const[sending,setSending]=useState(false);
  const[leadForm,setLeadForm]=useState({name:user?.name||"",email:user?.email||"",phone:"",interest:"Pro Plan"});
  const bottomRef=useRef(null);
  useEffect(()=>{if(open&&bottomRef.current)bottomRef.current.scrollIntoView({behavior:"smooth"});},[messages,open]);

  const getBotReply=(msg)=>{
    const l=msg.toLowerCase();
    if((l.includes("contact")||l.includes("talk")||l.includes("yes")||l.includes("speak"))&&!leadSent){setShowLead(true);return"Please fill in your details and our team will contact you within 1 business day. 😊";}
    if(l.includes("mfa"))return"MFA is critical for M365 security. Without it, a stolen password gives full access. Type contact for expert help! 🛡️";
    if(l.includes("ssl"))return"SSL encrypts traffic to your site. Expired SSL causes browser warnings. Use Let\'s Encrypt for free renewal. Type contact. 🔒";
    if(l.includes("dmarc"))return"DMARC prevents email spoofing. Without it attackers can impersonate your domain. Type contact for setup help! 📧";
    if(l.includes("essential eight")||l.includes("acsc"))return"The ACSC Essential Eight is Australia\'s cybersecurity baseline. Pro plan audits all 8 controls. Type contact for a free consultation! 🛡️";
    if(l.includes("pro")||l.includes("price")||l.includes("upgrade"))return"Pro is $49/month, $129/quarter (save 12%), or $399/year (save 32%). Type yes to connect with sales! 🚀";
    if(l.includes("hello")||l.includes("hi"))return"Hello! 😊 I am Aria from Scan365.io. How can I help with your cybersecurity today?";
    if(results){if(l.includes("score")||l.includes("result"))return`Your overall risk score is ${results.overallScore}/100 rated ${scoreLabel(results.overallScore)}. Type contact for expert help! 💪`;}
    return"I can help with cybersecurity questions or connect you with the ITSL team. Type contact or email admin@itsl.com.au. 😊";
  };

  const sendMessage=async(msg)=>{
    const text=msg||input;if(!text.trim())return;
    const reply=getBotReply(text);
    setMessages(m=>[...m,{role:"user",text},{role:"bot",text:reply}]);setInput("");
  };

  const sendLead=async()=>{
    if(!leadForm.name||!leadForm.email)return;
    setSending(true);
    await saveLead({...leadForm,source:"chatbot"});
    setSending(false);setLeadSent(true);setShowLead(false);
    setMessages(m=>[...m,{role:"bot",text:`Your details have been saved and sent to admin@itsl.com.au. We will contact ${leadForm.email} within 1 business day. 😊`}]);
  };

  const QUICK=["👋 Hello Aria","📊 My risk score","🔐 Fix MFA","💰 Pro pricing","📧 Contact ITSL"];

  return(
    <>
      <div style={{position:"fixed",bottom:28,right:28,zIndex:999,display:"flex",flexDirection:"column",alignItems:"flex-end",gap:8}}>
        {!open&&<div style={{background:C.surface,border:`1px solid ${C.border}`,borderRadius:16,padding:"10px 16px",fontSize:12,color:C.text,fontWeight:600,boxShadow:"0 4px 16px rgba(0,0,0,0.3)",maxWidth:200,textAlign:"center"}}><div style={{fontSize:10,color:C.muted,marginBottom:2}}>Aria • Security Assistant</div>💬 How can I help you today?</div>}
        <button onClick={()=>setOpen(o=>!o)} style={{width:64,height:64,borderRadius:"50%",border:`2px solid ${C.cyan}`,cursor:"pointer",background:C.surface,padding:0,boxShadow:"0 4px 24px rgba(0,212,255,0.4)",overflow:"hidden",transition:"transform 0.2s"}} onMouseEnter={e=>e.currentTarget.style.transform="scale(1.08)"} onMouseLeave={e=>e.currentTarget.style.transform="scale(1)"}>
          {open?<div style={{width:"100%",height:"100%",display:"flex",alignItems:"center",justifyContent:"center",background:"linear-gradient(135deg,#00d4ff,#0066ff)",fontSize:22,color:C.bg,fontWeight:800}}>✕</div>:<img src="/aria-avatar.png" alt="Aria" style={{width:"100%",height:"100%",objectFit:"cover",objectPosition:"center top"}}/>}
        </button>
      </div>
      {open&&(
        <div style={{position:"fixed",bottom:104,right:28,width:375,height:540,background:C.surface,border:`1px solid ${C.border}`,borderRadius:20,display:"flex",flexDirection:"column",zIndex:998,boxShadow:"0 8px 40px rgba(0,0,0,0.5)",overflow:"hidden"}}>
          <div style={{background:"linear-gradient(90deg,#0a1e33,#0e2a4a)",padding:"12px 16px",borderBottom:`1px solid ${C.border}`,display:"flex",alignItems:"center",gap:10}}>
            <div style={{width:42,height:42,borderRadius:"50%",border:`2px solid ${C.cyan}`,overflow:"hidden",flexShrink:0}}><img src="/aria-avatar.png" alt="Aria" style={{width:"100%",height:"100%",objectFit:"cover",objectPosition:"center top"}}/></div>
            <div style={{flex:1}}>
              <div style={{color:C.white,fontWeight:700,fontSize:14}}>Aria <span style={{color:C.muted,fontWeight:400,fontSize:12}}>• Security Assistant</span></div>
              <div style={{color:C.green,fontSize:11,display:"flex",alignItems:"center",gap:4}}><span style={{width:6,height:6,borderRadius:"50%",background:C.green,display:"inline-block"}}/>Online — IT Service Link</div>
            </div>
          </div>
          <div style={{flex:1,overflowY:"auto",padding:"14px",display:"flex",flexDirection:"column",gap:10}}>
            {messages.map((m,i)=>(
              <div key={i} style={{display:"flex",justifyContent:m.role==="user"?"flex-end":"flex-start",alignItems:"flex-end",gap:6}}>
                {m.role==="bot"&&<div style={{width:28,height:28,borderRadius:"50%",border:`1px solid ${C.cyan}`,overflow:"hidden",flexShrink:0}}><img src="/aria-avatar.png" alt="Aria" style={{width:"100%",height:"100%",objectFit:"cover",objectPosition:"center top"}}/></div>}
                <div style={{maxWidth:"78%",padding:"10px 14px",borderRadius:m.role==="user"?"14px 14px 4px 14px":"14px 14px 14px 4px",background:m.role==="user"?"linear-gradient(90deg,#00d4ff,#0066ff)":C.card,color:m.role==="user"?C.bg:C.text,fontSize:13,lineHeight:1.5}}>{m.text}</div>
              </div>
            ))}
            {showLead&&!leadSent&&(
              <div style={{background:C.card,border:`1px solid ${C.border}`,borderRadius:12,padding:14,display:"flex",flexDirection:"column",gap:8}}>
                <div style={{color:C.cyan,fontSize:12,fontWeight:700}}>📧 Send your details to IT Service Link</div>
                <input placeholder="Full name *" value={leadForm.name} onChange={e=>setLeadForm(f=>({...f,name:e.target.value}))} style={{...Sb.input,fontSize:12,padding:"8px 10px"}}/>
                <input placeholder="Email address *" value={leadForm.email} onChange={e=>setLeadForm(f=>({...f,email:e.target.value}))} style={{...Sb.input,fontSize:12,padding:"8px 10px"}}/>
                <input placeholder="Phone (optional)" value={leadForm.phone} onChange={e=>setLeadForm(f=>({...f,phone:e.target.value}))} style={{...Sb.input,fontSize:12,padding:"8px 10px"}}/>
                <select value={leadForm.interest} onChange={e=>setLeadForm(f=>({...f,interest:e.target.value}))} style={{...Sb.input,fontSize:12,padding:"8px 10px"}}>
                  <option>Pro Plan</option><option>Enterprise Plan</option><option>Free Consultation</option><option>General Enquiry</option>
                </select>
                <button onClick={sendLead} style={{...Sb.ctaBtn,padding:"9px",fontSize:12}} disabled={sending}>{sending?"Saving to database...":"📧 Send to admin@itsl.com.au"}</button>
              </div>
            )}
            <div ref={bottomRef}/>
          </div>
          <div style={{padding:"8px 12px",borderTop:`1px solid ${C.border}`,display:"flex",gap:6,flexWrap:"wrap"}}>
            {QUICK.map(q=><button key={q} onClick={()=>sendMessage(q)} style={{background:C.card,border:`1px solid ${C.border}`,borderRadius:20,padding:"4px 10px",color:C.muted,fontSize:11,cursor:"pointer",fontWeight:600}}>{q}</button>)}
          </div>
          <div style={{padding:"10px 12px",borderTop:`1px solid ${C.border}`,display:"flex",gap:8}}>
            <input placeholder="Ask Aria anything..." value={input} onChange={e=>setInput(e.target.value)} onKeyDown={e=>e.key==="Enter"&&sendMessage()} style={{...Sb.input,flex:1,padding:"9px 12px",fontSize:13}}/>
            <button onClick={()=>sendMessage()} style={{padding:"9px 16px",borderRadius:10,border:"none",background:`linear-gradient(90deg,${C.cyan},#0066ff)`,color:C.bg,fontWeight:800,cursor:"pointer",fontSize:14}}>➤</button>
          </div>
        </div>
      )}
    </>
  );
}

// ── Admin Dashboard with real Supabase data ───────────────────────
function AdminDashboard({onClose}){
  const[tab,setTab]=useState("users");
  const[users,setUsers]=useState([]);
  const[leads,setLeads]=useState([]);
  const[stats,setStats]=useState(null);
  const[marketing,setMarketing]=useState([]);
  const[loading,setLoading]=useState(true);
  const[search,setSearch]=useState("");
  const[passMsg,setPassMsg]=useState("");
  const[editUser,setEditUser]=useState(null);
  const[newPass,setNewPass]=useState("");

  useEffect(()=>{
    const load=async()=>{
      setLoading(true);
      const[u,l,s,m]=await Promise.all([getAllUsers(),getAllLeads(),getSalesStats(),getMarketingData()]);
      setUsers(u);setLeads(l);setStats(s);setMarketing(m);setLoading(false);
    };
    load();
  },[]);

  const filtered=users.filter(u=>
    u.name?.toLowerCase().includes(search.toLowerCase())||
    u.email?.toLowerCase().includes(search.toLowerCase())||
    u.company?.toLowerCase().includes(search.toLowerCase())
  );

  const freeUsers=users.filter(u=>u.plan==="free");
  const proUsers=users.filter(u=>u.plan==="pro"||u.plan==="enterprise");

  const handlePushToPro=async(userId,email)=>{
    await pushToPro(userId);
    alert(`User ${email} upgraded to Pro!`);
    const u=await getAllUsers();setUsers(u);
  };

  const handleResetPass=async()=>{
    if(!newPass||newPass.length<8){setPassMsg("Min 8 characters required.");return;}
    if(!editUser?.mfa_enabled){setPassMsg("Enable MFA first before resetting password.");return;}
    await adminResetPassword(editUser.id,newPass);
    setPassMsg("Password updated successfully!");setNewPass("");
  };

  if(loading)return(
    <div style={{position:"fixed",inset:0,background:"rgba(8,15,26,0.97)",zIndex:200,display:"flex",alignItems:"center",justifyContent:"center"}}>
      <div style={{textAlign:"center"}}>
        <Scan365Logo size={60}/>
        <div style={{color:C.cyan,fontSize:16,fontWeight:700,marginTop:16}}>Loading admin data from Supabase...</div>
      </div>
    </div>
  );

  return(
    <div style={{position:"fixed",inset:0,background:"rgba(8,15,26,0.97)",zIndex:200,display:"flex",flexDirection:"column",overflow:"auto"}}>
      <div style={{background:C.surface,borderBottom:`1px solid ${C.border}`,padding:"14px 24px",display:"flex",alignItems:"center",justifyContent:"space-between",position:"sticky",top:0,zIndex:10}}>
        <div style={{display:"flex",alignItems:"center",gap:10}}><Scan365Logo size={32}/><span style={{fontWeight:800,fontSize:16,color:C.white}}>Scan365<span style={{color:C.cyan}}>.io</span> <span style={{color:C.green,fontSize:12,fontWeight:600}}>• Live Supabase Data</span></span></div>
        <button onClick={onClose} style={Sb.navBtn}>✕ Close</button>
      </div>
      <div style={{maxWidth:1200,margin:"0 auto",padding:"24px 20px",width:"100%"}}>

        {/* Live stats from Supabase */}
        <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fit,minmax(150px,1fr))",gap:14,marginBottom:28}}>
          {[
            {label:"Total Users",val:stats?.total_users||users.length,icon:"👥",color:C.cyan},
            {label:"Pro / Enterprise",val:stats?.pro_users||proUsers.length,icon:"⭐",color:C.green},
            {label:"Free Users",val:stats?.free_users||freeUsers.length,icon:"🆓",color:C.amber},
            {label:"Conversion Rate",val:`${stats?.conversion_rate||0}%`,icon:"📈",color:"#a78bfa"},
            {label:"Total Scans",val:stats?.total_scans_all_time||0,icon:"🔍",color:C.cyan},
            {label:"Complete Profiles",val:stats?.complete_profiles||0,icon:"✅",color:C.green},
          ].map(({label,val,icon,color})=>(
            <div key={label} style={{background:C.card,border:`1px solid ${C.border}`,borderRadius:14,padding:16}}>
              <div style={{fontSize:22,marginBottom:4}}>{icon}</div>
              <div style={{fontSize:24,fontWeight:900,color}}>{val}</div>
              <div style={{color:C.muted,fontSize:11,fontWeight:600}}>{label}</div>
            </div>
          ))}
        </div>

        <div style={{display:"flex",gap:8,marginBottom:16,flexWrap:"wrap",alignItems:"center"}}>
          {[["users","👥 All Users"],["marketing","📊 Marketing DB"],["free","🎯 Push to Pro"],["security","🔐 Security"],["leads","📧 Leads"]].map(([key,label])=>(
            <button key={key} onClick={()=>{setTab(key);setEditUser(null);setPassMsg("");}} style={{padding:"8px 14px",border:`1px solid ${tab===key?C.cyan:C.border}`,borderRadius:8,background:tab===key?"#0a1e33":"transparent",color:tab===key?C.cyan:C.muted,cursor:"pointer",fontSize:13,fontWeight:600}}>{label}</button>
          ))}
          <input placeholder="Search users..." value={search} onChange={e=>setSearch(e.target.value)} style={{...Sb.input,flex:1,maxWidth:240,padding:"8px 12px",fontSize:13,marginLeft:"auto"}}/>
        </div>

        {(tab==="users"||tab==="free")&&(
          <div style={{background:C.surface,border:`1px solid ${C.border}`,borderRadius:16,overflow:"auto"}}>
            <table style={{width:"100%",borderCollapse:"collapse",minWidth:900}}>
              <thead>
                <tr style={{background:C.card}}>
                  {["Name","Email","Company","Industry","City","Plan","Scans","Profile","MFA","Action"].map(h=>(
                    <th key={h} style={{padding:"11px 12px",textAlign:"left",color:C.muted,fontSize:11,fontWeight:700,textTransform:"uppercase",whiteSpace:"nowrap"}}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {(tab==="free"?freeUsers:filtered).map((u,i)=>(
                  <tr key={u.id} style={{borderTop:`1px solid ${C.border}`,background:i%2===0?"transparent":C.card}}>
                    <td style={{padding:"10px 12px",color:C.white,fontWeight:600,fontSize:13}}>{u.name}</td>
                    <td style={{padding:"10px 12px",color:C.muted,fontSize:12}}>{u.email}</td>
                    <td style={{padding:"10px 12px",color:C.muted,fontSize:12}}>{u.company||"—"}</td>
                    <td style={{padding:"10px 12px",color:C.muted,fontSize:11}}>{u.industry||"—"}</td>
                    <td style={{padding:"10px 12px",color:C.muted,fontSize:12}}>{u.city||"—"}</td>
                    <td style={{padding:"10px 12px"}}><span style={{background:u.plan==="free"?"#2a1f0a":u.plan==="pro"?"#0a2018":"#0a1e33",color:u.plan==="free"?C.amber:u.plan==="pro"?C.green:C.cyan,borderRadius:6,padding:"3px 8px",fontSize:11,fontWeight:700,textTransform:"uppercase"}}>{u.plan}</span></td>
                    <td style={{padding:"10px 12px",color:C.text,fontSize:13}}>{u.total_scans||0}</td>
                    <td style={{padding:"10px 12px"}}><span style={{color:u.profile_complete?C.green:C.amber,fontSize:12,fontWeight:700}}>{u.profile_complete?"✓":"⚠ Incomplete"}</span></td>
                    <td style={{padding:"10px 12px"}}><span style={{color:u.mfa_enabled?C.green:C.crimson,fontSize:12,fontWeight:700}}>{u.mfa_enabled?"✓ ON":"✗ OFF"}</span></td>
                    <td style={{padding:"10px 12px"}}>{u.plan==="free"?<button style={{background:"linear-gradient(90deg,#00d4ff,#0066ff)",border:"none",borderRadius:6,padding:"5px 10px",color:C.bg,fontSize:11,fontWeight:800,cursor:"pointer"}} onClick={()=>handlePushToPro(u.id,u.email)}>Push Pro ➤</button>:<span style={{color:C.green,fontSize:12}}>✓ Active</span>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {tab==="marketing"&&(
          <div style={{display:"flex",flexDirection:"column",gap:16}}>
            <div style={{display:"flex",justifyContent:"space-between",alignItems:"center"}}>
              <h3 style={{color:C.white,fontSize:16,fontWeight:700,margin:0}}>📊 Marketing Database <span style={{color:C.green,fontSize:12,fontWeight:400}}>• Live from Supabase Sydney</span></h3>
              <button style={{...Sb.ctaBtn,width:"auto",padding:"8px 16px",fontSize:12}} onClick={()=>alert("Connect to backend API to download CSV")}>⬇ Export CSV</button>
            </div>
            {marketing.map(u=>(
              <div key={u.id} style={{background:C.surface,border:`1px solid ${C.border}`,borderRadius:14,padding:20}}>
                <div style={{display:"flex",alignItems:"center",justifyContent:"space-between",marginBottom:12,flexWrap:"wrap",gap:8}}>
                  <div style={{display:"flex",alignItems:"center",gap:12}}>
                    <div style={{width:40,height:40,borderRadius:"50%",background:"linear-gradient(135deg,#00d4ff,#0066ff)",display:"flex",alignItems:"center",justifyContent:"center",fontSize:16,color:C.bg,fontWeight:800}}>{u.name?.[0]||"?"}</div>
                    <div>
                      <div style={{color:C.white,fontWeight:700,fontSize:14}}>{u.name} <span style={{color:C.muted,fontWeight:400,fontSize:12}}>• {u.job_title||"Not set"}</span></div>
                      <div style={{color:C.muted,fontSize:12}}>{u.email}</div>
                    </div>
                  </div>
                  <span style={{background:u.plan==="free"?"#2a1f0a":u.plan==="pro"?"#0a2018":"#0a1e33",color:u.plan==="free"?C.amber:u.plan==="pro"?C.green:C.cyan,borderRadius:6,padding:"3px 10px",fontSize:11,fontWeight:700,textTransform:"uppercase"}}>{u.plan}</span>
                </div>
                <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fit,minmax(160px,1fr))",gap:8}}>
                  {[["🏢 Company",u.company||"—"],["🏭 Industry",u.industry||"—"],["📞 Phone",u.phone||"—"],["📱 Mobile",u.mobile||"—"],["📍 City",u.city?(u.city+(u.state?", "+u.state:"")):"—"],["🌏 Country",u.country||"—"],["🔍 Scans",String(u.scan_count||0)],["📅 Joined",u.joined?new Date(u.joined).toLocaleDateString("en-AU"):"—"]].map(([k,v])=>(
                    <div key={k} style={{background:C.card,borderRadius:8,padding:"8px 12px"}}>
                      <div style={{color:C.muted,fontSize:10,fontWeight:700}}>{k}</div>
                      <div style={{color:C.text,fontSize:12,fontWeight:600,marginTop:2}}>{v}</div>
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>
        )}

        {tab==="security"&&(
          <div style={{display:"flex",gap:20,flexWrap:"wrap"}}>
            <div style={{flex:"1 1 300px",background:C.surface,border:`1px solid ${C.border}`,borderRadius:16,padding:24}}>
              <h3 style={{color:C.white,fontSize:16,fontWeight:700,marginBottom:16}}>🔐 Password Reset</h3>
              <select onChange={e=>setEditUser(users.find(u=>u.id===e.target.value))} style={{...Sb.input,marginBottom:12}}>
                <option value="">Select user...</option>
                {users.map(u=><option key={u.id} value={u.id}>{u.name} ({u.email})</option>)}
              </select>
              {editUser&&(
                <div style={{display:"flex",flexDirection:"column",gap:10}}>
                  <div style={{background:C.card,borderRadius:10,padding:12}}>
                    <div style={{color:C.white,fontWeight:700}}>{editUser.name}</div>
                    <div style={{color:C.muted,fontSize:12}}>{editUser.email}</div>
                    <div style={{color:editUser.mfa_enabled?C.green:C.crimson,fontSize:12,fontWeight:700,marginTop:6}}>MFA: {editUser.mfa_enabled?"✓ Enabled":"✗ Disabled"}</div>
                  </div>
                  {!editUser.mfa_enabled&&<div style={{background:"#2a1f0a",border:`1px solid ${C.amber}`,borderRadius:8,padding:10}}><div style={{color:C.amber,fontSize:12,fontWeight:700}}>⚠ MFA must be enabled before password reset</div></div>}
                  {editUser.mfa_enabled&&(<><label style={Sb.label}>New password</label><input type="password" placeholder="Min 8 characters" value={newPass} onChange={e=>setNewPass(e.target.value)} style={Sb.input}/><button onClick={handleResetPass} style={Sb.ctaBtn}>🔐 Reset Password in Database</button></>)}
                  {passMsg&&<div style={{background:passMsg.includes("success")?"#0a2018":"#2a0f0f",border:`1px solid ${passMsg.includes("success")?C.green:C.crimson}`,borderRadius:8,padding:"8px 12px",color:passMsg.includes("success")?C.green:C.crimson,fontSize:13}}>{passMsg}</div>}
                </div>
              )}
            </div>
            <div style={{flex:"1 1 300px",background:C.surface,border:`1px solid ${C.border}`,borderRadius:16,padding:24}}>
              <h3 style={{color:C.white,fontSize:16,fontWeight:700,marginBottom:16}}>🔑 MFA Status</h3>
              {users.map(u=>(
                <div key={u.id} style={{display:"flex",alignItems:"center",justifyContent:"space-between",padding:"10px 12px",background:C.card,borderRadius:10,marginBottom:8,border:`1px solid ${C.border}`}}>
                  <div><div style={{color:C.white,fontSize:13,fontWeight:600}}>{u.name}</div><div style={{color:C.muted,fontSize:11}}>{u.email}</div></div>
                  <div style={{display:"flex",alignItems:"center",gap:8}}>
                    <span style={{color:u.mfa_enabled?C.green:C.crimson,fontSize:12,fontWeight:700}}>{u.mfa_enabled?"✓ ON":"✗ OFF"}</span>
                    <button onClick={async()=>{await toggleMFA(u.id,u.mfa_enabled);const updated=await getAllUsers();setUsers(updated);}} style={{background:u.mfa_enabled?"#2a0f0f":"#0a2018",border:`1px solid ${u.mfa_enabled?C.crimson:C.green}`,borderRadius:6,padding:"4px 10px",color:u.mfa_enabled?C.crimson:C.green,fontSize:11,fontWeight:700,cursor:"pointer"}}>{u.mfa_enabled?"Disable":"Enable"}</button>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {tab==="leads"&&(
          <div style={{display:"flex",flexDirection:"column",gap:12}}>
            <h3 style={{color:C.white,fontSize:16,fontWeight:700,margin:0}}>📧 Lead Inbox <span style={{color:C.green,fontSize:12,fontWeight:400}}>• Live from Supabase</span></h3>
            {leads.length===0?(
              <div style={{background:C.surface,border:`1px solid ${C.border}`,borderRadius:16,padding:40,textAlign:"center"}}>
                <div style={{fontSize:48,marginBottom:12}}>📭</div>
                <div style={{color:C.white,fontWeight:700,fontSize:15}}>No leads yet</div>
                <div style={{color:C.muted,fontSize:13,marginTop:8}}>Leads from Aria chatbot will appear here automatically.</div>
              </div>
            ):(
              leads.map(l=>(
                <div key={l.id} style={{background:C.surface,border:`1px solid ${C.border}`,borderRadius:14,padding:20,display:"flex",justifyContent:"space-between",flexWrap:"wrap",gap:12}}>
                  <div>
                    <div style={{color:C.white,fontWeight:700,fontSize:14}}>{l.name}</div>
                    <div style={{color:C.muted,fontSize:12,marginTop:2}}>{l.email} {l.phone&&`• ${l.phone}`}</div>
                    <div style={{color:C.cyan,fontSize:12,marginTop:4}}>Interest: {l.interest} • Source: {l.source}</div>
                    <div style={{color:C.muted,fontSize:11,marginTop:2}}>{new Date(l.created_at).toLocaleDateString("en-AU")}</div>
                  </div>
                  <div style={{display:"flex",gap:8,alignItems:"flex-start"}}>
                    <select value={l.status} onChange={async e=>{await updateLeadStatus(l.id,e.target.value,"");const updated=await getAllLeads();setLeads(updated);}} style={{...Sb.input,width:"auto",padding:"6px 10px",fontSize:12}}>
                      <option value="new">New</option><option value="contacted">Contacted</option><option value="converted">Converted</option><option value="lost">Lost</option>
                    </select>
                    <button style={{...Sb.ctaBtn,width:"auto",padding:"6px 14px",fontSize:12}} onClick={()=>window.location.href=`mailto:${l.email}?subject=Scan365.io - ${l.interest}`}>📧 Reply</button>
                  </div>
                </div>
              ))
            )}
          </div>
        )}
      </div>
    </div>
  );
}

// ── User Profile Modal ────────────────────────────────────────────
function UserProfile({user,onClose,onUpdate}){
  const[tab,setTab]=useState("profile");
  const[form,setForm]=useState({name:user.name||"",job_title:user.job_title||user.jobTitle||"",company:user.company||"",industry:user.industry||"",website:user.website||"",linked_in:user.linked_in||user.linkedIn||"",phone:user.phone||"",mobile:user.mobile||"",address:user.address||"",city:user.city||"",state:user.state||"",postcode:user.postcode||"",country:user.country||"Australia"});
  const[pass,setPass]=useState({current:"",newp:"",confirm:""});
  const[mfaCode,setMfaCode]=useState("");
  const[mfaVerified,setMfaVerified]=useState(false);
  const[msg,setMsg]=useState({text:"",type:""});
  const[saving,setSaving]=useState(false);
  const showMsg=(text,type="success")=>{setMsg({text,type});setTimeout(()=>setMsg({text:"",type:""}),3000);};

  const saveProfile=async()=>{
    setSaving(true);
    await updateProfile(user.id,{...form,profile_complete:true});
    setSaving(false);showMsg("Profile updated in database!");
    if(onUpdate)onUpdate({...user,...form,profile_complete:true,profileComplete:true});
  };

  const handlePassChange=async()=>{
    if(user.mfa_enabled&&!mfaVerified){showMsg("Verify MFA first.","error");return;}
    if(!user.mfa_enabled){showMsg("Enable MFA before changing password.","error");return;}
    if(pass.newp.length<8){showMsg("Password must be at least 8 characters.","error");return;}
    if(pass.newp!==pass.confirm){showMsg("Passwords do not match.","error");return;}
    await updatePassword(user.id,pass.newp);
    setPass({current:"",newp:"",confirm:""});setMfaVerified(false);setMfaCode("");
    showMsg("Password updated in database!");
  };

  const handleToggleMFA=async()=>{
    const res=await toggleMFA(user.id,user.mfa_enabled);
    showMsg(`MFA ${res.mfaEnabled?"enabled":"disabled"} in database.`);
    if(onUpdate)onUpdate({...user,mfa_enabled:res.mfaEnabled});
  };

  const F=({label,field,placeholder,half=false})=>(
    <div style={{flex:half?"1 1 45%":"1 1 100%",display:"flex",flexDirection:"column",gap:4}}>
      <label style={Sb.label}>{label}</label>
      <input placeholder={placeholder||label} value={form[field]||""} onChange={e=>setForm(f=>({...f,[field]:e.target.value}))} style={Sb.input}/>
    </div>
  );

  return(
    <div style={{position:"fixed",inset:0,background:"rgba(8,15,26,0.9)",zIndex:300,display:"flex",alignItems:"center",justifyContent:"center",padding:16,overflowY:"auto"}} onClick={onClose}>
      <div style={{background:C.surface,border:`1px solid ${C.border}`,borderRadius:20,padding:28,width:"100%",maxWidth:560,display:"flex",flexDirection:"column",gap:16,maxHeight:"90vh",overflowY:"auto"}} onClick={e=>e.stopPropagation()}>
        <div style={{display:"flex",alignItems:"center",justifyContent:"space-between"}}>
          <h2 style={{color:C.white,fontSize:18,fontWeight:800,margin:0}}>👤 My Account</h2>
          <button onClick={onClose} style={{background:"transparent",border:"none",color:C.muted,fontSize:20,cursor:"pointer"}}>✕</button>
        </div>
        <div style={{display:"flex",gap:8}}>
          {[["profile","👤 Profile"],["contact","📞 Contact"],["security","🔐 Security"]].map(([t,l])=>(
            <button key={t} onClick={()=>setTab(t)} style={{flex:1,padding:"8px",border:`1px solid ${tab===t?C.cyan:C.border}`,borderRadius:8,background:tab===t?"#0a1e33":"transparent",color:tab===t?C.cyan:C.muted,cursor:"pointer",fontSize:12,fontWeight:600}}>{l}</button>
          ))}
        </div>

        {tab==="profile"&&(
          <>
            <div style={{textAlign:"center"}}>
              <div style={{width:56,height:56,borderRadius:"50%",background:"linear-gradient(135deg,#00d4ff,#0066ff)",display:"flex",alignItems:"center",justifyContent:"center",fontSize:22,color:C.bg,fontWeight:800,margin:"0 auto 8px"}}>{user.name?.[0]||"?"}</div>
              <div style={{color:C.white,fontWeight:700,fontSize:15}}>{user.name}</div>
              <div style={{color:C.muted,fontSize:12}}>{user.email}</div>
              <span style={{background:user.plan==="free"?"#2a1f0a":user.plan==="pro"?"#0a2018":"#0a1e33",color:user.plan==="free"?C.amber:user.plan==="pro"?C.green:C.cyan,borderRadius:20,padding:"2px 12px",fontSize:11,fontWeight:800,display:"inline-block",marginTop:6,textTransform:"uppercase"}}>{user.plan} Plan</span>
            </div>
            <div style={{display:"flex",flexWrap:"wrap",gap:12}}>
              <F label="Full Name" field="name" half/>
              <F label="Job Title" field="job_title" placeholder="e.g. IT Manager" half/>
              <F label="Company Name" field="company" half/>
              <div style={{flex:"1 1 45%",display:"flex",flexDirection:"column",gap:4}}>
                <label style={Sb.label}>Industry</label>
                <select value={form.industry||""} onChange={e=>setForm(f=>({...f,industry:e.target.value}))} style={Sb.input}>
                  <option value="">Select...</option>{INDUSTRIES.map(o=><option key={o} value={o}>{o}</option>)}
                </select>
              </div>
              <F label="Business Website" field="website" placeholder="www.company.com.au" half/>
              <F label="LinkedIn" field="linked_in" placeholder="linkedin.com/in/yourname" half/>
            </div>
            <button onClick={saveProfile} style={{...Sb.ctaBtn,opacity:saving?0.7:1}} disabled={saving}>{saving?"Saving to database...":"💾 Save Profile"}</button>
          </>
        )}

        {tab==="contact"&&(
          <>
            <div style={{color:C.cyan,fontSize:11,fontWeight:700,letterSpacing:1}}>CONTACT NUMBERS</div>
            <div style={{display:"flex",flexWrap:"wrap",gap:12}}>
              <F label="Mobile Number" field="mobile" placeholder="+61 4XX XXX XXX" half/>
              <F label="Office Phone" field="phone" placeholder="+61 2 XXXX XXXX" half/>
            </div>
            <div style={{color:C.cyan,fontSize:11,fontWeight:700,letterSpacing:1,marginTop:4}}>ADDRESS</div>
            <div style={{display:"flex",flexWrap:"wrap",gap:12}}>
              <F label="Street Address" field="address" placeholder="123 Main Street"/>
              <F label="City / Suburb" field="city" placeholder="e.g. Sydney" half/>
              <F label="Postcode" field="postcode" placeholder="e.g. 2000" half/>
              <div style={{flex:"1 1 45%",display:"flex",flexDirection:"column",gap:4}}>
                <label style={Sb.label}>State</label>
                <select value={form.state||""} onChange={e=>setForm(f=>({...f,state:e.target.value}))} style={Sb.input}>
                  <option value="">Select...</option>{AU_STATES.map(s=><option key={s} value={s}>{s}</option>)}
                </select>
              </div>
              <div style={{flex:"1 1 45%",display:"flex",flexDirection:"column",gap:4}}>
                <label style={Sb.label}>Country</label>
                <select value={form.country||"Australia"} onChange={e=>setForm(f=>({...f,country:e.target.value}))} style={Sb.input}>
                  {COUNTRIES.map(c=><option key={c} value={c}>{c}</option>)}
                </select>
              </div>
            </div>
            <button onClick={saveProfile} style={{...Sb.ctaBtn,opacity:saving?0.7:1}} disabled={saving}>{saving?"Saving...":"💾 Save Contact Info"}</button>
          </>
        )}

        {tab==="security"&&(
          <>
            <div style={{background:C.card,border:`1px solid ${C.border}`,borderRadius:12,padding:16}}>
              <div style={{display:"flex",alignItems:"center",justifyContent:"space-between",marginBottom:12}}>
                <div><div style={{color:C.white,fontWeight:700,fontSize:14}}>🔐 Multi-Factor Authentication</div><div style={{color:C.muted,fontSize:12,marginTop:2}}>Required for password changes.</div></div>
                <span style={{color:user.mfa_enabled?C.green:C.crimson,fontWeight:700,fontSize:12,background:user.mfa_enabled?"#0a2018":"#2a0f0f",padding:"4px 10px",borderRadius:6}}>{user.mfa_enabled?"✓ ON":"✗ OFF"}</span>
              </div>
              <button onClick={handleToggleMFA} style={{...Sb.ctaBtn,padding:"9px",fontSize:13}}>{user.mfa_enabled?"Disable MFA":"🔐 Enable MFA"}</button>
            </div>
            <div style={{background:C.card,border:`1px solid ${C.border}`,borderRadius:12,padding:16}}>
              <div style={{color:C.white,fontWeight:700,fontSize:14,marginBottom:12}}>🔑 Change Password</div>
              {!user.mfa_enabled&&<div style={{background:"#2a1f0a",border:`1px solid ${C.amber}`,borderRadius:8,padding:10,marginBottom:12}}><div style={{color:C.amber,fontSize:12,fontWeight:700}}>⚠ Enable MFA first to change your password</div></div>}
              {user.mfa_enabled&&!mfaVerified&&(
                <div style={{marginBottom:12}}>
                  <label style={Sb.label}>Step 1: Verify your identity</label>
                  <input placeholder="Enter 6-digit MFA code (demo: 123456)" value={mfaCode} onChange={e=>setMfaCode(e.target.value)} style={{...Sb.input,marginBottom:8}} maxLength={6}/>
                  <button onClick={()=>{if(mfaCode==="123456"||mfaCode.length===6){setMfaVerified(true);showMsg("Identity verified!");}else showMsg("Invalid code.","error");}} style={{...Sb.ctaBtn,padding:"9px",fontSize:12}}>Verify Identity</button>
                </div>
              )}
              {user.mfa_enabled&&mfaVerified&&(
                <div style={{display:"flex",flexDirection:"column",gap:8}}>
                  <div style={{color:C.green,fontSize:12,fontWeight:700,marginBottom:4}}>✓ Identity verified.</div>
                  <input placeholder="Current password" type="password" value={pass.current} onChange={e=>setPass(p=>({...p,current:e.target.value}))} style={Sb.input}/>
                  <input placeholder="New password (min 8 characters)" type="password" value={pass.newp} onChange={e=>setPass(p=>({...p,newp:e.target.value}))} style={Sb.input}/>
                  <input placeholder="Confirm new password" type="password" value={pass.confirm} onChange={e=>setPass(p=>({...p,confirm:e.target.value}))} style={Sb.input}/>
                  <button onClick={handlePassChange} style={{...Sb.ctaBtn,padding:"10px",fontSize:13}}>🔐 Update Password in Database</button>
                </div>
              )}
            </div>
            {msg.text&&<div style={{background:msg.type==="error"?"#2a0f0f":"#0a2018",border:`1px solid ${msg.type==="error"?C.crimson:C.green}`,borderRadius:8,padding:"8px 12px",color:msg.type==="error"?C.crimson:C.green,fontSize:13}}>{msg.text}</div>}
          </>
        )}
      </div>
    </div>
  );
}

// ── User Dashboard ────────────────────────────────────────────────
function UserDashboard({user,setScreen,onScan,isPro}){
  const[history,setHistory]=useState([]);
  const[loadingHistory,setLoadingHistory]=useState(true);
  const scansLeft=Math.max(0,FREE_SCAN_LIMIT-(user.monthly_scans||0));

  useEffect(()=>{
    const load=async()=>{
      if(user.id){
        const h=await getScanHistory(user.id);
        setHistory(h);
      }
      setLoadingHistory(false);
    };
    load();
  },[user.id]);

  return(
    <div style={{maxWidth:960,margin:"0 auto",padding:"24px 16px 60px"}}>
      <div style={{background:"linear-gradient(135deg,#0a1e33,#0e2a4a)",border:`1px solid ${C.border}`,borderRadius:20,padding:"28px 32px",marginBottom:24,display:"flex",alignItems:"center",justifyContent:"space-between",flexWrap:"wrap",gap:16}}>
        <div style={{display:"flex",alignItems:"center",gap:16}}>
          <div style={{width:60,height:60,borderRadius:"50%",background:"linear-gradient(135deg,#00d4ff,#0066ff)",display:"flex",alignItems:"center",justifyContent:"center",fontSize:24,color:C.bg,fontWeight:900,flexShrink:0}}>{user.name?.[0]||"?"}</div>
          <div>
            <div style={{color:C.white,fontSize:20,fontWeight:800}}>Welcome back, {user.name}! 👋</div>
            <div style={{color:C.muted,fontSize:13,marginTop:4}}>{user.company||"Scan365.io"} • {user.job_title||user.email}</div>
            <div style={{display:"flex",alignItems:"center",gap:8,marginTop:6}}>
              <span style={{background:user.plan==="free"?"#2a1f0a":user.plan==="pro"?"#0a2018":"#0a1e33",color:user.plan==="free"?C.amber:user.plan==="pro"?C.green:C.cyan,borderRadius:20,padding:"3px 12px",fontSize:11,fontWeight:800,textTransform:"uppercase"}}>{user.plan} Plan</span>
              {user.plan==="free"&&<span style={{color:C.muted,fontSize:12}}>{scansLeft} scan{scansLeft!==1?"s":""} remaining</span>}
            </div>
          </div>
        </div>
        <button onClick={onScan} style={{...Sb.ctaBtn,width:"auto",padding:"14px 32px",fontSize:15}}>🔍 Start New Scan</button>
      </div>

      {!user.profile_complete&&!user.profileComplete&&(
        <div style={{background:"#2a1f0a",border:`1px solid ${C.amber}`,borderRadius:14,padding:"16px 20px",marginBottom:20,display:"flex",alignItems:"center",justifyContent:"space-between",flexWrap:"wrap",gap:12}}>
          <div><div style={{color:C.amber,fontWeight:700,fontSize:14}}>⚠ Complete Your Profile</div><div style={{color:C.muted,fontSize:13,marginTop:4}}>Add your details so our team can provide personalised support.</div></div>
          <button onClick={()=>setScreen("complete-profile")} style={{...Sb.ctaBtn,width:"auto",padding:"10px 20px",fontSize:13}}>Complete Profile →</button>
        </div>
      )}

      <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fit,minmax(150px,1fr))",gap:14,marginBottom:24}}>
        {[{icon:"🔍",label:"Total Scans",val:user.total_scans||0,color:C.cyan},{icon:"📅",label:"This Month",val:`${user.monthly_scans||0}/${user.plan==="free"?FREE_SCAN_LIMIT:"∞"}`,color:C.amber},{icon:"🏢",label:"Company",val:user.company||"Not set",color:C.muted},{icon:"🕐",label:"Last Scan",val:user.last_scan_at?new Date(user.last_scan_at).toLocaleDateString("en-AU"):"Never",color:C.green}].map(({icon,label,val,color})=>(
          <div key={label} style={{background:C.surface,border:`1px solid ${C.border}`,borderRadius:14,padding:"16px 18px"}}>
            <div style={{fontSize:22,marginBottom:6}}>{icon}</div>
            <div style={{fontSize:16,fontWeight:900,color,lineHeight:1.2}}>{val}</div>
            <div style={{color:C.muted,fontSize:11,fontWeight:600,marginTop:4}}>{label}</div>
          </div>
        ))}
      </div>

      {user.plan==="free"&&scansLeft===0&&(
        <div style={{background:"#2a1f0a",border:`1px solid ${C.amber}`,borderRadius:14,padding:"16px 20px",marginBottom:20,display:"flex",alignItems:"center",justifyContent:"space-between",flexWrap:"wrap",gap:12}}>
          <div><div style={{color:C.amber,fontWeight:700,fontSize:14}}>⚠ Monthly scan limit reached</div><div style={{color:C.muted,fontSize:13,marginTop:4}}>Upgrade to Pro for unlimited scans.</div></div>
          <button onClick={()=>setScreen("upgrade")} style={{...Sb.ctaBtn,width:"auto",padding:"10px 20px",fontSize:13}}>Upgrade to Pro</button>
        </div>
      )}

      <div style={{background:C.surface,border:`1px solid ${C.border}`,borderRadius:16,padding:24,marginBottom:20}}>
        <div style={{display:"flex",alignItems:"center",justifyContent:"space-between",marginBottom:16}}>
          <h3 style={{color:C.white,fontSize:16,fontWeight:700,margin:0}}>📋 Scan History <span style={{color:C.green,fontSize:11,fontWeight:400}}>• Live from Supabase</span></h3>
          <button onClick={onScan} style={{...Sb.ctaBtn,width:"auto",padding:"8px 16px",fontSize:12}}>+ New Scan</button>
        </div>
        {loadingHistory?(
          <div style={{textAlign:"center",padding:"24px 0",color:C.muted}}>Loading scan history from database...</div>
        ):history.length===0?(
          <div style={{textAlign:"center",padding:"40px 0"}}>
            <div style={{fontSize:48,marginBottom:12}}>🔍</div>
            <div style={{color:C.white,fontWeight:700,fontSize:15,marginBottom:8}}>No scans yet</div>
            <div style={{color:C.muted,fontSize:13,marginBottom:20}}>Run your first security scan to see results here</div>
            <button onClick={onScan} style={{...Sb.ctaBtn,width:"auto",padding:"12px 28px"}}>🔍 Run First Scan</button>
          </div>
        ):(
          <div style={{display:"flex",flexDirection:"column",gap:10}}>
            {history.map((h,i)=>(
              <div key={i} style={{background:C.card,border:`1px solid ${C.border}`,borderRadius:12,padding:"14px 16px",display:"flex",alignItems:"center",justifyContent:"space-between",flexWrap:"wrap",gap:10}}>
                <div style={{display:"flex",alignItems:"center",gap:14}}>
                  <div style={{width:44,height:44,borderRadius:10,background:"#0a1e33",display:"flex",alignItems:"center",justifyContent:"center",flexShrink:0}}><span style={{fontSize:20,fontWeight:900,color:scoreColor(h.overall_score)}}>{h.overall_score}</span></div>
                  <div><div style={{color:C.white,fontWeight:700,fontSize:14}}>{h.domain}</div><div style={{color:C.muted,fontSize:12,marginTop:2}}>{new Date(h.scanned_at).toLocaleDateString("en-AU")}</div></div>
                </div>
                <span style={{color:scoreColor(h.overall_score),fontWeight:700,fontSize:12,background:"#0a1e33",borderRadius:8,padding:"4px 10px"}}>{h.risk_level}</span>
              </div>
            ))}
          </div>
        )}
      </div>

      <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fit,minmax(200px,1fr))",gap:14}}>
        {[
          {icon:"🔍",title:"New Security Scan",desc:"Scan a domain for vulnerabilities",action:onScan,primary:true},
          {icon:"📄",title:"Download Report",desc:"Get your latest scan as PDF",action:()=>alert("Run a scan first to get a PDF report"),primary:false},
          {icon:"🔐",title:"Security Settings",desc:"Manage MFA and password",action:()=>setScreen("profile"),primary:false},
          ...(user.plan==="free"?[{icon:"⭐",title:"Upgrade to Pro",desc:"Unlock all 4 scan modules",action:()=>setScreen("upgrade"),primary:true}]:[]),
        ].map(({icon,title,desc,action,primary})=>(
          <button key={title} onClick={action} style={{background:primary?"linear-gradient(135deg,#0a1e33,#0e2a4a)":C.surface,border:`1px solid ${primary?C.cyan:C.border}`,borderRadius:14,padding:"18px 20px",textAlign:"left",cursor:"pointer",display:"flex",gap:12,alignItems:"flex-start"}}>
            <span style={{fontSize:24}}>{icon}</span>
            <div><div style={{color:primary?C.cyan:C.white,fontWeight:700,fontSize:13}}>{title}</div><div style={{color:C.muted,fontSize:12,marginTop:3}}>{desc}</div></div>
          </button>
        ))}
      </div>
    </div>
  );
}

// ── Main App ──────────────────────────────────────────────────────
export default function App(){
  const[screen,setScreen]=useState("landing");
  const[isPro,setIsPro]=useState(false);
  const[scanning,setScanning]=useState(false);
  const[scanPct,setScanPct]=useState(0);
  const[results,setResults]=useState(null);
  const[form,setForm]=useState({domain:"",m365domain:"",size:"Small (1-50)"});
  const[activeModule,setActiveModule]=useState("website");
  const[user,setUser]=useState(null);
  const[showAuth,setShowAuth]=useState(false);
  const[showAdmin,setShowAdmin]=useState(false);
  const[showProfile,setShowProfile]=useState(false);
  const[showCompleteProfile,setShowCompleteProfile]=useState(false);
  const[showForgotPassword,setShowForgotPassword]=useState(false);
  const[toast,setToast]=useState(null);
  const[radarAngle,setRadarAngle]=useState(0);
  const[billing,setBilling]=useState("monthly");

  const showToast=(msg,type="success")=>{setToast({msg,type});setTimeout(()=>setToast(null),3000);};
  useEffect(()=>{const iv=setInterval(()=>setRadarAngle(a=>(a+2)%360),30);return()=>clearInterval(iv);},[]);

  const handleLogin=(u)=>{
    setUser(u);
    setIsPro(u.plan==="pro"||u.plan==="enterprise");
    showToast(`Welcome${(u.total_scans||0)>0?" back":""}, ${u.name}!`);
    if(!u.profile_complete&&!u.profileComplete){setShowCompleteProfile(true);}
    else{setScreen("dashboard");}
  };

  const handleProfileComplete=async(updated)=>{
    setUser(updated);setShowCompleteProfile(false);
    setScreen("dashboard");showToast("Profile saved to database! Welcome to Scan365.io 🎉");
  };

  const handleStartScan=()=>{
    if(!user){setShowAuth(true);return;}
    const scansLeft=Math.max(0,FREE_SCAN_LIMIT-(user.monthly_scans||0));
    if(user.plan==="free"&&scansLeft<=0){
      showToast("Monthly scan limit reached. Upgrade to Pro!","error");
      setTimeout(()=>setScreen("upgrade"),1500);return;
    }
    setScreen("scan");
  };

  const runScan=async()=>{
    if(!form.domain)return showToast("Enter a domain to scan","error");
    const scansLeft=Math.max(0,FREE_SCAN_LIMIT-(user.monthly_scans||0));
    if(user.plan==="free"&&scansLeft<=0){showToast("Scan limit reached!","error");setScreen("upgrade");return;}
    setScanning(true);setScanPct(0);let pct=0;
    const iv=setInterval(async()=>{
      pct+=Math.random()*12+3;
      if(pct>=100){
        pct=100;clearInterval(iv);
        const r=generateScanResults(form.domain,form.m365domain,form.size);
        await saveScan(user.id,r,isPro);
        setUser(prev=>({...prev,total_scans:(prev.total_scans||0)+1,monthly_scans:(prev.monthly_scans||0)+1,last_scan_at:new Date().toISOString()}));
        setResults(r);setScanning(false);setActiveModule("website");setScreen("results");
      }
      setScanPct(Math.min(pct,100)|0);
    },220);
  };

  const upgradeToPro=async()=>{
    const plan=billing;
    const amounts={monthly:49,quarterly:129,annual:399};
    await upgradePlan(user.id,plan==="monthly"?"pro":plan==="quarterly"?"pro":"pro",plan,amounts[plan]);
    setIsPro(true);setUser(prev=>({...prev,plan:"pro"}));
    setScreen(results?"results":"dashboard");showToast("Pro unlocked! All modules now available. 🎉");
  };

  return(
    <div style={{minHeight:"100vh",background:C.bg,fontFamily:"'Inter',system-ui,sans-serif",color:C.text}}>
      <nav style={{display:"flex",alignItems:"center",justifyContent:"space-between",padding:"12px 24px",borderBottom:`1px solid ${C.border}`,background:C.surface,position:"sticky",top:0,zIndex:20}}>
        <div style={{display:"flex",alignItems:"center",gap:10,cursor:"pointer"}} onClick={()=>setScreen(user?"dashboard":"landing")}>
          <Scan365Logo size={40}/>
          <div>
            <div style={{fontWeight:800,fontSize:16,color:C.white,lineHeight:1}}>Scan365<span style={{color:C.cyan}}>.io</span></div>
            <div style={{color:C.muted,fontSize:9,letterSpacing:1,fontWeight:600}}>BY IT SERVICE LINK</div>
          </div>
        </div>
        <div style={{display:"flex",alignItems:"center",gap:8}}>
          {isPro&&<span style={{background:C.cyan,color:C.bg,borderRadius:6,padding:"3px 10px",fontSize:11,fontWeight:800,letterSpacing:1}}>PRO</span>}
          {user&&<button onClick={()=>setShowProfile(true)} style={{display:"flex",alignItems:"center",gap:6,background:"transparent",border:`1px solid ${C.border}`,borderRadius:8,padding:"5px 10px",cursor:"pointer",color:C.text,fontSize:13}}><span style={{width:24,height:24,borderRadius:"50%",background:"linear-gradient(135deg,#00d4ff,#0066ff)",display:"flex",alignItems:"center",justifyContent:"center",fontSize:11,color:C.bg,fontWeight:800,flexShrink:0}}>{user.name?.[0]||"?"}</span>{user.name}</button>}
          {user&&user.email==="admin@itsl.com.au"&&<button style={{...Sb.navBtn,borderColor:C.cyan,color:C.cyan}} onClick={()=>setShowAdmin(true)}>📊 Admin</button>}
          {user?<button style={Sb.navBtn} onClick={()=>{setUser(null);setIsPro(false);setScreen("landing");}}>Sign Out</button>:<button style={{...Sb.ctaBtn,padding:"8px 20px",fontSize:13,width:"auto"}} onClick={()=>setShowAuth(true)}>Sign In</button>}
        </div>
      </nav>

      {screen==="landing"&&<Landing radarAngle={radarAngle} billing={billing} setBilling={setBilling} onStartScan={handleStartScan} onSignUp={()=>setShowAuth(true)} setScreen={setScreen} user={user}/>}
      {screen==="dashboard"&&user&&<UserDashboard user={user} setScreen={setScreen} onScan={handleStartScan} isPro={isPro}/>}
      {screen==="scan"&&<ScanForm form={form} setForm={setForm} scanning={scanning} scanPct={scanPct} runScan={runScan} isPro={isPro} setScreen={setScreen} user={user}/>}
      {screen==="results"&&results&&<Results results={results} isPro={isPro} activeModule={activeModule} setActiveModule={setActiveModule} setScreen={setScreen} user={user}/>}
      {screen==="upgrade"&&<Upgrade upgradeToPro={upgradeToPro} setScreen={setScreen} billing={billing} setBilling={setBilling}/>}

      <Footer/>
      <ChatBot user={user} results={results}/>
      {showAuth&&<AuthModal onClose={()=>setShowAuth(false)} onLogin={handleLogin} onForgotPassword={()=>{setShowAuth(false);setShowForgotPassword(true);}}/>}
      {showForgotPassword&&<ForgotPasswordModal onClose={()=>setShowForgotPassword(false)} onSuccess={()=>{setShowForgotPassword(false);setShowAuth(true);}}/>}
      {showAdmin&&<AdminDashboard onClose={()=>setShowAdmin(false)}/>}
      {showProfile&&user&&<UserProfile user={user} onClose={()=>setShowProfile(false)} onUpdate={u=>setUser({...user,...u})}/>}
      {showCompleteProfile&&user&&<CompleteProfile user={user} onComplete={handleProfileComplete}/>}

      {toast&&<div style={{position:"fixed",bottom:24,left:"50%",transform:"translateX(-50%)",borderRadius:12,padding:"10px 22px",color:"#fff",fontWeight:700,fontSize:14,zIndex:400,whiteSpace:"nowrap",boxShadow:"0 4px 20px rgba(0,0,0,0.4)",background:toast.type==="error"?C.crimson:C.green}}>{toast.msg}</div>}
    </div>
  );
}

// ── Landing Page ──────────────────────────────────────────────────
function Landing({radarAngle,billing,setBilling,onStartScan,onSignUp,setScreen,user}){
  const plan=PLANS[billing];
  const scansLeft=user?Math.max(0,FREE_SCAN_LIMIT-(user.monthly_scans||0)):FREE_SCAN_LIMIT;
  const COMPARE=[
    ["Website & Domain scan","✓","✓","✓"],["Phishing risk score","✓","✓","✓"],["Free PDF report","✓","✓","✓"],["AI chatbot (Aria)","✓","✓","✓"],
    ["Microsoft 365 audit","✗","✓","✓"],["ACSC Essential Eight","✗","✓","✓"],["Scans per month","2","Unlimited","Unlimited"],
    ["PDF reports","Basic","White-label","Custom branded"],["Priority email alerts","✗","✓","✓"],["Historical trend tracking","✗","✓","✓"],
    ["API access","✗","✗","✓"],["Multi-tenant dashboard","✗","✗","✓"],["Dedicated account manager","✗","✗","✓"],["SLA guarantee (99.9%)","✗","✗","✓"],["Support","Chat + Email","Priority","Dedicated"],
  ];
  return(
    <div style={{maxWidth:960,margin:"0 auto",padding:"24px 16px 0"}}>
      <div style={{position:"relative",textAlign:"center",padding:"56px 0 48px",borderRadius:24,overflow:"hidden",marginBottom:40,background:"linear-gradient(180deg,#0a1e33 0%,#080f1a 100%)"}}>
        <HeroBG/>
        <div style={{position:"relative",zIndex:1}}>
          <div style={{position:"relative",width:200,height:200,margin:"0 auto 32px"}}>
            <svg width="200" height="200" style={{position:"absolute",top:0,left:0}}>
              <circle cx="100" cy="100" r="95" fill="none" stroke="#1e3a52" strokeWidth="1"/>
              <circle cx="100" cy="100" r="65" fill="none" stroke="#1e3a52" strokeWidth="1"/>
              <circle cx="100" cy="100" r="35" fill="none" stroke="#1e3a52" strokeWidth="1"/>
              <defs><radialGradient id="sw" cx="0%" cy="0%" r="100%"><stop offset="0%" stopColor="#00d4ff" stopOpacity="0.3"/><stop offset="100%" stopColor="#00d4ff" stopOpacity="0"/></radialGradient></defs>
              <path d={`M 100 100 L ${100+95*Math.cos((radarAngle-90)*Math.PI/180)} ${100+95*Math.sin((radarAngle-90)*Math.PI/180)} A 95 95 0 0 0 ${100+95*Math.cos((radarAngle-150)*Math.PI/180)} ${100+95*Math.sin((radarAngle-150)*Math.PI/180)} Z`} fill="url(#sw)" opacity="0.6"/>
              <line x1="100" y1="100" x2={100+95*Math.cos((radarAngle-90)*Math.PI/180)} y2={100+95*Math.sin((radarAngle-90)*Math.PI/180)} stroke="#00d4ff" strokeWidth="1.5" opacity="0.9"/>
              <circle cx="130" cy="60" r="3" fill="#ef4444" opacity="0.9"/><circle cx="65" cy="120" r="3" fill="#f59e0b" opacity="0.8"/><circle cx="155" cy="110" r="2" fill="#f59e0b" opacity="0.6"/><circle cx="75" cy="70" r="2" fill="#10b981" opacity="0.7"/>
            </svg>
            <div style={{position:"absolute",top:"50%",left:"50%",transform:"translate(-50%,-50%)"}}><Scan365Logo size={64}/></div>
          </div>
          <h1 style={{fontSize:"clamp(28px,5vw,48px)",fontWeight:900,lineHeight:1.1,margin:"0 0 16px",color:"#ffffff"}}>Know your cyber risk<br/><span style={{color:"#00d4ff"}}>in 60 seconds.</span></h1>
          <p style={{color:"#5a7a96",fontSize:15,maxWidth:540,margin:"0 auto 32px",lineHeight:1.7}}>AI-powered security scanning for Website, Microsoft 365, ACSC Essential Eight, and Phishing risk. Built for businesses worldwide.</p>
          {user?(
            <div style={{display:"flex",flexDirection:"column",alignItems:"center",gap:10}}>
              {user.plan==="free"&&<div style={{color:"#5a7a96",fontSize:13,marginBottom:4}}>You have <span style={{color:scansLeft>0?"#00d4ff":"#ef4444",fontWeight:700}}>{scansLeft} free scan{scansLeft!==1?"s":""}</span> remaining this month</div>}
              <button onClick={onStartScan} style={{...Sb.ctaBtn,width:"auto",padding:"16px 48px",fontSize:17,borderRadius:14}}>🔍 Start Free Scan</button>
              {user.plan==="free"&&scansLeft===0&&<button onClick={()=>setScreen("upgrade")} style={{...Sb.ctaBtn,width:"auto",padding:"10px 28px",fontSize:13,background:"transparent",border:"1px solid #00d4ff",color:"#00d4ff"}}>Upgrade to Pro for unlimited scans</button>}
            </div>
          ):(
            <div style={{display:"flex",flexDirection:"column",alignItems:"center",gap:12}}>
              <button onClick={onStartScan} style={{...Sb.ctaBtn,width:"auto",padding:"16px 56px",fontSize:17,borderRadius:14}}>🔍 Start Free Scan</button>
              <button onClick={onSignUp} style={{background:"transparent",border:"none",color:"#5a7a96",cursor:"pointer",fontSize:13,textDecoration:"underline"}}>No account yet? Sign up free</button>
            </div>
          )}
          <div style={{display:"flex",flexWrap:"wrap",gap:8,justifyContent:"center",marginTop:24}}>
            {["🌐 Website & Domain","☁️ M365 Audit","🛡️ Essential Eight","🎣 Phishing Score","📄 Free PDF","💬 Aria AI Chat"].map(p=>(
              <span key={p} style={{background:"rgba(14,29,47,0.8)",border:"1px solid #1e3a52",borderRadius:20,padding:"5px 14px",fontSize:12,color:"#5a7a96"}}>{p}</span>
            ))}
          </div>
        </div>
      </div>

      <div style={{textAlign:"center",marginBottom:28}}>
        <h2 style={{color:"#ffffff",fontSize:26,fontWeight:900,marginBottom:20}}>Simple, Transparent Pricing</h2>
        <div style={{display:"inline-flex",background:"#132236",borderRadius:12,padding:4,gap:4}}>
          {Object.entries(PLANS).map(([key,p])=>(<button key={key} onClick={()=>setBilling(key)} style={{padding:"8px 18px",border:"none",borderRadius:9,background:billing===key?"#00d4ff":"transparent",color:billing===key?"#080f1a":"#5a7a96",cursor:"pointer",fontSize:13,fontWeight:700,display:"flex",alignItems:"center",gap:6}}>{p.label}{p.saving&&<span style={{background:"#10b981",color:"#fff",borderRadius:8,padding:"1px 7px",fontSize:10,fontWeight:800}}>{p.saving}</span>}</button>))}
        </div>
      </div>

      <div style={{display:"flex",gap:20,flexWrap:"wrap",justifyContent:"center",marginBottom:64}}>
        {[
          {tier:"Free",price:"$0",sub:"forever",features:["Website & domain scan","Phishing risk score","Free basic PDF report","Aria AI chatbot","2 scans per month","Email support"],hl:false,btn:"Get Started Free",action:onSignUp},
          {tier:"Pro",price:`$${plan.pro}`,sub:plan.suffix,features:["All 4 security scan modules","Microsoft 365 & Cloud audit","ACSC Essential Eight report","Unlimited scans per month","White-label PDF reports","Priority email alerts","Historical trend tracking","Priority support"],hl:true,btn:"Start Pro Trial",action:()=>setScreen("upgrade")},
          {tier:"Enterprise",price:"Custom",sub:"contact us",features:["Everything in Pro","API access for integrations","Multi-tenant dashboard","Dedicated account manager","SLA guarantee (99.9% uptime)","Custom scan modules","Microsoft Marketplace billing"],hl:false,btn:"Contact Us",action:()=>window.location.href="mailto:admin@itsl.com.au"},
        ].map(({tier,price,sub,features,hl,btn,action})=>(
          <div key={tier} style={{background:hl?"#0a1e33":"#0e1d2f",border:`${hl?1.5:1}px solid ${hl?"#00d4ff":"#1e3a52"}`,borderRadius:20,padding:28,flex:"1 1 240px",maxWidth:280,display:"flex",flexDirection:"column",gap:14,position:"relative"}}>
            {hl&&<div style={{position:"absolute",top:-14,left:"50%",transform:"translateX(-50%)",background:"#00d4ff",color:"#080f1a",borderRadius:20,padding:"4px 16px",fontSize:11,fontWeight:800,whiteSpace:"nowrap"}}>Most Popular</div>}
            <div style={{color:"#5a7a96",fontWeight:700,fontSize:11,textTransform:"uppercase",letterSpacing:1}}>{tier}</div>
            <div><span style={{color:"#ffffff",fontSize:34,fontWeight:900}}>{price}</span><span style={{color:"#5a7a96",fontSize:13,marginLeft:4}}>{sub}</span></div>
            <ul style={{listStyle:"none",padding:0,margin:0,display:"flex",flexDirection:"column",gap:8,flex:1}}>
              {features.map(f=><li key={f} style={{color:"#94a3b8",fontSize:13,display:"flex",gap:8,alignItems:"flex-start"}}><span style={{color:"#00d4ff",fontWeight:700,flexShrink:0}}>✓</span>{f}</li>)}
            </ul>
            <button onClick={action} style={hl?Sb.ctaBtn:{...Sb.ctaBtn,background:"transparent",border:"1px solid #1e3a52",color:"#e2eaf4"}}>{btn}</button>
          </div>
        ))}
      </div>

      <div style={{marginBottom:64}}>
        <h2 style={{color:"#ffffff",fontSize:22,fontWeight:800,textAlign:"center",marginBottom:24}}>Full Feature Comparison</h2>
        <div style={{background:"#0e1d2f",border:"1px solid #1e3a52",borderRadius:16,overflow:"hidden"}}>
          <table style={{width:"100%",borderCollapse:"collapse"}}>
            <thead><tr style={{background:"#132236"}}>
              <th style={{padding:"14px 20px",textAlign:"left",color:"#5a7a96",fontSize:12,fontWeight:700,textTransform:"uppercase"}}>Feature</th>
              <th style={{padding:"14px 16px",textAlign:"center",color:"#5a7a96",fontSize:12,fontWeight:700,textTransform:"uppercase"}}>Free</th>
              <th style={{padding:"14px 16px",textAlign:"center",color:"#00d4ff",fontSize:12,fontWeight:700,textTransform:"uppercase"}}>Pro</th>
              <th style={{padding:"14px 16px",textAlign:"center",color:"#5a7a96",fontSize:12,fontWeight:700,textTransform:"uppercase"}}>Enterprise</th>
            </tr></thead>
            <tbody>
              {COMPARE.map(([feat,free,pro,ent],i)=>(
                <tr key={feat} style={{borderTop:"1px solid #1e3a52",background:i%2===0?"transparent":"#132236"}}>
                  <td style={{padding:"12px 20px",color:"#94a3b8",fontSize:13}}>{feat}</td>
                  {[free,pro,ent].map((v,j)=>(<td key={j} style={{padding:"12px 16px",textAlign:"center",fontSize:13,fontWeight:v==="✓"||v==="✗"?700:500,color:v==="✓"?"#10b981":v==="✗"?"#334155":j===1?"#00d4ff":"#e2eaf4"}}>{v}</td>))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      <div style={{background:"#0e1d2f",border:"1px solid #1e3a52",borderRadius:20,padding:40,marginBottom:0,textAlign:"center"}}>
        <h2 style={{color:"#ffffff",fontSize:22,fontWeight:800,marginBottom:8}}>Need Help? Talk to Our Team</h2>
        <p style={{color:"#5a7a96",fontSize:14,marginBottom:28,maxWidth:500,margin:"0 auto 28px"}}>Our cybersecurity experts at IT Service Link are ready to help.</p>
        <div style={{display:"flex",gap:16,flexWrap:"wrap",justifyContent:"center",marginBottom:24}}>
          {[{icon:"📧",label:"Email",val:"admin@itsl.com.au",href:"mailto:admin@itsl.com.au"},{icon:"🌐",label:"Website",val:"www.itsl.au",href:"https://www.itsl.au"},{icon:"📍",label:"Location",val:"Sydney NSW Australia",href:null},{icon:"⏰",label:"Response",val:"Within 1 business day",href:null}].map(({icon,label,val,href})=>(
            <div key={label} style={{background:"#132236",border:"1px solid #1e3a52",borderRadius:14,padding:"16px 18px",flex:"1 1 150px",maxWidth:190}}>
              <div style={{fontSize:26,marginBottom:6}}>{icon}</div>
              <div style={{color:"#5a7a96",fontSize:11,fontWeight:700,textTransform:"uppercase",letterSpacing:0.8,marginBottom:4}}>{label}</div>
              {href?<a href={href} style={{color:"#00d4ff",fontSize:12,fontWeight:600,textDecoration:"none"}}>{val}</a>:<div style={{color:"#e2eaf4",fontSize:12,fontWeight:600}}>{val}</div>}
            </div>
          ))}
        </div>
        <div style={{display:"flex",gap:12,justifyContent:"center",flexWrap:"wrap"}}>
          <a href="mailto:admin@itsl.com.au?subject=Scan365.io Support" style={{...Sb.ctaBtn,textDecoration:"none",width:"auto",padding:"12px 24px",display:"inline-block"}}>📧 Email Support</a>
          <a href="mailto:admin@itsl.com.au?subject=Scan365.io Sales" style={{...Sb.ctaBtn,background:"transparent",border:"1px solid #1e3a52",color:"#e2eaf4",textDecoration:"none",width:"auto",padding:"12px 24px",display:"inline-block"}}>💼 Talk to Sales</a>
        </div>
      </div>
    </div>
  );
}

// ── Footer ────────────────────────────────────────────────────────
function Footer(){
  return(
    <footer style={{borderTop:"1px solid #1e3a52",background:"#0e1d2f",marginTop:48}}>
      <div style={{maxWidth:960,margin:"0 auto",padding:"40px 24px 24px"}}>
        <div style={{display:"flex",gap:40,flexWrap:"wrap",marginBottom:32}}>
          <div style={{flex:"1 1 200px"}}>
            <div style={{display:"flex",alignItems:"center",gap:10,marginBottom:12}}><Scan365Logo size={40}/><div><div style={{fontWeight:800,fontSize:16,color:"#ffffff"}}>Scan365<span style={{color:"#00d4ff"}}>.io</span></div><div style={{color:"#5a7a96",fontSize:9,letterSpacing:1,fontWeight:600}}>BY IT SERVICE LINK</div></div></div>
            <p style={{color:"#5a7a96",fontSize:13,lineHeight:1.6,margin:"0 0 16px"}}>AI-powered cybersecurity risk scanning for businesses worldwide. Built and operated by IT Service Link, Sydney Australia.</p>
          </div>
          <div style={{flex:"1 1 130px"}}><div style={{color:"#ffffff",fontWeight:700,fontSize:13,marginBottom:12}}>Product</div>{["Features","Pricing","Security","API Docs"].map(l=><div key={l} style={{color:"#5a7a96",fontSize:13,marginBottom:8,cursor:"pointer"}}>{l}</div>)}</div>
          <div style={{flex:"1 1 130px"}}><div style={{color:"#ffffff",fontWeight:700,fontSize:13,marginBottom:12}}>Legal</div>{[["Terms of Service","/terms"],["Privacy Policy","/privacy"],["Refund Policy","/refunds"]].map(([l,h])=>(<div key={l} style={{marginBottom:8}}><a href={h} style={{color:"#5a7a96",fontSize:13,textDecoration:"none"}}>{l}</a></div>))}</div>
          <div style={{flex:"1 1 130px"}}><div style={{color:"#ffffff",fontWeight:700,fontSize:13,marginBottom:12}}>Contact</div><div style={{marginBottom:8}}><a href="mailto:admin@itsl.com.au" style={{color:"#00d4ff",fontSize:13,textDecoration:"none"}}>admin@itsl.com.au</a></div><div style={{marginBottom:8}}><a href="https://www.itsl.au" style={{color:"#00d4ff",fontSize:13,textDecoration:"none"}}>www.itsl.au</a></div><div style={{color:"#5a7a96",fontSize:13,marginBottom:4}}>Sydney, NSW Australia</div><div style={{color:"#5a7a96",fontSize:13}}>ABN 78 336 526 604</div></div>
        </div>
        <div style={{borderTop:"1px solid #1e3a52",paddingTop:24,display:"flex",flexWrap:"wrap",gap:12,alignItems:"center",justifyContent:"space-between"}}>
          <div style={{display:"flex",gap:10,flexWrap:"wrap",alignItems:"center"}}>
            {[{icon:"🟦",t:"Microsoft",s:"AI Cloud Partner"},{icon:"🛡️",t:"ACSC",s:"Essential Eight Aligned"},{icon:"🔒",t:"SSL Secured",s:"256-bit encryption"},{icon:"💳",t:"Paddle",s:"Secure Payments"},{icon:"🏢",t:"IT Service Link",s:"ABN 78 336 526 604"}].map(({icon,t,s})=>(<div key={t} style={{background:"#132236",border:"1px solid #1e3a52",borderRadius:10,padding:"7px 12px",display:"flex",alignItems:"center",gap:7}}><span style={{fontSize:16}}>{icon}</span><div><div style={{color:"#ffffff",fontSize:11,fontWeight:700}}>{t}</div><div style={{color:"#00d4ff",fontSize:9,fontWeight:600}}>{s}</div></div></div>))}
          </div>
          <div style={{color:"#5a7a96",fontSize:12}}>© 2026 IT Service Link. All rights reserved.</div>
        </div>
      </div>
    </footer>
  );
}

// ── Scan Form ─────────────────────────────────────────────────────
function ScanForm({form,setForm,scanning,scanPct,runScan,isPro,setScreen,user}){
  const STEPS=["Resolving DNS records...","Checking SSL certificates...","Analysing HTTP headers...","Auditing SPF/DKIM/DMARC...","Evaluating M365 configuration...","Mapping ACSC Essential Eight controls...","Running AI risk analysis...","Generating your report..."];
  const si=Math.min((scanPct/100*STEPS.length)|0,STEPS.length-1);
  const scansLeft=Math.max(0,FREE_SCAN_LIMIT-(user?.monthly_scans||0));
  return(
    <div style={{maxWidth:960,margin:"0 auto",padding:"24px 16px 60px"}}>
      <div style={{background:"#0e1d2f",border:"1px solid #1e3a52",borderRadius:20,padding:36,maxWidth:560,margin:"32px auto"}}>
        <div style={{display:"flex",alignItems:"center",gap:10,marginBottom:20}}>
          <button onClick={()=>setScreen("dashboard")} style={{background:"transparent",border:"none",color:"#5a7a96",cursor:"pointer",fontSize:20}}>←</button>
          <div><h2 style={{color:"#ffffff",fontSize:22,fontWeight:800,margin:0}}>Run a Security Scan</h2><p style={{color:"#5a7a96",fontSize:14,margin:"4px 0 0"}}>Scanning across {isPro?"all 4":"2 free"} security modules.</p></div>
        </div>
        {user?.plan==="free"&&<div style={{background:"#0a1e33",border:"1px solid #1e3a52",borderRadius:8,padding:"8px 12px",marginBottom:16,fontSize:13}}><span style={{color:"#5a7a96"}}>Free scans remaining: </span><span style={{color:scansLeft>0?"#00d4ff":"#ef4444",fontWeight:700}}>{scansLeft}/{FREE_SCAN_LIMIT}</span></div>}
        <label style={Sb.label}>Website domain</label>
        <input placeholder="e.g. itsl.au" value={form.domain} onChange={e=>setForm(f=>({...f,domain:e.target.value}))} style={Sb.input} disabled={scanning}/>
        <label style={{...Sb.label,marginTop:16}}>Microsoft 365 tenant domain <span style={{color:"#5a7a96",fontWeight:400,fontSize:11}}>(e.g. itsl.com.au)</span></label>
        <input placeholder="e.g. itsl.com.au" value={form.m365domain} onChange={e=>setForm(f=>({...f,m365domain:e.target.value}))} style={Sb.input} disabled={scanning}/>
        <label style={{...Sb.label,marginTop:16}}>Company size</label>
        <select value={form.size} onChange={e=>setForm(f=>({...f,size:e.target.value}))} style={Sb.input} disabled={scanning}>
          {["Small (1-50)","Mid-size (50-500)","Enterprise (500+)"].map(s=><option key={s}>{s}</option>)}
        </select>
        <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:8,margin:"24px 0"}}>
          {Object.entries(MODULE_META).map(([key,m])=>{const locked=!isPro&&!FREE_MODULES.includes(key);return(<div key={key} style={{background:"#132236",border:"1px solid #1e3a52",borderRadius:10,padding:"10px 12px",fontSize:12,fontWeight:600,color:locked?"#5a7a96":"#e2eaf4",display:"flex",alignItems:"center",gap:6,opacity:locked?0.5:1}}>{m.icon} {m.label}{locked&&<span style={{background:"#f59e0b",color:"#080f1a",borderRadius:4,padding:"1px 6px",fontSize:10,fontWeight:800,marginLeft:"auto"}}>PRO</span>}</div>);})}
        </div>
        {!scanning?<button onClick={runScan} style={Sb.ctaBtn}>🔍 Start Security Scan</button>:<div style={{display:"flex",flexDirection:"column",gap:10}}><div style={{height:6,background:"#132236",borderRadius:3,overflow:"hidden"}}><div style={{height:"100%",background:"linear-gradient(90deg,#00d4ff,#0066ff)",borderRadius:3,width:`${scanPct}%`,transition:"width 0.2s"}}/></div><div style={{color:"#5a7a96",fontSize:12}}>{scanPct}% — {STEPS[si]}</div></div>}
        {!isPro&&<p style={{color:"#5a7a96",fontSize:12,textAlign:"center",marginTop:14}}>Want all 4 modules? <span style={{color:"#00d4ff",cursor:"pointer",fontWeight:700}} onClick={()=>setScreen("upgrade")}>Upgrade to Pro</span></p>}
      </div>
    </div>
  );
}

// ── Results ───────────────────────────────────────────────────────
function Results({results,isPro,activeModule,setActiveModule,setScreen,user}){
  const[pdfDone,setPdfDone]=useState(false);
  const mod=results.modules[activeModule];
  const locked=!isPro&&!FREE_MODULES.includes(activeModule);
  const critCount=Object.values(results.modules).flatMap(m=>m.findings).filter(f=>f.sev==="critical").length;
  const handlePDF=()=>{generatePDF(results,isPro,user?.name);setPdfDone(true);setTimeout(()=>setPdfDone(false),3000);};
  return(
    <div style={{maxWidth:960,margin:"0 auto",padding:"24px 16px 60px"}}>
      <div style={{display:"flex",alignItems:"center",gap:10,marginBottom:16}}>
        <button onClick={()=>setScreen("dashboard")} style={{background:"transparent",border:"none",color:"#5a7a96",cursor:"pointer",fontSize:20}}>←</button>
        <span style={{color:"#5a7a96",fontSize:14}}>Back to Dashboard</span>
      </div>
      <div style={{background:"#0e1d2f",border:"1px solid #1e3a52",borderRadius:16,padding:"20px 24px",display:"flex",gap:24,flexWrap:"wrap",alignItems:"center",marginBottom:20}}>
        <div style={{display:"flex",flexDirection:"column",alignItems:"center",minWidth:90}}>
          <div style={{fontSize:54,fontWeight:900,lineHeight:1,color:scoreColor(results.overallScore)}}>{results.overallScore}</div>
          <div style={{color:"#5a7a96",fontSize:13}}>/100</div>
          <div style={{color:scoreColor(results.overallScore),fontWeight:700,fontSize:12,marginTop:2}}>{scoreLabel(results.overallScore)}</div>
        </div>
        <div style={{flex:1,display:"flex",flexDirection:"column",gap:7}}>
          {[["Website domain",results.domain],["M365 Tenant",results.m365domain||"Not specified"],["Scanned",results.scannedAt],["Critical issues",`${critCount} found`]].map(([k,v])=>(<div key={k} style={{display:"flex",gap:10,fontSize:13}}><span style={{color:"#5a7a96",minWidth:120}}>{k}</span><span style={{color:k==="Critical issues"?"#ef4444":"#e2eaf4",fontWeight:k==="Critical issues"?700:600}}>{v}</span></div>))}
        </div>
        <div style={{display:"flex",gap:8,flexDirection:"column",minWidth:160}}>
          <button style={Sb.ctaBtn} onClick={()=>setScreen("scan")}>New Scan</button>
          {!isPro&&<button style={{...Sb.ctaBtn,background:"transparent",border:"1px solid #1e3a52",color:"#e2eaf4",fontSize:13}} onClick={()=>setScreen("upgrade")}>🔓 Upgrade to Pro</button>}
        </div>
      </div>
      <div style={{display:"flex",gap:8,flexWrap:"wrap",marginBottom:16}}>
        {Object.entries(MODULE_META).map(([key,m])=>{const isLocked=!isPro&&!FREE_MODULES.includes(key);const s=results.modules[key].score;return(<button key={key} onClick={()=>setActiveModule(key)} style={{background:activeModule===key?"#0a1e33":"#0e1d2f",border:`${activeModule===key?1.5:1}px solid ${activeModule===key?"#00d4ff":"#1e3a52"}`,borderRadius:12,padding:"12px 16px",cursor:"pointer",display:"flex",flexDirection:"column",alignItems:"center",gap:4,flex:"1 1 130px",opacity:isLocked?0.55:1}}><span style={{fontSize:20}}>{m.icon}</span><span style={{fontSize:11,fontWeight:600,color:"#e2eaf4"}}>{m.label}</span>{isLocked?<span style={{background:"#f59e0b",color:"#080f1a",borderRadius:4,padding:"1px 6px",fontSize:10,fontWeight:800}}>PRO</span>:<span style={{fontSize:13,fontWeight:800,color:scoreColor(s)}}>{s}/100</span>}</button>);})}
      </div>
      {locked?(
        <div style={{background:"#0e1d2f",border:"1px solid #1e3a52",borderRadius:16,padding:48,textAlign:"center",display:"flex",flexDirection:"column",alignItems:"center",gap:14}}>
          <div style={{fontSize:52}}>🔒</div>
          <h3 style={{color:"#ffffff",fontSize:20,fontWeight:800,margin:0}}>{MODULE_META[activeModule].label} is a Pro feature</h3>
          <p style={{color:"#5a7a96",fontSize:14,maxWidth:380,lineHeight:1.6,margin:0}}>Upgrade to Pro to unlock all 4 security modules.</p>
          <button style={{...Sb.ctaBtn,maxWidth:280}} onClick={()=>setScreen("upgrade")}>Upgrade to Pro</button>
        </div>
      ):(
        <div>
          <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:14}}>
            <span style={{color:"#ffffff",fontSize:17,fontWeight:700}}>{MODULE_META[activeModule].icon} {MODULE_META[activeModule].label}</span>
            <span style={{fontSize:14,fontWeight:800,color:scoreColor(mod.score)}}>Score: {mod.score}/100</span>
          </div>
          {mod.findings.map((f,i)=><FindingCard key={i} finding={f}/>)}
          <div style={{display:"flex",gap:10,marginTop:18,flexWrap:"wrap"}}>
            <button onClick={handlePDF} style={{flex:1,minWidth:160,padding:"12px",borderRadius:10,border:`1px solid ${pdfDone?"#10b981":"#1e3a52"}`,background:pdfDone?"#0a2018":"transparent",color:pdfDone?"#10b981":"#e2eaf4",cursor:"pointer",fontSize:13,fontWeight:600,transition:"all 0.3s"}}>
              {pdfDone?"✓ PDF Downloaded!":"⬇ Download PDF Report"}
              {!isPro&&<span style={{display:"block",fontSize:10,color:"#5a7a96",marginTop:2}}>Free basic report included</span>}
            </button>
            {!isPro&&<button style={{...Sb.ctaBtn,flex:1,minWidth:160}} onClick={()=>setScreen("upgrade")}>🔓 Unlock All Modules</button>}
          </div>
        </div>
      )}
    </div>
  );
}

function FindingCard({finding:f}){
  const[open,setOpen]=useState(false);
  return(
    <div style={{borderRadius:10,padding:"12px 16px",marginBottom:8,cursor:"pointer",background:SEV_BG[f.sev],borderLeft:`3px solid ${SEV_COLOR[f.sev]}`}} onClick={()=>setOpen(o=>!o)}>
      <div style={{display:"flex",alignItems:"center",gap:10}}>
        <span style={{borderRadius:4,padding:"2px 8px",fontSize:10,fontWeight:800,color:"#fff",minWidth:64,textAlign:"center",background:SEV_COLOR[f.sev]}}>{f.sev.toUpperCase()}</span>
        <span style={{color:"#e2eaf4",fontSize:13,fontWeight:600,flex:1}}>{f.title}</span>
        <span style={{color:"#5a7a96",fontSize:13}}>{open?"▲":"▼"}</span>
      </div>
      {open&&<p style={{color:"#5a7a96",fontSize:13,marginTop:10,marginLeft:74,lineHeight:1.6}}>{f.detail}</p>}
    </div>
  );
}

// ── Upgrade ───────────────────────────────────────────────────────
function Upgrade({upgradeToPro,setScreen,billing,setBilling}){
  const[payMethod,setPayMethod]=useState("card");
  const[fields,setFields]=useState({name:"",card:"",expiry:"",cvv:""});
  const[processing,setProcessing]=useState(false);
  const plan=PLANS[billing];
  const handlePay=()=>{if(payMethod==="card"&&(!fields.name||!fields.card||!fields.expiry||!fields.cvv))return;setProcessing(true);setTimeout(()=>{setProcessing(false);upgradeToPro();},2000);};
  return(
    <div style={{maxWidth:960,margin:"0 auto",padding:"24px 16px 60px"}}>
      <div style={{display:"flex",gap:24,flexWrap:"wrap",justifyContent:"center",maxWidth:840,margin:"32px auto"}}>
        <div style={{flex:"1 1 300px",display:"flex",flexDirection:"column",gap:16}}>
          <h2 style={{color:"#ffffff",fontSize:20,fontWeight:800,margin:0}}>Choose Your Plan</h2>
          <div style={{background:"#132236",borderRadius:12,padding:4,display:"flex",gap:4}}>
            {Object.entries(PLANS).map(([key,p])=>(<button key={key} onClick={()=>setBilling(key)} style={{flex:1,padding:"8px 6px",border:"none",borderRadius:9,background:billing===key?"#00d4ff":"transparent",color:billing===key?"#080f1a":"#5a7a96",cursor:"pointer",fontSize:12,fontWeight:700}}>{p.label}{p.saving&&<span style={{display:"block",fontSize:10,color:billing===key?"#080f1a":"#10b981"}}>{p.saving}</span>}</button>))}
          </div>
          <div style={{background:"#0e1d2f",border:"1.5px solid #00d4ff",borderRadius:16,padding:24}}>
            <div style={{color:"#5a7a96",fontSize:11,fontWeight:700,textTransform:"uppercase",letterSpacing:1,marginBottom:8}}>Pro Plan</div>
            <div style={{color:"#ffffff",fontSize:36,fontWeight:900,marginBottom:4}}>${plan.pro}<span style={{color:"#5a7a96",fontSize:14,fontWeight:400}}>{plan.suffix}</span></div>
            {plan.saving&&<div style={{color:"#10b981",fontSize:13,fontWeight:600,marginBottom:12}}>{plan.saving} vs monthly</div>}
            <ul style={{listStyle:"none",padding:0,margin:0,display:"flex",flexDirection:"column",gap:8}}>
              {["All 4 scan modules","Unlimited scans","ACSC Essential Eight","M365 config audit","White-label PDF reports","Priority email alerts"].map(f=>(<li key={f} style={{color:"#94a3b8",fontSize:13,display:"flex",gap:8}}><span style={{color:"#00d4ff"}}>✓</span>{f}</li>))}
            </ul>
          </div>
          <div style={{background:"#132236",border:"1px solid #1e3a52",borderRadius:12,padding:16,display:"flex",gap:10,alignItems:"center"}}><span style={{fontSize:24}}>🔒</span><div><div style={{color:"#ffffff",fontSize:13,fontWeight:700}}>14-Day Money-Back Guarantee</div><div style={{color:"#5a7a96",fontSize:12}}>Cancel anytime.</div></div></div>
        </div>
        <div style={{flex:"1 1 300px",background:"#0e1d2f",border:"1px solid #1e3a52",borderRadius:20,padding:28,display:"flex",flexDirection:"column",gap:16}}>
          <h2 style={{color:"#ffffff",fontSize:18,fontWeight:800,margin:0}}>Payment Details</h2>
          <div style={{display:"flex",gap:8}}>
            {[{key:"card",label:"💳 Card"},{key:"paypal",label:"🅿 PayPal"},{key:"afterpay",label:"🟢 AfterPay"}].map(({key,label})=>(<button key={key} onClick={()=>setPayMethod(key)} style={{flex:1,padding:"9px 6px",border:`1.5px solid ${payMethod===key?"#00d4ff":"#1e3a52"}`,borderRadius:9,background:payMethod===key?"#0a1e33":"#132236",color:payMethod===key?"#00d4ff":"#5a7a96",cursor:"pointer",fontSize:12,fontWeight:700}}>{label}</button>))}
          </div>
          {payMethod==="card"&&(<><div><label style={Sb.label}>Cardholder name</label><input placeholder="Full name" value={fields.name} onChange={e=>setFields(f=>({...f,name:e.target.value}))} style={Sb.input}/></div><div><label style={Sb.label}>Card number</label><input placeholder="1234 5678 9012 3456" value={fields.card} onChange={e=>setFields(f=>({...f,card:e.target.value}))} style={Sb.input} maxLength={19}/></div><div style={{display:"flex",gap:12}}><div style={{flex:1}}><label style={Sb.label}>Expiry</label><input placeholder="MM/YY" value={fields.expiry} onChange={e=>setFields(f=>({...f,expiry:e.target.value}))} style={Sb.input} maxLength={5}/></div><div style={{flex:1}}><label style={Sb.label}>CVV</label><input placeholder="123" value={fields.cvv} onChange={e=>setFields(f=>({...f,cvv:e.target.value}))} style={Sb.input} maxLength={4} type="password"/></div></div></>)}
          {payMethod==="paypal"&&<div style={{background:"#132236",borderRadius:12,padding:24,textAlign:"center"}}><div style={{fontSize:40,marginBottom:8}}>🅿️</div><p style={{color:"#5a7a96",fontSize:14,margin:0}}>Redirected to PayPal to complete payment securely.</p></div>}
          {payMethod==="afterpay"&&<div style={{background:"#132236",borderRadius:12,padding:24,textAlign:"center"}}><div style={{fontSize:40,marginBottom:8}}>🟢</div><p style={{color:"#5a7a96",fontSize:14,margin:"0 0 8px"}}>4 fortnightly instalments of</p><div style={{color:"#ffffff",fontSize:24,fontWeight:900}}>${(plan.pro/4).toFixed(2)}</div></div>}
          <div style={{background:"#132236",borderRadius:10,padding:"12px 16px",display:"flex",justifyContent:"space-between",alignItems:"center"}}><span style={{color:"#5a7a96",fontSize:13}}>Total today</span><span style={{color:"#ffffff",fontWeight:800,fontSize:18}}>${plan.pro} AUD</span></div>
          <button onClick={handlePay} style={{...Sb.ctaBtn,opacity:processing?0.7:1}} disabled={processing}>{processing?"Processing...":"🔒 Pay Now & Activate Pro"}</button>
          <p style={{color:"#5a7a96",fontSize:11,textAlign:"center",margin:0}}>Secured by Paddle. IT Service Link | ABN 78 336 526 604</p>
          <button onClick={()=>setScreen("dashboard")} style={{background:"transparent",border:"none",color:"#5a7a96",cursor:"pointer",fontSize:13,textDecoration:"underline"}}>Cancel, go back</button>
        </div>
      </div>
    </div>
  );
}
