const $ = s => document.querySelector(s);
const fileInput = $("#fileInput"), dropzone = $("#dropzone"), scanSection=$("#scanSection");
const resultsSection=$("#resultsSection"), fileList=$("#fileList"), results=$("#results");
let files=[];

const suspiciousExt = new Set(["exe","dll","scr","com","bat","cmd","ps1","vbs","vbe","js","jse","wsf","wsh","msi","jar","hta","apk","dmg","pkg","iso","lnk","reg"]);
const archiveExt = new Set(["zip","rar","7z","iso","img","tar","gz","bz2"]);
const executableExt = new Set(["exe","dll","scr","com","msi","elf","apk","dmg","pkg","jar"]);

function fmtBytes(n){if(n<1024)return `${n} B`;if(n<1048576)return `${(n/1024).toFixed(1)} KB`;if(n<1073741824)return `${(n/1048576).toFixed(1)} MB`;return `${(n/1073741824).toFixed(1)} GB`}
function ext(name){return name.toLowerCase().split(".").pop() || ""}
function escapeHtml(s){return s.replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#039;"}[c]))}
function renderQueue(){
  scanSection.classList.toggle("hidden",files.length===0);
  $("#queueTitle").textContent=`${files.length} file${files.length===1?"":"s"}`;
  fileList.innerHTML=files.map((f,i)=>`<div class="file-row"><div class="file-icon">${escapeHtml(ext(f.name).slice(0,4).toUpperCase()||"FILE")}</div><div><div class="file-name">${escapeHtml(f.name)}</div><div class="file-meta">${fmtBytes(f.size)} · ${escapeHtml(f.type||"unknown MIME type")}</div></div><button class="remove" data-i="${i}" aria-label="Remove">×</button></div>`).join("");
  fileList.querySelectorAll(".remove").forEach(b=>b.onclick=()=>{files.splice(+b.dataset.i,1);renderQueue()});
}
function addFiles(list){for(const f of list){if(!files.some(x=>x.name===f.name&&x.size===f.size&&x.lastModified===f.lastModified))files.push(f)}renderQueue()}
fileInput.onchange=e=>addFiles(e.target.files);
["dragenter","dragover"].forEach(ev=>dropzone.addEventListener(ev,e=>{e.preventDefault();dropzone.classList.add("drag")}));
["dragleave","drop"].forEach(ev=>dropzone.addEventListener(ev,e=>{e.preventDefault();dropzone.classList.remove("drag")}));
dropzone.addEventListener("drop",e=>addFiles(e.dataTransfer.files));
$("#clearBtn").onclick=()=>{files=[];renderQueue();resultsSection.classList.add("hidden")};
$("#newScanBtn").onclick=()=>{resultsSection.classList.add("hidden");window.scrollTo({top:0,behavior:"smooth"})};

async function sha256(file){
  const buffer=await file.arrayBuffer();
  const hash=await crypto.subtle.digest("SHA-256",buffer);
  return [...new Uint8Array(hash)].map(b=>b.toString(16).padStart(2,"0")).join("");
}
function readPrefix(file,n=64){return file.slice(0,n).arrayBuffer().then(b=>new Uint8Array(b))}
function detectMagic(bytes){
  if(bytes.length>=4 && bytes[0]===0x4d&&bytes[1]===0x5a)return "Windows PE executable";
  if(bytes.length>=4 && bytes[0]===0x7f&&bytes[1]===0x45&&bytes[2]===0x4c&&bytes[3]===0x46)return "ELF executable";
  if(bytes.length>=2 && bytes[0]===0x50&&bytes[1]===0x4b)return "ZIP/container format";
  if(bytes.length>=8 && bytes[0]===0x89&&bytes[1]===0x50&&bytes[2]===0x4e&&bytes[3]===0x47)return "PNG image";
  if(bytes.length>=3 && bytes[0]===0xff&&bytes[1]===0xd8&&bytes[2]===0xff)return "JPEG image";
  if(bytes.length>=5 && bytes[0]===0x25&&bytes[1]===0x50&&bytes[2]===0x44&&bytes[3]===0x46)return "PDF document";
  return "Unknown / generic format";
}
function heuristic(file, magic){
  const e=ext(file.name), parts=file.name.toLowerCase().split(".");
  const reasons=[];
  if(suspiciousExt.has(e)) reasons.push(`Potentially executable or script extension (.${e})`);
  if(parts.length>=3 && suspiciousExt.has(parts.at(-1))) reasons.push("Multiple file extensions ending in an executable/script type");
  if(archiveExt.has(e)) reasons.push("Archive/container requires deeper inspection");
  if(magic.includes("executable") && !executableExt.has(e)) reasons.push("Detected executable content does not match the filename extension");
  if(file.size>500*1024*1024) reasons.push("Very large file; deeper scanning may be appropriate");
  return reasons;
}
async function scanFile(file){
  const [hash, prefix]=await Promise.all([sha256(file),readPrefix(file)]);
  const magic=detectMagic(prefix), reasons=heuristic(file,magic);
  let level=reasons.some(x=>x.includes("does not match"))?"bad":reasons.length?"warn":"good";
  return {file,hash,magic,reasons,level};
}
function renderResult(r){
  const label={good:"No obvious indicators",warn:"Review recommended",bad:"Suspicious"}[r.level];
  const checks=[
    ["SHA-256","Calculated locally"],
    ["File type",r.magic],
    ["Extension",`.${ext(r.file.name)||"none"}`],
    ["Heuristics",r.reasons.length?`${r.reasons.length} indicator(s)`:"No indicators"]
  ];
  return `<article class="result"><div class="result-top"><span class="status ${r.level}"></span><span class="result-name">${escapeHtml(r.file.name)}</span><span class="badge ${r.level}">${label}</span></div>
  <div class="checks">${checks.map(c=>`<div class="check"><b>${escapeHtml(c[0])}</b>${escapeHtml(c[1])}</div>`).join("")}</div>
  ${r.reasons.length?`<div class="hash"><b>Notes:</b> ${r.reasons.map(escapeHtml).join(" · ")}</div>`:""}
  <div class="hash">SHA-256: ${r.hash}</div></article>`;
}
$("#scanBtn").onclick=async()=>{
  if(!files.length)return;
  $("#scanBtn").disabled=true;$("#scanBtn").textContent="Scanning locally…";resultsSection.classList.remove("hidden");results.innerHTML="";
  const out=[];
  for(const f of files){const r=await scanFile(f);out.push(r);results.innerHTML+=renderResult(r)}
  $("#scanBtn").disabled=false;$("#scanBtn").textContent="Start scan";
  resultsSection.scrollIntoView({behavior:"smooth",block:"start"});
};
