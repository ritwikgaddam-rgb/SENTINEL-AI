const J='.gmail_quote, .gmail_signature, .gmail_extra, [data-smartmail="gmail_signature"], blockquote',X="div,p,li,ul,ol,table,tr,td,blockquote,pre,section,article";function H(s,v){const u=[],d=[];let h=0,c=null,l=!1;function f(e){h+=e.length,l=h>4e4,l||u.push(e)}function S(){u.length&&!u.at(-1).endsWith(`
`)&&f(`
`)}function m(e){if(!l){if(e.nodeType===Node.TEXT_NODE&&e.data){const n=e.parentElement.closest(X);c&&n!==c&&S(),c=n;const g=h;f(e.data),l||d.push({node:e,start:g,end:h})}else if(e.nodeType===Node.ELEMENT_NODE){if(!v&&e.matches(J))u.length&&f(`

`);else if(e.matches("br"))f(`
`);else if(!e.matches('script,style,[hidden],[contenteditable="false"]'))for(const n of e.childNodes)m(n)}}}for(const e of s.childNodes)m(e);return{text:u.join(""),nodes:d,oversized:l}}function Y(s,v){const u=[0];for(const c of s.text)u.push(u.at(-1)+c.length);const d=new Map,h=new Map;for(const c of[...v].sort((l,f)=>f.start-l.start)){const l=u[c.start],f=u[c.end];if(l===void 0||f===void 0||l>=f)return null;const S=s.nodes.filter(e=>e.start<f&&e.end>l);if(!S.length)return null;const m=s.text.slice(l,f);S.forEach(({node:e,start:n,end:g},L)=>{d.has(e)||d.set(e,{before:e.data,after:e.data});const y=d.get(e);y.after=y.after.slice(0,Math.max(l,n)-n)+(L===0?c.replacement:"")+y.after.slice(Math.min(f,g)-n);const E=e.parentElement.closest("a[href]");if(E&&!h.has(E)){const A=E.getAttribute("href");let N=A;try{N=decodeURIComponent(A)}catch{}N.toLowerCase().includes(m.toLowerCase())&&h.set(E,A)}})}return{changes:d,links:h}}function w(s,v,u){const d=document.createElement(s);return v&&(d.className=v),u!==void 0&&(d.textContent=u),d}function V(s,v){var u;return(u=chrome.runtime)!=null&&u.id?chrome.runtime.sendMessage({type:"COMPOSE_PRIVACY",text:s,selected:v}).then(d=>{if(!(d!=null&&d.success))throw new Error("Local privacy analysis unavailable");return d.data}):Promise.reject(new Error("Extension unavailable"))}function j(s){return s.ambiguous===!1&&s.confidence==="high"}function Z(s,v,u,d){const h=w("div","sentinel-compose-indicator theme-"+u),c=w("img");c.src=d,c.style.cssText="height:16px;width:auto",c.tabIndex=0,c.setAttribute("role","button"),c.setAttribute("aria-label","Sentinel AI Privacy Guard"),c.setAttribute("aria-expanded","false"),h.title="Sentinel AI Privacy Guard";const l=w("div","sentinel-gmail-bar-container theme-"+u+" sentinel-compose-panel");l.hidden=!0;const f=w("section","sentinel-gmail-audit-drawer");f.setAttribute("aria-label","Draft redaction"),l.append(f),h.append(c,l),v.style.position="relative",v.append(h);let S=!1,m=[],e=null,n=new Set,g=0,L,y=null,E="Checking draft…";function A(t,a,r=!1){const p=w("button","sentinel-bar-toggle-btn",t);return p.type="button",p.disabled=r,p.addEventListener("click",a),p}function N(t,a,r){const p=w("label","sentinel-compose-choice"),x=w("input");return x.type="checkbox",x.checked=a,x.addEventListener("change",()=>r(x.checked)),p.append(x,document.createTextNode(t)),{wrapper:p,checkbox:x}}function b(){let t=h.querySelector(".sentinel-compose-badge-num");if(m.length?(t||(t=w("span","sentinel-compose-badge-num"),h.append(t)),t.textContent=m.length):t==null||t.remove(),l.hidden)return;const a=w("div","sentinel-audit-header");a.append(w("div","sentinel-audit-title","Draft Privacy Guard"),A("Collapse",()=>_(!1)));const r=N("Include quotes and signature",S,i=>{S=i,C()}),p=w("div","sentinel-compose-findings"),x=w("div","sentinel-compose-actions"),O=[],$=new Map;for(const i of m)$.has(i.category)||$.set(i.category,[]),$.get(i.category).push(i);function P(){for(const{input:i,ids:o}of O){const k=o.filter(z=>n.has(z)).length;i.checked=k===o.length,i.indeterminate=k>0&&k<o.length}R.disabled=!e||n.size===0,I.disabled=!e||!m.some(i=>j(i)||n.has(i.id))}function M(i,o){for(const k of i)o?n.add(k):n.delete(k);P()}for(const i of $.values()){const o=w("div","sentinel-audit-marker"),k=i.map(q=>q.id),z=i[0].replacement.slice(1,-1),G=N(z+" ("+i.length+")",!1,q=>M(k,q));G.wrapper.classList.add("sentinel-audit-marker-title"),O.push({input:G.checkbox,ids:k}),o.append(G.wrapper),i.forEach((q,F)=>{const W=q.validation==="invalid_format_or_checksum"?" · Invalid format or checksum":j(q)?"":" · Review",U=N("#"+(F+1)+" "+q.masked_preview+W,n.has(q.id),K=>M([q.id],K));O.push({input:U.checkbox,ids:[q.id]}),o.append(U.wrapper)}),p.append(o)}const R=A("Redact selected",()=>T(m.filter(i=>n.has(i.id)))),D=m.map(i=>i.id),I=A("Redact all",()=>T(m.filter(i=>j(i)||n.has(i.id))));if(I.title="Redacts automatic matches and any review items you selected",x.append(A("Select all",()=>M(D,!0),!m.length),A("Deselect all",()=>M(D,!1),!m.length),R,I,A("Undo",B,!y)),f.replaceChildren(a,r.wrapper),E){const i=w("p","sentinel-audit-marker-desc",E);i.setAttribute("role","status"),f.append(i)}f.append(p,x),P()}function _(t){l.hidden=!t,c.setAttribute("aria-expanded",String(t)),h.title=t?"":"Sentinel AI Privacy Guard",t?b():c.focus()}function C(){if(!s.isConnected)return;const t=++g;clearTimeout(L),e=null,m=[],n=new Set,E="Checking draft…",b(),L=setTimeout(async()=>{const a=H(s,S);if(E=a.oversized?"Draft is too long for local analysis.":"No sensitive information detected.",a.oversized||!a.text.trim()){b();return}try{const r=await V(a.text);if(t!==g||!s.isConnected)return;if(a.text!==H(s,S).text){C();return}e=a.text,m=r.findings,n=new Set(m.filter(j).map(p=>p.id)),E=m.length?"":"No sensitive information detected."}catch{if(t!==g||!s.isConnected)return;E="Local privacy analysis unavailable."}b()},220)}function T(t){const a=H(s,S);if(e===null||a.oversized||e!==a.text){C();return}if(!t.length)return;const r=Y(a,t);if(!r){C();return}for(const[p,x]of r.changes)p.data=x.after;for(const p of r.links.keys())p.removeAttribute("href");y=r,s.dispatchEvent(new Event("input",{bubbles:!0})),V(a.text,t.map(p=>p.id)).catch(()=>{})}function B(){if(!y)return;const t=y;if(y=null,[...t.changes].some(([a,r])=>!s.contains(a)||a.data!==r.after)||[...t.links.keys()].some(a=>!s.contains(a)||a.hasAttribute("href"))){b();return}for(const[a,r]of t.changes)a.data=r.before;for(const[a,r]of t.links)a.setAttribute("href",r);s.dispatchEvent(new Event("input",{bubbles:!0}))}h.addEventListener("click",t=>{t.stopPropagation(),t.composedPath().includes(l)||_(l.hidden)}),h.addEventListener("keydown",t=>{t.key==="Escape"&&!l.hidden&&_(!1),t.target===c&&["Enter"," "].includes(t.key)&&(t.preventDefault(),_(l.hidden))}),s.addEventListener("input",C),new MutationObserver(C).observe(s,{childList:!0,characterData:!0,subtree:!0}),C()}(function(){console.log("[Sentinel AI] In-page Email Guardian active.");let s="cold",v=!0;const u="http://127.0.0.1:8000";typeof chrome<"u"&&chrome.storage&&chrome.storage.local&&(chrome.storage.local.get(["sentinel_theme","sentinel_mode","sentinel_gmailOverlay"],e=>{e.sentinel_theme&&(s=e.sentinel_theme),e.sentinel_mode&&e.sentinel_mode,typeof e.sentinel_gmailOverlay=="boolean"&&(v=e.sentinel_gmailOverlay)}),chrome.storage.onChanged.addListener(e=>{e.sentinel_theme&&(s=e.sentinel_theme.newValue),e.sentinel_mode&&e.sentinel_mode.newValue,e.sentinel_gmailOverlay&&(v=e.sentinel_gmailOverlay.newValue)}));function d(){const e=s==="warm"?"SentinelAILogoIcon-SentinelOnly(Orange).svg":"SentinelAILogoIconOnlySentinel(Purple).svg";return typeof chrome<"u"&&chrome.runtime&&chrome.runtime.getURL?chrome.runtime.getURL(`logos/${e}`):`logos/${e}`}async function h(e,n,g,L){try{const y=await fetch(`${u}/api/scan-email`,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({text:e,sender:n,subject:g,links:L}),redirect:"error",referrerPolicy:"no-referrer",signal:AbortSignal.timeout(8e3)});if(y.ok)return await y.json()}catch{}return{risk_level:"unknown",assessment:"Analysis unavailable",safety_score:null,markers:[]}}const c=e=>typeof e=="string"?e.replaceAll("<","&lt;").replaceAll(">","&gt;"):"";function l(){if(!v)return;document.querySelectorAll(".adn.ads").forEach(async n=>{var i;if(n.getAttribute("data-sentinel-scanned")==="true"||n.querySelector(".sentinel-gmail-bar-container"))return;n.setAttribute("data-sentinel-scanned","true");const g=n.querySelector(".a3s, .ii.gt"),L=g?g.innerText.trim():"";if(!L||L.length<15)return;const y=n.querySelector(".gD"),E=y?y.getAttribute("email")||y.innerText:"",A=(((i=document.querySelector("h2.hP"))==null?void 0:i.textContent)||"").slice(0,500),N=[...g.querySelectorAll("a[href]")].slice(0,40).map(o=>({url:o.getAttribute("href"),label:o.textContent.slice(0,200)})),b=await h(L.slice(0,2e4),E.slice(0,500),A,N),_=["safe","suspicious","danger"].includes(b.risk_level)?b.risk_level:"unknown",C=Number.isFinite(b.safety_score)&&b.safety_score>=0&&b.safety_score<=100?b.safety_score+"% Safe":"Score unavailable",T=Array.isArray(b.markers)?b.markers.filter(o=>o&&typeof o.description=="string").slice(0,32):[],B=Number.isSafeInteger(b.private_items_count)?b.private_items_count:0,t=_==="safe",a=_==="suspicious";if((_==="danger"||_==="suspicious")&&g&&!g.querySelector(".sentinel-threat-banner")){const o=document.createElement("div");o.className=`sentinel-threat-banner ${_}`;const k=T.length?c(T[0].description):"This email exhibits deceptive phishing heuristics. Proceed with caution.";o.innerHTML=`
          <div class="sentinel-threat-icon">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" width="18" height="18" style="display:block;">
              <path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/>
              <line x1="12" y1="9" x2="12" y2="13"/>
              <line x1="12" y1="17" x2="12.01" y2="17"/>
            </svg>
          </div>
          <div class="sentinel-threat-content">
            <div class="sentinel-threat-heading">
              <span>Sentinel AI Security Alert (${C})</span>
            </div>
            <div class="sentinel-threat-details">${k}</div>
          </div>
        `,g.insertBefore(o,g.firstChild)}const r=document.createElement("div");r.className=`sentinel-gmail-bar-container theme-${s}`;const p=t?"No clear indicators":a?"Security Caution":_==="danger"?"Threat Flagged":"No score",x=t?"Review unexpected requests independently. Privacy findings are shown separately.":T.length?c(T[0].description):"A local assessment could not be completed.";let O="";T.length>0?O=T.map(o=>`
          <div class="sentinel-audit-marker ${["danger","high","medium","low","safe"].includes(o.severity)?o.severity:"medium"}">
            <div class="sentinel-audit-marker-title">${c(o.title)}</div>
            <div class="sentinel-audit-marker-desc">${c(o.description)}</div>
          </div>
        `).join(""):O=`
          <div class="sentinel-audit-marker safe">
            <div class="sentinel-audit-marker-title">No Direct Phishing Flags Found</div>
            <div class="sentinel-audit-marker-desc">No urgent social engineering patterns, direct credential demands, or rogue external links were detected.</div>
          </div>
        `,r.innerHTML=`
        <div class="sentinel-gmail-bar ${_}">
          <div class="sentinel-bar-left">
            <img src="${d()}" class="sentinel-bar-logo" alt="Sentinel AI" />
            <span class="sentinel-bar-title">${p}</span>
            <span class="sentinel-bar-sep">•</span>
            <span class="sentinel-bar-summary">${x}</span>
          </div>
          <div class="sentinel-bar-right">
            <span class="sentinel-bar-score">${C}</span>
            <button class="sentinel-bar-toggle-btn" type="button">
              <span>Audit Details</span>
              <svg class="sentinel-chevron-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" width="12" height="12">
                <polyline points="6 9 12 15 18 9"/>
              </svg>
            </button>
          </div>
        </div>

        <div class="sentinel-gmail-audit-drawer" style="display: none;">
          <div class="sentinel-audit-header">
            <div class="sentinel-audit-title">
              <img src="${d()}" style="height:14px; width:auto;" />
              <span>Sentinel AI Security Audit</span>
            </div>
            <span class="sentinel-audit-score">${C}</span>
          </div>
          <div class="sentinel-audit-markers-list">
            ${O}
          </div>
          ${B>0?`
            <div class="sentinel-audit-privacy-footer">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" width="13" height="13">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
              </svg>
              <span>${B} Sensitive identity point(s) detected</span>
            </div>
          `:""}
        </div>
      `;const $=r.querySelector(".sentinel-bar-toggle-btn"),P=r.querySelector(".sentinel-gmail-bar"),M=r.querySelector(".sentinel-gmail-audit-drawer"),R=r.querySelector(".sentinel-chevron-icon"),D=o=>{o.stopPropagation();const k=M.style.display!=="none";M.style.display=k?"none":"block",R&&(R.style.transform=k?"rotate(0deg)":"rotate(180deg)")};$&&$.addEventListener("click",D),P&&P.addEventListener("click",D);const I=n.querySelector(".gE.iv.gt");I&&I.nextSibling?I.parentNode.insertBefore(r,I.nextSibling):I?I.parentNode.appendChild(r):n.insertBefore(r,n.firstChild)})}const f=new WeakSet;function S(){v&&document.querySelectorAll('.Am.Al.editable, [contenteditable="true"][aria-label*="Message Body"]').forEach(e=>{if(f.has(e)||e.closest(".gmail_quote, blockquote"))return;const n=e.closest(".M9")||e.parentElement;n&&(f.add(e),Z(e,n,s,d()))})}new MutationObserver(()=>{l(),S()}).observe(document.body,{childList:!0,subtree:!0}),setTimeout(()=>{l(),S()},1e3)})();
