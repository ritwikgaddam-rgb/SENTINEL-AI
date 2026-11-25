const J='.gmail_quote, .gmail_signature, .gmail_extra, [data-smartmail="gmail_signature"], blockquote',X="div,p,li,ul,ol,table,tr,td,blockquote,pre,section,article";function H(s,g){const f=[],c=[];let m=0,o=null,l=!1;function p(e){m+=e.length,l=m>4e4,l||f.push(e)}function x(){f.length&&!f.at(-1).endsWith(`
`)&&p(`
`)}function t(e){if(!l){if(e.nodeType===Node.TEXT_NODE&&e.data){const a=e.parentElement.closest(X);o&&a!==o&&x(),o=a;const k=m;p(e.data),l||c.push({node:e,start:k,end:m})}else if(e.nodeType===Node.ELEMENT_NODE){if(!g&&e.matches(J))f.length&&p(`

`);else if(e.matches("br"))p(`
`);else if(!e.matches('script,style,[hidden],[contenteditable="false"]'))for(const a of e.childNodes)t(a)}}}for(const e of s.childNodes)t(e);return{text:f.join(""),nodes:c,oversized:l}}function Y(s,g){const f=[0];for(const o of s.text)f.push(f.at(-1)+o.length);const c=new Map,m=new Map;for(const o of[...g].sort((l,p)=>p.start-l.start)){const l=f[o.start],p=f[o.end];if(l===void 0||p===void 0||l>=p)return null;const x=s.nodes.filter(e=>e.start<p&&e.end>l);if(!x.length)return null;const t=s.text.slice(l,p);x.forEach(({node:e,start:a,end:k},_)=>{c.has(e)||c.set(e,{before:e.data,after:e.data});const A=c.get(e);A.after=A.after.slice(0,Math.max(l,a)-a)+(_===0?o.replacement:"")+A.after.slice(Math.min(p,k)-a);const w=e.parentElement.closest("a[href]");if(w&&!m.has(w)){const E=w.getAttribute("href");let d=E;try{d=decodeURIComponent(E)}catch{}d.toLowerCase().includes(t.toLowerCase())&&m.set(w,E)}})}return{changes:c,links:m}}function y(s,g,f){const c=document.createElement(s);return g&&(c.className=g),f!==void 0&&(c.textContent=f),c}function V(s,g){var f;return(f=chrome.runtime)!=null&&f.id?chrome.runtime.sendMessage({type:"COMPOSE_PRIVACY",text:s,selected:g}).then(c=>{if(!(c!=null&&c.success))throw new Error("Local privacy analysis unavailable");return c.data}):Promise.reject(new Error("Extension unavailable"))}function j(s){return s.ambiguous===!1&&s.confidence==="high"}function Z(s,g,f,c){const m=y("div","sentinel-compose-indicator theme-"+f),o=y("img");o.src=c,o.style.cssText="height:16px;width:auto",o.tabIndex=0,o.setAttribute("role","button"),o.setAttribute("aria-label","Sentinel AI Privacy Guard"),o.setAttribute("aria-expanded","false"),m.title="Sentinel AI Privacy Guard";const l=y("div","sentinel-gmail-bar-container theme-"+f+" sentinel-compose-panel");l.hidden=!0;const p=y("section","sentinel-gmail-audit-drawer");p.setAttribute("aria-label","Draft redaction"),l.append(p),m.append(o,l),g.style.position="relative",g.append(m);let x=!1,t=[],e=null,a=new Set,k=0,_,A=null,w="Checking draft…";function E(n,i,u=!1){const h=y("button","sentinel-bar-toggle-btn",n);return h.type="button",h.disabled=u,h.addEventListener("click",i),h}function d(n,i,u){const h=y("label","sentinel-compose-choice"),b=y("input");return b.type="checkbox",b.checked=i,b.addEventListener("change",()=>u(b.checked)),h.append(b,document.createTextNode(n)),{wrapper:h,checkbox:b}}function S(){let n=m.querySelector(".sentinel-compose-badge-num");if(t.length?(n||(n=y("span","sentinel-compose-badge-num"),m.append(n)),n.textContent=t.length):n==null||n.remove(),l.hidden)return;const i=y("div","sentinel-audit-header");i.append(y("div","sentinel-audit-title","Draft Privacy Guard"),E("Collapse",()=>O(!1)));const u=d("Include quotes and signature",x,r=>{x=r,q()}),h=y("div","sentinel-compose-findings"),b=y("div","sentinel-compose-actions"),P=[],M=new Map;for(const r of t)M.has(r.category)||M.set(r.category,[]),M.get(r.category).push(r);function R(){for(const{input:r,ids:T}of P){const N=T.filter(z=>a.has(z)).length;r.checked=N===T.length,r.indeterminate=N>0&&N<T.length}D.disabled=!e||a.size===0,$.disabled=!e||!t.some(r=>j(r)||a.has(r.id))}function L(r,T){for(const N of r)T?a.add(N):a.delete(N);R()}for(const r of M.values()){const T=y("div","sentinel-audit-marker"),N=r.map(I=>I.id),z=r[0].replacement.slice(1,-1),G=d(z+" ("+r.length+")",!1,I=>L(N,I));G.wrapper.classList.add("sentinel-audit-marker-title"),P.push({input:G.checkbox,ids:N}),T.append(G.wrapper),r.forEach((I,F)=>{const W=I.validation==="invalid_format_or_checksum"?" · Invalid format or checksum":j(I)?"":" · Review",U=d("#"+(F+1)+" "+I.masked_preview+W,a.has(I.id),K=>L([I.id],K));P.push({input:U.checkbox,ids:[I.id]}),T.append(U.wrapper)}),h.append(T)}const D=E("Redact selected",()=>B(t.filter(r=>a.has(r.id)))),v=t.map(r=>r.id),$=E("Redact all",()=>B(t.filter(r=>j(r)||a.has(r.id))));if($.title="Redacts automatic matches and any review items you selected",b.append(E("Select all",()=>L(v,!0),!t.length),E("Deselect all",()=>L(v,!1),!t.length),D,$,E("Undo",C,!A)),p.replaceChildren(i,u.wrapper),w){const r=y("p","sentinel-audit-marker-desc",w);r.setAttribute("role","status"),p.append(r)}p.append(h,b),R()}function O(n){l.hidden=!n,o.setAttribute("aria-expanded",String(n)),m.title=n?"":"Sentinel AI Privacy Guard",n?S():o.focus()}function q(){if(!s.isConnected)return;const n=++k;clearTimeout(_),e=null,t=[],a=new Set,w="Checking draft…",S(),_=setTimeout(async()=>{const i=H(s,x);if(w=i.oversized?"Draft is too long for local analysis.":"No sensitive information detected.",i.oversized||!i.text.trim()){S();return}try{const u=await V(i.text);if(n!==k||!s.isConnected)return;if(i.text!==H(s,x).text){q();return}e=i.text,t=u.findings,a=new Set(t.filter(j).map(h=>h.id)),w=t.length?"":"No sensitive information detected."}catch{if(n!==k||!s.isConnected)return;w="Local privacy analysis unavailable."}S()},220)}function B(n){const i=H(s,x);if(e===null||i.oversized||e!==i.text){q();return}if(!n.length)return;const u=Y(i,n);if(!u){q();return}for(const[h,b]of u.changes)h.data=b.after;for(const h of u.links.keys())h.removeAttribute("href");A=u,s.dispatchEvent(new Event("input",{bubbles:!0})),V(i.text,n.map(h=>h.id)).catch(()=>{})}function C(){if(!A)return;const n=A;if(A=null,[...n.changes].some(([i,u])=>!s.contains(i)||i.data!==u.after)||[...n.links.keys()].some(i=>!s.contains(i)||i.hasAttribute("href"))){S();return}for(const[i,u]of n.changes)i.data=u.before;for(const[i,u]of n.links)i.setAttribute("href",u);s.dispatchEvent(new Event("input",{bubbles:!0}))}m.addEventListener("click",n=>{n.stopPropagation(),n.composedPath().includes(l)||O(l.hidden)}),m.addEventListener("keydown",n=>{n.key==="Escape"&&!l.hidden&&O(!1),n.target===o&&["Enter"," "].includes(n.key)&&(n.preventDefault(),O(l.hidden))}),s.addEventListener("input",q),new MutationObserver(q).observe(s,{childList:!0,characterData:!0,subtree:!0}),q()}(function(){console.log("[Sentinel AI] In-page Email Guardian active.");let s="cold",g=!0;const f="http://127.0.0.1:8000";typeof chrome<"u"&&chrome.storage&&chrome.storage.local&&(chrome.storage.local.get(["sentinel_theme","sentinel_mode","sentinel_gmailOverlay"],t=>{t.sentinel_theme&&(s=t.sentinel_theme),t.sentinel_mode&&t.sentinel_mode,typeof t.sentinel_gmailOverlay=="boolean"&&(g=t.sentinel_gmailOverlay)}),chrome.storage.onChanged.addListener(t=>{t.sentinel_theme&&(s=t.sentinel_theme.newValue),t.sentinel_mode&&t.sentinel_mode.newValue,t.sentinel_gmailOverlay&&(g=t.sentinel_gmailOverlay.newValue)}));function c(){const t=s==="warm"?"SentinelAILogoIcon-SentinelOnly(Orange).svg":"SentinelAILogoIconOnlySentinel(Purple).svg";return typeof chrome<"u"&&chrome.runtime&&chrome.runtime.getURL?chrome.runtime.getURL(`logos/${t}`):`logos/${t}`}async function m(t,e,a,k){try{const _=await fetch(`${f}/api/scan-email`,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({text:t,sender:e,subject:a,links:k})});if(_.ok)return await _.json()}catch{}return{risk_level:"unknown",assessment:"Analysis unavailable",safety_score:null,markers:[]}}function o(){if(!g)return;document.querySelectorAll(".adn.ads").forEach(async e=>{var D;if(e.getAttribute("data-sentinel-scanned")==="true"||e.querySelector(".sentinel-gmail-bar-container"))return;e.setAttribute("data-sentinel-scanned","true");const a=e.querySelector(".a3s, .ii.gt"),k=a?a.innerText.trim():"";if(!k||k.length<15)return;const _=e.querySelector(".gD"),A=_?_.getAttribute("email")||_.innerText:"",w=(((D=document.querySelector("h2.hP"))==null?void 0:D.textContent)||"").slice(0,500),E=[...a.querySelectorAll("a[href]")].slice(0,40).map(v=>({url:v.getAttribute("href"),label:v.textContent.slice(0,200)})),d=await m(k.slice(0,2e4),A.slice(0,500),w,E),S=["safe","suspicious","danger"].includes(d.risk_level)?d.risk_level:"unknown",O=Number.isFinite(d.safety_score)?d.safety_score+"% Safe":"Score unavailable",q=S==="safe",B=S==="suspicious";if((S==="danger"||S==="suspicious")&&a&&!a.querySelector(".sentinel-threat-banner")){const v=document.createElement("div");v.className=`sentinel-threat-banner ${S}`;const $=d.markers&&d.markers[0]?d.markers[0].description:"This email exhibits deceptive phishing heuristics. Proceed with caution.";v.innerHTML=`
          <div class="sentinel-threat-icon">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" width="18" height="18" style="display:block;">
              <path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/>
              <line x1="12" y1="9" x2="12" y2="13"/>
              <line x1="12" y1="17" x2="12.01" y2="17"/>
            </svg>
          </div>
          <div class="sentinel-threat-content">
            <div class="sentinel-threat-heading">
              <span>Sentinel AI Security Alert (${O})</span>
            </div>
            <div class="sentinel-threat-details">${$}</div>
          </div>
        `,a.insertBefore(v,a.firstChild)}const C=document.createElement("div");C.className=`sentinel-gmail-bar-container theme-${s}`;const n=q?"No clear indicators":B?"Security Caution":S==="danger"?"Threat Flagged":"No score",i=q?"Review unexpected requests independently. Privacy findings are shown separately.":d.markers&&d.markers[0]?d.markers[0].description:"A local assessment could not be completed.";let u="";d.markers&&d.markers.length>0?u=d.markers.map(v=>`
          <div class="sentinel-audit-marker ${v.severity||"medium"}">
            <div class="sentinel-audit-marker-title">${v.title}</div>
            <div class="sentinel-audit-marker-desc">${v.description}</div>
          </div>
        `).join(""):u=`
          <div class="sentinel-audit-marker safe">
            <div class="sentinel-audit-marker-title">No Direct Phishing Flags Found</div>
            <div class="sentinel-audit-marker-desc">No urgent social engineering patterns, direct credential demands, or rogue external links were detected.</div>
          </div>
        `,C.innerHTML=`
        <div class="sentinel-gmail-bar ${S}">
          <div class="sentinel-bar-left">
            <img src="${c()}" class="sentinel-bar-logo" alt="Sentinel AI" />
            <span class="sentinel-bar-title">${n}</span>
            <span class="sentinel-bar-sep">•</span>
            <span class="sentinel-bar-summary">${i}</span>
          </div>
          <div class="sentinel-bar-right">
            <span class="sentinel-bar-score">${O}</span>
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
              <img src="${c()}" style="height:14px; width:auto;" />
              <span>Sentinel AI Security Audit</span>
            </div>
            <span class="sentinel-audit-score">${O}</span>
          </div>
          <div class="sentinel-audit-markers-list">
            ${u}
          </div>
          ${d.private_items_count>0?`
            <div class="sentinel-audit-privacy-footer">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" width="13" height="13">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
              </svg>
              <span>${d.private_items_count} Sensitive identity point(s) detected</span>
            </div>
          `:""}
        </div>
      `;const h=C.querySelector(".sentinel-bar-toggle-btn"),b=C.querySelector(".sentinel-gmail-bar"),P=C.querySelector(".sentinel-gmail-audit-drawer"),M=C.querySelector(".sentinel-chevron-icon"),R=v=>{v.stopPropagation();const $=P.style.display!=="none";P.style.display=$?"none":"block",M&&(M.style.transform=$?"rotate(0deg)":"rotate(180deg)")};h&&h.addEventListener("click",R),b&&b.addEventListener("click",R);const L=e.querySelector(".gE.iv.gt");L&&L.nextSibling?L.parentNode.insertBefore(C,L.nextSibling):L?L.parentNode.appendChild(C):e.insertBefore(C,e.firstChild)})}const l=new WeakSet;function p(){g&&document.querySelectorAll('.Am.Al.editable, [contenteditable="true"][aria-label*="Message Body"]').forEach(t=>{if(l.has(t)||t.closest(".gmail_quote, blockquote"))return;const e=t.closest(".M9")||t.parentElement;e&&(l.add(t),Z(t,e,s,c()))})}new MutationObserver(()=>{o(),p()}).observe(document.body,{childList:!0,subtree:!0}),setTimeout(()=>{o(),p()},1e3)})();
