const K='.gmail_quote, .gmail_signature, .gmail_extra, [data-smartmail="gmail_signature"], blockquote',J="div,p,li,ul,ol,table,tr,td,blockquote,pre,section,article";function G(i,g){const p=[],d=[];let m=0,l=null,r=!1;function h(t){m+=t.length,r=m>4e4,r||p.push(t)}function x(){p.length&&!p.at(-1).endsWith(`
`)&&h(`
`)}function e(t){if(!r){if(t.nodeType===Node.TEXT_NODE&&t.data){const a=t.parentElement.closest(J);l&&a!==l&&x(),l=a;const k=m;h(t.data),r||d.push({node:t,start:k,end:m})}else if(t.nodeType===Node.ELEMENT_NODE){if(!g&&t.matches(K))p.length&&h(`

`);else if(t.matches("br"))h(`
`);else if(!t.matches('script,style,[hidden],[contenteditable="false"]'))for(const a of t.childNodes)e(a)}}}for(const t of i.childNodes)e(t);return{text:p.join(""),nodes:d,oversized:r}}function X(i,g){const p=[0];for(const l of i.text)p.push(p.at(-1)+l.length);const d=new Map,m=new Map;for(const l of[...g].sort((r,h)=>h.start-r.start)){const r=p[l.start],h=p[l.end];if(r===void 0||h===void 0||r>=h)return null;const x=i.nodes.filter(t=>t.start<h&&t.end>r);if(!x.length)return null;const e=i.text.slice(r,h);x.forEach(({node:t,start:a,end:k},_)=>{d.has(t)||d.set(t,{before:t.data,after:t.data});const A=d.get(t);A.after=A.after.slice(0,Math.max(r,a)-a)+(_===0?l.replacement:"")+A.after.slice(Math.min(h,k)-a);const w=t.parentElement.closest("a[href]");if(w&&!m.has(w)){const E=w.getAttribute("href");let u=E;try{u=decodeURIComponent(E)}catch{}u.toLowerCase().includes(e.toLowerCase())&&m.set(w,E)}})}return{changes:d,links:m}}function y(i,g,p){const d=document.createElement(i);return g&&(d.className=g),p!==void 0&&(d.textContent=p),d}function U(i,g){var p;return(p=chrome.runtime)!=null&&p.id?chrome.runtime.sendMessage({type:"COMPOSE_PRIVACY",text:i,selected:g}).then(d=>{if(!(d!=null&&d.success))throw new Error("Local privacy analysis unavailable");return d.data}):Promise.reject(new Error("Extension unavailable"))}function Y(i,g,p,d){const m=y("div","sentinel-compose-indicator theme-"+p),l=y("img");l.src=d,l.style.cssText="height:16px;width:auto",l.tabIndex=0,l.setAttribute("role","button"),l.setAttribute("aria-label","Sentinel AI Privacy Guard"),l.setAttribute("aria-expanded","false"),m.title="Sentinel AI Privacy Guard";const r=y("div","sentinel-gmail-bar-container theme-"+p+" sentinel-compose-panel");r.hidden=!0;const h=y("section","sentinel-gmail-audit-drawer");h.setAttribute("aria-label","Draft redaction"),r.append(h),m.append(l,r),g.style.position="relative",g.append(m);let x=!1,e=[],t=null,a=new Set,k=0,_,A=null,w="Checking draft…";function E(n,s,f=!1){const o=y("button","sentinel-bar-toggle-btn",n);return o.type="button",o.disabled=f,o.addEventListener("click",s),o}function u(n,s,f){const o=y("label","sentinel-compose-choice"),b=y("input");return b.type="checkbox",b.checked=s,b.addEventListener("change",()=>f(b.checked)),o.append(b,document.createTextNode(n)),{wrapper:o,checkbox:b}}function S(){let n=m.querySelector(".sentinel-compose-badge-num");if(e.length?(n||(n=y("span","sentinel-compose-badge-num"),m.append(n)),n.textContent=e.length):n==null||n.remove(),r.hidden)return;const s=y("div","sentinel-audit-header");s.append(y("div","sentinel-audit-title","Draft Privacy Guard"),E("Collapse",()=>O(!1)));const f=u("Include quotes and signature",x,c=>{x=c,I()}),o=y("div","sentinel-compose-findings"),b=y("div","sentinel-compose-actions"),P=[],$=new Map;for(const c of e)$.has(c.category)||$.set(c.category,[]),$.get(c.category).push(c);function D(){for(const{input:c,ids:T}of P){const N=T.filter(j=>a.has(j)).length;c.checked=N===T.length,c.indeterminate=N>0&&N<T.length}R.disabled=!t||a.size===0}function L(c,T){for(const N of c)T?a.add(N):a.delete(N);D()}for(const c of $.values()){const T=y("div","sentinel-audit-marker"),N=c.map(q=>q.id),j=c[0].replacement.slice(1,-1),z=u(j+" ("+c.length+")",!1,q=>L(N,q));z.wrapper.classList.add("sentinel-audit-marker-title"),P.push({input:z.checkbox,ids:N}),T.append(z.wrapper),c.forEach((q,V)=>{const F=q.validation==="invalid_format_or_checksum"?" · Invalid format or checksum":q.ambiguous?" · Review":"",H=u("#"+(V+1)+" "+q.masked_preview+F,a.has(q.id),W=>L([q.id],W));P.push({input:H.checkbox,ids:[q.id]}),T.append(H.wrapper)}),o.append(T)}const R=E("Redact selected",()=>B(e.filter(c=>a.has(c.id)))),v=e.map(c=>c.id),M=E("Redact all",()=>B(e),!e.length);if(M.title="Includes review-only matches",b.append(E("Select all",()=>L(v,!0),!e.length),E("Deselect all",()=>L(v,!1),!e.length),R,M,E("Undo",C,!A)),h.replaceChildren(s,f.wrapper),w){const c=y("p","sentinel-audit-marker-desc",w);c.setAttribute("role","status"),h.append(c)}h.append(o,b),D()}function O(n){r.hidden=!n,l.setAttribute("aria-expanded",String(n)),m.title=n?"":"Sentinel AI Privacy Guard",n?S():l.focus()}function I(){if(!i.isConnected)return;const n=++k;clearTimeout(_),t=null,e=[],a=new Set,w="Checking draft…",S(),_=setTimeout(async()=>{const s=G(i,x);if(w=s.oversized?"Draft is too long for local analysis.":"No sensitive information detected.",s.oversized||!s.text.trim()){S();return}try{const f=await U(s.text);if(n!==k||!i.isConnected)return;if(s.text!==G(i,x).text){I();return}t=s.text,e=f.findings,a=new Set(e.filter(o=>!o.ambiguous).map(o=>o.id)),w=e.length?"":"No sensitive information detected."}catch{if(n!==k||!i.isConnected)return;w="Local privacy analysis unavailable."}S()},220)}function B(n){const s=G(i,x);if(t===null||s.oversized||t!==s.text){I();return}if(!n.length)return;const f=X(s,n);if(!f){I();return}for(const[o,b]of f.changes)o.data=b.after;for(const o of f.links.keys())o.removeAttribute("href");A=f,i.dispatchEvent(new Event("input",{bubbles:!0})),U(s.text,n.map(o=>o.id)).catch(()=>{})}function C(){if(!A)return;const n=A;if(A=null,[...n.changes].some(([s,f])=>!i.contains(s)||s.data!==f.after)||[...n.links.keys()].some(s=>!i.contains(s)||s.hasAttribute("href"))){S();return}for(const[s,f]of n.changes)s.data=f.before;for(const[s,f]of n.links)s.setAttribute("href",f);i.dispatchEvent(new Event("input",{bubbles:!0}))}m.addEventListener("click",n=>{n.stopPropagation(),n.composedPath().includes(r)||O(r.hidden)}),m.addEventListener("keydown",n=>{n.key==="Escape"&&!r.hidden&&O(!1),n.target===l&&["Enter"," "].includes(n.key)&&(n.preventDefault(),O(r.hidden))}),i.addEventListener("input",I),new MutationObserver(I).observe(i,{childList:!0,characterData:!0,subtree:!0}),I()}(function(){console.log("[Sentinel AI] In-page Email Guardian active.");let i="cold",g=!0;const p="http://127.0.0.1:8000";typeof chrome<"u"&&chrome.storage&&chrome.storage.local&&(chrome.storage.local.get(["sentinel_theme","sentinel_mode","sentinel_gmailOverlay"],e=>{e.sentinel_theme&&(i=e.sentinel_theme),e.sentinel_mode&&e.sentinel_mode,typeof e.sentinel_gmailOverlay=="boolean"&&(g=e.sentinel_gmailOverlay)}),chrome.storage.onChanged.addListener(e=>{e.sentinel_theme&&(i=e.sentinel_theme.newValue),e.sentinel_mode&&e.sentinel_mode.newValue,e.sentinel_gmailOverlay&&(g=e.sentinel_gmailOverlay.newValue)}));function d(){const e=i==="warm"?"SentinelAILogoIcon-SentinelOnly(Orange).svg":"SentinelAILogoIconOnlySentinel(Purple).svg";return typeof chrome<"u"&&chrome.runtime&&chrome.runtime.getURL?chrome.runtime.getURL(`logos/${e}`):`logos/${e}`}async function m(e,t,a,k){try{const _=await fetch(`${p}/api/scan-email`,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({text:e,sender:t,subject:a,links:k})});if(_.ok)return await _.json()}catch{}return{risk_level:"unknown",assessment:"Analysis unavailable",safety_score:null,markers:[]}}function l(){if(!g)return;document.querySelectorAll(".adn.ads").forEach(async t=>{var R;if(t.getAttribute("data-sentinel-scanned")==="true"||t.querySelector(".sentinel-gmail-bar-container"))return;t.setAttribute("data-sentinel-scanned","true");const a=t.querySelector(".a3s, .ii.gt"),k=a?a.innerText.trim():"";if(!k||k.length<15)return;const _=t.querySelector(".gD"),A=_?_.getAttribute("email")||_.innerText:"",w=(((R=document.querySelector("h2.hP"))==null?void 0:R.textContent)||"").slice(0,500),E=[...a.querySelectorAll("a[href]")].slice(0,40).map(v=>({url:v.getAttribute("href"),label:v.textContent.slice(0,200)})),u=await m(k.slice(0,2e4),A.slice(0,500),w,E),S=["safe","suspicious","danger"].includes(u.risk_level)?u.risk_level:"unknown",O=Number.isFinite(u.safety_score)?u.safety_score+"% Safe":"Score unavailable",I=S==="safe",B=S==="suspicious";if((S==="danger"||S==="suspicious")&&a&&!a.querySelector(".sentinel-threat-banner")){const v=document.createElement("div");v.className=`sentinel-threat-banner ${S}`;const M=u.markers&&u.markers[0]?u.markers[0].description:"This email exhibits deceptive phishing heuristics. Proceed with caution.";v.innerHTML=`
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
            <div class="sentinel-threat-details">${M}</div>
          </div>
        `,a.insertBefore(v,a.firstChild)}const C=document.createElement("div");C.className=`sentinel-gmail-bar-container theme-${i}`;const n=I?"No clear indicators":B?"Security Caution":S==="danger"?"Threat Flagged":"No score",s=I?"Review unexpected requests independently. Privacy findings are shown separately.":u.markers&&u.markers[0]?u.markers[0].description:"A local assessment could not be completed.";let f="";u.markers&&u.markers.length>0?f=u.markers.map(v=>`
          <div class="sentinel-audit-marker ${v.severity||"medium"}">
            <div class="sentinel-audit-marker-title">${v.title}</div>
            <div class="sentinel-audit-marker-desc">${v.description}</div>
          </div>
        `).join(""):f=`
          <div class="sentinel-audit-marker safe">
            <div class="sentinel-audit-marker-title">No Direct Phishing Flags Found</div>
            <div class="sentinel-audit-marker-desc">No urgent social engineering patterns, direct credential demands, or rogue external links were detected.</div>
          </div>
        `,C.innerHTML=`
        <div class="sentinel-gmail-bar ${S}">
          <div class="sentinel-bar-left">
            <img src="${d()}" class="sentinel-bar-logo" alt="Sentinel AI" />
            <span class="sentinel-bar-title">${n}</span>
            <span class="sentinel-bar-sep">•</span>
            <span class="sentinel-bar-summary">${s}</span>
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
              <img src="${d()}" style="height:14px; width:auto;" />
              <span>Sentinel AI Security Audit</span>
            </div>
            <span class="sentinel-audit-score">${O}</span>
          </div>
          <div class="sentinel-audit-markers-list">
            ${f}
          </div>
          ${u.private_items_count>0?`
            <div class="sentinel-audit-privacy-footer">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" width="13" height="13">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
              </svg>
              <span>${u.private_items_count} Sensitive identity point(s) detected</span>
            </div>
          `:""}
        </div>
      `;const o=C.querySelector(".sentinel-bar-toggle-btn"),b=C.querySelector(".sentinel-gmail-bar"),P=C.querySelector(".sentinel-gmail-audit-drawer"),$=C.querySelector(".sentinel-chevron-icon"),D=v=>{v.stopPropagation();const M=P.style.display!=="none";P.style.display=M?"none":"block",$&&($.style.transform=M?"rotate(0deg)":"rotate(180deg)")};o&&o.addEventListener("click",D),b&&b.addEventListener("click",D);const L=t.querySelector(".gE.iv.gt");L&&L.nextSibling?L.parentNode.insertBefore(C,L.nextSibling):L?L.parentNode.appendChild(C):t.insertBefore(C,t.firstChild)})}const r=new WeakSet;function h(){g&&document.querySelectorAll('.Am.Al.editable, [contenteditable="true"][aria-label*="Message Body"]').forEach(e=>{if(r.has(e)||e.closest(".gmail_quote, blockquote"))return;const t=e.closest(".M9")||e.parentElement;t&&(r.add(e),Y(e,t,i,d()))})}new MutationObserver(()=>{l(),h()}).observe(document.body,{childList:!0,subtree:!0}),setTimeout(()=>{l(),h()},1e3)})();
