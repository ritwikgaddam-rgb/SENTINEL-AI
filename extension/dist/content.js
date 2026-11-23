(function(){console.log("[Sentinel AI] In-page Email Guardian active.");let m="cold",h=!0;const $="http://127.0.0.1:8000";typeof chrome<"u"&&chrome.storage&&chrome.storage.local&&(chrome.storage.local.get(["sentinel_theme","sentinel_mode","sentinel_gmailOverlay"],t=>{t.sentinel_theme&&(m=t.sentinel_theme),t.sentinel_mode&&t.sentinel_mode,typeof t.sentinel_gmailOverlay=="boolean"&&(h=t.sentinel_gmailOverlay)}),chrome.storage.onChanged.addListener(t=>{t.sentinel_theme&&(m=t.sentinel_theme.newValue),t.sentinel_mode&&t.sentinel_mode.newValue,t.sentinel_gmailOverlay&&(h=t.sentinel_gmailOverlay.newValue)}));const g=new RegExp("(?<!\\d)\\d{4}[\\s-]?\\d{4}[\\s-]?\\d{4}(?!\\d)","g"),p=new RegExp("(?<!\\d)(?:\\+91[\\s-]?)?[6-9]\\d{9}(?!\\d)","g");function y(){const t=m==="warm"?"SentinelAILogoIcon-SentinelOnly(Orange).svg":"SentinelAILogoIconOnlySentinel(Purple).svg";return typeof chrome<"u"&&chrome.runtime&&chrome.runtime.getURL?chrome.runtime.getURL(`logos/${t}`):`logos/${t}`}async function x(t,n){try{const a=await fetch(`${$}/api/scan-email`,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({text:t,sender:n})});if(a.ok)return await a.json()}catch{}const r=t.toLowerCase(),i=/urgent|suspended|deactivated|password|verify|immediately|within \d+ hours/.test(r),s=t.match(g)||[],o=t.match(p)||[],e=[];return i&&e.push({id:"urgency_trigger",title:"High-Pressure Psychological Trigger",description:"Message contains urgency keywords common in account-takeover scams.",severity:"danger"}),s.length>0&&e.push({id:"aadhaar_present",title:"Unredacted Aadhaar Number Detected",description:`Exposes ${s.length} Indian national ID number(s).`,severity:"danger"}),{risk_level:i||s.length>0?"danger":"safe",safety_score:i||s.length>0?25:96,markers:e,privacy:{aadhaar_numbers:s,phone_numbers:o},private_items_count:s.length+o.length}}function b(){if(!h)return;document.querySelectorAll(".adn.ads").forEach(async n=>{if(n.getAttribute("data-sentinel-scanned")==="true"||n.querySelector(".sentinel-gmail-bar-container"))return;n.setAttribute("data-sentinel-scanned","true");const r=n.querySelector(".a3s, .ii.gt"),i=r?r.innerText.trim():"";if(!i||i.length<15)return;const s=n.querySelector(".gD"),o=s?s.getAttribute("email")||s.innerText:"",e=await x(i,o),a=e.risk_level||"safe",l=a==="safe",L=a==="suspicious";if((a==="danger"||a==="suspicious")&&r&&!r.querySelector(".sentinel-threat-banner")){const d=document.createElement("div");d.className=`sentinel-threat-banner ${a}`;const v=e.markers&&e.markers[0]?e.markers[0].description:"This email exhibits deceptive phishing heuristics. Proceed with caution.";d.innerHTML=`
          <div class="sentinel-threat-icon">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" width="18" height="18" style="display:block;">
              <path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/>
              <line x1="12" y1="9" x2="12" y2="13"/>
              <line x1="12" y1="17" x2="12.01" y2="17"/>
            </svg>
          </div>
          <div class="sentinel-threat-content">
            <div class="sentinel-threat-heading">
              <span>Sentinel AI Security Alert (${e.safety_score}% Safety Score)</span>
            </div>
            <div class="sentinel-threat-details">${v}</div>
          </div>
        `,r.insertBefore(d,r.firstChild)}const c=document.createElement("div");c.className=`sentinel-gmail-bar-container theme-${m}`;const C=l?"Verified Safe":L?"Security Caution":"Threat Flagged",P=l?"No deceptive links, spoofed headers, or unredacted identity points detected in this message.":e.markers&&e.markers[0]?e.markers[0].description:"Potential social engineering or phishing markers detected.";let f="";e.markers&&e.markers.length>0?f=e.markers.map(d=>`
          <div class="sentinel-audit-marker ${d.severity||"medium"}">
            <div class="sentinel-audit-marker-title">${d.title}</div>
            <div class="sentinel-audit-marker-desc">${d.description}</div>
          </div>
        `).join(""):f=`
          <div class="sentinel-audit-marker safe">
            <div class="sentinel-audit-marker-title">No Direct Phishing Flags Found</div>
            <div class="sentinel-audit-marker-desc">No urgent social engineering patterns, direct credential demands, or rogue external links were detected.</div>
          </div>
        `,c.innerHTML=`
        <div class="sentinel-gmail-bar ${a}">
          <div class="sentinel-bar-left">
            <img src="${y()}" class="sentinel-bar-logo" alt="Sentinel AI" />
            <span class="sentinel-bar-title">${C}</span>
            <span class="sentinel-bar-sep">•</span>
            <span class="sentinel-bar-summary">${P}</span>
          </div>
          <div class="sentinel-bar-right">
            <span class="sentinel-bar-score">${e.safety_score}% Safe</span>
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
              <img src="${y()}" style="height:14px; width:auto;" />
              <span>Sentinel AI Security Audit</span>
            </div>
            <span class="sentinel-audit-score">${e.safety_score}% Safe</span>
          </div>
          <div class="sentinel-audit-markers-list">
            ${f}
          </div>
          ${e.private_items_count>0?`
            <div class="sentinel-audit-privacy-footer">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" width="13" height="13">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
              </svg>
              <span>${e.private_items_count} Sensitive identity point(s) detected</span>
            </div>
          `:""}
        </div>
      `;const S=c.querySelector(".sentinel-bar-toggle-btn"),A=c.querySelector(".sentinel-gmail-bar"),w=c.querySelector(".sentinel-gmail-audit-drawer"),_=c.querySelector(".sentinel-chevron-icon"),E=d=>{d.stopPropagation();const v=w.style.display!=="none";w.style.display=v?"none":"block",_&&(_.style.transform=v?"rotate(0deg)":"rotate(180deg)")};S&&S.addEventListener("click",E),A&&A.addEventListener("click",E);const u=n.querySelector(".gE.iv.gt");u&&u.nextSibling?u.parentNode.insertBefore(c,u.nextSibling):u?u.parentNode.appendChild(c):n.insertBefore(c,n.firstChild)})}function k(){if(!h)return;document.querySelectorAll('.Am.Al.editable, div[aria-label*="Message Body"]').forEach(n=>{const r=n.closest(".M9")||n.parentElement;if(!r||r.hasAttribute("data-sentinel-compose-attached"))return;r.setAttribute("data-sentinel-compose-attached","true"),r.style.position="relative";const i=document.createElement("div");i.className=`sentinel-compose-indicator theme-${m}`,i.title="Sentinel AI Privacy Guard: Monitoring unredacted Aadhaar & Phone data",i.innerHTML=`
        <img src="${y()}" style="height:16px; width:auto;" />
      `,r.appendChild(i),n.addEventListener("input",()=>{const s=n.innerText||n.textContent||"",o=s.match(g)||[],e=s.match(p)||[],a=o.length+e.length;let l=i.querySelector(".sentinel-compose-badge-num");a>0?(l||(l=document.createElement("span"),l.className="sentinel-compose-badge-num",i.appendChild(l)),l.innerText=a):l&&l.remove()}),i.addEventListener("click",s=>{s.stopPropagation();let o=n.innerHTML;const e=o.match(g)||[],a=o.match(p)||[];if(e.length===0&&a.length===0){alert("Sentinel AI Privacy Guard: No unredacted Aadhaar or Phone numbers detected in this draft.");return}if(confirm(`Sentinel AI detected ${e.length} Aadhaar number(s) and ${a.length} Phone number(s). Would you like to automatically redact them with [AADHAAR] and [PHONE] tags?`)){o=o.replace(g,"[AADHAAR]"),o=o.replace(p,"[PHONE]"),n.innerHTML=o;const l=i.querySelector(".sentinel-compose-badge-num");l&&l.remove()}})})}new MutationObserver(()=>{b(),k()}).observe(document.body,{childList:!0,subtree:!0}),setTimeout(()=>{b(),k()},1e3)})();
