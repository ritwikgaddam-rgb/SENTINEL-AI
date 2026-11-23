(function(){console.log("[Sentinel AI] In-page Email Guardian active.");let m="cold",g=!0;const E="http://127.0.0.1:8000";typeof chrome<"u"&&chrome.storage&&chrome.storage.local&&(chrome.storage.local.get(["sentinel_theme","sentinel_mode","sentinel_gmailOverlay"],e=>{e.sentinel_theme&&(m=e.sentinel_theme),e.sentinel_mode&&e.sentinel_mode,typeof e.sentinel_gmailOverlay=="boolean"&&(g=e.sentinel_gmailOverlay)}),chrome.storage.onChanged.addListener(e=>{e.sentinel_theme&&(m=e.sentinel_theme.newValue),e.sentinel_mode&&e.sentinel_mode.newValue,e.sentinel_gmailOverlay&&(g=e.sentinel_gmailOverlay.newValue)}));const h=new RegExp("(?<!\\d)\\d{4}[\\s-]?\\d{4}[\\s-]?\\d{4}(?!\\d)","g"),v=new RegExp("(?<!\\d)(?:\\+91[\\s-]?)?[6-9]\\d{9}(?!\\d)","g");function y(){const e=m==="warm"?"SentinelAILogoIcon-SentinelOnly(Orange).svg":"SentinelAILogoIconOnlySentinel(Purple).svg";return typeof chrome<"u"&&chrome.runtime&&chrome.runtime.getURL?chrome.runtime.getURL(`logos/${e}`):`logos/${e}`}async function k(e,t){try{const n=await fetch(`${E}/api/scan-email`,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({text:e,sender:t})});if(n.ok)return await n.json()}catch{}const r=e.toLowerCase(),s=/urgent|suspended|deactivated|password|verify|immediately|within \d+ hours/.test(r),a=e.match(h)||[],i=e.match(v)||[],l=[];return s&&l.append({id:"urgency_trigger",title:"High-Pressure Psychological Trigger",description:"Message contains urgency keywords common in account-takeover scams.",severity:"danger"}),a.length>0&&l.push({id:"aadhaar_present",title:"Unredacted Aadhaar Number Detected",description:`Exposes ${a.length} Indian national ID number(s).`,severity:"danger"}),{risk_level:s||a.length>0?"danger":"safe",safety_score:s||a.length>0?25:96,markers:l,privacy:{aadhaar_numbers:a,phone_numbers:i},private_items_count:a.length+i.length}}function b(){if(!g)return;document.querySelectorAll(".gE.iv.gt, .adn.ads").forEach(async t=>{if(t.hasAttribute("data-sentinel-scanned"))return;t.setAttribute("data-sentinel-scanned","true");const r=t.closest(".gs")||t.parentElement,s=r?r.querySelector(".a3s, .ii.gt"):null,a=s?s.innerText.trim():"";if(!a||a.length<15)return;const i=t.querySelector(".gD"),l=i?i.getAttribute("email")||i.innerText:"",n=await k(a,l),o=n.risk_level||"safe",p=document.createElement("div");p.className=`sentinel-gmail-badge theme-${m} ${o}`,p.innerHTML=`
        <img src="${y()}" class="sentinel-badge-logo" alt="Sentinel AI" />
        <span>${o==="safe"?"Verified Safe":o==="suspicious"?"Caution":"Threat Detected"}</span>
      `;const c=document.createElement("div");c.className=`sentinel-gmail-popover theme-${m}`,c.style.display="none";let f="";n.markers&&n.markers.length>0?f=n.markers.map(d=>`
          <div class="sentinel-popover-marker ${d.severity||"medium"}">
            <div class="sentinel-popover-marker-title">${d.title}</div>
            <div class="sentinel-popover-marker-desc">${d.description}</div>
          </div>
        `).join(""):f=`
          <div class="sentinel-popover-marker safe">
            <div class="sentinel-popover-marker-title">Clean Audit</div>
            <div class="sentinel-popover-marker-desc">No deceptive heuristics or privacy violations detected.</div>
          </div>
        `,c.innerHTML=`
        <div class="sentinel-popover-header">
          <div class="sentinel-popover-title">
            <img src="${y()}" style="height:14px; width:auto;" />
            <span>Sentinel AI Security Audit</span>
          </div>
          <span style="font-size:11px; opacity:0.8;">${n.safety_score}% Safe</span>
        </div>
        <div>${f}</div>
        ${n.private_items_count>0?`
          <div style="margin-top:8px; padding-top:6px; border-top:1px solid rgba(255,255,255,0.1); font-size:11px; display:flex; justify-content:space-between; align-items:center;">
            <span>🛡️ ${n.private_items_count} Identity points exposed</span>
          </div>
        `:""}
      `,p.addEventListener("click",d=>{d.stopPropagation(),c.style.display=c.style.display==="none"?"block":"none"}),document.addEventListener("click",d=>{!p.contains(d.target)&&!c.contains(d.target)&&(c.style.display="none")});const u=document.createElement("div");u.style.position="relative",u.style.display="inline-block",u.appendChild(p),u.appendChild(c);const _=t.querySelector(".g3")||t.querySelector(".gK")||t;_.parentNode.insertBefore(u,_)})}function A(){if(!g)return;document.querySelectorAll('.Am.Al.editable, div[aria-label*="Message Body"]').forEach(t=>{const r=t.closest(".M9")||t.parentElement;if(!r||r.hasAttribute("data-sentinel-compose-attached"))return;r.setAttribute("data-sentinel-compose-attached","true"),r.style.position="relative";const s=document.createElement("div");s.className=`sentinel-compose-indicator theme-${m}`,s.title="Sentinel AI Privacy Guard: Monitoring unredacted Aadhaar & Phone data",s.innerHTML=`
        <img src="${y()}" style="height:16px; width:auto;" />
      `,r.appendChild(s),t.addEventListener("input",()=>{const a=t.innerText||t.textContent||"",i=a.match(h)||[],l=a.match(v)||[],n=i.length+l.length;let o=s.querySelector(".sentinel-compose-badge-num");n>0?(o||(o=document.createElement("span"),o.className="sentinel-compose-badge-num",s.appendChild(o)),o.innerText=n):o&&o.remove()}),s.addEventListener("click",a=>{a.stopPropagation();let i=t.innerHTML;const l=i.match(h)||[],n=i.match(v)||[];if(l.length===0&&n.length===0){alert("Sentinel AI Privacy Guard: No unredacted Aadhaar or Phone numbers detected in this draft.");return}if(confirm(`Sentinel AI detected ${l.length} Aadhaar number(s) and ${n.length} Phone number(s). Would you like to automatically redact them with [AADHAAR] and [PHONE] tags?`)){i=i.replace(h,"[AADHAAR]"),i=i.replace(v,"[PHONE]"),t.innerHTML=i;const o=s.querySelector(".sentinel-compose-badge-num");o&&o.remove()}})})}new MutationObserver(()=>{b(),A()}).observe(document.body,{childList:!0,subtree:!0}),setTimeout(()=>{b(),A()},1e3)})();
