const $=s=>document.querySelector(s);
const savedHistory=(()=>{try{return JSON.parse(localStorage.getItem('sentinel-scan-history')||'[]').slice(-8);}catch{return[];}})();
const state={api:false,sampleMode:false,data:null,scanning:false,regionFocus:'All regions',manualRegion:false,demoFixes:new Set(),pendingFixes:new Set(),manualLock:false,selectedNode:'admin',scanCount:(()=>{try{return Number(localStorage.getItem('sentinel-demo-phase')||0);}catch{return 0;}})(),history:savedHistory,category:'users'};
const REGIONS=[
 {name:'North America',short:'AMER',x:165,y:145,point:'.point-americas',satellites:[[-22,12,25],[20,-10,22]]},
 {name:'Europe',short:'EMEA',x:455,y:136,point:'.point-europe',satellites:[[-17,12,22],[20,-9,19]]},
 {name:'Asia Pacific',short:'APAC',x:745,y:184,point:'.point-asia',satellites:[[-22,-10,25],[21,9,23]]}
];
const esc=v=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const wait=ms=>new Promise(resolve=>setTimeout(resolve,ms));
function sample(variant=0){
 const people=[
  {id:'user-101',name:'Avery Morgan',email:'avery@example.test',type:'Human',owner:'Platform team',sample_region:'North America',roles:['roles/owner'],mfa:false,key_age_days:0},
  {id:'svc-204',name:'svc-reporting',email:'svc-reporting@example.test',type:'Service account',owner:'Data team',sample_region:'Europe',roles:['roles/editor'],mfa:null,key_age_days:245},
  {id:'ext-310',name:'External access',email:'allUsers',type:'External principal',owner:'Public access',sample_region:'Asia Pacific',roles:['allUsers'],mfa:null,key_age_days:0},
  {id:'user-115',name:'Jordan Lee',email:'jordan@example.test',type:'Human',owner:'Engineering',sample_region:'North America',roles:['roles/viewer'],mfa:true,key_age_days:0}
 ];
 const keyCycles=[245,135,218,78,260,160];people[1].key_age_days=keyCycles[variant%keyCycles.length];
 people[0].roles=variant%2===1?['roles/viewer']:['roles/owner'];
 if(variant%2===1)people[0].mfa=true;
 if(variant%3===2)people[3].roles=['roles/editor'];
 people[0].suspicious_login=variant%2===1;
 return analyze(people);
}
function varyDemoSnapshot(base){
 state.scanCount+=1;const phase=state.scanCount,people=(base.identities||[]).map(person=>({...person,roles:[...(person.roles||[])]}));
 try{localStorage.setItem('sentinel-demo-phase',String(state.scanCount));}catch{}
 let humanIndex=0,serviceIndex=0;const humanCount=people.filter(person=>person.type==='Human').length,keyCycle=[245,128,218,74,267,154];
 for(const person of people){if(person.type==='Human'){person.mfa=((humanIndex+phase)%4)!==0;person.suspicious_login=(humanIndex+phase)%Math.max(1,humanCount)===0;humanIndex++;}else if(person.type==='Service account'){person.key_age_days=keyCycle[(phase+serviceIndex)%keyCycle.length];serviceIndex++;}}
 const scenarioAdmin=people.find(person=>person.id==='user-101');if(scenarioAdmin)scenarioAdmin.roles=phase%2===1?['roles/viewer']:['roles/owner'];
 const rotatingUser=people.find(person=>person.id==='user-115');if(rotatingUser&&phase%3===2)rotatingUser.roles=['roles/editor'];
 const rescored=analyze(people,new Date().toISOString());return {...rescored,mode:'sample-demo',scan_number:phase};
}
function analyze(people,timestamp=new Date().toISOString()){
 people=people.map(person=>({...person,roles:[...(person.roles||[])],findings:[]}));
 const rules=[
  [p=>p.roles.some(r=>['allUsers','allAuthenticatedUsers'].includes(r)),'IAM-001','Public principal has access','Critical',50,'Public principals can expose resources to anyone on the internet.'],
  [p=>p.roles.includes('roles/owner'),'IAM-002','Project Owner role assigned','Critical',45,'Owner includes broad project permissions; review whether this access is needed.'],
  [p=>p.roles.includes('roles/editor'),'IAM-003','Project Editor role assigned','High',30,'Editor allows broad changes across project resources.'],
  [p=>p.type==='Human'&&p.roles.includes('roles/owner')&&p.mfa===false,'IAM-004','Human administrator without MFA','High',25,'A human administrator has no MFA in this sample record.'],
  [p=>p.type==='Service account'&&p.key_age_days>180,'IAM-005','Service account key older than 180 days','High',25,p=>`A user-managed service-account key is ${p.key_age_days} days old.`],
  [p=>p.type==='Human'&&p.mfa===false,'IAM-006','MFA is disabled','High',25,'This human identity has MFA disabled in the synthetic dataset.'],
  [p=>p.type==='Service account'&&p.key_age_days>90&&p.key_age_days<=180,'IAM-007','Service account key nearing rotation','Medium',15,p=>`User-managed key age is ${p.key_age_days} days; review rotation.`],
  [p=>p.status==='Inactive'&&p.roles.length>0,'IAM-008','Inactive identity still has access','High',25,'Inactive identity retains one or more project roles.'],
  [p=>p.external===true&&!p.roles.some(role=>['roles/viewer','roles/browser'].includes(role)),'IAM-009','External identity has elevated access','High',25,'External identity has a role broader than basic viewing.'],
  [p=>p.unused_role===true,'IAM-010','Potentially unused role assignment','Medium',15,'Synthetic access review data marks this role as unused for 90 days.'],
  [p=>p.suspicious_login===true,'IAM-011','Unusual sign-in signal (synthetic)','High',25,'Illustrative activity marks this sign-in as unusual; no real sign-in logs were read.']
 ];
 const findings=[];
 for(const p of people){p.findings=[];for(const [test,id,title,severity,points,evidence] of rules){if(test(p)){const f={id:`${p.id}:${id}`,identity_id:p.id,identity_name:p.name,rule_id:id,title,severity,points,evidence:typeof evidence==='function'?evidence(p):evidence,recommendation:'Review this access with its owner and use the narrowest permissions that support the work.',status:'Open'};p.findings.push(f);findings.push(f);}}p.score=Math.min(100,p.findings.reduce((n,f)=>n+f.points,0));p.level=p.score>=70?'Critical':p.score>=40?'High':p.score>=15?'Medium':'Low';}
 const critical=findings.filter(f=>f.severity==='Critical').length,high=findings.filter(f=>f.severity==='High').length;
 return {timestamp,identities:people,findings,metrics:{identity_count:people.length,finding_count:findings.length,critical_count:critical,high_count:high,risk_score:Math.round(people.reduce((n,p)=>n+p.score,0)/Math.max(1,people.length)),compliance:Math.max(0,100-critical*15-high*8)}};
}
function applyDemoFixes(data){
 if(!state.demoFixes.size)return data;
 const identities=data.identities.map(person=>({...person,roles:[...(person.roles||[])]}));
 for(const key of state.demoFixes){const [identityId,ruleId]=key.split(':');const person=identities.find(item=>item.id===identityId);if(!person)continue;
  if(ruleId==='IAM-001')person.roles=person.roles.filter(role=>!['allUsers','allAuthenticatedUsers'].includes(role));
  if(ruleId==='IAM-002')person.roles=[...person.roles.filter(role=>role!=='roles/owner'),'roles/viewer'];
  if(ruleId==='IAM-003')person.roles=[...person.roles.filter(role=>role!=='roles/editor'),'roles/viewer'];
  if(ruleId==='IAM-004')person.mfa=true;
  if(ruleId==='IAM-005')person.key_age_days=0;
  if(ruleId==='IAM-006'||ruleId==='IAM-004')person.mfa=true;
  if(ruleId==='IAM-007'||ruleId==='IAM-005')person.key_age_days=0;
  if(ruleId==='IAM-008')person.roles=[];
  if(ruleId==='IAM-009')person.roles=['roles/viewer'];
  if(ruleId==='IAM-010')person.unused_role=false;
  if(ruleId==='IAM-011')person.suspicious_login=false;
 }
 const reviewed=new Set((data.findings||[]).filter(item=>item.status==='Reviewed').map(item=>item.id));
 const rescored=analyze(identities,data.timestamp);
 rescored.findings.forEach(item=>{if(reviewed.has(item.id))item.status='Reviewed';});
 return rescored;
}
function render(data){
 data=applyDemoSettings(applyDemoFixes(data));
 state.data=data;const m=data.metrics||{};
 $('#radarScore').textContent=m.risk_score??0;$('#identityCount').textContent=m.identity_count??data.identities.length;$('#findingCount').textContent=data.findings.filter(f=>f.status==='Open').length;$('#openCount').textContent=data.findings.filter(f=>f.status==='Open').length;$('#criticalCount').textContent=m.critical_count??data.findings.filter(f=>f.severity==='Critical').length;
 $('#privilegedCount').textContent=data.identities.filter(person=>person.roles.some(role=>/owner|editor|admin|securityAdmin/i.test(role))).length;
 $('#complianceBar').style.width=`${Math.min(100,(m.critical_count||0)*15)}%`;
 $('#scanMessage').textContent=state.api?'Local analysis reviewed the synthetic IAM records. No cloud account is connected.':'Browser analysis reviewed synthetic identity records. No cloud account is connected.';
 const sev=$('#filterSeverity').value, query=$('#searchInput').value.trim().toLowerCase();
 const findings=data.findings.filter(f=>sev==='all'||f.severity===sev);
 $('#findingList').innerHTML=findings.length?findings.map(f=>{const pending=state.pendingFixes.has(`${f.identity_id}:${f.rule_id}`);return `<article class="finding"><i class="severity-line ${esc(f.severity.toLowerCase())}"></i><div class="finding-title"><b>${esc(f.title)}</b><small>${esc(f.identity_name)} · ${esc(f.rule_id)}</small></div><div class="finding-evidence">${esc(f.evidence)}</div><div class="finding-fix">${esc(f.recommendation)}</div><span class="severity ${esc(f.severity.toLowerCase())}">${esc(f.severity.toUpperCase())}</span><div class="row-actions">${f.status==='Open'?`<button data-review="${esc(f.id)}">MARK REVIEWED</button>`:'<span class="reviewed">✓ REVIEWED</span>'}<button class="fix-button" data-fix="${esc(f.id)}" ${pending?'data-verify="1"':''}>${pending?'VERIFY FIX':'SIMULATE FIX'}</button></div></article>`;}).join(''):'<div class="empty">No findings match this filter.</div>';
 const people=data.identities.filter(p=>`${p.name} ${p.email} ${p.owner}`.toLowerCase().includes(query));
 $('#identityRows').innerHTML=people.length?people.map(p=>`<tr><td><div class="identity-name"><b>${esc(p.name)}</b><small>${esc(p.email)} · ${esc(p.owner)}</small></div></td><td>${esc(p.type)}</td><td>${p.roles.map(r=>`<span class="role-chip">${esc(r)}</span>`).join(' ')}</td><td class="score ${esc(p.level)}">${p.score} · ${esc(p.level)}</td><td>${p.key_age_days?`${p.key_age_days} days`:'—'}</td></tr>`).join(''):'<tr><td colspan="5" class="empty-cell">No matching identities.</td></tr>';
 const alerts=data.findings.slice(0,4);$('#alertList').innerHTML=alerts.length?alerts.map(f=>`<div class="alert"><span class="alert-icon ${esc(f.severity.toLowerCase())}">!</span><span><b>${esc(f.title)}</b><small>${esc(f.identity_name)} · ${esc(f.evidence)}</small></span><time>LOCAL</time></div>`).join(''):'<div class="empty">No alerts in this scan.</div>';
 renderLocker(data);
 renderLiveDock(data);
 renderVisuals(data);
 renderTopology(data);
 renderAnalytics(data);
}
function applyDemoSettings(data){
 if(!data?.identities)return data;
 const includeMfa=$('#includeMfaSetting')?.checked!==false,includeKeys=$('#includeKeySetting')?.checked!==false;
 const identities=data.identities.map(person=>({...person,roles:[...(person.roles||[])],findings:(person.findings||[]).filter(item=>(includeMfa||!['IAM-004','IAM-006'].includes(item.rule_id))&&(includeKeys||!['IAM-005','IAM-007'].includes(item.rule_id)))}));
 const findings=identities.flatMap(person=>person.findings);for(const person of identities){person.score=Math.min(100,person.findings.reduce((sum,item)=>sum+(item.points||0),0));person.level=person.score>=70?'Critical':person.score>=40?'High':person.score>=15?'Medium':'Low';}
 const critical=findings.filter(item=>item.severity==='Critical').length,high=findings.filter(item=>item.severity==='High').length;
 return {...data,identities,findings,metrics:{...data.metrics,identity_count:identities.length,finding_count:findings.length,critical_count:critical,high_count:high,risk_score:Math.round(identities.reduce((sum,person)=>sum+person.score,0)/Math.max(1,identities.length)),compliance:Math.max(0,100-critical*15-high*8)}};
}
function renderLiveDock(data){
 const open=data.findings.filter(item=>item.status==='Open').length;
 $('#liveDockState').textContent=state.scanning?'SCANNING':state.pendingFixes.size?'FIX STAGED · VERIFY':'MONITORING';
 $('#liveDockState').dataset.state=state.scanning?'scanning':state.pendingFixes.size?'pending':open?'risk':'clear';
 $('#liveDockRisk').textContent=data.metrics.risk_score;
 $('#liveDockFindings').textContent=open;
 $('#liveDockLock').textContent=$('#resourceLocker').dataset.state==='locked'?'LOCKED':'UNLOCKED';
 $('#liveDockProgress').style.width=$('#progressBar').style.width||'0%';
}
const CATEGORY_META={
 users:['User identities','Review user accounts, MFA status, inactivity, and unusual sign-in signals.',person=>person.type==='Human'],
 admins:['Admin accounts','Inspect Owner, Editor, and other elevated identities.',person=>person.roles.some(role=>/owner|editor|admin|securityAdmin/i.test(role))],
 roles:['IAM roles','Look for broad, unused, or risky role assignments.',person=>person.roles.length>0],
 permissions:['Permissions','Trace public access and excessive privilege across the sample.',person=>person.roles.some(role=>/owner|editor|allUsers|allAuthenticatedUsers/i.test(role))],
 mfa:['MFA protection','Find human accounts without multi-factor authentication.',person=>person.type==='Human'],
 resources:['Cloud resources','Review sample project resource relationships and access exposure.',person=>person.findings.length>0],
 policies:['Access policies','Inspect policy signals such as public principals and broad roles.',person=>person.findings.length>0]
};
function selectScanCategory(name){if(!CATEGORY_META[name])return;state.category=name;const [title,description,match]=CATEGORY_META[name],people=(state.data?.identities||[]).filter(match),findings=people.flatMap(person=>person.findings||[]),priority=['Critical','High','Medium','Low'].find(level=>findings.some(item=>item.severity===level))||'—';$('#categoryTitle').textContent=title;$('#categoryDescription').textContent=description;$('#categoryAffected').textContent=state.data?people.length:'--';$('#categorySignals').textContent=state.data?findings.length:'--';$('#categorySeverity').textContent=priority;document.querySelectorAll('.radar-category').forEach(button=>button.classList.toggle('selected',button.dataset.scanCategory===name));}
function renderAnalytics(data){
 const levels=['Critical','High','Medium','Low'],counts=Object.fromEntries(levels.map(level=>[level,data.identities.filter(item=>item.level===level).length])),max=Math.max(1,...Object.values(counts));
 $('#scannerDistribution').innerHTML=levels.map(level=>`<button type="button" class="distribution-row" data-severity-filter="${level}"><span class="distribution-label ${level.toLowerCase()}">${level}</span><i><b class="${level.toLowerCase()}" style="width:${counts[level]/max*100}%"></b></i><strong>${counts[level]}</strong></button>`).join('');
 $('#postureValue').textContent=`${data.metrics.compliance??0}%`;$('#postureFill').style.width=`${data.metrics.compliance??0}%`;
 const total=data.findings.length,verified=Math.min(state.demoFixes.size,total);$('#remediationValue').textContent=`${verified} / ${total}`;$('#remediationFill').style.width=`${total?verified/total*100:0}%`;
 const records=state.history.slice(-6),points=records.map((item,index)=>({x:10+(records.length===1?170:index*340/(records.length-1)),y:82-(item.risk_score||0)*.72}));
 $('#trendLine').setAttribute('d',points.length?points.map((point,index)=>`${index?'L':'M'}${point.x} ${point.y}`).join(' '):'M0 70H360');
 $('#trendPoints').innerHTML=points.map((point,index)=>`<circle cx="${point.x}" cy="${point.y}" r="3.4"><title>Scan ${index+1}: risk ${records[index].risk_score}/100</title></circle>`).join('');
 $('#trendLabels').innerHTML=records.length?records.map((item,index)=>`<span title="${new Date(item.timestamp).toLocaleString()}">#${index+1}</span>`).join(''):'';
 $('#trendSummary').textContent=records.length?`${records.length} recent scans · ${records[records.length-1].risk_score}/100 now`:'Waiting for scans';
 $('#lastScanTime').textContent=records.length?new Date(records[records.length-1].timestamp).toLocaleTimeString([], {hour:'2-digit',minute:'2-digit'}):'Not run yet';
 $('#historyList').innerHTML=records.length?[...records].reverse().map((item,index)=>`<div class="history-item"><b>#${records.length-index}</b><span>${new Date(item.timestamp).toLocaleString()}</span><strong>${item.risk_score}/100</strong><small>${item.identity_count} identities</small><em>${item.finding_count} findings</em></div>`).join(''):'<div class="empty">Run a sample scan to start history.</div>';
 selectScanCategory(state.category);
}
function renderLocker(data){
 const atRisk=data.findings.some(item=>['Critical','High'].includes(item.severity));
 const locked=atRisk||state.pendingFixes.size>0||state.manualLock;
 const card=$('#resourceLocker');card.dataset.state=locked?'locked':'unlocked';
 const moderate=data.findings.some(item=>item.severity==='Medium');
 $('#lockerTitle').textContent=atRisk?'LOCKED · HIGH RISK PRESENT':state.pendingFixes.size?'LOCKED · VERIFY FIX FIRST':locked?'LOCKED · MANUAL CONTAINMENT':'UNLOCKED · HIGH RISK CLEARED';
 $('#lockerDetail').textContent=atRisk?'Critical or high sample findings remain. Simulate a fix, then run its verification scan.':state.pendingFixes.size?'A simulated remediation is waiting for a verification scan.':locked?'No high risk remains; this sample resource is manually contained.':moderate?'Critical/High risks cleared. Moderate sample findings may still need review.':'No Critical or High sample findings remain.';
 const button=$('#lockerButton');button.disabled=atRisk||state.pendingFixes.size>0;button.textContent=atRisk?'LOCKED BY RISK':state.pendingFixes.size?'VERIFY BEFORE UNLOCK':locked?'UNLOCK RESOURCE':'LOCK RESOURCE';
 $('#heroShieldState').classList.toggle('safe',!locked);
 $('#mapShieldState').classList.toggle('safe',!locked);
 $('#heroShieldState').setAttribute('aria-label',locked?'IAM shield locked due to sample risk':'IAM shield unlocked; no critical or high sample risks');
}
function simulateFix(id){
 const finding=state.data?.findings.find(item=>item.id===id);if(!finding)return;
 state.pendingFixes.add(`${finding.identity_id}:${finding.rule_id}`);
 launchFixArrow(finding);
 render(state.data);
 document.querySelector('#findings').scrollIntoView({behavior:'smooth',block:'start'});
 toast(`Remediation staged for ${finding.identity_name}. Run verification before the lock can open.`);
}
function launchFixArrow(finding){
 const region=state.data?.identities.find(person=>person.id===finding.identity_id)?.sample_region;
 const destinations={'North America':[165,145],'Europe':[455,136],'Asia Pacific':[745,184]};
 const [x,y]=destinations[region]||destinations['North America'];
 const layer=$('#mapFixFlights');if(!layer)return;
 const marker=`fix-${Date.now()}`;
 layer.insertAdjacentHTML('beforeend',`<g id="${marker}" class="map-fix-flight"><path d="M500 45 Q ${x} ${Math.max(35,y-55)} ${x} ${y}"/><path class="flight-head" d="M${x-6} ${y-10} L${x} ${y} L${x+6} ${y-10}"/><circle r="5"><animateMotion dur="1.15s" fill="freeze" path="M500 45 Q ${x} ${Math.max(35,y-55)} ${x} ${y}"/></circle></g>`);
 setTimeout(()=>document.getElementById(marker)?.remove(),1700);
}
async function verifyFix(id){
 const finding=state.data?.findings.find(item=>item.id===id);if(!finding)return;
 const key=`${finding.identity_id}:${finding.rule_id}`;if(!state.pendingFixes.has(key))return;
 const button=$('#nodeVerifyButton');button.disabled=true;button.textContent='SCANNING…';$('.topology-panel').classList.add('is-scanning');
 await wait(800);state.pendingFixes.delete(key);state.demoFixes.add(key);
 let fresh=state.data;
 if(state.api&&location.protocol!=='file:'){try{const response=await fetch('/api/scan',{method:'POST'});if(response.ok)fresh=await response.json();}catch{}}
 render(fresh);$('.topology-panel').classList.remove('is-scanning');
 const stillOpen=state.data.findings.some(item=>item.id===id);
 toast(stillOpen?'Verification did not clear this sample finding. Resource remains restricted.':'Verification passed. Sample risk cleared; its lock can now open.');
}
const TOPOLOGY_NODES={
 admin:{title:'Admin identity',type:'IAM principal',identity:'user-101',description:'Human administrator with broad project permissions. This illustrative access path stays restricted while high risk remains.'},
 guest:{title:'External principal',type:'Public identity',identity:'ext-310',description:'Public principal access can make a resource reachable by anyone. The sample model flags this as critical.'},
 developer:{title:'Developer account',type:'Service identity',identity:'svc-204',description:'Service identity with a broad editor role and an aged key in the sample inventory.'},
 app:{title:'Application user',type:'Human identity',identity:'user-115',description:'Read only sample identity with MFA enabled.'},
 compute:{title:'Compute / VM',type:'Cloud resource',identity:'user-101',description:'Illustrative compute resource reached by the sample administrator path.'},
 storage:{title:'Object storage',type:'Storage resource',identity:'ext-310',description:'Illustrative bucket associated with the public principal sample finding.'},
 database:{title:'Database',type:'Data service',identity:'svc-204',description:'Illustrative data service linked to the sample service account role.'},
 function:{title:'Serverless app',type:'Application resource',identity:'user-115',description:'Illustrative application endpoint with a lower risk sample access path.'}
};
function renderTopology(data){
 const node=TOPOLOGY_NODES[state.selectedNode]||TOPOLOGY_NODES.admin,person=data.identities.find(item=>item.id===node.identity);
 const findings=person?.findings||[],related=findings.find(item=>state.pendingFixes.has(`${item.identity_id}:${item.rule_id}`))||findings[0],score=person?.score??0,level=person?.level||'Low';
 const key=related?`${related.identity_id}:${related.rule_id}`:'',pending=Boolean(key&&state.pendingFixes.has(key)),locked=['Critical','High'].includes(level)||pending;
 $('#nodeTitle').textContent=node.title;$('#nodeDescription').textContent=node.description;$('#nodeType').textContent=node.type;
 $('#nodeOwner').textContent=person?.owner||'Sample platform team';$('#nodeRole').textContent=person?.roles?.join(', ')||'roles/viewer';$('#nodeScore').textContent=`${score}/100 · ${level}`;
 const stateBox=$('#nodeSecurityState');stateBox.className=`node-security-state ${locked?'restricted':level==='Medium'?'moderate':'secure'}`;
 stateBox.innerHTML=`<span>${locked?'🔒':level==='Medium'?'◈':'🔓'}</span><b>${pending?'Fix staged · verification required':locked?'Access restricted · risk detected':level==='Medium'?'Monitor · moderate risk':'Secure · risk cleared'}</b>`;
 const fix=$('#nodeFixButton'),verify=$('#nodeVerifyButton');fix.disabled=!related||pending;fix.textContent=pending?'FIX STAGED':related?'SIMULATE FIX':'NO FIX NEEDED';verify.disabled=!pending;
 document.querySelectorAll('.topology-node').forEach(button=>{const meta=TOPOLOGY_NODES[button.dataset.node],linked=data.identities.find(item=>item.id===meta.identity),risky=['Critical','High'].includes(linked?.level);button.classList.toggle('restricted',risky);button.classList.toggle('secure',!risky);button.classList.toggle('moderate',linked?.level==='Medium');button.classList.toggle('selected',button.dataset.node===state.selectedNode);button.querySelector('.node-lock').textContent=risky?'🔒':'🔓';button.setAttribute('aria-label',`${meta.title}. ${linked?.level||'Low'} sample risk, score ${linked?.score??0}.`);});
 const links={admin:'cloud-vpc',guest:'cloud-admin',developer:'cloud-guest',app:'cloud-app',compute:'cloud-compute',storage:'cloud-storage',database:'cloud-database',function:'cloud-function'};
 const pathIdentity={'cloud-vpc':'user-101','cloud-admin':'ext-310','cloud-guest':'svc-204','cloud-database':'svc-204','cloud-app':'user-115','cloud-compute':'user-101','cloud-storage':'ext-310','cloud-function':'user-115'};
 document.querySelectorAll('.topology-link').forEach(path=>{const linked=data.identities.find(item=>item.id===pathIdentity[path.dataset.link]),safe=!['Critical','High'].includes(linked?.level);path.classList.toggle('selected-path',path.dataset.link===links[state.selectedNode]);path.classList.toggle('resolved',safe);document.querySelectorAll(`[data-drop="${path.dataset.link}"], [data-impact="${path.dataset.link}"]`).forEach(marker=>{marker.classList.toggle('safe',safe);marker.classList.toggle('risky',!safe);});});
 $('#topologyCloud').classList.toggle('secure',!data.findings.some(item=>['Critical','High'].includes(item.severity))&&!state.pendingFixes.size);
}
function selectTopologyNode(name){if(!TOPOLOGY_NODES[name])return;state.selectedNode=name;if(state.data)renderTopology(state.data);}
function renderVisuals(data){
 const levels=['Critical','High','Medium','Low'];
 const counts=Object.fromEntries(levels.map(level=>[level,data.findings.filter(f=>f.severity===level).length]));
 const maxCount=Math.max(1,...Object.values(counts));
 $('#severityChart').innerHTML=levels.map(level=>`<button type="button" class="severity-row" data-severity-filter="${level}" aria-label="Filter findings by ${level}"><span>${level}</span><span class="severity-track"><i class="severity-fill ${level.toLowerCase()}" style="width:${counts[level]/maxCount*100}%"></i></span><b class="severity-value">${counts[level]}</b></button>`).join('');
 const top=data.findings[0];
 $('#riskSummary').textContent=top?`Top sample signal: ${top.title}. Review its evidence and owner before considering any real-world action.`:'No sample findings were triggered by this scan.';
 $('#identityHeatmap').innerHTML=data.identities.length?data.identities.map(person=>`<button type="button" class="heat-cell ${esc(person.level)}" data-heat-identity="${esc(person.id)}" title="${esc(person.name)}: score ${person.score}; click to inspect"><span>${esc(person.name)}</span><b>${person.score}</b></button>`).join(''):'<div class="chart-empty">No identities available in this scan.</div>';
 const regionStats=REGIONS.map(region=>{
  const identities=data.identities.filter(person=>person.sample_region===region.name);
  const score=Math.round(identities.reduce((sum,person)=>sum+(person.score||0),0)/Math.max(1,identities.length));
  const ids=new Set(identities.map(person=>person.id));
  const findingCount=data.findings.filter(finding=>ids.has(finding.identity_id)).length;
  const identityIds=new Set(identities.map(person=>person.id));
  const regionFindings=data.findings.filter(finding=>identityIds.has(finding.identity_id));
  const tone=regionFindings.some(finding=>finding.severity==='Critical')?'critical':regionFindings.some(finding=>finding.severity==='High')?'elevated':score>=15?'medium':'monitor';
  const atRisk=regionFindings.some(finding=>['Critical','High'].includes(finding.severity));
  return {...region,identities,score,findingCount,tone,atRisk};
 });
 const heatLayer=$('#mapHeatLayer');
 heatLayer.innerHTML=regionStats.filter(region=>region.identities.length).map(region=>`<circle class="heat-glow ${region.tone}" data-heat-region="${esc(region.name)}" cx="${region.x}" cy="${region.y}" r="${42+region.score*.42}" opacity="${.42+region.score/190}"/>${region.satellites.map(([dx,dy,radius],index)=>`<circle class="heat-glow satellite ${region.tone}" data-heat-region="${esc(region.name)}" cx="${region.x+dx}" cy="${region.y+dy}" r="${radius+region.findingCount*1.5}" opacity="${.38+region.score/240-index*.04}"/>`).join('')}<circle class="heat-core ${region.tone}" data-heat-region="${esc(region.name)}" cx="${region.x}" cy="${region.y}" r="${6+Math.min(region.findingCount,5)}"><title>${esc(region.name)} · average risk ${region.score}/100 · ${region.findingCount} sample signals</title></circle>`).join('');
 $('#mapRegionControls').innerHTML=regionStats.map(region=>`<button type="button" class="region-chip" data-region-focus="${esc(region.name)}"><span>${esc(region.short)}</span><b>${region.score}</b><small>${region.identities.length} ID · ${region.findingCount} signals</small></button>`).join('');
 document.querySelectorAll('.world-point').forEach(point=>{const region=regionStats.find(item=>item.name===point.dataset.region);point.classList.toggle('region-at-risk',Boolean(region?.atRisk));point.setAttribute('aria-label',`${region?.atRisk?'Locked · high-risk sample findings · ':''}Focus ${point.dataset.region} sample risk`);});
 if(!REGIONS.some(region=>region.name===state.regionFocus))state.regionFocus='All regions';
 setRegionFocus(state.regionFocus,false);
}
function setRegionFocus(regionName,manual=true){
 if(manual)state.manualRegion=true;
 state.regionFocus=regionName;
 const all=regionName==='All regions';
 const identities=all?(state.data?.identities||[]):(state.data?.identities||[]).filter(person=>person.sample_region===regionName);
 const scores=identities.map(person=>person.score||0);
 const score=Math.round(scores.reduce((sum,value)=>sum+value,0)/Math.max(1,scores.length));
 const identityIds=new Set(identities.map(person=>person.id));
 const signalCount=(state.data?.findings||[]).filter(finding=>identityIds.has(finding.identity_id)).length;
 $('#mapRegionTitle').textContent=all?'All sample regions':regionName;
 const scoreNode=$('#mapRegionScore');
 if(state.data)animateValue(scoreNode,score);else scoreNode.textContent='--';
 $('#mapRegionIdentityCount').textContent=state.data?identities.length:'--';
 $('#mapAutoButton').textContent=state.manualRegion?'AUTO FOLLOW':'AUTO FOLLOWING';
 $('#mapAutoButton').setAttribute('aria-pressed',String(!state.manualRegion));
 document.querySelectorAll('.region-chip').forEach(button=>button.classList.toggle('active',button.dataset.regionFocus===regionName));
 document.querySelectorAll('.world-point').forEach(point=>point.classList.toggle('selected',point.dataset.region===regionName));
 document.querySelectorAll('[data-heat-region]').forEach(zone=>zone.classList.toggle('focused',zone.dataset.heatRegion===regionName||all));
 const label=$('#mapPulseLabel');
 if(label&&state.manualRegion)label.textContent=`FOCUS · ${all?'ALL SAMPLE REGIONS':regionName.toUpperCase()} · ${signalCount} SIGNALS`;
}
function animateValue(element,target){const from=Number(element.textContent);if(!Number.isFinite(from)){element.textContent=target;return;}const start=performance.now();const step=now=>{const ratio=Math.min(1,(now-start)/420);element.textContent=Math.round(from+(target-from)*(1-Math.pow(1-ratio,3)));if(ratio<1)requestAnimationFrame(step);};requestAnimationFrame(step);}
function setScanActivity(value){const level=Math.max(0,Math.min(100,value));$('#scanNeedle').style.transform=`rotate(${-90+level*1.8}deg)`;$('#scanMeterValue').textContent=`${Math.round(level)}%`;$('#scanMeterState').textContent=state.scanning?'SCANNING':level?'COOLING':'IDLE';$('.scan-meter').classList.toggle('is-active',state.scanning);if($('#radarProgressFill'))$('#radarProgressFill').style.width=`${level}%`;if($('#radarProgressValue'))$('#radarProgressValue').textContent=`${Math.round(level)}%`;}
function progress(p,msg){$('#progressBar').style.width=`${p}%`;$('#progressText').textContent=msg;$('#progressPercent').textContent=`${p}%`;$('#radarMessage').textContent=msg;if($('#liveDockProgress'))$('#liveDockProgress').style.width=`${p}%`;if(state.scanning&&$('#liveDockState')){$('#liveDockState').textContent='SCANNING';$('#liveDockState').dataset.state='scanning';}setScanActivity(state.scanning?p:0);for(const [id,n] of [['step1',15],['step2',50],['step3',80]]){$(`#${id}`).textContent=p>=n?'DONE':p?'CHECKING':'READY';$(`#${id}`).parentElement.classList.toggle('active',p>0&&p<n);$(`#${id}`).parentElement.classList.toggle('done',p>=n);}}
function toast(msg){const el=$('#toast');el.textContent=msg;el.classList.add('show');setTimeout(()=>el.classList.remove('show'),2400);}
async function load(){
 if(location.protocol==='file:'){$('#backendLabel').textContent='Browser analysis';$('#sourceLabel').textContent='Offline sample data';$('#connectionBadge').textContent='BROWSER MODE';$('#helpBanner').hidden=false;render(sample(advanceDemoPhase()));progress(0,'Ready for an IAM scan');$('#scanState').textContent='READY';$('#scanState').className='state complete';$('#pipelineState').textContent='READY';$('#pipelineState').className='state complete';return;}
 try{const health=await fetch('/api/health').then(r=>r.json());state.api=health.ok===true;state.sampleMode=health.mode==='sample-demo';$('#backendLabel').textContent=state.api?'Backend running':'Backend offline';$('#sourceLabel').textContent=state.api?'Local analysis API':'Browser analysis';$('#connectionBadge').textContent=state.api?'LOCAL API ONLINE':'BROWSER MODE';$('#helpBanner').hidden=state.api;const data=state.api?await fetch('/api/dashboard').then(r=>r.json()):null;render(data?.identities?.length?data:sample(advanceDemoPhase()));}
 catch{state.api=false;state.sampleMode=false;$('#backendLabel').textContent='Browser analysis';$('#sourceLabel').textContent='Backend not connected';$('#connectionBadge').textContent='BROWSER MODE';$('#helpBanner').hidden=false;render(sample(advanceDemoPhase()));}
 $('#scanState').textContent='READY';$('#scanState').className='state complete';$('#pipelineState').textContent='READY';$('#pipelineState').className='state complete';progress(0,'Ready for an IAM scan');
 if(state.api&&state.sampleMode)await scan();
}
function advanceDemoPhase(){state.scanCount+=1;try{localStorage.setItem('sentinel-demo-phase',String(state.scanCount));}catch{}return state.scanCount;}
function saveScanRecord(data){const record={timestamp:data.timestamp||new Date().toISOString(),risk_score:data.metrics.risk_score||0,identity_count:data.metrics.identity_count||data.identities.length,finding_count:data.findings.filter(item=>item.status==='Open').length,critical_count:data.metrics.critical_count||0};state.history.push(record);state.history=state.history.slice(-8);try{localStorage.setItem('sentinel-scan-history',JSON.stringify(state.history));}catch{}}
async function scan(){const buttons=[$('#scanButton'),$('#startScanButton')];buttons.forEach(button=>button.disabled=true);state.scanning=true;setScanActivity(0);$('#radarStage').classList.add('scanning');$('#threat-map').classList.add('is-scanning');$('.topology-panel').classList.add('is-scanning');$('#scanState').textContent='SCANNING';$('#scanState').className='state running';$('#pipelineState').textContent='SCANNING';$('#pipelineState').className='state running';let data;try{if(state.api&&location.protocol!=='file:'){for(const [p,msg] of [[12,'Discovering identities and services'],[34,'Inspecting roles and permissions'],[57,'Checking MFA and credential hygiene'],[79,'Scoring sample access risk'],[96,'Preparing recommendations and verification']]){progress(p,msg);await wait(320);}const response=await fetch('/api/scan',{method:'POST'});const result=await response.json();if(!response.ok)throw new Error(result.error||`Scan failed (${response.status}).`);data=state.sampleMode||result.mode==='sample-demo'?varyDemoSnapshot(result):result;}else{for(const [p,msg] of [[18,'Discovering identity records'],[45,'Checking IAM roles and permissions'],[72,'Reviewing MFA and key hygiene'],[100,'Preparing risk report']]){progress(p,msg);await wait(320);}data=sample(advanceDemoPhase());}saveScanRecord(data);render(data);$('#scanState').textContent='SCAN COMPLETE';$('#scanState').className='state complete';$('#pipelineState').textContent='COMPLETE';$('#pipelineState').className='state complete';$('#radarMessage').textContent=`Scan ${data.scan_number||state.history.length} complete · synthetic snapshot refreshed.`;toast(`IAM scan complete: ${data.metrics.identity_count} identities, ${data.metrics.finding_count} signals.`);}catch(error){$('#scanState').textContent='SCAN FAILED';$('#scanState').className='state error';$('#pipelineState').textContent='FAILED';$('#pipelineState').className='state error';$('#progressText').textContent=error.message;$('#radarMessage').textContent=error.message;toast(`Scan failed: ${error.message}`);}finally{state.scanning=false;setScanActivity(0);if($('#scanState').textContent==='SCAN COMPLETE'){ $('#radarProgressFill').style.width='100%';$('#radarProgressValue').textContent='100%';}$('#radarStage').classList.remove('scanning');$('#threat-map').classList.remove('is-scanning');$('.topology-panel').classList.remove('is-scanning');buttons.forEach(button=>button.disabled=false);}}
async function review(id){const item=state.data?.findings.find(f=>f.id===id);if(!item)return;if(state.api&&location.protocol!=='file:'){try{await fetch(`/api/findings/${encodeURIComponent(id)}/review`,{method:'POST'});}catch{}}item.status='Reviewed';render(state.data);toast('Marked reviewed. No cloud access changed.');}
$('#scanButton').addEventListener('click',scan);
$('#startScanButton').addEventListener('click',scan);
document.querySelectorAll('.radar-category').forEach(button=>button.addEventListener('click',()=>selectScanCategory(button.dataset.scanCategory)));
$('#scannerDistribution').addEventListener('click',event=>{const button=event.target.closest('[data-severity-filter]');if(!button)return;$('#filterSeverity').value=button.dataset.severityFilter;$('#filterSeverity').dispatchEvent(new Event('change'));$('#findings').scrollIntoView({behavior:'smooth',block:'start'});});
$('#clearHistoryButton').addEventListener('click',()=>{state.history=[];try{localStorage.removeItem('sentinel-scan-history');}catch{}if(state.data)renderAnalytics(state.data);toast('This browser’s synthetic scan history was cleared.');});
$('#includeMfaSetting').addEventListener('change',()=>state.data&&render(state.data));
$('#includeKeySetting').addEventListener('change',()=>state.data&&render(state.data));
$('#filterSeverity').addEventListener('change',()=>state.data&&render(state.data));
$('#searchInput').addEventListener('input',()=>state.data&&render(state.data));
$('#findingList').addEventListener('click',event=>{const button=event.target.closest('[data-review]');if(button)review(button.dataset.review);});
$('#findingList').addEventListener('click',event=>{const button=event.target.closest('[data-fix]');if(!button)return;if(button.hasAttribute('data-verify'))verifyFix(button.dataset.fix);else simulateFix(button.dataset.fix);});
document.querySelectorAll('.topology-node').forEach(button=>button.addEventListener('click',()=>selectTopologyNode(button.dataset.node)));
$('#nodeFixButton').addEventListener('click',()=>{const node=TOPOLOGY_NODES[state.selectedNode],finding=state.data?.findings.find(item=>item.identity_id===node.identity);if(finding)simulateFix(finding.id);});
$('#nodeVerifyButton').addEventListener('click',()=>{const node=TOPOLOGY_NODES[state.selectedNode],finding=state.data?.findings.find(item=>item.identity_id===node.identity&&state.pendingFixes.has(`${item.identity_id}:${item.rule_id}`));if(finding)verifyFix(finding.id);});
$('#identityHeatmap').addEventListener('click',event=>{const cell=event.target.closest('[data-heat-identity]');if(!cell)return;const person=state.data?.identities.find(item=>item.id===cell.dataset.heatIdentity);if(!person)return;const node=Object.entries(TOPOLOGY_NODES).find(([,meta])=>meta.identity===person.id);if(node){selectTopologyNode(node[0]);$('#topology').scrollIntoView({behavior:'smooth',block:'center'});}});
$('#severityChart').addEventListener('click',event=>{const button=event.target.closest('[data-severity-filter]');if(!button)return;$('#filterSeverity').value=button.dataset.severityFilter;$('#filterSeverity').dispatchEvent(new Event('change'));$('#findings').scrollIntoView({behavior:'smooth'});});
$('#mapRegionControls').addEventListener('click',event=>{const button=event.target.closest('[data-region-focus]');if(button)setRegionFocus(button.dataset.regionFocus);});
document.querySelectorAll('.world-point').forEach(point=>point.addEventListener('click',()=>setRegionFocus(point.dataset.region)));
$('#mapAutoButton').addEventListener('click',()=>{state.manualRegion=false;setRegionFocus(REGIONS[(state.signalPhase||0)%REGIONS.length].name,false);});
$('#lockerButton').addEventListener('click',()=>{if(!state.data)return;const atRisk=state.data.findings.some(item=>['Critical','High'].includes(item.severity));if(atRisk){toast('Resolve high-risk findings and verify the scan before unlock.');return;}state.manualLock=!state.manualLock;render(state.data);toast(state.manualLock?'Resource lock engaged.':'Resource unlocked (simulation).');});
const navLinks=[...document.querySelectorAll('.sidebar nav a')];
const navSections=navLinks.map(link=>document.querySelector(link.getAttribute('href'))).filter(Boolean);
let scrollQueued=false;
window.addEventListener('scroll',()=>{if(scrollQueued)return;scrollQueued=true;requestAnimationFrame(()=>{const visible=navSections.filter(section=>section.getBoundingClientRect().top<=170);const current=visible[visible.length-1]||navSections[0];navLinks.forEach(link=>link.classList.toggle('active',document.querySelector(link.getAttribute('href'))===current));scrollQueued=false;});},{passive:true});
function cycleMapSignals(){
 const points=[...document.querySelectorAll('.world-point')];
 const label=$('#mapPulseLabel');
 if(!points.length||!label)return;
 let phase=0;
 const update=()=>{
  points.forEach((point,index)=>{
   const isEmerging=(index+phase)%points.length<2;
   point.classList.toggle('emerging',isEmerging);
   point.classList.toggle('easing',!isEmerging);
  });
  state.signalPhase=phase;
  const region=REGIONS[phase%REGIONS.length];
  if(!state.manualRegion)setRegionFocus(region.name,false);
  label.textContent=state.scanning?'SAMPLE SCAN ACTIVE':state.manualRegion?`FOCUS · ${state.regionFocus.toUpperCase()}`:`SIMULATED ${phase%2===0?'EMERGING':'EASING'} · ${region.short}`;
  phase=(phase+1)%points.length;
 };
 update();
 window.setInterval(update,1700);
}
function startAmbientTyping(){
 const target=$('#ambientCodeText');if(!target)return;
 const lines=[
  'scan.sample_identities()  // local analysis',
  'check: public_principal → roles/owner',
  'review: mfa_status · credential_age',
  'score = explainable_iam_risk(findings)',
  'recommendation: apply least privilege',
  'verify(simulated_fix)  // no cloud changes'
 ];
 if(matchMedia('(prefers-reduced-motion: reduce)').matches){target.textContent=lines.join('\n');return;}
 let row=0,column=0,text='';
 const type=()=>{
  const line=lines[row];text+=line[column++]||'';
  if(column>=line.length){text+='\n';row=(row+1)%lines.length;column=0;}
  const visible=text.split('\n');if(visible.length>7)text=visible.slice(-7).join('\n');
  target.textContent=text;window.setTimeout(type,32+Math.random()*34);
 };
 type();
}
cycleMapSignals();
startAmbientTyping();
load();
