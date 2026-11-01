const $ = selector => document.querySelector(selector);
const state = { api: false, source: 'demo', cloud: null, scanning: false, scanId: null, identities: [], findings: [], toastTimer: null, pollTimer: null, localHistory: [], remediationPlan: null };
const localPeople = [
  {id:'u-1001',name:'Alex Morgan',email:'alex.morgan@acme.demo',type:'Human',owner:'Platform Security',mfa:false,admin:true,permissions:['*'],key_age_days:0,inactive_days:2},
  {id:'s-2001',name:'svc-deploy-prod',email:'service · Production',type:'Service account',owner:'Platform Engineering',mfa:null,admin:false,permissions:['compute:*','iam:PassRole'],key_age_days:241,inactive_days:0},
  {id:'u-1002',name:'Taylor Kim',email:'taylor.kim@acme.demo',type:'Human',owner:'Data Platform',mfa:true,admin:false,permissions:['storage:*','database:read'],key_age_days:0,inactive_days:1},
  {id:'s-2002',name:'svc-legacy-api',email:'service · Legacy API',type:'Service account',owner:'Application Team',mfa:null,admin:true,permissions:['*'],key_age_days:195,inactive_days:96},
  {id:'u-1004',name:'Jamie Patel',email:'jamie.patel@acme.demo',type:'Human',owner:'Engineering',mfa:false,admin:false,permissions:['compute:read'],key_age_days:0,inactive_days:1},
  {id:'u-1006',name:'Riley Chen',email:'riley.chen@acme.demo',type:'Human',owner:'Engineering',mfa:true,admin:false,permissions:['storage:read'],key_age_days:126,inactive_days:0},
  {id:'s-2005',name:'svc-monitoring',email:'service · Observability',type:'Service account',owner:'SRE',mfa:null,admin:false,permissions:['logs:read','metrics:read'],key_age_days:40,inactive_days:0}
];
const localRules = [
  {id:'IAM-001',title:'Privileged identity without MFA',severity:'Critical',points:45,test:p=>p.admin&&p.type==='Human'&&p.mfa===false,evidence:'Privileged access is enabled while MFA is disabled.',recommendation:'Enable MFA, verify a break-glass path, then review all admin grants.'},
  {id:'IAM-002',title:'Wildcard or broad permissions',severity:'High',points:28,test:p=>p.permissions.some(x=>x==='*'||x.endsWith(':*')),evidence:p=>`Effective permissions include broad grant(s): ${p.permissions.join(', ')}.`,recommendation:'Replace wildcard actions with the smallest resource-scoped permissions needed.'},
  {id:'IAM-003',title:'Stale access key',severity:'High',points:20,test:p=>p.key_age_days>180,evidence:p=>`Credential age is ${p.key_age_days} days; policy threshold is 180 days.`,recommendation:'Rotate the key, validate dependent workloads, and revoke the old key.'},
  {id:'IAM-004',title:'Inactive privileged identity',severity:'High',points:25,test:p=>p.inactive_days>90&&(p.admin||p.permissions.some(x=>x.includes('*'))),evidence:p=>`Identity has been inactive for ${p.inactive_days} days and retains broad access.`,recommendation:'Confirm ownership and business need; disable the identity or remove privileged grants.'},
  {id:'IAM-005',title:'Human identity without MFA',severity:'Medium',points:15,test:p=>p.type==='Human'&&p.mfa===false&&!p.admin,evidence:'MFA is not enabled for this human identity.',recommendation:'Require MFA through the organization identity provider.'},
  {id:'IAM-006',title:'Access key approaching rotation limit',severity:'Medium',points:10,test:p=>p.key_age_days>90&&p.key_age_days<=180,evidence:p=>`Credential age is ${p.key_age_days} days; rotate before day 180.`,recommendation:'Rotate the key before it reaches the 180-day review threshold.'}
];
const localControls = [
  {name:'MFA coverage',framework:'CIS 6.3',percent:71,status:'Attention'},
  {name:'Least privilege',framework:'NIST AC-6',percent:57,status:'Attention'},
  {name:'Credential rotation',framework:'CIS 1.4',percent:71,status:'Attention'},
  {name:'Dormant privileged access',framework:'NIST AC-2',percent:86,status:'Attention'}
];
function buildLocalInventory() {
  const items = localPeople.map(person => {
    const findings = localRules.filter(rule => rule.test(person)).map(rule => ({id:`offline:${person.id}:${rule.id}`,scan_id:'offline',identity_id:person.id,identity_name:person.name,identity_type:person.type,owner:person.owner,rule_id:rule.id,title:rule.title,severity:rule.severity,evidence:typeof rule.evidence==='function'?rule.evidence(person):rule.evidence,recommendation:rule.recommendation,status:'Open',created_at:new Date().toISOString()}));
    const score = Math.min(100,findings.reduce((sum,item)=>sum+(localRules.find(rule=>rule.id===item.rule_id)?.points||0),0));
    return {...person,findings,score,level:score>=70?'Critical':score>=40?'High':score>=15?'Medium':'Low'};
  });
  return {identities:items,findings:items.flatMap(item=>item.findings)};
}

function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, ch => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch]));
}
function notify(message) {
  const toast = $('#toast'); toast.textContent = message; toast.classList.add('show');
  clearTimeout(state.toastTimer); state.toastTimer = setTimeout(() => toast.classList.remove('show'), 3000);
}
async function api(path, options = {}) {
  const response = await fetch(path, {headers:{'Content-Type':'application/json', ...(options.headers || {})}, ...options});
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.error || `API request failed (${response.status})`);
  return data;
}
function setApiStatus(online) {
  state.api = online;
  $('#backendStatus').textContent = online ? 'Local API connected' : 'Backend not started';
  $('#dataSource').textContent = online ? 'Checking selected scan source' : 'Preview only · use Start-IAM-Analyzer.bat';
  $('#backendHelp').hidden = online;
  $('#connectionLabel').textContent = online ? 'LOCAL API ONLINE' : 'OFFLINE DEMO MODE';
  document.querySelector('.live-tag').classList.toggle('offline', !online);
  $('#footerNote').textContent = online ? (state.source === 'google_cloud' ? 'Loopback backend · Google APIs over internet · Explicit approval required for changes' : 'Loopback API · Synthetic demo data · Google Cloud not scanned') : 'Browser-only mode · Synthetic data only · Cloud scanning unavailable';
  $('#dialogSource').innerHTML = `<i></i> ${online ? 'Local API · Results saved in SQLite' : 'Offline preview · Results stay in this tab'}`;
}
function updateCloudStatus(status) {
  state.cloud = status;
  $('#cloudProjectLabel').textContent = status.project_id || 'PROJECT NOT CONFIGURED';
  document.querySelector('.environment').classList.toggle('disconnected', !status.connected);
  if (status.project_id) $('#gcpProjectInput').value = status.project_id;
  if (!state.api) {
    $('#gcpStatusText').textContent = 'Backend is offline. Use Start-IAM-Analyzer.bat to configure this project and scan it.';
  } else if (!status.project_configured) {
    $('#gcpStatusText').textContent = 'No project configured. Enter a project ID above; no credentials are needed in this form.';
  } else if (!status.credentials_detected) {
    $('#gcpStatusText').textContent = `Project ${status.project_id} saved. Application Default Credentials were not detected on the backend machine.`;
  } else {
    $('#gcpStatusText').textContent = `Project ${status.project_id} saved. ADC file detected; permissions are checked when you start a scan.`;
  }
  $('#connectionLabel').textContent = state.source === 'google_cloud'
    ? status.connected ? 'GOOGLE CLOUD SCAN READY' : status.credentials_detected ? 'GCP PROJECT CONFIGURED' : 'GCP CREDENTIALS NEEDED'
    : state.api ? 'LOCAL API · SAMPLE MODE' : 'OFFLINE DEMO MODE';
  $('#scannerDescription').textContent = state.source === 'google_cloud'
    ? 'Backend reads direct project IAM policy and service-account key metadata. No cloud policies are changed.'
    : 'Browser demo scans synthetic identities. Select Google Cloud for a live project scan.';
  $('#scanSourceTag').textContent = state.source === 'google_cloud' ? 'GOOGLE CLOUD · READ ONLY' : state.api ? 'PYTHON DEMO SCANNER' : 'BROWSER DEMO';
}
function relativeAge(iso) {
  if (!iso) return '—';
  const minutes = Math.max(0, Math.floor((Date.now() - new Date(iso).getTime()) / 60000));
  if (minutes < 1) return 'just now';
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.floor(hours / 24)}d ago`;
}
function updateClock() {
  $('#clock').textContent = new Intl.DateTimeFormat(undefined, {hour:'2-digit', minute:'2-digit', second:'2-digit', hour12:false}).format(new Date());
}
function setRiskScore(score) {
  const safeScore = Number(score) || 0;
  $('#riskScore').textContent = safeScore;
  $('#riskRing').style.strokeDashoffset = String(264 - (264 * safeScore / 100));
  const label = safeScore >= 70 ? ['CRITICAL EXPOSURE','critical-chip'] : safeScore >= 40 ? ['ELEVATED RISK','high-chip'] : ['LOWER EXPOSURE','low-chip'];
  $('#riskLabel').textContent = label[0];
  $('#riskLabel').parentElement.className = `state-chip ${label[1]}`;
}
function renderOverview(data, identities, findings) {
  const humans = identities.filter(item => item.type === 'Human').length;
  $('#identityTotal').textContent = data.identity_count ?? identities.length;
  $('#humanTotal').textContent = humans;
  $('#serviceTotal').textContent = identities.length - humans;
  setRiskScore(data.overall_score);
  $('#criticalTotal').textContent = findings.filter(item => item.severity === 'Critical' && item.status === 'Open').length;
  $('#navFindingCount').textContent = findings.filter(item => item.status === 'Open').length;
  const compliance = data.compliance?.percent ?? data.compliance_percent ?? 0;
  $('#compliancePercent').textContent = compliance;
  $('#complianceTrack').style.width = `${compliance}%`;
  $('#complianceState').innerHTML = `<span class="compliance-mark">◆</span> ${compliance >= 90 ? 'Controls mostly aligned' : 'Review control gaps'}`;
  $('#lastScanLabel').textContent = data.completed_at ? `Last scan ${relativeAge(data.completed_at)}` : 'No completed scan yet';
}
function strongestSignal(identity) {
  const finding = identity.findings?.[0];
  if (finding) return finding.title;
  if (identity.inactive_days > 0) return `Inactive ${identity.inactive_days}d`;
  return 'No active rule signals';
}
function renderIdentities(items) {
  state.identities = items;
  const query = $('#searchInput').value.trim().toLowerCase();
  const filtered = items.filter(item => `${item.name} ${item.owner} ${item.email}`.toLowerCase().includes(query));
  $('#identityRows').innerHTML = filtered.map(item => {
    const initials = item.name.split(/[-\s]+/).filter(Boolean).slice(0,2).map(part => part[0]).join('').toUpperCase();
    const credentials = item.key_age_days > 0 ? `${item.key_age_days} days` : item.type === 'Human' ? 'Federated' : 'N/A';
    const typeClass = item.type === 'Service account' ? ' service' : '';
    return `<tr><td><div class="identity-person"><span class="identity-mini${typeClass}">${escapeHtml(initials)}</span><span><b>${escapeHtml(item.name)}</b><small>${escapeHtml(item.owner)}</small></span></div></td><td>${escapeHtml(item.type)}</td><td class="table-score ${escapeHtml(item.level)}">${item.score}</td><td class="identity-signal">${escapeHtml(strongestSignal(item))}</td><td class="credential-age">${escapeHtml(credentials)}</td><td class="table-level ${escapeHtml(item.level)}">${escapeHtml(item.level.toUpperCase())}</td></tr>`;
  }).join('');
  $('#identityEmpty').hidden = filtered.length > 0;
}
function renderFindings(items) {
  state.findings = items;
  const severity = $('#severityFilter').value;
  const status = $('#statusFilter').value;
  const filtered = items.filter(item => (severity === 'all' || item.severity === severity) && (status === 'all' || item.status === status));
  $('#findingCountBadge').textContent = items.filter(item => item.status === 'Open').length;
  if (!filtered.length) { $('#findingList').innerHTML = '<div class="feed-empty">No findings match these filters.</div>'; renderAlerts(items); return; }
  $('#findingList').innerHTML = filtered.slice(0, 9).map(item => {
    const supportedGcpFix = state.source === 'google_cloud' && ['GCP-001','GCP-002','GCP-003','GCP-004','GCP-006'].includes(item.rule_id);
    return `<div class="finding-row"><span class="finding-severity ${escapeHtml(item.severity.toLowerCase())}"></span><div class="finding-title"><b>${escapeHtml(item.title)}</b><small>${escapeHtml(item.identity_name)} · ${escapeHtml(item.rule_id)}</small></div><div class="finding-evidence">${escapeHtml(item.evidence)}</div><div class="finding-recommend">${escapeHtml(item.recommendation)}</div><span class="severity-badge ${escapeHtml(item.severity.toLowerCase())}">${escapeHtml(item.severity.toUpperCase())}</span>${item.status === 'Open' ? `<div class="finding-actions">${supportedGcpFix ? `<button class="review-button preview-fix" data-preview="${escapeHtml(item.id)}">PREVIEW FIX</button>` : `<button class="review-button copy-fix" data-copy="${escapeHtml(item.recommendation)}">COPY GUIDANCE</button>`}<button class="review-button" data-review="${escapeHtml(item.id)}">MARK REVIEWED</button></div>` : '<span class="reviewed-label">✓ REVIEWED</span>'}</div>`;
  }).join('');
  renderAlerts(items);
}
function renderAlerts(items) {
  const recent = [...items].sort((a,b) => ({Critical:0,High:1,Medium:2}[a.severity] - {Critical:0,High:1,Medium:2}[b.severity])).slice(0,4);
  if (!recent.length) { $('#alertFeed').innerHTML = '<div class="feed-empty">No findings in the latest scan.</div>'; return; }
  $('#alertFeed').innerHTML = recent.map(item => `<div class="alert-item"><span class="alert-icon ${escapeHtml(item.severity.toLowerCase())}">${item.severity === 'Critical' ? '!' : item.severity === 'High' ? '↗' : '◎'}</span><div class="alert-main"><b>${escapeHtml(item.title)}</b><span>${escapeHtml(item.identity_name)} · ${escapeHtml(item.evidence)}</span></div><span class="alert-age">${relativeAge(item.created_at)}</span></div>`).join('');
}
function renderControls(controls) {
  $('#controlsList').innerHTML = controls.length ? controls.map(control => {
    const unassessed = control.percent == null || control.status === 'Not assessed';
    const percentText = unassessed ? 'NOT ASSESSED' : `${escapeHtml(control.status.toUpperCase())} · ${control.percent}%`;
    return `<div class="control-item"><span class="control-name">${escapeHtml(control.name)} <small>${escapeHtml(control.framework)}</small></span><span class="control-status ${control.status === 'Attention' ? 'attention' : ''} ${unassessed ? 'unassessed' : ''}">${percentText}</span><div class="control-bar ${unassessed ? 'unassessed' : ''}"><i class="${control.status === 'Attention' ? 'attention' : ''}" style="width:${unassessed ? 0 : control.percent}%"></i></div></div>`;
  }).join('') : '<div class="feed-empty">Run a scan to calculate project controls.</div>';
}
function renderHistory(history) {
  const svg = $('#trendChart');
  const riskLine = $('#riskLine'); const complianceLine = $('#complianceLine'); const riskArea = $('#riskArea');
  const dots = $('#chartDots');
  if (!history.length) { riskLine.setAttribute('d',''); complianceLine.setAttribute('d',''); riskArea.setAttribute('d',''); $('#chartLabels').innerHTML = '<span>No scan history yet</span>'; return; }
  const data = history.slice(-8); const xFor = index => data.length === 1 ? 350 : 8 + index * (684 / (data.length - 1));
  const yFor = value => 190 - Math.max(0, Math.min(100, Number(value) || 0)) * 1.8;
  const riskPoints = data.map((row,index) => [xFor(index), yFor(row.overall_score)]);
  const compliancePoints = data.map((row,index) => [xFor(index), yFor(row.compliance_percent)]);
  const pathOf = points => points.map(([x,y],index) => `${index ? 'L' : 'M'}${x.toFixed(1)} ${y.toFixed(1)}`).join(' ');
  riskLine.setAttribute('d', pathOf(riskPoints)); complianceLine.setAttribute('d', pathOf(compliancePoints));
  riskArea.setAttribute('d', `${pathOf(riskPoints)} L ${riskPoints.at(-1)[0]} 190 L ${riskPoints[0][0]} 190 Z`);
  dots.innerHTML = riskPoints.map(([x,y]) => `<circle class="chart-dot-risk" cx="${x}" cy="${y}" r="3.5"/>`).join('') + compliancePoints.map(([x,y]) => `<circle class="chart-dot-compliance" cx="${x}" cy="${y}" r="3"/>`).join('');
  $('#chartLabels').innerHTML = data.map(row => `<span>${new Date(row.completed_at).toLocaleDateString(undefined,{month:'short',day:'numeric'})}</span>`).join('');
  svg.setAttribute('aria-label', `Trend chart with ${data.length} completed scan${data.length === 1 ? '' : 's'}`);
}
function renderOfflineDashboard() {
  if (state.source === 'google_cloud') {
    setApiStatus(false);
    $('#connectionLabel').textContent = 'GCP BACKEND REQUIRED';
    $('#dataSource').textContent = 'Local backend not reachable';
    document.querySelector('.live-tag').classList.add('offline');
    $('#riskScore').textContent = '—'; $('#riskLabel').textContent = 'NOT SCANNED'; $('#riskLabel').parentElement.className = 'state-chip high-chip';
    $('#riskRing').style.strokeDashoffset = '264';
    $('#identityTotal').textContent = '—'; $('#humanTotal').textContent = '—'; $('#serviceTotal').textContent = '—';
    $('#criticalTotal').textContent = '—'; $('#navFindingCount').textContent = '—';
    $('#compliancePercent').textContent = '—'; $('#complianceTrack').style.width = '0%';
    $('#lastScanLabel').textContent = 'Open with the local backend to scan Google Cloud';
    state.identities = []; state.findings = [];
    $('#identityRows').innerHTML = ''; $('#identityEmpty').hidden = false; $('#identityEmpty').textContent = 'GCP scan requires the backend. Start it with Start-IAM-Analyzer.bat.';
    $('#findingList').innerHTML = '<div class="feed-empty">Select Google Cloud, configure ADC, and run a live scan.</div>';
    $('#alertFeed').innerHTML = '<div class="feed-empty">No Google Cloud scan results yet.</div>';
    renderControls([]); renderHistory([]);
    $('#scanSourceTag').textContent = 'GCP BACKEND REQUIRED';
    $('#scannerDescription').textContent = 'A real Google Cloud scan needs the Python backend and local ADC credentials. This page will not substitute sample data.';
    $('#gcpStatusText').textContent = 'Backend is offline. Use Start-IAM-Analyzer.bat to configure this project and scan it.';
    return;
  }
  const inventory = buildLocalInventory();
  state.identities = inventory.identities;
  state.findings = inventory.findings;
  const compliance = Math.round(localControls.reduce((sum,item)=>sum+item.percent,0)/localControls.length);
  const score = Math.round(inventory.identities.reduce((sum,item)=>sum+item.score,0)/inventory.identities.length);
  const timestamp = new Date().toISOString();
  if (!state.localHistory.length) state.localHistory.push({id:'offline-baseline',completed_at:timestamp,overall_score:score,compliance_percent:compliance});
  const overview = {identity_count:inventory.identities.length,overall_score:score,completed_at:state.localHistory.at(-1).completed_at,compliance:{percent:compliance,controls:localControls}};
  setApiStatus(false);
  $('#dataSource').textContent = 'Offline sample inventory';
  renderOverview(overview,inventory.identities,inventory.findings);
  renderIdentities(inventory.identities);
  renderFindings(inventory.findings);
  renderControls(localControls);
  renderHistory(state.localHistory);
}
async function loadDashboard() {
  try {
    const sourceQuery = `?source=${encodeURIComponent(state.source)}`;
    const [health, cloud, overview, identityData, findingData, history] = await Promise.all([
      api('/api/health'), api('/api/cloud/status'), api(`/api/overview${sourceQuery}`), api(`/api/identities${sourceQuery}`), api(`/api/findings${sourceQuery}`), api(`/api/history${sourceQuery}`)
    ]);
    setApiStatus(health.status === 'ok');
    updateCloudStatus(cloud);
    $('#dataSource').textContent = state.source === 'google_cloud' ? cloud.connected ? `GCP project · ${cloud.project_id}` : 'GCP project not scanned' : 'Synthetic demo inventory';
    renderOverview(overview, identityData.items, findingData.items);
    renderIdentities(identityData.items); renderFindings(findingData.items);
    renderControls(overview.compliance.controls); renderHistory(history.items);
  } catch (error) {
    renderOfflineDashboard();
  }
}
function setScannerState(mode, text) {
  const element = $('#scanState'); element.className = `scan-state ${mode}`;
  element.querySelector('span').textContent = text;
}
function updateScanUi(job) {
  const progress = Math.max(0, Math.min(100, Number(job.progress) || 0));
  $('#scanProgress').style.width = `${progress}%`; $('#scanPercent').textContent = `${progress}%`;
  $('#scanProgressText').textContent = job.phase || job.status;
  $('#dialogProgress').style.width = `${progress}%`; $('#dialogPercent').textContent = `${progress}%`;
  $('#dialogPhase').innerHTML = `<span class="pulse-dot"></span> ${escapeHtml(job.phase || job.status)}${job.status === 'running' ? '…' : ''}`;
  const steps = ['inventory','permissions','credentials','controls'];
  steps.forEach((name,index) => {
    const module = document.querySelector(`[data-module="${name}"]`);
    const activeStep = Math.min(3, Math.floor(progress / 25));
    module.classList.toggle('active', job.status === 'running' && index === activeStep);
    module.classList.toggle('done', progress >= (index + 1) * 25);
    module.querySelector('.module-state').textContent = progress >= (index + 1) * 25 ? 'DONE' : job.status === 'running' && index === activeStep ? 'SCANNING' : 'READY';
  });
  setScannerState(job.status === 'running' ? 'running' : job.status === 'completed' ? 'complete' : 'idle', job.status === 'running' ? 'SCAN IN PROGRESS' : job.status === 'completed' ? 'SCAN COMPLETE' : 'SCANNER IDLE');
}
function finishScan(job) {
  state.scanning = false; clearTimeout(state.pollTimer);
  $('#scanSource').disabled = false;
  updateScanUi(job);
  $('#dialogDescription').textContent = state.source === 'google_cloud' ? 'The backend completed a read-only scan of the configured Google Cloud project.' : state.api ? 'The local Python rule engine completed its review of the synthetic identity inventory.' : 'The browser rule engine completed its review of the offline sample inventory.';
  const summary = job.summary || {total_identities:job.total_identities, findings:0, critical:job.critical_count, high:job.high_count, overall_score:job.overall_score, compliance_percent:job.compliance_percent};
  $('#dialogResult').innerHTML = `<div class="dialog-stat"><b>${summary.total_identities ?? 0}</b><small>Identities reviewed</small></div><div class="dialog-stat"><b>${summary.critical ?? 0}</b><small>Critical findings</small></div><div class="dialog-stat"><b>${summary.findings ?? ((summary.critical || 0)+(summary.high || 0))}</b><small>Rule detections</small></div>`;
  $('#dialogResult').hidden = false; $('#dialogDone').hidden = false;
  $('#dialogPhase').innerHTML = `<span class="pulse-dot"></span> Scan complete · ${state.api ? 'results saved in local SQLite' : 'results held in this browser session'}`;
  if (state.api) loadDashboard();
  else {
    const timestamp = new Date().toISOString();
    const localData = buildLocalInventory();
    state.localHistory.push({id:`offline-${Date.now()}`,completed_at:timestamp,overall_score:Math.round(localData.identities.reduce((sum,item)=>sum+item.score,0)/localData.identities.length),compliance_percent:Math.round(localControls.reduce((sum,item)=>sum+item.percent,0)/localControls.length)});
    renderOfflineDashboard();
  }
}
async function pollScan(scanId) {
  try {
    const job = await api(`/api/scans/${encodeURIComponent(scanId)}`);
    updateScanUi(job);
    if (job.status === 'completed') return finishScan(job);
    if (job.status === 'failed') { state.scanning = false; $('#scanSource').disabled = false; $('#dialogPhase').textContent = `Scan failed: ${job.error || 'unknown error'}`; setScannerState('idle','SCAN FAILED'); return; }
    state.pollTimer = setTimeout(() => pollScan(scanId), 450);
  } catch (error) { state.scanning = false; $('#scanSource').disabled = false; $('#dialogPhase').textContent = error.message; setScannerState('idle','API ERROR'); }
}
async function startScan() {
  if (state.scanning) return;
  if (state.source === 'google_cloud' && !state.api) {
    notify('GCP live scans need the local Python backend. Start it with Start-IAM-Analyzer.bat.');
    return;
  }
  state.scanning = true;
  $('#scanSource').disabled = true;
  $('#dialogDescription').textContent = state.source === 'google_cloud' ? 'Starting a read-only scan of the configured Google Cloud project.' : state.api ? 'Starting the Python rule engine against the synthetic demo inventory.' : 'Running browser-only sample checks. Scan history is not saved in this mode.';
  $('#dialogResult').hidden = true; $('#dialogDone').hidden = true;
  $('#dialogProgress').style.width = '0%'; $('#dialogPercent').textContent = '0%';
  $('#modalOverlay').hidden = false; $('#scanDialog').showModal();
  setScannerState('running','STARTING SCAN');
  document.querySelectorAll('.scan-module').forEach(module => { module.classList.remove('active','done'); module.querySelector('.module-state').textContent = 'READY'; });
  if (!state.api) {
    const localStages = [{progress:18,phase:'Inventorying offline sample identities'},{progress:46,phase:'Evaluating wildcard and privileged permissions'},{progress:73,phase:'Checking MFA, key age, and inactivity'},{progress:91,phase:'Mapping detections to CIS/NIST reference controls'}];
    localStages.forEach((stage,index) => setTimeout(() => updateScanUi({status:'running',...stage}),index*650));
    setTimeout(() => {
      const localData = buildLocalInventory();
      finishScan({status:'completed',progress:100,phase:'Offline sample scan complete',summary:{total_identities:localData.identities.length,findings:localData.findings.length,critical:localData.findings.filter(item=>item.severity==='Critical').length,high:localData.findings.filter(item=>item.severity==='High').length,overall_score:Math.round(localData.identities.reduce((sum,item)=>sum+item.score,0)/localData.identities.length),compliance_percent:Math.round(localControls.reduce((sum,item)=>sum+item.percent,0)/localControls.length)}});
    },localStages.length*650);
    return;
  }
  try {
    const job = await api('/api/scans', {method:'POST',body:JSON.stringify({source:state.source})});
    state.scanId = job.id;
    $('#dialogPhase').innerHTML = '<span class="pulse-dot"></span> Scan job queued…';
    pollScan(job.id);
  } catch (error) { state.scanning = false; $('#scanSource').disabled = false; setScannerState('idle','API ERROR'); $('#dialogPhase').textContent = error.message; notify('Could not start scan.'); }
}
function closeDialog() {
  if ($('#scanDialog').open) $('#scanDialog').close();
  $('#modalOverlay').hidden = true;
}
function openGcpDialog() {
  $('#modalOverlay').hidden = false;
  $('#gcpDialog').showModal();
  if (state.cloud?.project_id) $('#gcpProjectInput').value = state.cloud.project_id;
}
function closeGcpDialog() {
  if ($('#gcpDialog').open) $('#gcpDialog').close();
  $('#modalOverlay').hidden = true;
}
async function saveGcpProject() {
  if (!state.api) return notify('Start the backend with Start-IAM-Analyzer.bat before saving a GCP project.');
  const projectId = $('#gcpProjectInput').value.trim();
  try {
    const result = await api('/api/cloud/project',{method:'POST',body:JSON.stringify({project_id:projectId})});
    $('#scanSource').value = 'google_cloud'; state.source = 'google_cloud';
    notify(`${result.project_id} saved locally. Next, configure ADC and run a scan.`);
    await loadDashboard();
  } catch (error) { $('#gcpStatusText').textContent = error.message; notify(`Could not save project: ${error.message}`); }
}
async function markReviewed(findingId) {
  if (!state.api) {
    state.findings = state.findings.map(item => item.id === findingId ? {...item,status:'Reviewed'} : item);
    renderFindings(state.findings);
    renderOverview({identity_count:state.identities.length,overall_score:Math.round(state.identities.reduce((sum,item)=>sum+item.score,0)/state.identities.length),completed_at:state.localHistory.at(-1)?.completed_at,compliance:{percent:Math.round(localControls.reduce((sum,item)=>sum+item.percent,0)/localControls.length)}},state.identities,state.findings);
    return notify('Marked reviewed in this browser session only. No cloud permissions were changed.');
  }
  try {
    await api(`/api/findings/${encodeURIComponent(findingId)}/review`, {method:'POST',body:JSON.stringify({status:'Reviewed'})});
    notify('Marked reviewed in the local findings database. No cloud permissions were changed.');
    await loadDashboard();
  } catch (error) { notify(`Review update failed: ${error.message}`); }
}
async function previewRemediation(findingId) {
  if (!state.api || state.source !== 'google_cloud') return notify('Remediation preview requires the local backend and a Google Cloud scan.');
  try {
    const plan = await api('/api/remediation/preview', {method:'POST',body:JSON.stringify({finding_id:findingId})});
    state.remediationPlan = plan;
    $('#remediationSummary').textContent = plan.summary;
    $('#remediationImpact').textContent = plan.impact;
    const targetDetails = plan.rule_id === 'GCP-006' ? `Key: ${plan.target.key_name}` : `Principal: ${plan.target.member} · Role: ${plan.target.role}${plan.target.condition ? ` · Condition: ${JSON.stringify(plan.target.condition)}` : ''}`;
    $('#remediationTarget').textContent = targetDetails;
    $('#remediationConfirm').checked = false;
    $('#applyRemediation').disabled = true;
    $('#remediationStatus').textContent = `Plan ${plan.id.slice(0,8)} · ${plan.project_id} · Approval required`;
    $('#modalOverlay').hidden = false; $('#remediationDialog').showModal();
  } catch (error) { notify(`Preview failed: ${error.message}`); }
}
async function applyRemediation() {
  const plan = state.remediationPlan;
  if (!plan || !$('#remediationConfirm').checked) return;
  $('#applyRemediation').disabled = true;
  $('#remediationStatus').textContent = 'Applying approved change…';
  try {
    const result = await api(`/api/remediation/${encodeURIComponent(plan.id)}/apply`, {method:'POST',body:JSON.stringify({confirm:true})});
    $('#remediationStatus').textContent = `${result.message} ${result.result?.message || ''}`;
    notify('Approved cloud change applied. Run a fresh Google Cloud scan to verify.');
    state.remediationPlan = null;
    await loadDashboard();
  } catch (error) {
    $('#remediationStatus').textContent = `Not applied: ${error.message}`;
    $('#applyRemediation').disabled = false;
  }
}

$('#scanButton').addEventListener('click', startScan);
$('#scanSource').addEventListener('change', () => { state.source = $('#scanSource').value; loadDashboard(); });
$('#gcpSetupButton').addEventListener('click', openGcpDialog);
$('#closeGcpDialog').addEventListener('click', closeGcpDialog);
$('#saveGcpProject').addEventListener('click', saveGcpProject);
$('#closeDialog').addEventListener('click', closeDialog); $('#dialogDone').addEventListener('click', closeDialog);
$('#modalOverlay').addEventListener('click', () => { document.querySelectorAll('dialog[open]').forEach(dialog => dialog.close()); $('#modalOverlay').hidden = true; });
$('#scanDialog').addEventListener('close', () => { $('#modalOverlay').hidden = true; });
$('#gcpDialog').addEventListener('close', () => { $('#modalOverlay').hidden = true; });
$('#remediationDialog').addEventListener('close', () => { $('#modalOverlay').hidden = true; });
$('#severityFilter').addEventListener('change', () => renderFindings(state.findings));
$('#statusFilter').addEventListener('change', () => renderFindings(state.findings));
$('#searchInput').addEventListener('input', () => renderIdentities(state.identities));
$('#findingList').addEventListener('click', event => { const button = event.target.closest('[data-review]'); if (button) markReviewed(button.dataset.review); });
$('#findingList').addEventListener('click', event => { const button = event.target.closest('[data-preview]'); if (button) previewRemediation(button.dataset.preview); });
$('#findingList').addEventListener('click', async event => {
  const button = event.target.closest('[data-copy]');
  if (!button) return;
  try { await navigator.clipboard.writeText(button.dataset.copy); notify('Remediation recommendation copied. Apply it through your approved cloud change process.'); }
  catch { notify(button.dataset.copy); }
});
$('#alertButton').addEventListener('click', () => document.querySelector('#findings').scrollIntoView({behavior:'smooth'}));
$('#closeRemediation').addEventListener('click', () => $('#remediationDialog').close());
$('#remediationConfirm').addEventListener('change', event => { $('#applyRemediation').disabled = !event.target.checked; });
$('#applyRemediation').addEventListener('click', applyRemediation);
updateClock(); setInterval(updateClock, 1000); loadDashboard();
setInterval(() => { if (!state.scanning && state.api) loadDashboard(); }, 30000);
