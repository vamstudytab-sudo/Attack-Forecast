(() => {
  const state = {
    graph: {nodes:[],edges:[],overview_nodes:[],overview_edges:[],summary:{}},
    timeline: {events:[]}, summary: {}, status: {},
    graphMode: 'overview', showNormal: true,
    selectedNode: null, selectedEvent: null, nodeIntel: null,
    chatMode: 'detailed', timelineFilter: 'all',
    viewBox: {x:0,y:0,w:1200,h:700}, fitted: true,
  };

  const $ = (id) => document.getElementById(id);
  const fmtPct = (v) => `${Math.round((Number(v)||0)*100)}%`;
  const esc = (s='') => String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  const api = async (path, opts={}) => {
    const r = await fetch(path, opts);
    if (!r.ok) { let d={}; try{d=await r.json()}catch{}; throw new Error(d.detail || `${r.status} ${r.statusText}`); }
    return r.json();
  };

  function setBackend(ok, message='') {
    $('backendPill').textContent = ok ? '● Backend online' : '● Backend offline';
    $('backendPill').classList.toggle('online', ok); $('backendPill').classList.toggle('offline', !ok);
    if (!ok && message) $('datasetMessage').textContent = `Backend error: ${message}`;
  }

  async function refresh() {
    try {
      const [g,t,s,st] = await Promise.all([api('/api/graph'),api('/api/timeline'),api('/api/summary'),api('/api/status')]);
      state.graph=g; state.timeline=t; state.summary=s; state.status=st;
      setBackend(true); renderSummary(); renderGraph(); renderTimeline();
      $('datasetName').textContent = st.dataset_name || 'No dataset loaded';
      $('headerStage').textContent = s.current_stage || 'Normal';
      $('timelineBadge').textContent = (t.events||[]).length;
    } catch(e){ setBackend(false,e.message); }
  }

  function renderSummary(){
    const s=state.summary||{};
    $('currentStage').textContent=s.current_stage||'Normal';
    $('hostRelationCount').textContent=`${Number(s.hosts||0).toLocaleString()} hosts • ${Number(s.relationships||0).toLocaleString()} relationships`;
    $('detectionConfidence').textContent=fmtPct(s.detection_confidence);
    $('detectionCategory').textContent=(s.detection_category||'No malicious detection').replaceAll('_',' ');
    $('networkRisk').textContent=`${Number(s.network_risk_score||0).toFixed(1)} / 100`;
    $('networkRiskLevel').textContent=s.network_risk_level||'LOW';
    $('forecastProbability').textContent=fmtPct(s.forecast_confidence);
    $('forecastStage').textContent=`${s.forecast_stage||'No forecast'}${s.predicted_target?` → ${s.predicted_target} • target risk ${s.target_risk_score}/100`:''}`;
  }

  function filteredGraph(){
    const g=state.graph||{};
    if(state.graphMode==='overview') return {nodes:g.overview_nodes||[],edges:state.showNormal?(g.overview_edges||[]):(g.overview_edges||[]).filter(e=>e.attack!=='NORMAL')};
    const nodes=g.nodes||[], edges=g.edges||[];
    if(state.graphMode==='attack'){
      // Keep the investigation view readable: prediction is always retained,
      // while observed attack edges are ranked by risk/malicious evidence.
      const predicted=edges.filter(e=>e.predicted);
      const observed=edges.filter(e=>!e.predicted&&e.attack!=='NORMAL').sort((a,b)=>
        ((b.risk_score||0)-(a.risk_score||0)) || ((b.malicious_count||0)-(a.malicious_count||0)) || ((b.flow_count||0)-(a.flow_count||0))
      ).slice(0,10);
      const imp=[...observed,...predicted]; const ids=new Set(); imp.forEach(e=>{ids.add(e.source);ids.add(e.target)});
      if(!ids.size) nodes.slice().sort((a,b)=>(b.risk_score||0)-(a.risk_score||0)).slice(0,8).forEach(n=>ids.add(n.id));
      return {nodes:nodes.filter(n=>ids.has(n.id)),edges:imp.filter(e=>ids.has(e.source)&&ids.has(e.target))};
    }
    // Host view is an exact-IP investigation view, not a 90-node hairball.
    const allowedEdges=state.showNormal?edges:edges.filter(e=>e.attack!=='NORMAL'||e.predicted);
    if(state.selectedNode){
      const first=allowedEdges.filter(e=>e.source===state.selectedNode||e.target===state.selectedNode);
      const ids=new Set([state.selectedNode]);first.forEach(e=>{ids.add(e.source);ids.add(e.target)});
      const second=allowedEdges.filter(e=>ids.has(e.source)||ids.has(e.target)).sort((a,b)=>(b.risk_score||0)-(a.risk_score||0)).slice(0,32);
      second.forEach(e=>{ids.add(e.source);ids.add(e.target)});
      const kept=[...first,...second].filter((e,i,a)=>a.findIndex(x=>x.id===e.id)===i).slice(0,40);
      return {nodes:nodes.filter(n=>ids.has(n.id)).slice(0,28),edges:kept.filter(e=>ids.has(e.source)&&ids.has(e.target))};
    }
    const top=[...nodes].sort((a,b)=>(b.risk_score||0)-(a.risk_score||0)).slice(0,24);
    const ids=new Set(top.map(n=>n.id));
    return {nodes:top,edges:allowedEdges.filter(e=>ids.has(e.source)&&ids.has(e.target)).slice(0,50)};
  }

  function layoutGraph(nodes,edges){
    const pos={};
    if(state.graphMode==='overview'){
      const sorted=[...nodes].sort((a,b)=>(b.risk_score||0)-(a.risk_score||0)); const cols=Math.max(2,Math.ceil(Math.sqrt(sorted.length)));
      sorted.forEach((n,i)=>pos[n.id]={x:90+(i%cols)*340,y:90+Math.floor(i/cols)*180});
    } else if(state.graphMode==='attack'){
      const predictedIds=new Set(edges.filter(e=>e.predicted).map(e=>e.target));
      const sourceIds=new Set(edges.filter(e=>!e.predicted&&e.attack!=='NORMAL').map(e=>e.source));
      const targetIds=new Set(edges.filter(e=>!e.predicted&&e.attack!=='NORMAL').map(e=>e.target));
      const cols=[[],[],[],[]];
      nodes.forEach(n=>{ if(predictedIds.has(n.id))cols[3].push(n); else if(sourceIds.has(n.id))cols[0].push(n); else if(targetIds.has(n.id))cols[1].push(n); else cols[2].push(n); });
      const xs=[80,430,780,1130]; cols.forEach((arr,c)=>arr.sort((a,b)=>(b.risk_score||0)-(a.risk_score||0)).forEach((n,i)=>pos[n.id]={x:xs[c],y:100+i*135}));
    } else {
      const sorted=[...nodes].sort((a,b)=>(b.risk_score||0)-(a.risk_score||0)); const cols=8;
      sorted.forEach((n,i)=>pos[n.id]={x:70+(i%cols)*220,y:70+Math.floor(i/cols)*100});
    }
    return pos;
  }

  function riskClass(r){r=String(r||'LOW').toLowerCase();return ['low','medium','high','critical'].includes(r)?r:'low'}
  function edgeClass(e){if(e.predicted)return 'edge-predicted';if(e.attack==='CREDENTIAL_ATTACK'||e.attack==='MULTI_STAGE')return 'edge-credential';if(e.attack==='RECONNAISSANCE')return 'edge-recon';return 'edge-normal'}
  function marker(e){if(e.predicted)return 'arrowPred';if(e.attack==='CREDENTIAL_ATTACK'||e.attack==='MULTI_STAGE')return 'arrowCred';if(e.attack==='RECONNAISSANCE')return 'arrowRecon';return 'arrowNormal'}

  function renderGraph(){
    const {nodes,edges}=filteredGraph(), pos=layoutGraph(nodes,edges), svg=$('graphSvg'), vp=$('graphViewport');
    $('graphEmpty').classList.toggle('hidden',nodes.length>0); vp.innerHTML='';
    const nodeW=state.graphMode==='overview'?230:190, nodeH=state.graphMode==='overview'?82:72;
    const ns='http://www.w3.org/2000/svg';
    function add(tag,attrs,parent=vp){const el=document.createElementNS(ns,tag);Object.entries(attrs||{}).forEach(([k,v])=>el.setAttribute(k,v));parent.appendChild(el);return el}

    edges.forEach(e=>{
      const a=pos[e.source],b=pos[e.target];if(!a||!b)return;
      const x1=a.x+nodeW,y1=a.y+nodeH/2,x2=b.x,y2=b.y+nodeH/2; const bend=Math.max(55,(x2-x1)*.45);
      const d=`M ${x1} ${y1} C ${x1+bend} ${y1}, ${x2-bend} ${y2}, ${x2} ${y2}`;
      add('path',{d,class:edgeClass(e),'marker-end':`url(#${marker(e)})`});
      if(e.attack!=='NORMAL'||e.predicted){
        const mx=(x1+x2)/2,my=(y1+y2)/2-12; let label=e.predicted?`Predicted lateral movement • ${fmtPct(state.summary.forecast_confidence)}`:`${e.relationship||e.attack} • ${e.flow_count||0} flows${e.confidence?` • ${fmtPct(e.confidence)}`:''}`;
        const width=Math.min(300,Math.max(130,label.length*5.4)); add('rect',{x:mx-width/2,y:my-13,width,height:24,rx:6,class:'edge-label-bg'}); const tx=add('text',{x:mx,y:my+3,'text-anchor':'middle',class:'edge-label'});tx.textContent=label;
      }
    });

    nodes.forEach(n=>{
      const p=pos[n.id]; if(!p)return; const g=add('g',{class:`node ${riskClass(n.risk)} ${state.selectedNode===n.id?'selected-node':''} ${edges.some(e=>e.predicted&&e.target===n.id)?'predicted':''}`,transform:`translate(${p.x},${p.y})`});
      add('rect',{width:nodeW,height:nodeH,rx:10},g);
      const t1=add('text',{x:14,y:24,class:'node-title'},g); t1.textContent=n.label||n.id;
      const role=n.type==='subnet'?`${n.host_count||0} hosts`:(n.role||'host').replaceAll('_',' '); const t2=add('text',{x:14,y:44,class:'node-role'},g);t2.textContent=role;
      const tr=add('text',{x:nodeW-13,y:25,'text-anchor':'end',class:'node-risk',fill:n.risk==='CRITICAL'?'#ef5965':n.risk==='HIGH'?'#f0b44a':n.risk==='MEDIUM'?'#4da3ff':'#90a3b7'},g);tr.textContent=`Risk ${Math.round(Number(n.risk_score||0))}`;
      const tc=add('text',{x:nodeW-13,y:48,'text-anchor':'end',class:'node-count'},g);tc.textContent=n.type==='subnet'?`${Number(n.flow_count||0).toLocaleString()} flow touches`:`${Number(n.flows||0).toLocaleString()} flows`;
      g.addEventListener('click',()=>selectNode(n));
    });

    const s=state.graph.summary||{};
    $('graphSubtitle').textContent=state.graphMode==='overview'?`Whole-network overview: all ${Number(s.total_nodes_in_dataset||0).toLocaleString()} observed hosts grouped into ${s.overview_groups||0} network groups`:
      state.graphMode==='full'?`Host view: focused exact-IP investigation from ${Number(s.total_nodes_in_dataset||0).toLocaleString()} observed hosts${state.selectedNode?` • selected ${state.selectedNode}`:''}`:
      `Attack path: observed malicious relationships + predicted next target • full dataset has ${Number(s.total_nodes_in_dataset||0).toLocaleString()} hosts`;
    state._positions=pos; state._nodeW=nodeW; state._nodeH=nodeH;
    if(state.fitted) fitGraph(); else applyViewBox();
  }

  function fitGraph(){
    const {nodes}=filteredGraph(); const pos=state._positions||{}; if(!nodes.length){state.viewBox={x:0,y:0,w:1200,h:700};applyViewBox();return}
    const xs=nodes.map(n=>pos[n.id]?.x||0),ys=nodes.map(n=>pos[n.id]?.y||0), pad=90;
    const minX=Math.min(...xs)-pad,minY=Math.min(...ys)-pad,maxX=Math.max(...xs)+(state._nodeW||190)+pad,maxY=Math.max(...ys)+(state._nodeH||72)+pad;
    state.viewBox={x:minX,y:minY,w:Math.max(480,maxX-minX),h:Math.max(300,maxY-minY)};state.fitted=true;applyViewBox();
  }
  function applyViewBox(){$('graphSvg').setAttribute('viewBox',`${state.viewBox.x} ${state.viewBox.y} ${state.viewBox.w} ${state.viewBox.h}`)}
  function zoom(f){const v=state.viewBox,cx=v.x+v.w/2,cy=v.y+v.h/2,nw=v.w*f,nh=v.h*f;state.viewBox={x:cx-nw/2,y:cy-nh/2,w:nw,h:nh};state.fitted=false;applyViewBox()}

  async function selectNode(n){
    if(n.type==='subnet'){state.selectedNode=null;state.nodeIntel=null;$('hostInspector').classList.add('hidden');return}
    state.selectedNode=n.id; renderGraph(); $('chatContext').textContent=`Context: selected host ${n.id}`; buildSuggestions();
    try{state.nodeIntel=await api(`/api/node/${encodeURIComponent(n.id)}`);renderInspector()}catch{state.nodeIntel=null}
  }
  function renderInspector(){const n=state.nodeIntel;if(!n)return;$('hostInspector').classList.remove('hidden');$('inspectorIp').textContent=n.id;$('inspectorRisk').textContent=Number(n.risk_score||0).toFixed(1);$('inspectorRiskLevel').textContent=n.risk;
    $('inspectorGrid').innerHTML=[['Total flows',n.total_flows],['Malicious',n.malicious_flows],['Recon',n.recon_flows],['Credential',n.credential_flows],['Connected hosts',n.connected_host_count],['Avg confidence',fmtPct(n.average_detection_confidence)]].map(([a,b])=>`<div class="inspector-cell"><b>${esc(b)}</b><span>${esc(a)}</span></div>`).join('');
    const comp=n.risk_breakdown?.components||{};$('riskBreakdown').innerHTML=Object.entries(comp).map(([k,v])=>`<div class="risk-row"><span>${esc(k.replaceAll('_',' '))}</span><b>${esc(v)}</b></div>`).join('')||'<div class="risk-row"><span>No breakdown available</span></div>';
  }

  function renderTimeline(){
    let ev=[...(state.timeline.events||[])]; const f=state.timelineFilter;
    if(f==='malicious')ev=ev.filter(e=>e.status==='malicious'); if(f==='suspicious')ev=ev.filter(e=>e.status==='suspicious'||e.status==='malicious'); if(f==='selected'&&state.selectedNode)ev=ev.filter(e=>e.source===state.selectedNode||e.destination===state.selectedNode);
    ev.reverse(); $('timelineBody').innerHTML=ev.map(e=>`<tr data-id="${esc(e.id)}" class="${state.selectedEvent===e.id?'selected':''}"><td>${esc(e.timestamp||'—')}</td><td>${esc(e.event||'—')}</td><td><code>${esc(e.source||'—')}</code></td><td><code>${esc(e.destination||'—')}</code></td><td>${esc(e.port??'—')} / ${esc(e.protocol||'—')}</td><td>${esc(e.mitre_id||'—')} ${esc(e.mitre_technique||'')}</td><td>${esc(e.dataset_label||'—')}</td><td>${e.confidence!=null?fmtPct(e.confidence):'—'}</td><td><span class="status-chip ${esc(e.status||'normal')}">${esc(e.status||'normal')}</span></td></tr>`).join('') || '<tr><td colspan="9" style="text-align:center;color:#7890a8;padding:24px">No events match this filter.</td></tr>';
    [...$('timelineBody').querySelectorAll('tr[data-id]')].forEach(tr=>tr.onclick=()=>{const e=(state.timeline.events||[]).find(x=>x.id===tr.dataset.id);if(!e)return;state.selectedEvent=e.id;const candidate=e.destination||e.source;if(candidate) selectNode({id:candidate,type:'ip',label:candidate,risk:'LOW',risk_score:0});renderTimeline();});
  }

  function toggleChat(open){$('dashboard').classList.toggle('chat-open',open);setTimeout(()=>{state.fitted=true;fitGraph()},240)}
  function toggleTimeline(open){$('dashboard').classList.toggle('timeline-open',open);setTimeout(()=>{state.fitted=true;fitGraph()},240)}

  function buildSuggestions(){const qs=state.selectedNode?[`Why is ${state.selectedNode} high risk?`,`What happened to this host?`,`Explain its MITRE techniques`,`What should I do now?`,`Why is the next target predicted?`]:['Summarize the attack','What is happening now?','Why is lateral movement predicted?','Which host is most risky?','What defensive action should I take?'];$('suggestions').innerHTML=qs.map(q=>`<button>${esc(q)}</button>`).join('');[...$('suggestions').querySelectorAll('button')].forEach(b=>b.onclick=()=>sendChat(b.textContent))}
  function addChat(role,text,evidence=[]){const d=document.createElement('div');d.className=`chat-msg ${role}`;d.innerHTML=`${role==='bot'?'<div class="chat-role">SOC COPILOT</div>':''}<div>${esc(text).replaceAll('\n','<br>')}</div>${evidence?.length?`<div class="evidence"><b>Retrieved evidence</b><br>${evidence.slice(0,3).map(x=>'• '+esc(x.text)).join('<br>')}</div>`:''}${role==='bot'?'<button class="listen-btn">🔊 Read aloud</button>':''}`;$('chatMessages').appendChild(d);$('chatMessages').scrollTop=$('chatMessages').scrollHeight;const listen=d.querySelector('.listen-btn');if(listen)listen.onclick=()=>speak(text)}
  async function sendChat(text){text=(text||$('chatInput').value).trim();if(!text)return;$('chatInput').value='';toggleChat(true);addChat('user',text);addChat('bot','Analyzing current graph and timeline context…');const loading=$('chatMessages').lastElementChild;try{const r=await api('/api/chat',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({message:text,response_mode:state.chatMode,selected_node:state.selectedNode,selected_event:state.selectedEvent})});loading.remove();addChat('bot',r.answer,r.evidence||[])}catch(e){loading.remove();addChat('bot',`I could not query the backend: ${e.message}`)}}
  function speak(text){if(!('speechSynthesis'in window)){ $('voiceStatus').textContent='Text-to-speech is not supported in this browser.';return }speechSynthesis.cancel();const u=new SpeechSynthesisUtterance(text);u.rate=1;speechSynthesis.speak(u);$('voiceStatus').textContent='Voice: reading answer aloud…';u.onend=()=>$('voiceStatus').textContent='Voice: ready • answers can be read aloud'}
  function startMic(){const SR=window.SpeechRecognition||window.webkitSpeechRecognition;if(!SR){$('voiceStatus').textContent='Speech-to-text is not supported here. Try Edge or Chrome.';return}const r=new SR();r.lang='en-IN';r.interimResults=false;r.maxAlternatives=1;$('voiceStatus').textContent='🎤 Listening…';r.onresult=e=>{$('chatInput').value=e.results[0][0].transcript;$('voiceStatus').textContent='Voice captured — press Send or edit the text.'};r.onerror=e=>$('voiceStatus').textContent=`Voice error: ${e.error}`;r.onend=()=>{if($('voiceStatus').textContent==='🎤 Listening…')$('voiceStatus').textContent='Voice: ready'};r.start()}

  function setBusy(msg,pct,show=true){$('datasetMessage').textContent=msg||$('datasetMessage').textContent;$('progressWrap').classList.toggle('hidden',!show);$('progressBar').style.width=`${pct||0}%`}
  function uploadFile(file){if(!file)return;const ext=file.name.toLowerCase().split('.').pop();if(!['csv','zip'].includes(ext)){$('datasetMessage').textContent='Upload a .csv or .zip file.';return}const fd=new FormData();fd.append('file',file);const xhr=new XMLHttpRequest();xhr.open('POST','/api/upload');setBusy(`Uploading ${file.name}…`,0,true);xhr.upload.onprogress=e=>{if(e.lengthComputable){const p=Math.round(e.loaded/e.total*100);setBusy(p<100?`Uploading ${file.name}… ${p}%`:`Upload complete — analyzing and building graph…`,p,true)}};xhr.onload=async()=>{if(xhr.status>=200&&xhr.status<300){let r={};try{r=JSON.parse(xhr.responseText)}catch{};$('datasetMessage').textContent=`Processed ${Number(r.processed_rows||0).toLocaleString()} flows • ${r.graph_nodes||0} hosts • ${r.graph_edges||0} relationships`;state.graphMode='overview';setModeButtons();setBusy('',0,false);await refresh()}else{let d={};try{d=JSON.parse(xhr.responseText)}catch{};$('datasetMessage').textContent=`Upload failed: ${d.detail||xhr.statusText}`;setBusy('',0,false)}};xhr.onerror=()=>{$('datasetMessage').textContent='Upload failed: backend connection error.';setBusy('',0,false)};xhr.send(fd)}
  function uploadFolder(fileList){
    const all=[...(fileList||[])];
    const files=all.filter(f=>f.name.toLowerCase().endsWith('.csv'));
    if(!files.length){$('datasetMessage').textContent='The selected folder contains no CSV files.';return}
    const firstPath=files[0].webkitRelativePath||files[0].name;
    const folderName=firstPath.includes('/')?firstPath.split('/')[0]:'Uploaded dataset folder';
    const totalSize=files.reduce((a,f)=>a+(f.size||0),0);
    const fd=new FormData();
    files.forEach(f=>{fd.append('files',f,f.name);fd.append('relative_paths',f.webkitRelativePath||f.name)});
    fd.append('folder_name',folderName);
    const xhr=new XMLHttpRequest();
    xhr.open('POST','/api/upload-folder');
    setBusy(`Uploading folder ${folderName}: ${files.length} CSV file(s)…`,0,true);
    xhr.upload.onprogress=e=>{
      if(e.lengthComputable){
        const p=Math.round(e.loaded/e.total*100);
        const mb=(e.loaded/1024/1024).toFixed(1), totalMb=(e.total/1024/1024).toFixed(1);
        setBusy(p<100?`Uploading ${folderName}… ${p}% • ${mb}/${totalMb} MB`:`Upload complete — analyzing ${files.length} CSV files and building graph/timeline…`,p,true);
      }
    };
    xhr.onload=async()=>{
      if(xhr.status>=200&&xhr.status<300){
        let r={};try{r=JSON.parse(xhr.responseText)}catch{}
        const skipped=(r.skipped_files||[]).length;
        $('datasetMessage').textContent=`Folder analyzed: ${Number(r.processed_rows||0).toLocaleString()} flow samples • ${Number(r.graph_nodes||0).toLocaleString()} hosts • ${Number(r.graph_edges||0).toLocaleString()} relationships • ${Number(r.timeline_events||0).toLocaleString()} timeline events${skipped?` • ${skipped} file(s) skipped`:''}`;
        state.graphMode='overview';state.selectedNode=null;state.selectedEvent=null;setModeButtons();setBusy('',0,false);await refresh();
      }else{
        let d={};try{d=JSON.parse(xhr.responseText)}catch{}
        $('datasetMessage').textContent=`Folder upload failed: ${d.detail||xhr.statusText}`;setBusy('',0,false);
      }
    };
    xhr.onerror=()=>{$('datasetMessage').textContent='Folder upload failed: backend connection error.';setBusy('',0,false)};
    xhr.send(fd);
  }
  async function replay(){try{await api('/api/replay/start',{method:'POST'});$('datasetMessage').textContent='Real CICIDS2017 replay running…';state.graphMode='attack';setModeButtons();await refresh()}catch(e){$('datasetMessage').textContent=`Replay failed: ${e.message}`}}
  async function reset(){try{await api('/api/replay/reset',{method:'POST'});state.selectedNode=null;state.selectedEvent=null;$('hostInspector').classList.add('hidden');$('datasetMessage').textContent='Runtime reset. Upload a dataset folder, CSV, or ZIP to build a new graph and timeline.';await refresh()}catch(e){$('datasetMessage').textContent=`Reset failed: ${e.message}`}}

  function setModeButtons(){document.querySelectorAll('.mode-btn[data-mode]').forEach(b=>b.classList.toggle('active',b.dataset.mode===state.graphMode))}
  document.querySelectorAll('.mode-btn[data-mode]').forEach(b=>b.onclick=()=>{state.graphMode=b.dataset.mode;state.fitted=true;setModeButtons();renderGraph()});
  $('normalToggle').onclick=()=>{state.showNormal=!state.showNormal;$('normalToggle').classList.toggle('active',state.showNormal);state.fitted=true;renderGraph()};$('normalToggle').classList.toggle('active',state.showNormal);
  $('fitBtn').onclick=fitGraph;$('fitSmall').onclick=fitGraph;$('zoomIn').onclick=()=>zoom(.78);$('zoomOut').onclick=()=>zoom(1.28);
  $('closeInspector').onclick=()=>{state.selectedNode=null;state.nodeIntel=null;$('hostInspector').classList.add('hidden');$('chatContext').textContent='Context: whole analyzed network';buildSuggestions();renderGraph()};
  $('chatIcon').onclick=()=>toggleChat(!$('dashboard').classList.contains('chat-open'));$('closeChat').onclick=()=>toggleChat(false);$('timelineIcon').onclick=()=>toggleTimeline(!$('dashboard').classList.contains('timeline-open'));$('closeTimeline').onclick=()=>toggleTimeline(false);
  document.querySelectorAll('.segmented button').forEach(b=>b.onclick=()=>{state.chatMode=b.dataset.mode;document.querySelectorAll('.segmented button').forEach(x=>x.classList.toggle('active',x===b))});
  document.querySelectorAll('.filter-btn[data-filter]').forEach(b=>b.onclick=()=>{state.timelineFilter=b.dataset.filter;document.querySelectorAll('.filter-btn[data-filter]').forEach(x=>x.classList.toggle('active',x===b));renderTimeline()});
  $('sendChat').onclick=()=>sendChat();$('chatInput').addEventListener('keydown',e=>{if(e.key==='Enter'&&!e.shiftKey){e.preventDefault();sendChat()}});$('micBtn').onclick=startMic;
  $('folderInput').onchange=e=>{const fs=[...(e.target.files||[])];e.target.value='';uploadFolder(fs)};$('fileInput').onchange=e=>{const f=e.target.files?.[0];e.target.value='';uploadFile(f)};$('replayBtn').onclick=replay;$('resetBtn').onclick=reset;

  // SVG pan/zoom
  let drag=null;const svg=$('graphSvg');svg.addEventListener('wheel',e=>{e.preventDefault();zoom(e.deltaY>0?1.12:.89)},{passive:false});svg.addEventListener('pointerdown',e=>{if(e.target.closest('.node'))return;drag={x:e.clientX,y:e.clientY,v:{...state.viewBox}};svg.classList.add('dragging');svg.setPointerCapture(e.pointerId)});svg.addEventListener('pointermove',e=>{if(!drag)return;const r=svg.getBoundingClientRect(),dx=(e.clientX-drag.x)*(drag.v.w/r.width),dy=(e.clientY-drag.y)*(drag.v.h/r.height);state.viewBox={...drag.v,x:drag.v.x-dx,y:drag.v.y-dy};state.fitted=false;applyViewBox()});svg.addEventListener('pointerup',e=>{drag=null;svg.classList.remove('dragging');try{svg.releasePointerCapture(e.pointerId)}catch{}});
  window.addEventListener('resize',()=>{state.fitted=true;fitGraph()});

  buildSuggestions();refresh();setInterval(refresh,2200);
})();
