// Exercise the actual inline control-plane script with a minimal DOM and deferred network.
// This verifies behavior, not browser layout or real DOM event parsing.
const assert = require('node:assert/strict');
const vm = require('node:vm');
const fs = require('node:fs');
const source = fs.readFileSync('control_plane/index.php', 'utf8').match(/<script>([\s\S]*?)<\/script>/)[1];
const elements = new Map();
function element(id) {
    if (!elements.has(id)) elements.set(id, {value:'', textContent:'', innerHTML:'', disabled:false, style:{}, listeners:{}, classList:{add(){},remove(){},toggle(){}}, addEventListener(event, fn){this.listeners[event]=fn;}});
    return elements.get(id);
}
Object.entries({statusFilter:'PENDING',kindFilter:'observed',sortFilter:'newest',userTier:'ADMIN',canApprovePerm:'1'}).forEach(([id,value])=>element(id).value=value);
const requests = [];
let timer;
const context = vm.createContext({
    document:{getElementById:element,addEventListener(){},hidden:false},
    window:{location:{search:''}}, URLSearchParams, AbortController, console,
    setInterval(){},clearInterval(){},setTimeout(fn){timer=fn;return 1;},clearTimeout(){timer=null;},
    fetch(url,options){
        if (!url.includes('approval_queue.php')) return Promise.resolve({ok:false});
        return new Promise(resolve=>requests.push({url,options,resolve}));
    }
});
const flush = () => new Promise(resolve=>setImmediate(resolve));
const sample = (page=1, total=103, action="');probe();//") => ({
    success:true, pagination:{page,pages:5,total},metrics:{pending:103,critical:2,expiring:2},as_of:'2026-01-01 12:00:00',
    data:[{id:42,incident_id:9,playbook_run_id:3,incident_number:'INC-2026-0042',incident_title:'<script>probe()</script>',incident_priority:'P1',incident_risk_score:10,action_name:action,action_description:'<img src=x>',required_tier:'LEAD',status:'PENDING',is_simulated:1,expires_in_seconds:3600}]
});
const respond = (request,data,ok=true) => request.resolve({ok,json:async()=>data});
(async()=>{
    vm.runInContext(source,context);
    assert.equal(requests.length,1);
    respond(requests[0],sample());await flush();
    assert.match(element('queueSummary').textContent,/103 matching requests/);
    assert.equal(element('metricPending').textContent,103);
    assert.equal(element('queueNext').disabled,false);
    assert.match(element('queueTbody').innerHTML,/SIMULATED/);
    assert.match(element('queueTbody').innerHTML,/&lt;script&gt;/);
    assert.doesNotMatch(element('queueTbody').innerHTML,/<script>|<img src=x>/);
    assert.match(element('queueTbody').innerHTML,/onclick="openQueueApprove\(42\)"/);
    vm.runInContext('openQueueApprove(42)',context);
    assert.equal(element('confirmActionName').textContent,"');probe();//");
    element('queueNext').listeners.click();
    assert.equal(new URLSearchParams(requests[1].url.split('?')[1]).get('page'),'2');
    respond(requests[1],sample(2));await flush();
    element('searchInput').value='old %_!';element('searchInput').listeners.input();timer();
    assert.equal(new URLSearchParams(requests[2].url.split('?')[1]).get('q'),'old %_!');
    assert.equal(new URLSearchParams(requests[2].url.split('?')[1]).get('page'),'1');
    element('kindFilter').value='all';element('kindFilter').listeners.change();
    assert.equal(requests[2].options.signal.aborted,true);
    respond(requests[3],sample(1,7,'new-response'));await flush();
    respond(requests[2],sample(1,999,'stale-response'));await flush();
    assert.match(element('queueSummary').textContent,/7 matching requests/);
    assert.doesNotMatch(element('queueTbody').innerHTML,/stale-response/);
    element('refreshBtn').listeners.click();
    respond(requests[4],{success:false,message:'Storage unavailable'},false);await flush();
    assert.equal(element('metricPending').textContent,'—');
    assert.equal(element('queueNext').disabled,true);
    assert.match(element('queueTbody').innerHTML,/unavailable/);
    assert.equal(element('queueSummary').textContent,'Storage unavailable');
    console.log('PASS: queue UI server search, paging, full metrics, simulation, escaped content, safe modal data, stale response suppression and failure state');
})().catch(error=>{console.error(error);process.exitCode=1;});
