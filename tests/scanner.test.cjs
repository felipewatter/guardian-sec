const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const os=require('node:os');
const make=()=>fs.mkdtempSync(path.join(os.tmpdir(),'guardian-sec-'));
const clean=p=>fs.rmSync(p,{recursive:true,force:true});
const put=(root,p,content)=>{const full=path.join(root,p);fs.mkdirSync(path.dirname(full),{recursive:true});fs.writeFileSync(full,content);};
const mod=async()=>await import('../dist/scanner.js');
test('detects credentials, records correct line, and never reports token values',async()=>{
  const root=make(),secret='AKIA'+'Z'.repeat(16);
  try{
    put(root,'config.js','console.log("safe");\nconst key="'+secret+'";\n');
    const {runScan}=await mod();const r=await runScan(root);
    assert.equal(r.findings.length,1);assert.equal(r.findings[0].ruleId,'aws-access-key');
    assert.equal(r.findings[0].line,2);assert.equal(r.findings[0].file,'config.js');
    assert.equal(JSON.stringify(r).includes(secret),false);
    assert.equal(r.score,0);
    assert.equal(r.checks.find(x=>x.id==='dependencies').status,'not_applicable');
    assert.equal(r.checks.find(x=>x.id==='history').status,'not_checked');
  }finally{clean(root);}
});
test('clean files score 100 only on assessed secrets category',async()=>{
  const root=make();
  try{
    put(root,'ok.js','export const allowed=true;');
    const r=await(await mod()).runScan(root);
    assert.equal(r.score,100);assert.equal(r.assessedWeight,50);
    assert.equal(r.findings.length,0);
  }finally{clean(root);}
});
test('a missing lockfile fails static dependency hygiene check',async()=>{
  const root=make();
  try{
    put(root,'package.json','{"name":"test","dependencies":{"x":"1.0.0"}}');
    const r=await(await mod()).runScan(root);
    assert.equal(r.findings[0].ruleId,'missing-npm-lockfile');
    assert.equal(r.checks.find(x=>x.id==='dependencies').status,'failed');
    assert.equal(r.score,67);
  }finally{clean(root);}
});
test('version wildcards and non-registry dependencies are clearly reported',async()=>{
  const root=make();
  try{
    put(root,'package.json',JSON.stringify({dependencies:{pkg:'*',example:'git+https://example.test/repo'}}));
    put(root,'package-lock.json','{"lockfileVersion":3,"packages":{}}');
    const r=await(await mod()).runScan(root);
    assert.deepEqual(r.findings.map(x=>x.ruleId).sort(),['non-registry-dependency','unbounded-dependency-version']);
  }finally{clean(root);}
});
test('workflow detects unpinned external action and broad permissions',async()=>{
  const root=make();
  try{
    put(root,'.github/workflows/main.yml','name: Main\npermissions: write-all\non: pull_request_target\njobs:\n  scan:\n    steps:\n      - uses: actions/checkout@v4\n');
    const r=await(await mod()).runScan(root);
    assert.deepEqual(r.findings.map(x=>x.ruleId).sort(),[
      'broad-token-permissions','privileged-pr-trigger','unpinned-github-action'].sort());
  }finally{clean(root);}
});
test('pinned workflow with scoped permissions reports no CI findings',async()=>{
  const root=make();
  try{
    put(root,'.github/workflows/main.yml','permissions:\n  contents: read\njobs:\n  scan:\n    steps:\n      - uses: actions/checkout@'+'a'.repeat(40)+'\n');
    const r=await(await mod()).runScan(root);
    assert.equal(r.findings.length,0);
    assert.equal(r.checks.find(x=>x.id==='cicd').status,'passed');
  }finally{clean(root);}
});
test('symbolic links outside root are not followed',{skip:process.platform==='win32'},async()=>{
  const root=make(),outside=make();
  try{
    put(outside,'secrets.js','const key="AKIA'+'T'.repeat(16)+'"');
    fs.symlinkSync(outside,path.join(root,'external'),'dir');
    fs.symlinkSync(path.join(outside,'secrets.js'),path.join(root,'reference.js'),'file');
    const r=await(await mod()).runScan(root);
    assert.equal(r.findings.length,0);
    assert.equal(r.skipped.symlinks,2);
  }finally{clean(root);clean(outside);}
});
test('sensitive binary or invalid UTF-8 files are counted but not parsed',async()=>{
  const root=make();
  try{
    put(root,'file.pem',Buffer.from([0,1,2,3]));
    put(root,'file2.pem',Buffer.from([0xff,0xfe]));
    const r=await(await mod()).runScan(root);
    assert.equal(r.skipped.binary,2);
  }finally{clean(root);}
});
test('oversized file and file count cause explicit errors',async()=>{
  const root=make();
  try{
    put(root,'large.js','x'.repeat(4000));
    const {runScan}=await mod();
    await assert.rejects(()=>runScan(root,{maxFileBytes:1024}),/limit/);
    put(root,'small.js','hello');
    await assert.rejects(()=>runScan(root,{maxFiles:1}),/limit/);
  }finally{clean(root);}
});
test('missing or linked root is invalid, not a clean result',async()=>{
  const root=make(),linked=root+'-link';
  try{
    const {runScan}=await mod();
    await assert.rejects(()=>runScan(path.join(root,'missing')));
    if(process.platform!=='win32'){
      fs.symlinkSync(root,linked,'dir');
      await assert.rejects(()=>runScan(linked));
    }
  }finally{fs.rmSync(linked,{force:true});clean(root);}
});
test('invalid package manifest is a failed/incomplete scan',async()=>{
  const root=make();
  try{
    put(root,'package.json','not JSON');
    await assert.rejects(()=>(async()=>{const m=await mod();return m.runScan(root)})());
  }finally{clean(root);}
});
test('history is not queried unless explicitly requested',async()=>{
  const root=make();
  try{
    put(root,'a.js','const safe=true');
    const r=await(await mod()).runScan(root);
    assert.equal(r.checks.find(x=>x.id==='history').status,'not_checked');
  }finally{clean(root);}
});
