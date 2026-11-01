const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const os=require('node:os');
const path=require('node:path');
const root=()=>fs.mkdtempSync(path.join(os.tmpdir(),'guardian-reports-'));
const put=(dir,name,text)=>{const full=path.join(dir,name);fs.mkdirSync(path.dirname(full),{recursive:true});fs.writeFileSync(full,text)};
test('SARIF output has standard schema, no credential snippets and correct lines',async()=>{
  const dir=root(),secret='ghp_'+'V'.repeat(36);
  try{
    put(dir,'credentials.ts','console.log(123)\nconst key="'+secret+'";\n');
    const {runScan}=await import('../dist/scanner.js');
    const {sarifReport,markdownReport,consoleReport}=await import('../dist/reporters/consoleReporter.js');
    const r=await runScan(dir);
    const sarif=sarifReport(r);
    assert.equal(sarif.version,'2.1.0');
    assert.equal(sarif.runs[0].results[0].ruleId,'github-token');
    assert.equal(sarif.runs[0].results[0].locations[0].physicalLocation.region?.startLine,undefined);
    assert.equal(sarif.runs[0].results[0].locations[0].physicalLocation.region.startLine,2);
    for(const value of [JSON.stringify(sarif),markdownReport(r),consoleReport(r)])
      assert.ok(!value.includes(secret),'Matched token leaked');
  }finally{fs.rmSync(dir,{recursive:true,force:true});}
});
test('CycloneDX SBOM is generated exclusively from npm lockfile',async()=>{
  const {generateBom}=await import('../dist/core/sbom.js');
  const file={relative:'package-lock.json',size:1,contents:JSON.stringify({lockfileVersion:3,packages:{
    '':{version:'1.0.0'},'node_modules/lodash':{version:'4.17.21'},
    'node_modules/@scope/widget':{version:'2.0.0'}
  }})};
  const bom=generateBom([file]);assert.equal(bom.bomFormat,'CycloneDX');
  assert.equal(bom.specVersion,'1.5');
  assert.equal(bom.components.length,2);
  assert.equal(bom.components[0].name,'@scope/widget');
  assert.ok(bom.components[0].purl.includes('%2F'));
});
test('SBOM fails without a valid lockfile',async()=>{
  const {generateBom}=await import('../dist/core/sbom.js');
  assert.throws(()=>generateBom([]),/No npm/);
  assert.throws(()=>generateBom([{relative:'package-lock.json',contents:'bad-json',size:5}]),/Invalid/);
});
test('reporter score accounts for unavailable checks instead of inventing coverage',async()=>{
  const {makeReport}=await import('../dist/core/model.js');
  const report=makeReport([],[
    {id:'secrets',status:'passed',weight:50,findings:0},
    {id:'history',status:'not_checked',weight:20,findings:0},
    {id:'cicd',status:'not_applicable',weight:25,findings:0}
  ],{scannedFiles:0,scannedBytes:0,skipped:{symlinks:0,directories:0,binary:0,unsupported:0}});
  assert.equal(report.score,100);
  assert.equal(report.assessedWeight,50);
});
