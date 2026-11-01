const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const os=require('node:os');
const path=require('node:path');
const {spawnSync}=require('node:child_process');
const cli=path.join(__dirname,'..','dist','cli.js');
const make=()=>fs.mkdtempSync(path.join(os.tmpdir(),'guardian-cli-'));
const run=args=>spawnSync(process.execPath,[cli,...args],{encoding:'utf8',timeout:10000});
test('CLI strict options, help and version',async()=>{
  const {parseArgs}=await import('../dist/cli.js');
  assert.equal(parseArgs(['scan','/tmp','--format=json','--history']).format,'json');
  for(const args of [[],['bad','folder'],['scan'],['scan','.','--unknown'],['scan','.','--fail-on=unsafe'],['scan','.','--max-files=0']])
    assert.throws(()=>parseArgs(args));
  assert.equal(run(['--help']).status,0);
  assert.match(run(['--version']).stdout,/2.1.0/);
});
test('CLI exit statuses 0 for clean and 1 for findings, with secret redaction',()=>{
  const dir=make(),secret='AKIA'+'W'.repeat(16);
  try{
    fs.writeFileSync(path.join(dir,'clean.js'),'console.log("hello")');
    assert.equal(run(['scan',dir,'--format=json']).status,0);
    fs.writeFileSync(path.join(dir,'bad.js'),'const k="'+secret+'"');
    const x=run(['scan',dir,'--format=json']);
    assert.equal(x.status,1,x.stderr);
    assert.ok(!x.stdout.includes(secret));
    assert.equal(JSON.parse(x.stdout).findings[0].ruleId,'aws-access-key');
    assert.equal(run(['scan',dir,'--fail-on=none']).status,0);
    assert.equal(run(['scan',dir,'--format=sarif']).status,1);
  }finally{fs.rmSync(dir,{recursive:true,force:true});}
});
test('CLI exit 2 for unreadable, huge or malformed scan inputs',()=>{
  const dir=make();
  try{
    assert.equal(run(['scan',path.join(dir,'not-found')]).status,2);
    fs.writeFileSync(path.join(dir,'big.js'),'x'.repeat(4000));
    const r=run(['scan',dir,'--max-file-bytes','1024','--format=json']);
    assert.equal(r.status,2);
    assert.equal(r.stdout.trim(),'');
    assert.doesNotMatch(r.stderr,/clean|no issues/i);
  }finally{fs.rmSync(dir,{recursive:true,force:true});}
});
test('CLI creates report only once; never overwrites existing result',()=>{
  const dir=make();
  try{
    fs.writeFileSync(path.join(dir,'sample.js'),'const safe=true');
    const output=path.join(dir,'report.json');
    assert.equal(run(['scan',dir,'--format=json','--output',output]).status,0);
    assert.equal(JSON.parse(fs.readFileSync(output,'utf8')).score,100);
    assert.equal(run(['scan',dir,'--format=json','--output',output]).status,2);
  }finally{fs.rmSync(dir,{recursive:true,force:true});}
});
test('CLI creates CycloneDX SBOM only with lockfile',()=>{
  const dir=make();
  try{
    assert.equal(run(['sbom',dir]).status,2);
    fs.writeFileSync(path.join(dir,'package-lock.json'),JSON.stringify({lockfileVersion:3,packages:{
      'node_modules/pkg':{version:'1.2.3'}
    }}));
    const result=run(['sbom',dir]);
    assert.equal(result.status,0,result.stderr);
    const bom=JSON.parse(result.stdout);
    assert.equal(bom.bomFormat,'CycloneDX');
    assert.equal(bom.components[0].name,'pkg');
  }finally{fs.rmSync(dir,{recursive:true,force:true});}
});
test('historical token in removed file is detectable, with no token disclosure',{skip:process.env.CI_SKIP_GIT==='1'},async()=>{
  const dir=make(),secret='AKIA'+'H'.repeat(16);
  const git=(args)=>spawnSync('git',args,{cwd:dir,encoding:'utf8'});
  try{
    const initialized=git(['init','-q']);if(initialized.error)return;
    git(['config','user.name','Guardian Test']);git(['config','user.email','guardian@example.test']);
    fs.writeFileSync(path.join(dir,'temporary.js'),'const token="'+secret+'";');
    assert.equal(git(['add','.']).status,0);
    assert.equal(git(['commit','-qm','add example']).status,0);
    fs.unlinkSync(path.join(dir,'temporary.js'));
    assert.equal(git(['add','-u']).status,0);
    assert.equal(git(['commit','-qm','remove example']).status,0);
    const {runScan}=await import('../dist/scanner.js');
    const r=await runScan(dir,{history:true});
    assert.ok(r.findings.some(f=>f.ruleId==='historical-secret'));
    assert.equal(JSON.stringify(r).includes(secret),false);
    assert.equal(r.checks.find(x=>x.id==='history').status,'failed');
  }finally{fs.rmSync(dir,{recursive:true,force:true});}
});
