import {spawn} from 'node:child_process';
import path from 'node:path';
import {finding,type Finding} from '../core/model.js';
type Command={stdout:string;code:number};
async function git(args:string[],cwd:string,maxBytes=4*1024*1024,timeoutMs=12000):Promise<Command>{
  return new Promise((resolve,reject)=>{
    const child=spawn('git',args,{cwd,windowsHide:true,shell:false,stdio:['ignore','pipe','pipe']});
    let stdout='',size=0,done=false;
    const timeout=setTimeout(()=>{child.kill('SIGKILL');fail();},timeoutMs);
    function fail(){if(done)return;done=true;clearTimeout(timeout);reject(Error('Git history command failed or exceeded bounds'));}
    child.stdout.on('data',(data:Buffer)=>{size+=data.length;if(size>maxBytes){child.kill('SIGKILL');fail();return;}stdout+=data.toString('utf8');});
    child.stderr.resume(); // never show errors containing repo paths or secrets
    child.on('error',fail);
    child.on('close',code=>{if(done)return;done=true;clearTimeout(timeout);if(code!==0)reject(Error('Git history command failed'));else resolve({stdout,code});});
  });
}
/** History scan is bounded and opt-in: last 30 commits reachable from any ref. */
export async function historyFindings(repoPath:string):Promise<Finding[]>{
  const directory=path.resolve(repoPath);
  const refs=await git(['rev-list','--max-count=30','--all'],directory,4096);
  const shas=refs.stdout.trim()?refs.stdout.trim().split(/\r?\n/):[];
  if(shas.some(sha=>!/^[a-f0-9]{40}$/.test(sha))||shas.length>30)throw Error('Unexpected git refs');
  const found:Finding[]=[];
  for(const sha of shas){
    const patch=await git(['show','--no-ext-diff','--no-renames','--format=','--unified=0',sha],directory);
    const lines=patch.stdout.split(/\r?\n/);
    for(const line of lines){
      if(!line.startsWith('+')||line.startsWith('+++'))continue;
      // Do not retain patch contents or return evidence containing secret material.
      if(/\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/.test(line) ||
         /\b(?:ghp|gho|ghs|ghu|ghr)_[A-Za-z0-9]{36,255}\b/.test(line) ||
         /-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----/.test(line)){
        found.push(finding('historical-secret','critical','git-commit/'+sha.slice(0,12),null,'history'));
        if(found.length>=1000)throw Error('History finding limit exceeded');
      }
    }
  }
  return found;
}
