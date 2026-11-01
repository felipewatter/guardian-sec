import {inventory,type SourceFile} from '../core/files.js';
import {finding,type Finding} from '../core/model.js';
const rules=[
  {id:'aws-access-key',severity:'high' as const,regex:/\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/},
  {id:'github-token',severity:'critical' as const,regex:/\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,255}\b/},
  {id:'github-fine-grained-token',severity:'critical' as const,regex:/\bgithub_pat_[A-Za-z0-9_]{22,255}\b/},
  {id:'private-key',severity:'critical' as const,regex:/-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----/},
  {id:'google-api-key',severity:'high' as const,regex:/\bAIza[A-Za-z0-9_-]{35}\b/},
  {id:'stripe-secret',severity:'critical' as const,regex:/\bsk_(?:live|test)_[A-Za-z0-9]{16,160}\b/},
  {id:'generic-secret',severity:'medium' as const,regex:/\b(?:password|passwd|client_secret|api_key|access_token)\s*[:=]\s*['"]?[A-Za-z0-9_+/.=-]{20,160}/i}
];
export function findSecrets(files:readonly SourceFile[]):Finding[]{
  const results:Finding[]=[];
  for(const file of files){
    const lines=file.contents.split(/\r?\n/);
    for(let i=0;i<lines.length;i++){
      for(const rule of rules){
        if(!rule.regex.test(lines[i]!))continue;
        if(results.length>=10000)throw Error('Finding limit exceeded; incomplete scan');
        results.push(finding(rule.id,rule.severity,file.relative,i+1,'secrets'));
      }
    }
  }
  return results;
}
/** Legacy API returning aggregate count, without exposing matching content. */
export async function secretsCheck(repoPath:string):Promise<{check:string;passed:boolean;findings:number}>{
  const {files}=await inventory(repoPath);
  const findings=findSecrets(files).length;
  return {check:'Secrets Exposure',passed:findings===0,findings};
}
