import type {SourceFile} from '../core/files.js';
import {finding,type Finding} from '../core/model.js';
type Manifest={dependencies?:unknown;devDependencies?:unknown;scripts?:unknown};
const object=(x:unknown):x is Record<string,unknown>=>x!==null&&typeof x==='object'&&!Array.isArray(x);
export function dependencyFindings(files:readonly SourceFile[]):{applicable:boolean;findings:Finding[]}{
  const findings:Finding[]=[];
  const manifests=files.filter(f=>f.relative==='package.json'||f.relative.endsWith('/package.json'));
  for(const f of manifests){
    const folder=f.relative.substring(0,f.relative.lastIndexOf('/')+1);
    let data:unknown;
    try{data=JSON.parse(f.contents)}
    catch{throw Error('Invalid package.json; scan incomplete');}
    if(!object(data))throw Error('Malformed package.json');
    const manifest=data as Manifest;
    if(!files.some(x=>x.relative===folder+'package-lock.json'))
      findings.push(finding('missing-npm-lockfile','high',f.relative,null,'dependencies'));
    for(const key of ['dependencies','devDependencies'] as const){
      if(manifest[key]!==undefined&&!object(manifest[key]))throw Error('Invalid dependency manifest');
      for(const [name,spec] of Object.entries((manifest[key] as Record<string,unknown>)||{})){
        // Unsupported nonsemver sources require explicit review; no execution or fetch.
        if(typeof spec!=='string')throw Error('Invalid dependency specification');
        if(/^(?:https?:|git(?:\+|:)|file:|link:|workspace:)/i.test(spec))
          findings.push(finding('non-registry-dependency','medium',f.relative,null,'dependencies'));
        if(spec.trim()==='*'||spec.trim()==='latest')
          findings.push(finding('unbounded-dependency-version','medium',f.relative,null,'dependencies'));
        void name;
      }
    }
    if(manifest.scripts!==undefined&&!object(manifest.scripts))throw Error('Invalid package scripts');
  }
  return {applicable:manifests.length>0,findings};
}
