import type {SourceFile} from './files.js';
type Component={type:'library';name:string;version:string;'bom-ref':string;purl?:string};
export type Bom={bomFormat:'CycloneDX';specVersion:'1.5';version:1;metadata:{tools:{components:{type:'application';name:string;version:string}[]}};components:Component[]};
function safe(s:unknown):s is string{return typeof s==='string'&&s.length>0&&s.length<=180&&/^[A-Za-z0-9@._+~\/-]+$/.test(s)}
export function generateBom(files:readonly SourceFile[]):Bom{
  const locks=files.filter(f=>f.relative==='package-lock.json'||f.relative.endsWith('/package-lock.json'));
  if(locks.length===0)throw Error('No npm package-lock.json found for SBOM');
  const components:Component[]=[];
  const seen=new Set<string>();
  for(const lock of locks){
    let v:unknown;
    try{v=JSON.parse(lock.contents)}catch{throw Error('Invalid lockfile JSON')}
    if(!v||typeof v!=='object'||Array.isArray(v))throw Error('Invalid lockfile object');
    const root=v as Record<string,unknown>;
    if(!root.packages||typeof root.packages!=='object'||Array.isArray(root.packages))
      throw Error('No npm lockfile packages map');
    for(const [loc,raw] of Object.entries(root.packages)){
      if(!loc||!loc.includes('node_modules/')||!raw||typeof raw!=='object'||Array.isArray(raw))continue;
      const obj=raw as Record<string,unknown>;
      const name=loc.slice(loc.lastIndexOf('node_modules/')+'node_modules/'.length);
      if(!safe(name)||!safe(obj.version))continue;
      const version=obj.version;
      const ref=name+'@'+version;
      if(seen.has(ref))continue;
      seen.add(ref);
      if(components.length>=10000)throw Error('Too many BOM components');
      const packageName=name.startsWith('@')?name.replace('/','%2F'):name;
      components.push({type:'library',name,version,'bom-ref':ref,purl:'pkg:npm/'+packageName+'@'+version});
    }
  }
  components.sort((a,b)=>a.name.localeCompare(b.name)||a.version.localeCompare(b.version));
  return {bomFormat:'CycloneDX',specVersion:'1.5',version:1,
    metadata:{tools:{components:[{type:'application',name:'guardian-sec',version:'2.1.0'}]}},
    components};
}
