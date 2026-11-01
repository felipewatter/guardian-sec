import {lstat,realpath,readdir,open} from 'node:fs/promises';
import {constants} from 'node:fs';
import path from 'node:path';
export type SourceFile={relative:string;contents:string;size:number};
export type Inventory={files:SourceFile[];bytes:number;skippedSymlinks:number;skippedDirectories:number;skippedBinary:number;skippedUnsupported:number};
export type Bounds={maxFiles?:number;maxFileBytes?:number;maxTotalBytes?:number;maxDepth?:number};
export const IGNORED_DIRS=new Set(['.git','node_modules','vendor','dist','build','coverage','.next','.cache','.venv','venv','__pycache__','.turbo']);
export function cleanPath(p:string):string{return p.replace(/[\u0000-\u001f\u007f-\u009f]/g,'?').slice(0,320);}
const supported=(p:string):boolean=>{
  const name=path.basename(p).toLowerCase();
  return /\.(?:js|jsx|ts|tsx|json|yaml|yml|env|py|go|rs|sh|bash|toml|ini|properties|tf|gradle|xml|pem|key|md|txt|config|conf|lock)$/.test(name) ||
    /^\.env(?:\..+)?$/.test(name) || name==='dockerfile'|| name==='package-lock.json'||
    p.split(path.sep).includes('workflows');
};
function bound(n:number,min:number,max:number,label:string):number{
  if(!Number.isSafeInteger(n)||n<min||n>max)throw Error('Invalid '+label);
  return n;
}
export async function inventory(directory:string,opts:Bounds={}):Promise<Inventory>{
  const maxFiles=bound(opts.maxFiles??10000,1,30000,'maxFiles');
  const maxFileBytes=bound(opts.maxFileBytes??1048576,1024,4194304,'maxFileBytes');
  const maxTotalBytes=bound(opts.maxTotalBytes??33554432,maxFileBytes,134217728,'maxTotalBytes');
  const maxDepth=bound(opts.maxDepth??24,0,48,'maxDepth');
  const root=path.resolve(directory);
  const stat=await lstat(root);
  if(!stat.isDirectory()||stat.isSymbolicLink())throw Error('Root must be a real directory');
  const rootActual=await realpath(root);
  const result:Inventory={files:[],bytes:0,skippedSymlinks:0,skippedDirectories:0,skippedBinary:0,skippedUnsupported:0};
  async function visit(dir:string,depth:number):Promise<void>{
    if(depth>maxDepth)throw Error('Directory depth limit exceeded; scan incomplete');
    const entries=(await readdir(dir,{withFileTypes:true})).sort((a,b)=>a.name.localeCompare(b.name));
    for(const entry of entries){
      const abs=path.join(dir,entry.name),relative=path.relative(root,abs);
      const stat=await lstat(abs);
      if(stat.isSymbolicLink()){result.skippedSymlinks++;continue;}
      if(stat.isDirectory()){
        if(IGNORED_DIRS.has(entry.name)){result.skippedDirectories++;continue;}
        await visit(abs,depth+1);continue;
      }
      if(!stat.isFile())continue;
      if(!supported(relative)){result.skippedUnsupported++;continue;}
      if(result.files.length>=maxFiles)throw Error('File limit exceeded; scan incomplete');
      if(stat.size>maxFileBytes||result.bytes+stat.size>maxTotalBytes)throw Error('Byte limit exceeded; scan incomplete');
      const actual=await realpath(abs);
      if(actual!==rootActual&&!actual.startsWith(rootActual+path.sep))
        throw Error('Path escapes scan root');
      const flags=constants.O_RDONLY | (process.platform!=='win32' ? (constants.O_NOFOLLOW||0) : 0);
      const fd=await open(abs,flags);
      let contents:string;
      let length:number;
      try{
        const current=await fd.stat();
        if(!current.isFile()||current.dev!==stat.dev||current.ino!==stat.ino||
          current.size>maxFileBytes||result.bytes+current.size>maxTotalBytes)
          throw Error('Changed file or limit exceeded');
        const buffer=await fd.readFile();
        length=buffer.length;
        if(length>maxFileBytes||result.bytes+length>maxTotalBytes)throw Error('Changed file or limit exceeded');
        if(buffer.subarray(0,4096).includes(0)){result.skippedBinary++;result.bytes+=length;continue;}
        try{contents=new TextDecoder('utf-8',{fatal:true}).decode(buffer)}
        catch{result.skippedBinary++;result.bytes+=length;continue;}
      }finally{await fd.close();}
      result.bytes+=length;
      result.files.push({relative:cleanPath(relative.split(path.sep).join('/')),contents,size:length});
    }
  }
  await visit(root,0);
  return result;
}
