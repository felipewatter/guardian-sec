#!/usr/bin/env node
import {writeFile} from 'node:fs/promises';
import {fileURLToPath} from 'node:url';
import path from 'node:path';
import {runScan} from './scanner.js';
import {inventory} from './core/files.js';
import {generateBom} from './core/sbom.js';
import {severities,type Severity} from './core/model.js';
import {consoleReport,markdownReport,sarifReport} from './reporters/consoleReporter.js';
type Options={command:'scan'|'sbom';directory:string;format:'text'|'json'|'md'|'sarif';output?:string;
  history:boolean;failOn:'none'|Severity;maxFiles:number;maxFileBytes:number;maxTotalBytes:number;maxDepth:number};
const HELP=['guardian-sec v2.1.0 — actual local posture checks, not a certification',
'Usage: guardian-sec scan <path> [--format text|json|md|sarif] [options]',
'       guardian-sec sbom <path> [--output FILE]',
'  --history               Opt in to scanning 30 recent Git commits (requires git)',
'  --output FILE           Create report as a new file; never overwrites',
'  --fail-on none|low|medium|high|critical  Default: high',
'  --max-files N           Default: 10000 (max 30000)',
'  --max-file-bytes N      Default: 1048576 (max 4194304)',
'  --max-total-bytes N     Default: 33554432 (max 134217728)',
'  --max-depth N           Default: 24 (max 48)',
'  --help / --version      Help or version',
'Exit 0=below configured threshold, 1=findings, 2=invalid/incomplete scan.',
'Output does not contain matched secrets. SBOM lists package metadata from npm lockfile.'
].join('\n');
function int(s:string,min:number,max:number):number{
  if(!/^(0|[1-9][0-9]*)$/.test(s))throw Error('Bad numeric argument');
  const v=Number(s);
  if(!Number.isSafeInteger(v)||v<min||v>max)throw Error('Numeric argument outside range');
  return v;
}
export function parseArgs(args:readonly string[]):Options|'help'|'version'{
  if(args.length===0)throw Error('Missing command');
  if(args[0]==='--help'||args[0]==='-h')return 'help';
  if(args[0]==='--version'||args[0]==='-v')return 'version';
  if(args[0]!=='scan'&&args[0]!=='sbom')throw Error('Unsupported command');
  const o:Options={command:args[0],directory:'',format:'text',history:false,failOn:'high',
    maxFiles:10000,maxFileBytes:1048576,maxTotalBytes:33554432,maxDepth:24};
  for(let i=1;i<args.length;i++){
    const arg=args[i]!,equal=arg.indexOf('='),flag=equal<0?arg:arg.slice(0,equal);
    if(flag==='--help')return 'help';
    if(flag==='--version')return 'version';
    if(flag==='--history'){if(equal>=0)throw Error('Unexpected history value');o.history=true;continue;}
    if(!flag.startsWith('--')){
      if(o.directory)throw Error('Multiple scan targets');
      o.directory=arg;continue;
    }
    if(!['--format','--output','--fail-on','--max-files','--max-file-bytes','--max-total-bytes','--max-depth'].includes(flag))
      throw Error('Invalid flag');
    const value=equal>=0?arg.slice(equal+1):args[++i];
    if(!value||(equal<0&&value.startsWith('--')))throw Error('Missing flag value');
    switch(flag){
      case '--format':if(!['text','json','md','sarif'].includes(value))throw Error('Unsupported format');
        o.format=value as Options['format'];break;
      case '--output':o.output=value;break;
      case '--fail-on':if(!['none','low','medium','high','critical'].includes(value))throw Error('Invalid severity');
        o.failOn=value as Options['failOn'];break;
      case '--max-files':o.maxFiles=int(value,1,30000);break;
      case '--max-file-bytes':o.maxFileBytes=int(value,1024,4194304);break;
      case '--max-total-bytes':o.maxTotalBytes=int(value,1024,134217728);break;
      case '--max-depth':o.maxDepth=int(value,0,48);break;
    }
  }
  if(!o.directory)throw Error('Missing path');
  if(o.maxTotalBytes<o.maxFileBytes)throw Error('Total bytes too small');
  if(o.command==='sbom'&&(o.history||o.failOn!=='high'||(o.format!=='json'&&o.format!=='text')))
    throw Error('SBOM only accepts JSON or text and no scan flags');
  return o;
}
export async function main(args:readonly string[]=process.argv.slice(2)):Promise<number>{
  let options:ReturnType<typeof parseArgs>;
  try{options=parseArgs(args)}catch{console.error('guardian-sec: invalid arguments. See --help.');return 2;}
  if(options==='help'){console.log(HELP);return 0;}
  if(options==='version'){console.log('2.1.0');return 0;}
  try{
    let output:string,exit=0;
    const bounds={maxFiles:options.maxFiles,maxFileBytes:options.maxFileBytes,
      maxTotalBytes:options.maxTotalBytes,maxDepth:options.maxDepth};
    if(options.command==='sbom'){
      const state=await inventory(options.directory,bounds);
      const bom=generateBom(state.files);
      output=JSON.stringify(bom,null,2);
    }else{
      const report=await runScan(options.directory,{...bounds,history:options.history});
      const min=options.failOn==='none'?100:severities[options.failOn];
      exit=report.findings.some(f=>severities[f.severity]>=min)?1:0;
      output=options.format==='json'?JSON.stringify({...report,passed:exit===0},null,2):
        options.format==='md'?markdownReport(report):
        options.format==='sarif'?JSON.stringify(sarifReport(report),null,2):
        consoleReport(report);
    }
    if(options.output)await writeFile(options.output,output+'\n',{flag:'wx',mode:0o600});
    else console.log(output);
    return exit;
  }catch{
    console.error('guardian-sec: scan failed or incomplete. No clean result issued.');
    return 2;
  }
}
if(process.argv[1] && path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  void main().then(code=>{process.exitCode=code;});
}
