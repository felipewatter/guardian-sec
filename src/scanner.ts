import {inventory,type Bounds} from './core/files.js';
import {makeReport,type Check,type Finding,type ScanReport} from './core/model.js';
import {findSecrets} from './checks/secretsCheck.js';
import {dependencyFindings} from './checks/dependencies.js';
import {workflowFindings} from './checks/workflows.js';
import {historyFindings} from './checks/history.js';
export type ScanOptions=Bounds & {history?:boolean};
export async function runScan(root:string,opts:ScanOptions={}):Promise<ScanReport>{
  const state=await inventory(root,opts);
  const secrets=findSecrets(state.files);
  const dependencies=dependencyFindings(state.files);
  const workflows=workflowFindings(state.files);
  const historical=opts.history?await historyFindings(root):[];
  const findings:Finding[]=[...secrets,...dependencies.findings,...workflows.findings,...historical];
  if(findings.length>10000)throw Error('Finding limit exceeded');
  const checks:Check[]=[
    {id:'secrets',status:secrets.length?'failed':'passed',findings:secrets.length,weight:50},
    {id:'dependencies',status:!dependencies.applicable?'not_applicable':dependencies.findings.length?'failed':'passed',
      findings:dependencies.findings.length,weight:25},
    {id:'cicd',status:!workflows.applicable?'not_applicable':workflows.findings.length?'failed':'passed',
      findings:workflows.findings.length,weight:25},
    {id:'history',status:!opts.history?'not_checked':historical.length?'failed':'passed',findings:historical.length,weight:20}
  ];
  return makeReport(findings,checks,{scannedFiles:state.files.length,scannedBytes:state.bytes,
    skipped:{symlinks:state.skippedSymlinks,directories:state.skippedDirectories,
      binary:state.skippedBinary,unsupported:state.skippedUnsupported}});
}
