export type Severity='low'|'medium'|'high'|'critical';
export const severities:Record<Severity,number>={low:1,medium:2,high:3,critical:4};
export type Finding={ruleId:string;severity:Severity;file:string;line:number|null;category:'secrets'|'dependencies'|'cicd'|'history'};
export type Check={id:string;status:'passed'|'failed'|'not_applicable'|'not_checked';findings:number;weight:number};
export type ScanReport={schemaVersion:1;scannedFiles:number;scannedBytes:number;
  skipped:{symlinks:number;directories:number;binary:number;unsupported:number};
  checks:Check[];findings:Finding[];score:number|null;assessedWeight:number;
  limitNote:string};
export const finding=(ruleId:string,severity:Severity,file:string,line:number|null,category:Finding['category']):Finding=>
  ({ruleId,severity,file,line,category});
export function makeReport(findings:Finding[],checks:Check[],counts:Omit<ScanReport,'schemaVersion'|'findings'|'checks'|'score'|'assessedWeight'|'limitNote'>):ScanReport{
  const assessed=checks.filter(c=>c.status==='passed'||c.status==='failed');
  const total=assessed.reduce((acc,c)=>acc+c.weight,0);
  const good=assessed.filter(c=>c.status==='passed').reduce((acc,c)=>acc+c.weight,0);
  findings.sort((a,b)=>a.file.localeCompare(b.file)||(a.line??0)-(b.line??0)||a.ruleId.localeCompare(b.ruleId));
  return {schemaVersion:1,...counts,checks,findings,
    score:total===0?null:Math.round(good/total*100),
    assessedWeight:total,
    limitNote:'Weighted score reflects implemented checks only; not a security certification.'};
}
