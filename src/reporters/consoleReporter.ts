import type {ScanReport} from '../core/model.js';
export function consoleReport(report:ScanReport):string{
  const lines=['Guardian Sec v2.1.0 — local security posture',
    'Files scanned: '+report.scannedFiles,
    'Score: '+(report.score===null?'N/A':report.score+'/100')+
      ' (assessed weight '+report.assessedWeight+'; indicative, not a certification)'];
  for(const check of report.checks)
    lines.push('['+check.status.toUpperCase()+'] '+check.id+' ('+check.findings+' findings)');
  for(const item of report.findings)
    lines.push('['+item.severity.toUpperCase()+'] '+item.ruleId+' @ '+item.file+
      (item.line===null?'':':'+item.line));
  lines.push('Total: '+report.findings.length+' potential findings');
  return lines.join('\n');
}
export function markdownReport(report:ScanReport):string{
  const lines=['# Guardian Sec v2.1.0 — Posture Report','',
    '**Indicative score:** '+(report.score===null?'N/A':report.score+'/100')+
    ' (only implemented, applicable checks; not a certification)','',
    '| Category | Result | Findings |','| --- | --- | ---: |'];
  for(const c of report.checks)lines.push('| '+c.id+' | '+c.status+' | '+c.findings+' |');
  lines.push('','## Findings','');
  if(!report.findings.length)lines.push('No patterns found in the inspected scope.');
  for(const f of report.findings)
    lines.push('- **'+f.severity+'** '+f.ruleId+' — '+f.file+(f.line===null?'':':'+f.line));
  lines.push('','Scope exclusions and incomplete checks are documented in SECURITY.md.');
  return lines.join('\n');
}
export function sarifReport(report:ScanReport):object{
  const rules=Array.from(new Set(report.findings.map(f=>f.ruleId))).sort();
  return {version:'2.1.0', $schema:'https://json.schemastore.org/sarif-2.1.0.json',
    runs:[{tool:{driver:{name:'guardian-sec',version:'2.1.0',
      rules:rules.map(id=>({id,shortDescription:{text:id}}))}},
      results:report.findings.map(f=>({
        ruleId:f.ruleId,level:f.severity==='critical'||f.severity==='high'?'error':f.severity==='medium'?'warning':'note',
        message:{text:'Potential '+f.ruleId+' detected; inspect source privately. No matched data is disclosed.'},
        locations:[{physicalLocation:{artifactLocation:{uri:f.file},
          ...(f.line===null?{}:{region:{startLine:f.line}})}}]
      }))}]};
}
