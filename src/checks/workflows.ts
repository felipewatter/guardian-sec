import type {SourceFile} from '../core/files.js';
import {finding,type Finding} from '../core/model.js';
export function workflowFindings(files:readonly SourceFile[]):{applicable:boolean;findings:Finding[]}{
  const workflows=files.filter(f=>/^\.github\/workflows\/[^/]+\.(?:yml|yaml)$/.test(f.relative));
  const findings:Finding[]=[];
  for(const f of workflows){
    const lines=f.contents.split(/\r?\n/);
    let hasPermissions=false;
    for(let i=0;i<lines.length;i++){
      const line=lines[i]!;
      if(/^\s*permissions\s*:/.test(line))hasPermissions=true;
      if(/^\s*pull_request_target\s*:/.test(line))
        findings.push(finding('privileged-pr-trigger','medium',f.relative,i+1,'cicd'));
      if(/^\s*permissions\s*:\s*write-all\s*(?:#.*)?$/.test(line))
        findings.push(finding('broad-token-permissions','high',f.relative,i+1,'cicd'));
      // Actions without full commit pin (40 hex SHA) can be retargeted.
      const use=/^\s*(?:-\s*)?uses\s*:\s*([^\s#]+)\s*/.exec(line);
      if(use&& !/^\.\/|^docker:/.test(use[1]!)&&!/@[0-9a-f]{40}$/i.test(use[1]!))
        findings.push(finding('unpinned-github-action','medium',f.relative,i+1,'cicd'));
    }
    if(!hasPermissions)findings.push(finding('missing-workflow-permissions','medium',f.relative,null,'cicd'));
  }
  return {applicable:workflows.length>0,findings};
}
