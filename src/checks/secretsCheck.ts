import fs from "fs";
import { glob } from "glob";

export async function secretsCheck(repoPath: string) {
  const files = await glob(`${repoPath}/**/*.{js,ts,json,env}`, {
    ignore: ["node_modules/**"]
  });

  let findings = 0;

  for (const file of files) {
    const content = fs.readFileSync(file, "utf-8");
    if (/AKIA[0-9A-Z]{16}/.test(content)) findings++;
    if (/-----BEGIN PRIVATE KEY-----/.test(content)) findings++;
  }

  return {
    check: "Secrets Exposure",
    passed: findings === 0,
    findings
  };
}
