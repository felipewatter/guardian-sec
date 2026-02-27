import { secretsCheck } from "./checks/secretsCheck.js";

export async function runScan(path: string) {
  return [
    await secretsCheck(path)
  ];
}
