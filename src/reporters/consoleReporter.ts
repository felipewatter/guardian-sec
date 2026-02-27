import chalk from "chalk";

export function consoleReport(results: any[]) {
  console.log("\n🔐 Guardian-Sec Report\n");
  results.forEach(r => {
    if (r.passed) {
      console.log(chalk.green(`✔ ${r.check}`));
    } else {
      console.log(chalk.red(`✖ ${r.check} - Issues: ${r.findings}`));
    }
  });
}
