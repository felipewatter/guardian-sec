#!/usr/bin/env node
import { Command } from "commander";
import { runScan } from "./scanner.js";
import { consoleReport } from "./reporters/consoleReporter.js";

const program = new Command();

program
  .name("guardian-sec")
  .description("Repository Security Scanner")
  .version("2.0.0");

program
  .command("scan")
  .argument("<path>", "Repository path")
  .action(async (path) => {
    const results = await runScan(path);
    consoleReport(results);
  });

program.parse();
