#!/usr/bin/env node
import { Command } from "commander";
import chalk from "chalk";
import ora from "ora";
import { parseRepoUrl, hasToken } from "../src/github.js";
import { scan, VALID_CHECK_NAMES } from "../src/scanner.js";
import { printReport, printJson } from "../src/reporter.js";
import type { CheckName } from "../src/types.js";

const program = new Command();

program
  .name("repoguard")
  .description("Scan GitHub repos for trust scoring before cloning")
  .version("1.0.0");

program
  .command("scan")
  .description("Scan a GitHub repository")
  .argument("<url>", "GitHub repository URL (e.g. https://github.com/user/repo)")
  .option(
    "--checks <checks>",
    `Comma-separated checks to run (${VALID_CHECK_NAMES.join(",")})`
  )
  .option("--json", "Output results as JSON")
  .action(async (url: string, opts: { checks?: string; json?: boolean }) => {
    // Parse URL
    let target;
    try {
      target = parseRepoUrl(url);
    } catch (e) {
      console.error(chalk.red(`Error: ${(e as Error).message}`));
      process.exit(1);
    }

    // Parse selected checks
    let selectedChecks: CheckName[] | undefined;
    if (opts.checks) {
      const names = opts.checks.split(",").map((s) => s.trim()) as CheckName[];
      const invalid = names.filter(
        (n) => !VALID_CHECK_NAMES.includes(n)
      );
      if (invalid.length > 0) {
        console.error(
          chalk.red(`Unknown check(s): ${invalid.join(", ")}`)
        );
        console.error(
          chalk.gray(`Valid checks: ${VALID_CHECK_NAMES.join(", ")}`)
        );
        process.exit(1);
      }
      selectedChecks = names;
    }

    const isJson = !!opts.json;

    if (!hasToken() && !isJson) {
      console.log(
        chalk.yellow("Warning: GITHUB_TOKEN not set. Rate limit: 60 req/hr.")
      );
      console.log(
        chalk.gray("  export GITHUB_TOKEN=ghp_... for 5000 req/hr\n")
      );
    }

    let spinner: ReturnType<typeof ora> | null = null;
    if (!isJson) {
      spinner = ora({
        text: `Scanning ${chalk.cyan(target.owner + "/" + target.repo)}...`,
        color: "cyan",
      }).start();
    }

    try {
      const result = await scan(target, selectedChecks, (msg) => {
        if (spinner) spinner.text = msg;
      });

      if (spinner) spinner.stop();

      if (opts.json) {
        printJson(result);
      } else {
        printReport(result);
      }

      // Exit with non-zero if dangerous
      if (result.finalScore < 40) {
        process.exit(2);
      }
    } catch (e) {
      if (spinner) spinner.fail(chalk.red(`Scan failed: ${(e as Error).message}`));
      else console.error(`Scan failed: ${(e as Error).message}`);
      process.exit(1);
    }
  });

program.parse();
