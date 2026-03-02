import chalk from "chalk";
import type { ScanResult, CheckResult, Finding } from "./types.js";

const BOX_WIDTH = 60;

function pad(text: string, width: number): string {
  const visibleLength = text.replace(
    // eslint-disable-next-line no-control-regex
    /\u001b\[[0-9;]*m/g,
    ""
  ).length;
  const diff = width - visibleLength;
  return diff > 0 ? text + " ".repeat(diff) : text;
}

function colorScore(score: number): string {
  if (score >= 90) return chalk.green(`${score}`);
  if (score >= 70) return chalk.yellow(`${score}`);
  if (score >= 40) return chalk.red(`${score}`);
  return chalk.redBright(`${score}`);
}

function colorRating(result: ScanResult): string {
  const { rating, finalScore } = result;
  const text = `${finalScore}/100  ${rating.emoji} ${rating.label}`;
  switch (rating.color) {
    case "green":
      return chalk.green.bold(text);
    case "yellow":
      return chalk.yellow.bold(text);
    case "red":
      return chalk.red.bold(text);
    case "redBright":
      return chalk.redBright.bold(text);
  }
}

function severityIcon(sev: Finding["severity"]): string {
  switch (sev) {
    case "critical":
      return chalk.redBright("\u2718");
    case "high":
      return chalk.red("!");
    case "medium":
      return chalk.yellow("\u25b2");
    case "low":
      return chalk.blue("\u25cb");
    case "info":
      return chalk.gray("\u2022");
  }
}

function line(char = "\u2550"): string {
  return char.repeat(BOX_WIDTH);
}

export function printReport(result: ScanResult): void {
  const target = `${result.target.owner}/${result.target.repo}`;

  console.log("");
  console.log(chalk.cyan("\u2554" + line() + "\u2557"));
  console.log(
    chalk.cyan("\u2551") +
      pad(chalk.bold("  RepoGuard Scan Results"), BOX_WIDTH) +
      chalk.cyan("\u2551")
  );
  console.log(
    chalk.cyan("\u2551") +
      pad(`  Target: ${chalk.white(target)}`, BOX_WIDTH) +
      chalk.cyan("\u2551")
  );
  console.log(chalk.cyan("\u2560" + line() + "\u2563"));
  console.log(chalk.cyan("\u2551") + " ".repeat(BOX_WIDTH) + chalk.cyan("\u2551"));
  console.log(
    chalk.cyan("\u2551") +
      pad(`  TRUST SCORE: ${colorRating(result)}`, BOX_WIDTH) +
      chalk.cyan("\u2551")
  );
  console.log(chalk.cyan("\u2551") + " ".repeat(BOX_WIDTH) + chalk.cyan("\u2551"));

  // Individual check scores
  const checkOrder = [
    "metadata",
    "identity",
    "code-patterns",
    "install-hooks",
    "dependencies",
  ];

  for (const name of checkOrder) {
    const check = result.checks[name];
    if (!check) continue;
    const label = padRight(capitalize(name), 15);
    const scoreStr = colorScore(check.score);
    const summaryText =
      check.summary.length > 30
        ? check.summary.slice(0, 30) + "..."
        : check.summary;

    console.log(
      chalk.cyan("\u2551") +
        pad(
          `  \u25b8 ${label} [${scoreStr}/100] ${chalk.gray(summaryText)}`,
          BOX_WIDTH
        ) +
        chalk.cyan("\u2551")
    );
  }

  // Findings
  const allFindings = Object.values(result.checks).flatMap(
    (c) => c.findings
  );
  const important = allFindings.filter(
    (f) => f.severity === "critical" || f.severity === "high"
  );

  if (important.length > 0) {
    console.log(chalk.cyan("\u2551") + " ".repeat(BOX_WIDTH) + chalk.cyan("\u2551"));
    console.log(
      chalk.cyan("\u2551") +
        pad(chalk.yellow.bold("  FINDINGS:"), BOX_WIDTH) +
        chalk.cyan("\u2551")
    );

    for (const f of important.slice(0, 10)) {
      const icon = severityIcon(f.severity);
      const loc = f.file
        ? f.line
          ? ` (${f.file}:${f.line})`
          : ` (${f.file})`
        : "";
      const msg = `${f.message}${loc}`;
      const truncated =
        msg.length > BOX_WIDTH - 6
          ? msg.slice(0, BOX_WIDTH - 9) + "..."
          : msg;
      console.log(
        chalk.cyan("\u2551") +
          pad(`  ${icon} ${truncated}`, BOX_WIDTH) +
          chalk.cyan("\u2551")
      );
    }

    if (important.length > 10) {
      console.log(
        chalk.cyan("\u2551") +
          pad(
            chalk.gray(`  ... and ${important.length - 10} more findings`),
            BOX_WIDTH
          ) +
          chalk.cyan("\u2551")
      );
    }
  }

  console.log(chalk.cyan("\u2551") + " ".repeat(BOX_WIDTH) + chalk.cyan("\u2551"));
  console.log(chalk.cyan("\u255a" + line() + "\u255d"));
  console.log("");
}

export function printJson(result: ScanResult): void {
  console.log(JSON.stringify(result, null, 2));
}

function capitalize(s: string): string {
  return s
    .split("-")
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
    .join(" ");
}

function padRight(s: string, n: number): string {
  return s.length >= n ? s : s + " ".repeat(n - s.length);
}
