import { readFile } from "fs/promises";
import { fileURLToPath } from "url";
import { dirname, join } from "path";
import { fetchFileContent } from "../github.js";
import type { RepoInfo, CheckResult, Finding } from "../types.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const DATA_DIR = join(__dirname, "..", "..", "data");

interface SuspiciousPattern {
  name: string;
  pattern: string;
  severity: "critical" | "high" | "medium" | "low";
  weight: number;
  description: string;
}

let patterns: SuspiciousPattern[] | null = null;

async function loadPatterns(): Promise<SuspiciousPattern[]> {
  if (patterns) return patterns;
  const raw = await readFile(
    join(DATA_DIR, "suspicious-patterns.json"),
    "utf-8"
  );
  patterns = JSON.parse(raw) as SuspiciousPattern[];
  return patterns;
}

// File extensions worth scanning
const SCANNABLE_EXTENSIONS = new Set([
  "js", "ts", "jsx", "tsx", "mjs", "cjs",
  "py", "rb", "sh", "bash", "zsh",
  "php", "pl", "lua", "go", "rs",
  "c", "cpp", "h", "hpp",
  "java", "kt", "scala",
  "ps1", "bat", "cmd",
  "yml", "yaml", "toml", "json",
]);

const MAX_FILES_TO_SCAN = 20;
const MAX_FILE_SIZE = 500_000; // 500KB

// Prioritize files that are more likely to contain malicious code
const HIGH_PRIORITY_FILES = new Set([
  "package.json", "setup.py", "setup.cfg", "Makefile",
  "install.sh", "build.sh", "init.sh", "run.sh",
  "Dockerfile", "docker-compose.yml",
]);

function prioritizeFiles(files: { path: string; type: string; size?: number }[]) {
  const highPri: typeof files = [];
  const normalPri: typeof files = [];
  for (const f of files) {
    const basename = f.path.split("/").pop() ?? "";
    if (HIGH_PRIORITY_FILES.has(basename) || f.path.includes("scripts/")) {
      highPri.push(f);
    } else {
      normalPri.push(f);
    }
  }
  return [...highPri, ...normalPri];
}

function getExtension(path: string): string {
  const parts = path.split(".");
  return parts.length > 1 ? parts[parts.length - 1].toLowerCase() : "";
}

export async function checkCodePatterns(
  repo: RepoInfo
): Promise<CheckResult> {
  const findings: Finding[] = [];
  let score = 100;

  const suspiciousPatterns = await loadPatterns();

  // Filter scannable files from tree, prioritize risky files
  const allScannable = repo.fileTree.filter(
    (f) =>
      f.type === "blob" &&
      SCANNABLE_EXTENSIONS.has(getExtension(f.path)) &&
      (f.size === undefined || f.size < MAX_FILE_SIZE)
  );
  const scannableFiles = prioritizeFiles(allScannable).slice(0, MAX_FILES_TO_SCAN);

  if (scannableFiles.length === 0) {
    return {
      name: "code-patterns",
      score: 80,
      findings: [
        { severity: "info", message: "No scannable source files found" },
      ],
      summary: "No source files to scan",
    };
  }

  // Fetch file contents in batches (sequential batches to avoid rate limits)
  const target = { owner: repo.owner, repo: repo.repo, url: repo.url };
  const batchSize = 5;
  let rateLimited = false;

  for (let i = 0; i < scannableFiles.length && !rateLimited; i += batchSize) {
    const batch = scannableFiles.slice(i, i + batchSize);
    const contents = await Promise.all(
      batch.map(async (f) => ({
        path: f.path,
        content: await fetchFileContent(target, f.path),
      }))
    );

    // If all null, likely rate limited
    if (contents.every((c) => c.content === null) && batch.length > 1) {
      rateLimited = true;
      findings.push({
        severity: "info",
        message: "API rate limit reached — code scan incomplete. Set GITHUB_TOKEN for full scan.",
      });
      break;
    }

    for (const { path, content } of contents) {
      if (!content) continue;

      const lines = content.split("\n");
      for (const sp of suspiciousPatterns) {
        let regex: RegExp;
        try {
          regex = new RegExp(sp.pattern, "gi");
        } catch {
          continue; // Skip invalid patterns
        }
        for (let lineIdx = 0; lineIdx < lines.length; lineIdx++) {
          if (regex.test(lines[lineIdx])) {
            score -= sp.weight;
            findings.push({
              severity: sp.severity,
              message: `${sp.description}: ${sp.name}`,
              file: path,
              line: lineIdx + 1,
            });
            // Reset regex state
            regex.lastIndex = 0;
            break; // One match per pattern per file is enough
          }
        }
      }
    }
  }

  score = Math.max(0, Math.min(100, score));

  const criticalCount = findings.filter(
    (f) => f.severity === "critical"
  ).length;
  const highCount = findings.filter((f) => f.severity === "high").length;

  const summary =
    findings.length === 0
      ? "No suspicious code patterns found"
      : `${criticalCount} critical, ${highCount} high-risk patterns found`;

  return { name: "code-patterns", score, findings, summary };
}
