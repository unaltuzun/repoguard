import { readFile } from "fs/promises";
import { fileURLToPath } from "url";
import { dirname, join } from "path";
import { distance } from "fastest-levenshtein";
import { fetchFileContent } from "../github.js";
import type { RepoInfo, CheckResult, Finding } from "../types.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const DATA_DIR = join(__dirname, "..", "..", "data");

interface MaliciousPackage {
  name: string;
  ecosystem: string;
  reason: string;
}

let maliciousPackages: MaliciousPackage[] | null = null;

async function loadMaliciousPackages(): Promise<MaliciousPackage[]> {
  if (maliciousPackages) return maliciousPackages;
  const raw = await readFile(
    join(DATA_DIR, "malicious-packages.json"),
    "utf-8"
  );
  maliciousPackages = JSON.parse(raw) as MaliciousPackage[];
  return maliciousPackages;
}

// Well-known packages for typosquat detection
const KNOWN_NPM = [
  "lodash", "express", "react", "axios", "webpack", "babel",
  "typescript", "eslint", "prettier", "jest", "mocha", "chalk",
  "commander", "inquirer", "dotenv", "cors", "uuid", "moment",
  "dayjs", "underscore", "async", "bluebird", "rxjs", "socket.io",
  "mongoose", "sequelize", "prisma", "next", "nuxt", "vue",
  "angular", "svelte", "tailwindcss", "nodemon", "pm2",
];

const KNOWN_PIP = [
  "requests", "flask", "django", "numpy", "pandas", "scipy",
  "tensorflow", "torch", "scikit-learn", "matplotlib", "pillow",
  "beautifulsoup4", "selenium", "celery", "boto3", "fastapi",
  "sqlalchemy", "pytest", "black", "mypy", "pydantic",
];

function isTyposquat(name: string, knownList: string[]): string | null {
  const lowerName = name.toLowerCase();
  // Too short names produce too many false positives
  if (lowerName.length < 5) return null;
  for (const known of knownList) {
    if (lowerName === known) continue;
    if (known.length < 5) continue;
    const dist = distance(lowerName, known);
    // Only flag if distance is 1 for short names, up to 2 for longer names
    const maxDist = Math.min(known.length, lowerName.length) >= 8 ? 2 : 1;
    if (dist > 0 && dist <= maxDist) {
      return known;
    }
  }
  return null;
}

interface DepFile {
  path: string;
  ecosystem: string;
  extract: (content: string) => string[];
  knownPackages: string[];
}

const DEP_FILES: DepFile[] = [
  {
    path: "package.json",
    ecosystem: "npm",
    extract: (content: string) => {
      try {
        const pkg = JSON.parse(content);
        return [
          ...Object.keys(pkg.dependencies ?? {}),
          ...Object.keys(pkg.devDependencies ?? {}),
        ];
      } catch {
        return [];
      }
    },
    knownPackages: KNOWN_NPM,
  },
  {
    path: "requirements.txt",
    ecosystem: "pip",
    extract: (content: string) =>
      content
        .split("\n")
        .map((l) => l.trim())
        .filter((l) => l && !l.startsWith("#"))
        .map((l) => l.split(/[=<>!~[\]]/)[0].trim()),
    knownPackages: KNOWN_PIP,
  },
  {
    path: "Cargo.toml",
    ecosystem: "crates",
    extract: (content: string) => {
      const deps: string[] = [];
      const depSection = content.match(
        /\[dependencies\]([\s\S]*?)(?:\[|$)/
      );
      if (depSection) {
        const lines = depSection[1].split("\n");
        for (const line of lines) {
          const match = line.match(/^(\S+)\s*=/);
          if (match) deps.push(match[1]);
        }
      }
      return deps;
    },
    knownPackages: [],
  },
  {
    path: "go.mod",
    ecosystem: "go",
    extract: (content: string) => {
      const deps: string[] = [];
      const lines = content.split("\n");
      let inRequire = false;
      for (const line of lines) {
        if (line.includes("require (")) {
          inRequire = true;
          continue;
        }
        if (inRequire && line.trim() === ")") {
          inRequire = false;
          continue;
        }
        if (inRequire) {
          const match = line.trim().match(/^(\S+)/);
          if (match) deps.push(match[1]);
        }
      }
      return deps;
    },
    knownPackages: [],
  },
];

export async function checkDependencies(
  repo: RepoInfo
): Promise<CheckResult> {
  const findings: Finding[] = [];
  let score = 100;

  const malicious = await loadMaliciousPackages();
  const target = { owner: repo.owner, repo: repo.repo, url: repo.url };

  for (const depFile of DEP_FILES) {
    const exists = repo.fileTree.some((f) => f.path === depFile.path);
    if (!exists) continue;

    const content = await fetchFileContent(target, depFile.path);
    if (!content) continue;

    const deps = depFile.extract(content);

    for (const dep of deps) {
      // Check against malicious list
      const mal = malicious.find(
        (m) =>
          m.name.toLowerCase() === dep.toLowerCase() &&
          m.ecosystem === depFile.ecosystem
      );
      if (mal) {
        score = 0; // Instant zero
        findings.push({
          severity: "critical",
          message: `Known malicious package: ${dep} (${mal.reason})`,
          file: depFile.path,
        });
        continue;
      }

      // Typosquat check
      if (depFile.knownPackages.length > 0) {
        const lookalike = isTyposquat(dep, depFile.knownPackages);
        if (lookalike) {
          score -= 20;
          findings.push({
            severity: "high",
            message: `Possible typosquat: "${dep}" looks like "${lookalike}"`,
            file: depFile.path,
          });
        }
      }
    }

    // Check for unpinned versions (npm)
    if (depFile.ecosystem === "npm") {
      try {
        const pkg = JSON.parse(content);
        const allDeps = {
          ...(pkg.dependencies ?? {}),
          ...(pkg.devDependencies ?? {}),
        };
        for (const [name, version] of Object.entries(allDeps)) {
          const v = version as string;
          if (v === "*" || v === "latest") {
            score -= 5;
            findings.push({
              severity: "medium",
              message: `Unpinned dependency: ${name}@${v}`,
              file: depFile.path,
            });
          }
        }
      } catch {
        // Already parsed above, ignore
      }
    }
  }

  score = Math.max(0, Math.min(100, score));

  const criticalCount = findings.filter(
    (f) => f.severity === "critical"
  ).length;
  const summary =
    criticalCount > 0
      ? `${criticalCount} malicious package(s) found!`
      : findings.length > 0
        ? `${findings.length} dependency concern(s)`
        : "Dependencies look clean";

  return { name: "dependencies", score, findings, summary };
}
