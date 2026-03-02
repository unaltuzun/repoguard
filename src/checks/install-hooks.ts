import { fetchFileContent } from "../github.js";
import type { RepoInfo, CheckResult, Finding } from "../types.js";

const DANGEROUS_COMMANDS = [
  { pattern: /curl\s+[^|]*\|\s*(?:ba)?sh/i, desc: "curl pipe to shell" },
  { pattern: /wget\s+[^|]*\|\s*(?:ba)?sh/i, desc: "wget pipe to shell" },
  { pattern: /\bnc\s+-[elp]/i, desc: "netcat listener/connection" },
  { pattern: /bash\s+-i\s+>&?\s*\/dev\/tcp/i, desc: "bash reverse shell" },
  { pattern: /python[23]?\s+-c\s+.*socket/i, desc: "python socket in one-liner" },
  { pattern: /\bchmod\s+\+x\b.*&&.*\.\//, desc: "chmod +x and execute" },
  { pattern: /\/dev\/tcp\//, desc: "/dev/tcp reverse shell" },
  { pattern: /mkfifo|mknod.*\/tmp/i, desc: "named pipe creation (reverse shell)" },
  { pattern: /powershell\s.*-enc/i, desc: "PowerShell encoded command" },
  { pattern: /\bbase64\s+-d\b.*\|\s*(?:ba)?sh/i, desc: "base64 decode pipe to shell" },
  { pattern: /\beval\s*\(\s*atob\b/i, desc: "eval(atob(...)) pattern" },
  { pattern: /\bcrypto(?:miner|night|jacking)/i, desc: "cryptominer reference" },
];

interface HookSource {
  file: string;
  type: string;
  extract: (content: string) => string[];
}

const HOOK_SOURCES: HookSource[] = [
  {
    file: "package.json",
    type: "npm",
    extract: (content: string) => {
      try {
        const pkg = JSON.parse(content);
        const scripts = pkg.scripts ?? {};
        const hookKeys = [
          "preinstall", "postinstall", "prepare",
          "prepack", "postpack", "prepublish",
          "prepublishOnly", "preuninstall", "postuninstall",
        ];
        return hookKeys
          .filter((k) => scripts[k])
          .map((k) => `${k}: ${scripts[k]}`);
      } catch {
        return [];
      }
    },
  },
  {
    file: "setup.py",
    type: "python",
    extract: (content: string) => {
      const hits: string[] = [];
      if (/cmdclass/i.test(content)) hits.push("cmdclass override detected");
      if (/\binstall\b.*class/i.test(content))
        hits.push("install command class override");
      if (/subprocess|os\.system|os\.popen/i.test(content))
        hits.push("system command execution in setup.py");
      return hits;
    },
  },
  {
    file: "Makefile",
    type: "make",
    extract: (content: string) => {
      const hits: string[] = [];
      // Look for install target
      const installMatch = content.match(
        /^install\s*:.*\n((?:\t.*\n?)*)/m
      );
      if (installMatch) {
        hits.push(`install target: ${installMatch[1].trim().split("\n")[0]}`);
      }
      return hits;
    },
  },
  {
    file: "Cargo.toml",
    type: "rust",
    extract: (content: string) => {
      const hits: string[] = [];
      if (/\[build-dependencies\]/i.test(content) || /build\s*=\s*"build\.rs"/i.test(content)) {
        hits.push("build.rs script detected");
      }
      return hits;
    },
  },
];

export async function checkInstallHooks(
  repo: RepoInfo
): Promise<CheckResult> {
  const findings: Finding[] = [];
  let score = 100;

  const target = { owner: repo.owner, repo: repo.repo, url: repo.url };

  // Check each hook source
  for (const source of HOOK_SOURCES) {
    const exists = repo.fileTree.some((f) => f.path === source.file);
    if (!exists) continue;

    const content = await fetchFileContent(target, source.file);
    if (!content) continue;

    const hooks = source.extract(content);
    if (hooks.length === 0) continue;

    for (const hook of hooks) {
      // Check if hook contains dangerous commands
      let isDangerous = false;
      for (const cmd of DANGEROUS_COMMANDS) {
        if (cmd.pattern.test(hook)) {
          isDangerous = true;
          score -= 40;
          findings.push({
            severity: "critical",
            message: `${source.type} hook: ${cmd.desc} — "${hook}"`,
            file: source.file,
          });
          break;
        }
      }

      if (!isDangerous) {
        // Still note the hook exists
        findings.push({
          severity: "info",
          message: `${source.type} hook: ${hook}`,
          file: source.file,
        });
      }
    }
  }

  // Also check build.rs content if it exists
  if (repo.fileTree.some((f) => f.path === "build.rs")) {
    const content = await fetchFileContent(target, "build.rs");
    if (content) {
      for (const cmd of DANGEROUS_COMMANDS) {
        if (cmd.pattern.test(content)) {
          score -= 40;
          findings.push({
            severity: "critical",
            message: `build.rs: ${cmd.desc}`,
            file: "build.rs",
          });
        }
      }
      if (/std::process::Command/i.test(content)) {
        score -= 10;
        findings.push({
          severity: "medium",
          message: "build.rs executes system commands",
          file: "build.rs",
        });
      }
    }
  }

  // Check for .github/workflows that run on PR (supply chain vector)
  const workflows = repo.fileTree.filter(
    (f) => f.path.startsWith(".github/workflows/") && f.path.endsWith(".yml")
  );
  for (const wf of workflows.slice(0, 5)) {
    const content = await fetchFileContent(target, wf.path);
    if (!content) continue;
    if (/pull_request_target/i.test(content)) {
      score -= 15;
      findings.push({
        severity: "high",
        message: "Workflow uses pull_request_target (potential supply chain risk)",
        file: wf.path,
      });
    }
  }

  score = Math.max(0, Math.min(100, score));

  const criticalCount = findings.filter(
    (f) => f.severity === "critical"
  ).length;
  const summary =
    criticalCount > 0
      ? `${criticalCount} dangerous install hook(s) found`
      : findings.length > 0
        ? `${findings.length} hook(s) found, none dangerous`
        : "No install hooks detected";

  return { name: "install-hooks", score, findings, summary };
}
