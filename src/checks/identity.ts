import { distance } from "fastest-levenshtein";
import { readFile } from "fs/promises";
import { fileURLToPath } from "url";
import { dirname, join } from "path";
import type { RepoInfo, CheckResult, Finding } from "../types.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const DATA_DIR = join(__dirname, "..", "..", "data");

interface PopularRepo {
  name: string;
  full_name: string;
}

let popularRepos: PopularRepo[] | null = null;

async function loadPopularRepos(): Promise<PopularRepo[]> {
  if (popularRepos) return popularRepos;
  const raw = await readFile(join(DATA_DIR, "popular-repos.json"), "utf-8");
  popularRepos = JSON.parse(raw) as PopularRepo[];
  return popularRepos;
}

function similarity(a: string, b: string): number {
  const maxLen = Math.max(a.length, b.length);
  if (maxLen === 0) return 100;
  const dist = distance(a.toLowerCase(), b.toLowerCase());
  return Math.round(((maxLen - dist) / maxLen) * 100);
}

export async function checkIdentity(repo: RepoInfo): Promise<CheckResult> {
  const findings: Finding[] = [];
  let score = 100;

  const repos = await loadPopularRepos();
  const repoName = repo.repo.toLowerCase();
  const fullName = `${repo.owner}/${repo.repo}`.toLowerCase();

  // Check repo name against popular repos
  let bestMatch: { name: string; full_name: string; sim: number } | null = null;

  for (const popular of repos) {
    // Skip if it IS the popular repo
    if (fullName === popular.full_name.toLowerCase()) continue;

    const nameSim = similarity(repoName, popular.name.toLowerCase());
    if (nameSim >= 80 && (!bestMatch || nameSim > bestMatch.sim)) {
      bestMatch = {
        name: popular.name,
        full_name: popular.full_name,
        sim: nameSim,
      };
    }
  }

  if (bestMatch) {
    if (bestMatch.sim >= 95 && !repo.isFork) {
      score -= 50;
      findings.push({
        severity: "critical",
        message: `Repo name ${bestMatch.sim}% similar to "${bestMatch.full_name}" but NOT a fork — likely typosquat`,
      });
    } else if (bestMatch.sim >= 90 && !repo.isFork) {
      score -= 35;
      findings.push({
        severity: "high",
        message: `Repo name ${bestMatch.sim}% similar to "${bestMatch.full_name}" — possible typosquat`,
      });
    } else if (bestMatch.sim >= 80) {
      score -= 15;
      findings.push({
        severity: "medium",
        message: `Repo name ${bestMatch.sim}% similar to "${bestMatch.full_name}"`,
      });
    }
  }

  // Fork analysis
  if (repo.isFork && repo.parentFullName) {
    findings.push({
      severity: "info",
      message: `Fork of ${repo.parentFullName}`,
    });

    // Check how many extra commits the fork has (approximation: compare commit count)
    const extraCommits = repo.recentCommits.length;
    if (extraCommits > 0) {
      // If fork has commits but very few stars → suspicious
      if (repo.stars < 5 && extraCommits > 0) {
        score -= 15;
        findings.push({
          severity: "medium",
          message: `Fork with modifications but very few stars — review changes carefully`,
        });
      }
    }
  }

  score = Math.max(0, Math.min(100, score));

  const summary =
    findings.length === 0
      ? "No identity/typosquat concerns"
      : bestMatch
        ? `Name ${bestMatch.sim}% similar to "${bestMatch.name}"`
        : "Fork analysis flagged concerns";

  return { name: "identity", score, findings, summary };
}
