import type { RepoInfo, CheckResult, Finding } from "../types.js";

export async function checkMetadata(repo: RepoInfo): Promise<CheckResult> {
  const findings: Finding[] = [];
  let score = 100;

  const now = Date.now();
  const repoAge = now - new Date(repo.createdAt).getTime();
  const ownerAge = now - new Date(repo.ownerCreatedAt).getTime();
  const dayMs = 86_400_000;

  // Repo age
  const repoAgeDays = repoAge / dayMs;
  if (repoAgeDays < 7) {
    score -= 30;
    findings.push({
      severity: "high",
      message: `Repo created ${Math.floor(repoAgeDays)} days ago`,
    });
  } else if (repoAgeDays < 30) {
    score -= 15;
    findings.push({
      severity: "medium",
      message: `Repo is only ${Math.floor(repoAgeDays)} days old`,
    });
  }

  // Owner account age
  const ownerAgeDays = ownerAge / dayMs;
  if (ownerAgeDays < 30) {
    score -= 25;
    findings.push({
      severity: "high",
      message: `Owner account created ${Math.floor(ownerAgeDays)} days ago`,
    });
  } else if (ownerAgeDays < 90) {
    score -= 10;
    findings.push({
      severity: "medium",
      message: `Owner account is ${Math.floor(ownerAgeDays)} days old`,
    });
  }

  // Stars
  if (repo.stars === 0) {
    score -= 10;
    findings.push({ severity: "low", message: "No stars" });
  } else if (repo.stars < 10) {
    score -= 5;
    findings.push({
      severity: "info",
      message: `Only ${repo.stars} stars`,
    });
  }

  // Contributors
  if (repo.contributors <= 1) {
    score -= 10;
    findings.push({
      severity: "medium",
      message: "Single contributor",
    });
  }

  // Commit frequency — check if all commits happened in a short window (dump detection)
  if (repo.recentCommits.length > 0) {
    const dates = repo.recentCommits
      .map((c) => new Date(c.date).getTime())
      .filter((d) => !isNaN(d));

    if (dates.length >= 2) {
      const span = Math.max(...dates) - Math.min(...dates);
      const spanHours = span / (1000 * 60 * 60);
      if (repo.recentCommits.length >= 10 && spanHours < 1) {
        score -= 20;
        findings.push({
          severity: "high",
          message: `${repo.recentCommits.length} commits all within ${spanHours.toFixed(1)} hours — possible bulk dump`,
        });
      }
    }
  } else {
    score -= 10;
    findings.push({ severity: "medium", message: "No commits found" });
  }

  // Last push (abandoned?)
  const lastPush = now - new Date(repo.pushedAt).getTime();
  const lastPushDays = lastPush / dayMs;
  if (lastPushDays > 365) {
    score -= 5;
    findings.push({
      severity: "info",
      message: `Last pushed ${Math.floor(lastPushDays)} days ago`,
    });
  }

  // Owner profile
  if (repo.ownerPublicRepos <= 1) {
    score -= 10;
    findings.push({
      severity: "medium",
      message: `Owner has only ${repo.ownerPublicRepos} public repo(s)`,
    });
  }
  if (repo.ownerFollowers === 0) {
    score -= 5;
    findings.push({
      severity: "low",
      message: "Owner has 0 followers",
    });
  }

  score = Math.max(0, Math.min(100, score));

  const summary =
    findings.length === 0
      ? "Repo metadata looks healthy"
      : `${findings.filter((f) => f.severity === "high" || f.severity === "critical").length} high-risk metadata flags`;

  return { name: "metadata", score, findings, summary };
}
