import type { CheckResult, ScanResult, Rating, RepoTarget } from "./types.js";

const WEIGHTS: Record<string, number> = {
  metadata: 0.2,
  identity: 0.2,
  "code-patterns": 0.25,
  "install-hooks": 0.25,
  dependencies: 0.1,
};

export function calculateScore(checks: Record<string, CheckResult>): number {
  let weightedSum = 0;
  let totalWeight = 0;

  for (const [name, result] of Object.entries(checks)) {
    const weight = WEIGHTS[name] ?? 0.1;
    weightedSum += result.score * weight;
    totalWeight += weight;
  }

  if (totalWeight === 0) return 0;
  return Math.round(weightedSum / totalWeight);
}

export function getRating(score: number): Rating {
  if (score >= 90)
    return { label: "SAFE", emoji: "\u2705", color: "green" };
  if (score >= 70)
    return { label: "CAUTION", emoji: "\u26a0\ufe0f", color: "yellow" };
  if (score >= 40)
    return { label: "RISKY", emoji: "\ud83d\udfe0", color: "red" };
  return { label: "DANGER", emoji: "\ud83d\udd34", color: "redBright" };
}

export function buildScanResult(
  target: RepoTarget,
  checks: Record<string, CheckResult>
): ScanResult {
  const finalScore = calculateScore(checks);
  const rating = getRating(finalScore);

  return {
    target,
    checks,
    finalScore,
    rating,
    scannedAt: new Date().toISOString(),
  };
}
