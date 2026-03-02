import type { RepoTarget, CheckResult, ScanResult, CheckName, CheckFn } from "./types.js";
import { fetchRepoInfo } from "./github.js";
import { buildScanResult } from "./scoring.js";
import { checkMetadata } from "./checks/metadata.js";
import { checkIdentity } from "./checks/identity.js";
import { checkCodePatterns } from "./checks/code-patterns.js";
import { checkInstallHooks } from "./checks/install-hooks.js";
import { checkDependencies } from "./checks/dependencies.js";

const ALL_CHECKS: Record<CheckName, CheckFn> = {
  metadata: checkMetadata,
  identity: checkIdentity,
  "code-patterns": checkCodePatterns,
  "install-hooks": checkInstallHooks,
  dependencies: checkDependencies,
};

export const VALID_CHECK_NAMES: CheckName[] = Object.keys(ALL_CHECKS) as CheckName[];

export async function scan(
  target: RepoTarget,
  selectedChecks?: CheckName[],
  onProgress?: (msg: string) => void
): Promise<ScanResult> {
  onProgress?.("Fetching repo info from GitHub...");
  const repoInfo = await fetchRepoInfo(target);

  const checksToRun = selectedChecks ?? (Object.keys(ALL_CHECKS) as CheckName[]);

  onProgress?.(`Running ${checksToRun.length} checks in parallel...`);

  const results = await Promise.all(
    checksToRun.map(async (name) => {
      const fn = ALL_CHECKS[name];
      if (!fn) throw new Error(`Unknown check: ${name}`);
      onProgress?.(`  ▸ ${name}...`);
      const result = await fn(repoInfo);
      return [name, result] as [string, CheckResult];
    })
  );

  const checks: Record<string, CheckResult> = Object.fromEntries(results);

  return buildScanResult(target, checks);
}
