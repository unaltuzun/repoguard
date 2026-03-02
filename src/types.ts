export interface RepoTarget {
  owner: string;
  repo: string;
  url: string;
}

export interface RepoInfo {
  owner: string;
  repo: string;
  url: string;
  // Repo metadata
  description: string | null;
  stars: number;
  forks: number;
  openIssues: number;
  createdAt: string;
  updatedAt: string;
  pushedAt: string;
  defaultBranch: string;
  isFork: boolean;
  parentFullName: string | null;
  // Owner metadata
  ownerType: string;
  ownerCreatedAt: string;
  ownerFollowers: number;
  ownerPublicRepos: number;
  // Derived
  contributors: number;
  recentCommits: CommitInfo[];
  fileTree: FileEntry[];
}

export interface CommitInfo {
  sha: string;
  message: string;
  date: string;
  author: string;
}

export interface FileEntry {
  path: string;
  type: "blob" | "tree";
  size?: number;
}

export interface Finding {
  severity: "critical" | "high" | "medium" | "low" | "info";
  message: string;
  file?: string;
  line?: number;
}

export interface CheckResult {
  name: string;
  score: number; // 0-100
  findings: Finding[];
  summary: string;
}

export type CheckName =
  | "metadata"
  | "identity"
  | "code-patterns"
  | "install-hooks"
  | "dependencies";

export interface ScanResult {
  target: RepoTarget;
  checks: Record<string, CheckResult>;
  finalScore: number;
  rating: Rating;
  scannedAt: string;
}

export interface Rating {
  label: string;
  emoji: string;
  color: "green" | "yellow" | "red" | "redBright";
}

export type CheckFn = (repo: RepoInfo) => Promise<CheckResult>;
