import { Octokit } from "octokit";
import type { RepoTarget, RepoInfo, CommitInfo, FileEntry } from "./types.js";

const token = process.env.GITHUB_TOKEN;

const octokit = new Octokit({
  auth: token,
});

export function hasToken(): boolean {
  return !!token;
}

export function parseRepoUrl(url: string): RepoTarget {
  const cleaned = url.replace(/\.git$/, "").replace(/\/$/, "");

  const ghMatch = cleaned.match(
    /(?:https?:\/\/)?github\.com\/([^/]+)\/([^/]+)/
  );
  if (ghMatch) {
    return {
      owner: ghMatch[1],
      repo: ghMatch[2],
      url: `https://github.com/${ghMatch[1]}/${ghMatch[2]}`,
    };
  }

  const shortMatch = cleaned.match(/^([^/]+)\/([^/]+)$/);
  if (shortMatch) {
    return {
      owner: shortMatch[1],
      repo: shortMatch[2],
      url: `https://github.com/${shortMatch[1]}/${shortMatch[2]}`,
    };
  }

  throw new Error(`Invalid GitHub URL: ${url}`);
}

function isRateLimitError(e: unknown): boolean {
  if (e && typeof e === "object" && "status" in e) {
    return (e as { status: number }).status === 403 || (e as { status: number }).status === 429;
  }
  const msg = String(e);
  return msg.includes("rate limit") || msg.includes("quota exhausted");
}

export async function fetchRepoInfo(target: RepoTarget): Promise<RepoInfo> {
  // Repo data is required — fail fast with clear message if rate limited
  let repoData;
  try {
    repoData = await fetchRepo(target);
  } catch (e) {
    if (isRateLimitError(e)) {
      const hint = token
        ? "Token rate limit exhausted. Wait or use a different token."
        : "Set GITHUB_TOKEN env var for higher rate limits (60 req/hr without token).";
      throw new Error(`GitHub API rate limit hit. ${hint}`);
    }
    throw e;
  }

  // These can fail gracefully
  const [ownerData, contributorsCount, commits, tree] = await Promise.all([
    fetchOwner(target.owner).catch(() => null),
    fetchContributorCount(target),
    fetchRecentCommits(target),
    fetchFileTree(target),
  ]);

  return {
    owner: target.owner,
    repo: target.repo,
    url: target.url,
    description: repoData.description,
    stars: repoData.stargazers_count,
    forks: repoData.forks_count,
    openIssues: repoData.open_issues_count,
    createdAt: repoData.created_at,
    updatedAt: repoData.updated_at,
    pushedAt: repoData.pushed_at,
    defaultBranch: repoData.default_branch,
    isFork: repoData.fork,
    parentFullName: repoData.parent?.full_name ?? null,
    ownerType: ownerData?.type ?? "Unknown",
    ownerCreatedAt: ownerData?.created_at ?? repoData.created_at,
    ownerFollowers: ownerData && "followers" in ownerData ? (ownerData.followers ?? 0) : 0,
    ownerPublicRepos: ownerData && "public_repos" in ownerData ? (ownerData.public_repos ?? 0) : 0,
    contributors: contributorsCount,
    recentCommits: commits,
    fileTree: tree,
  };
}

async function fetchRepo(target: RepoTarget) {
  const { data } = await octokit.rest.repos.get({
    owner: target.owner,
    repo: target.repo,
  });
  return data;
}

async function fetchOwner(owner: string) {
  const { data } = await octokit.rest.users.getByUsername({
    username: owner,
  });
  return data;
}

async function fetchContributorCount(target: RepoTarget): Promise<number> {
  try {
    const response = await octokit.rest.repos.listContributors({
      owner: target.owner,
      repo: target.repo,
      per_page: 1,
      anon: "false",
    });
    // Parse Link header to get total count from last page number
    const link = response.headers.link ?? "";
    const lastMatch = link.match(/[&?]page=(\d+)>;\s*rel="last"/);
    if (lastMatch) {
      return parseInt(lastMatch[1], 10);
    }
    return response.data.length;
  } catch {
    return 0;
  }
}

async function fetchRecentCommits(
  target: RepoTarget
): Promise<CommitInfo[]> {
  try {
    const { data } = await octokit.rest.repos.listCommits({
      owner: target.owner,
      repo: target.repo,
      per_page: 30,
    });
    return data.map((c) => ({
      sha: c.sha,
      message: c.commit.message,
      date: c.commit.author?.date ?? "",
      author: c.commit.author?.name ?? "unknown",
    }));
  } catch {
    return [];
  }
}

async function fetchFileTree(target: RepoTarget): Promise<FileEntry[]> {
  try {
    const { data } = await octokit.rest.git.getTree({
      owner: target.owner,
      repo: target.repo,
      tree_sha: "HEAD",
      recursive: "true",
    });
    return data.tree
      .filter((item) => item.type === "blob" || item.type === "tree")
      .map((item) => ({
        path: item.path ?? "",
        type: item.type as "blob" | "tree",
        size: item.size,
      }));
  } catch {
    return [];
  }
}

export async function fetchFileContent(
  target: RepoTarget,
  path: string
): Promise<string | null> {
  try {
    const { data } = await octokit.rest.repos.getContent({
      owner: target.owner,
      repo: target.repo,
      path,
    });
    if ("content" in data && data.encoding === "base64") {
      return Buffer.from(data.content, "base64").toString("utf-8");
    }
    return null;
  } catch {
    return null;
  }
}
