/**
 * flowcheck MCP server. Tools: audit_workflows, harden_plan.
 */
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { auditWorkflows, buildHardenPlan, VERSION } from "./core.js";

const server = new McpServer({ name: "flowcheck", version: VERSION });

server.tool(
  "audit_workflows",
  "Audit GitHub workflow files under a repo path for least-privilege problems: missing or write-all permissions, per-job grants broader than the job's steps need, pull_request_target or workflow_run or issue_comment triggers combined with a checkout of the PR head, secrets in fork-reachable contexts, secrets: inherit to reusable workflows, self-hosted runners on PR triggers, cache poisoning surface, whole-workspace artifact uploads, missing timeouts, and missing concurrency guards on deploy-shaped jobs. Returns a HARDENED, REVIEW, or EXPOSED verdict with file, job, and line evidence per finding, plus a hardened permissions plan per job.",
  {
    path: z.string().describe("Repo root, a .github/workflows directory, or a single workflow file"),
  },
  async ({ path }) => {
    const report = auditWorkflows(path);
    return { content: [{ type: "text" as const, text: JSON.stringify(report, null, 2) }] };
  },
);

server.tool(
  "harden_plan",
  "Build the least-privilege hardening plan for workflows under a repo path without writing any files. For each job, infers the permissions its steps actually need (checkout is contents: read, release creation is contents: write, GHCR push is packages: write, PR comments are pull-requests: write, and so on) and returns a paste-ready permissions block per job plus a top-level union block, with notes where a grant is removed or a privileged trigger shape needs a human decision.",
  {
    path: z.string().describe("Repo root, a .github/workflows directory, or a single workflow file"),
  },
  async ({ path }) => {
    const plan = buildHardenPlan(path);
    return { content: [{ type: "text" as const, text: JSON.stringify(plan, null, 2) }] };
  },
);

async function main(): Promise<void> {
  await server.connect(new StdioServerTransport());
}

void main();
