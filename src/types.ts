/**
 * flowcheck types.
 *
 * A Finding is one piece of evidence: the file, the job when the finding
 * is job scoped, the 1-based line in the workflow file, the rule id, the
 * severity, and a human sentence. A JobPlan is the hardened permissions
 * suggestion for one job, inferred from what its steps actually do.
 */
export type Severity = "critical" | "high" | "medium" | "low";
export type Verdict = "HARDENED" | "REVIEW" | "EXPOSED";

export interface Finding {
  rule: string;
  severity: Severity;
  file: string;
  job?: string;
  line: number;
  message: string;
}

export interface JobPlan {
  file: string;
  job: string;
  /** Text summary of the permissions the job effectively runs with today. */
  current: string;
  /** Inferred least-privilege grants, scope to access level. */
  suggested: Record<string, string>;
  /** A paste-ready permissions block for this job. */
  suggestedYaml: string;
  notes: string[];
}

export interface AuditReport {
  tool: "flowcheck";
  version: string;
  target: string;
  verdict: Verdict;
  counts: {
    files: number;
    jobs: number;
    findings: number;
    bySeverity: Record<Severity, number>;
  };
  findings: Finding[];
  plans: JobPlan[];
  caps: {
    maxFiles: number;
    maxFileBytes: number;
    filesSeen: number;
    truncated: boolean;
    skippedOversize: string[];
  };
  note?: string;
}

export interface HardenPlan {
  tool: "flowcheck";
  version: string;
  target: string;
  verdict: Verdict;
  jobs: JobPlan[];
  /** Paste-ready top-level permissions block covering every job. */
  topLevelYaml: string;
  findings: Finding[];
  note?: string;
}
