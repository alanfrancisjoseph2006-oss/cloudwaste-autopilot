/**
 * Typed client for the CloudWaste API.
 *
 * Every call runs server-side in a React Server Component with `no-store`.
 * Caching a FinOps dashboard is actively harmful: a stale "pending approvals: 3"
 * is worse than a slow one, and an operator acting on a cached finding is
 * acting on a picture of the account that has since changed.
 */

const BASE = process.env.CLOUDWASTE_API_URL ?? "http://127.0.0.1:8000";
const PREFIX = `${BASE}/api/v1`;

export class ApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
    readonly detail?: string,
  ) {
    super(message);
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let response: Response;
  try {
    response = await fetch(`${PREFIX}${path}`, {
      ...init,
      cache: "no-store",
      headers: {
        "Content-Type": "application/json",
        "X-User": "console@cloudwaste.local",
        ...(init?.headers ?? {}),
      },
    });
  } catch (cause) {
    // A connection refused here almost always means the API is not running,
    // so say that rather than surfacing a bare TypeError.
    throw new ApiError(
      `Cannot reach the CloudWaste API at ${BASE}. Is it running? ` +
        `Start it with: uvicorn cloudwaste.main:app --reload`,
      0,
      String(cause),
    );
  }

  if (!response.ok) {
    let detail: string | undefined;
    try {
      const body = await response.json();
      detail = body?.detail ?? JSON.stringify(body);
    } catch {
      detail = await response.text().catch(() => undefined);
    }
    throw new ApiError(
      `${init?.method ?? "GET"} ${path} failed (${response.status})`,
      response.status,
      detail,
    );
  }

  if (response.status === 204) return undefined as T;
  return (await response.json()) as T;
}

const post = <T>(path: string, body?: unknown) =>
  request<T>(path, {
    method: "POST",
    body: body === undefined ? undefined : JSON.stringify(body),
  });

// --------------------------------------------------------------------------
// Types
// --------------------------------------------------------------------------

export type RiskLevel = "low" | "medium" | "high" | "critical";

export interface Dashboard {
  account_id: string;
  monthly_spend: number;
  forecast_next_30_days: number;
  potential_monthly_savings: number;
  potential_annual_savings: number;
  realized_monthly_savings: number;
  waste_score: number;
  active_findings: number;
  resources_tracked: number;
  pending_approvals: number;
  findings_by_type: Record<string, { count: number; monthly_savings: number }>;
  findings_by_risk: Record<string, number>;
  cost_by_service: Record<string, number>;
  autopilot_enabled: boolean;
  dry_run: boolean;
}

export interface Evidence {
  source: string;
  metric: string;
  value: number | string | null;
  unit: string | null;
  window_days: number | null;
  detail: string;
}

export interface ScoreBreakdown {
  utilization_waste: number;
  cost_impact: number;
  inactivity: number;
  age: number;
  recommendation_confidence: number;
  anomaly_signal: number;
  total: number;
}

export interface Finding {
  finding_id: string;
  account_id: string;
  region: string;
  resource_id: string;
  resource_type: string;
  waste_type: string;
  waste_score: number;
  score_breakdown: ScoreBreakdown;
  confidence: number;
  confidence_reasons: string[];
  monthly_cost: number;
  potential_monthly_savings: number;
  risk: RiskLevel;
  status: string;
  title: string;
  summary: string;
  evidence: Evidence[];
  detector: string;
  first_seen_at: string;
}

export interface Simulation {
  current_monthly_cost: number;
  projected_monthly_cost: number;
  monthly_savings: number;
  annual_savings: number;
  savings_percent: number;
  restart_required: boolean;
  downtime_estimate_seconds: number;
  rollback_possible: boolean;
  rollback_method: string | null;
  risk: RiskLevel;
  performance_impact: string;
  assumptions: string[];
  priced_from: string;
}

export interface Recommendation {
  recommendation_id: string;
  finding_id: string;
  resource_id: string;
  resource_type: string;
  action_type: string;
  current_configuration: string;
  recommended_configuration: string;
  action_parameters: Record<string, unknown>;
  monthly_savings: number;
  annual_savings: number;
  confidence: number;
  risk: RiskLevel;
  restart_required: boolean;
  rollback_possible: boolean;
  rationale: string;
  simulation: Simulation | null;
}

export interface Resource {
  resource_id: string;
  resource_type: string;
  name: string | null;
  state: string | null;
  region: string;
  environment: string;
  owner: string | null;
  criticality: string;
  auto_remediation_allowed: boolean | null;
  tags: Record<string, string>;
  configuration: Record<string, unknown>;
  monthly_cost: number;
}

export interface VerificationResult {
  check: string;
  passed: boolean;
  detail: string;
}

export interface Action {
  action_id: string;
  recommendation_id: string;
  finding_id: string;
  resource_id: string;
  resource_type: string;
  action_type: string;
  risk: RiskLevel;
  policy_decision: string;
  policy_rule: string | null;
  approval_required: boolean;
  approval_status: string;
  approval_expires_at: string | null;
  approved_by: string | null;
  rejection_reason: string | null;
  execution_status: string;
  dry_run: boolean;
  error: string | null;
  verifications: VerificationResult[];
  realized_monthly_savings: number | null;
  requested_by: string;
  agent_id: string | null;
  reason: string;
  created_at: string;
}

export interface AuditEntry {
  audit_id: string;
  timestamp: string;
  action_id: string | null;
  resource_id: string | null;
  actor: string;
  agent_id: string | null;
  event: string;
  outcome: string;
  risk: RiskLevel | null;
  detail: Record<string, unknown>;
}

export interface AgentResponse {
  text: string;
  backend: string;
  model_id: string | null;
  turns: number;
  tool_calls: {
    name: string;
    arguments: Record<string, unknown>;
    error: string | null;
    result_preview: string | null;
  }[];
}

export interface PolicyRule {
  name: string;
  description: string;
  enabled: boolean;
  priority: number;
  resource_type: string | null;
  environment: string | null;
  action: string | null;
  max_risk: RiskLevel | null;
  min_confidence: number | null;
  effect: "allow" | "deny";
  auto_execute: boolean;
  require_approval: boolean;
}

// --------------------------------------------------------------------------
// Endpoints
// --------------------------------------------------------------------------

export const api = {
  /** Deployment info and safety switches. Lives at the root, not under /api/v1. */
  root: async () => {
    const response = await fetch(`${BASE}/`, { cache: "no-store" });
    if (!response.ok) {
      throw new ApiError("GET / failed", response.status);
    }
    return (await response.json()) as {
      version: string;
      safety: {
        dry_run_default: boolean;
        autopilot_enabled: boolean;
        autopilot_max_risk: string;
        summary: string;
      };
      configuration: Record<string, unknown>;
      executable_actions: string[];
    };
  },

  dashboard: () => request<Dashboard>("/dashboard"),

  scan: () =>
    post<{
      findings_created: number;
      recommendations_created: number;
      total_potential_monthly_savings: number;
    }>("/findings/scan"),

  findings: (query = "") =>
    request<{
      count: number;
      total_potential_monthly_savings: number;
      findings: Finding[];
    }>(`/findings${query}`),

  finding: (id: string) =>
    request<{
      finding: Finding;
      score_contributions: Record<string, number>;
      resource: Resource | null;
      recommendations: Recommendation[];
    }>(`/findings/${id}`),

  updateFinding: (id: string, status: string) =>
    request<Finding>(`/findings/${id}`, {
      method: "PATCH",
      body: JSON.stringify({ status }),
    }),

  recommendations: (query = "") =>
    request<{
      count: number;
      total_monthly_savings: number;
      recommendations: Recommendation[];
    }>(`/recommendations${query}`),

  costs: (days = 30) =>
    request<{
      total: number;
      forecast_next_30_days: number;
      by_service: Record<string, number>;
      by_region: Record<string, number>;
    }>(`/costs?days=${days}`),

  dailyCosts: (days = 30) =>
    request<{ series: { date: string; cost: number }[] }>(
      `/costs/daily?days=${days}`,
    ),

  anomalies: () =>
    request<{
      count: number;
      anomalies: {
        anomaly_id: string;
        service: string;
        start: string;
        expected_spend: number;
        actual_spend: number;
        excess: number;
        increase_percent: number;
      }[];
    }>("/costs/anomalies"),

  actions: (query = "") =>
    request<{ count: number; actions: Action[] }>(`/actions${query}`),

  action: (id: string) =>
    request<{
      action: Action;
      recommendation: Recommendation | null;
      resource: Resource | null;
      can_execute: boolean;
      can_execute_reason: string;
      audit: AuditEntry[];
    }>(`/actions/${id}`),

  createAction: (recommendationId: string) =>
    post<{ action: Action; risk: any; policy: any }>("/actions", {
      recommendation_id: recommendationId,
    }),

  approveAction: (id: string, note?: string) =>
    post<{ action: Action }>(`/actions/${id}/approve`, { note }),

  rejectAction: (id: string, reason: string) =>
    post<{ action: Action }>(`/actions/${id}/reject`, { reason }),

  executeAction: (id: string) =>
    post<{
      action: Action;
      succeeded: boolean;
      message: string;
      states: { state: string; ok: boolean; detail: string }[];
    }>(`/actions/${id}/execute`),

  rollbackAction: (id: string) =>
    post<{ action: Action; message: string }>(`/actions/${id}/rollback`),

  audit: (limit = 100) =>
    request<{ count: number; entries: AuditEntry[] }>(`/audit?limit=${limit}`),

  policies: () =>
    request<{
      rules: PolicyRule[];
      validation_problems: { severity: string; rule: string; message: string }[];
      deployment_ceilings: Record<string, unknown>;
    }>("/policies"),

  agentChat: (message: string) =>
    post<AgentResponse>("/agent/chat", { message }),

  agentExplain: (findingId: string) =>
    post<AgentResponse & { finding: Finding; evidence: Evidence[] }>(
      "/agent/explain",
      { finding_id: findingId },
    ),

  agentTools: () =>
    request<{ count: number; tools: { name: string; description: string }[] }>(
      "/agent/tools",
    ),
};

// --------------------------------------------------------------------------
// Formatting
// --------------------------------------------------------------------------

export const money = (value: number, decimals = 2) =>
  `$${value.toLocaleString("en-US", {
    minimumFractionDigits: decimals,
    maximumFractionDigits: decimals,
  })}`;

export const compactMoney = (value: number) =>
  value >= 10_000 ? `$${(value / 1000).toFixed(1)}k` : money(value, 0);

export const percent = (value: number, decimals = 0) =>
  `${value.toFixed(decimals)}%`;

export const titleCase = (value: string) =>
  value
    .replace(/_/g, " ")
    .replace(/\b\w/g, (character) => character.toUpperCase());

export const relativeTime = (iso: string) => {
  const then = new Date(iso).getTime();
  const seconds = Math.floor((Date.now() - then) / 1000);
  if (seconds < 60) return "just now";
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
};
