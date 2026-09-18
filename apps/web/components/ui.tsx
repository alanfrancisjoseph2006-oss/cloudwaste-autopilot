/**
 * Shared presentation components.
 *
 * The rule these encode: risk and savings never share a visual language. A
 * $900/month saving and a CRITICAL risk both want the operator's attention, but
 * for opposite reasons, and colouring them the same way is how someone approves
 * a database resize because it looked like a big green number.
 */

import Link from "next/link";
import type { Evidence, RiskLevel, ScoreBreakdown } from "@/lib/api";
import { money, percent, titleCase } from "@/lib/api";

export function RiskBadge({ risk }: { risk: RiskLevel | string }) {
  const level = String(risk).toLowerCase();
  return <span className={`badge badge-${level}`}>{level.toUpperCase()}</span>;
}

export function StatusBadge({ status }: { status: string }) {
  const tone: Record<string, string> = {
    OPEN: "badge-neutral",
    APPROVED: "badge-save",
    NOT_REQUIRED: "badge-save",
    COMPLETED: "badge-save",
    REMEDIATED: "badge-save",
    PENDING: "badge-medium",
    EXECUTING: "badge-medium",
    EXPIRED: "badge-high",
    REJECTED: "badge-critical",
    FAILED: "badge-critical",
    ROLLBACK_FAILED: "badge-critical",
    ROLLED_BACK: "badge-high",
    SUPPRESSED: "badge-neutral",
    STALE: "badge-neutral",
    NOT_STARTED: "badge-neutral",
  };
  return (
    <span className={`badge ${tone[status] ?? "badge-neutral"}`}>
      {status.replace(/_/g, " ")}
    </span>
  );
}

export function StatCard({
  label,
  value,
  sub,
  tone,
}: {
  label: string;
  value: string;
  sub?: string;
  tone?: "save" | "default";
}) {
  return (
    <div className="card">
      <div className="stat-label">{label}</div>
      <div className={`stat-value${tone === "save" ? " save" : ""}`}>{value}</div>
      {sub ? <div className="stat-sub">{sub}</div> : null}
    </div>
  );
}

/** Waste score: a cool-to-warm scale, independent of the risk palette. */
export function ScoreBar({ value, max = 100 }: { value: number; max?: number }) {
  const pct = Math.max(0, Math.min(100, (value / max) * 100));
  const color =
    value >= 80 ? "#fb923c" : value >= 60 ? "#fbbf24" : value >= 40 ? "#4f9cf9" : "#64748b";
  return (
    <div className="score-cell">
      <span style={{ minWidth: 26 }}>{value.toFixed(0)}</span>
      <div className="bar">
        <div className="bar-fill" style={{ width: `${pct}%`, background: color }} />
      </div>
    </div>
  );
}

/**
 * Confidence, shown separately from waste score and explicitly flagged when it
 * is too low to act on. Conflating the two is the mistake this UI exists to
 * avoid.
 */
export function ConfidenceBar({ value }: { value: number }) {
  const color = value >= 85 ? "#34d399" : value >= 70 ? "#4f9cf9" : "#fb923c";
  return (
    <div className="score-cell" title={
      value < 70
        ? "Below 70%: the evidence is not strong enough to act on without review"
        : "Evidence is strong enough to act on"
    }>
      <span style={{ minWidth: 34 }}>{percent(value)}</span>
      <div className="bar">
        <div className="bar-fill" style={{ width: `${value}%`, background: color }} />
      </div>
    </div>
  );
}

export function EvidenceList({ evidence }: { evidence: Evidence[] }) {
  if (!evidence.length) {
    return <p className="muted">No evidence recorded.</p>;
  }
  return (
    <div>
      {evidence.map((item, index) => (
        <div className="evidence" key={`${item.source}-${item.metric}-${index}`}>
          <div className="evidence-head">
            <span className="source-tag">{item.source}</span>
            <span style={{ fontSize: 13, fontWeight: 550 }}>
              {titleCase(item.metric)}
            </span>
            {item.value !== null && item.value !== undefined ? (
              <span className="mono muted">
                {typeof item.value === "number"
                  ? item.value.toLocaleString("en-US")
                  : item.value}
                {item.unit ? ` ${item.unit}` : ""}
              </span>
            ) : null}
          </div>
          <div className="evidence-detail">{item.detail}</div>
        </div>
      ))}
    </div>
  );
}

/** The arithmetic behind a waste score, so nobody has to trust the number. */
export function ScoreBreakdownTable({
  contributions,
  total,
}: {
  contributions: Record<string, number>;
  total: number;
}) {
  const entries = Object.entries(contributions).filter(([, v]) => v > 0);
  const max = Math.max(...entries.map(([, v]) => v), 1);
  return (
    <div>
      {entries.map(([name, value]) => (
        <div
          key={name}
          className="spread"
          style={{ marginBottom: 7, fontSize: 13 }}
        >
          <span className="muted" style={{ minWidth: 175 }}>
            {titleCase(name)}
          </span>
          <div className="bar" style={{ flex: 1, margin: "0 12px" }}>
            <div
              className="bar-fill"
              style={{ width: `${(value / max) * 100}%`, background: "#4f9cf9" }}
            />
          </div>
          <span className="mono" style={{ minWidth: 42, textAlign: "right" }}>
            +{value.toFixed(1)}
          </span>
        </div>
      ))}
      <div
        className="spread"
        style={{
          borderTop: "1px solid var(--border)",
          paddingTop: 9,
          marginTop: 10,
          fontWeight: 600,
        }}
      >
        <span>Waste score</span>
        <span className="mono">{total.toFixed(1)} / 100</span>
      </div>
    </div>
  );
}

export function SavingsCell({ value }: { value: number }) {
  if (value <= 0) {
    return <span className="faint">-</span>;
  }
  return (
    <span style={{ color: "var(--save)", fontWeight: 550 }}>{money(value)}</span>
  );
}

export function EmptyState({
  title,
  hint,
  action,
}: {
  title: string;
  hint?: string;
  action?: React.ReactNode;
}) {
  return (
    <div className="card empty">
      <p style={{ margin: 0, fontWeight: 550 }}>{title}</p>
      {hint ? (
        <p className="faint" style={{ marginTop: 6 }}>
          {hint}
        </p>
      ) : null}
      {action ? <div style={{ marginTop: 14 }}>{action}</div> : null}
    </div>
  );
}

export function ErrorState({ error }: { error: unknown }) {
  const message = error instanceof Error ? error.message : String(error);
  const detail =
    error && typeof error === "object" && "detail" in error
      ? String((error as { detail?: string }).detail ?? "")
      : "";
  return (
    <div className="banner banner-error">
      <div>
        <strong>Could not load this page.</strong>
        <div style={{ marginTop: 4 }}>{message}</div>
        {detail ? (
          <div className="faint" style={{ marginTop: 4 }}>
            {detail}
          </div>
        ) : null}
      </div>
    </div>
  );
}

export function ResourceLink({
  resourceId,
  findingId,
}: {
  resourceId: string;
  findingId?: string;
}) {
  const label = <span className="mono">{resourceId}</span>;
  return findingId ? (
    <Link href={`/findings/${findingId}`} style={{ color: "var(--accent)" }}>
      {label}
    </Link>
  ) : (
    label
  );
}
