import Link from "next/link";
import { notFound } from "next/navigation";
import { api, money, percent, titleCase } from "@/lib/api";
import {
  ConfidenceBar,
  ErrorState,
  EvidenceList,
  RiskBadge,
  ScoreBar,
  ScoreBreakdownTable,
  StatusBadge,
} from "@/components/ui";
import { ProposeButton } from "./propose-button";
import { ExplainPanel } from "./explain-panel";

export const dynamic = "force-dynamic";

/**
 * The finding detail page is where this product either earns trust or loses it.
 * It leads with the evidence and the arithmetic, not with the recommendation,
 * because the operator's real question is "why should I believe you?" and the
 * answer has to be checkable without leaving the page.
 */
export default async function FindingDetailPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;

  let data;
  try {
    data = await api.finding(id);
  } catch (error) {
    if (error && typeof error === "object" && (error as any).status === 404) {
      notFound();
    }
    return <ErrorState error={error} />;
  }

  const { finding, resource, recommendations, score_contributions } = data;
  const primary = recommendations[0];
  const simulation = primary?.simulation;

  return (
    <>
      <div style={{ marginBottom: 14 }}>
        <Link href="/findings" className="faint">
          &larr; All findings
        </Link>
      </div>

      <div className="page-head">
        <div>
          <h1>{finding.title}</h1>
          <p className="subtitle">
            <span className="mono">{finding.resource_id}</span> &middot;{" "}
            {finding.resource_type} &middot; {finding.region} &middot; detected by{" "}
            {finding.detector}
          </p>
        </div>
        <div className="row">
          <StatusBadge status={finding.status} />
          <RiskBadge risk={finding.risk} />
        </div>
      </div>

      {finding.confidence < 70 ? (
        <div className="banner banner-warn">
          <div>
            <strong>
              Confidence is {percent(finding.confidence)} &mdash; below the 70%
              threshold for acting.
            </strong>
            <div style={{ marginTop: 3 }}>
              This finding may be correct, but the evidence is not strong enough
              to act on without a human reading it. The reasons are listed under
              Confidence below.
            </div>
          </div>
        </div>
      ) : null}

      <div className="grid grid-4" style={{ marginBottom: 18 }}>
        <div className="card">
          <div className="stat-label">Monthly cost</div>
          <div className="stat-value">{money(finding.monthly_cost, 0)}</div>
          <div className="stat-sub">
            {resource?.configuration?.price_source === "cost_explorer"
              ? "Observed billing"
              : "Estimated from list pricing"}
          </div>
        </div>
        <div className="card">
          <div className="stat-label">Potential savings</div>
          <div className="stat-value save">
            {money(finding.potential_monthly_savings, 0)}
          </div>
          <div className="stat-sub">
            {money(finding.potential_monthly_savings * 12, 0)} per year
          </div>
        </div>
        <div className="card">
          <div className="stat-label">Waste score</div>
          <div className="stat-value">{finding.waste_score.toFixed(0)}</div>
          <div className="stat-sub">How much of the spend looks wasted</div>
        </div>
        <div className="card">
          <div className="stat-label">Confidence</div>
          <div className="stat-value">{percent(finding.confidence)}</div>
          <div className="stat-sub">How strong the evidence is</div>
        </div>
      </div>

      <div className="card" style={{ marginBottom: 18 }}>
        <h2>What was detected</h2>
        <p className="muted" style={{ margin: 0 }}>
          {finding.summary}
        </p>
      </div>

      <div className="grid grid-2" style={{ marginBottom: 18 }}>
        <div className="card">
          <h2>Evidence</h2>
          <p className="faint" style={{ marginTop: -6, marginBottom: 12 }}>
            Every claim below names the system it came from.
          </p>
          <EvidenceList evidence={finding.evidence} />
        </div>

        <div className="stack">
          <div className="card">
            <h2>How the score was calculated</h2>
            <ScoreBreakdownTable
              contributions={score_contributions}
              total={finding.waste_score}
            />
          </div>

          <div className="card">
            <h2>Confidence</h2>
            <div style={{ marginBottom: 10 }}>
              <ConfidenceBar value={finding.confidence} />
            </div>
            <ul
              style={{
                margin: 0,
                paddingLeft: 18,
                color: "var(--text-muted)",
                fontSize: 13,
              }}
            >
              {finding.confidence_reasons.map((reason, index) => (
                <li key={index} style={{ marginBottom: 4 }}>
                  {reason}
                </li>
              ))}
            </ul>
          </div>

          {resource ? (
            <div className="card">
              <h2>Resource</h2>
              <dl className="kv">
                <dt>Environment</dt>
                <dd>
                  {resource.environment}
                  {resource.environment === "unknown" ? (
                    <span className="faint">
                      {" "}
                      (untagged, treated as production)
                    </span>
                  ) : null}
                </dd>
                <dt>Owner</dt>
                <dd>{resource.owner ?? <span className="faint">unknown</span>}</dd>
                <dt>Criticality</dt>
                <dd>{resource.criticality}</dd>
                <dt>State</dt>
                <dd>{resource.state ?? "-"}</dd>
                {resource.auto_remediation_allowed === false ? (
                  <>
                    <dt>Auto-remediation</dt>
                    <dd style={{ color: "var(--risk-critical)" }}>
                      Opted out by owner
                    </dd>
                  </>
                ) : null}
              </dl>
              {Object.keys(resource.tags).length > 0 ? (
                <div style={{ marginTop: 12 }}>
                  <h3>Tags</h3>
                  <div className="row" style={{ flexWrap: "wrap", gap: 6 }}>
                    {Object.entries(resource.tags).map(([key, value]) => (
                      <span className="badge badge-neutral mono" key={key}>
                        {key}={value}
                      </span>
                    ))}
                  </div>
                </div>
              ) : null}
            </div>
          ) : null}
        </div>
      </div>

      {primary ? (
        <div className="card" style={{ marginBottom: 18 }}>
          <div className="spread" style={{ marginBottom: 12 }}>
            <h2 style={{ margin: 0 }}>
              Proposed action
              {recommendations.length > 1
                ? ` (${recommendations.length} steps)`
                : ""}
            </h2>
            <RiskBadge risk={primary.risk} />
          </div>

          {recommendations.map((recommendation, index) => (
            <div
              key={recommendation.recommendation_id}
              style={{
                marginBottom: 16,
                paddingBottom: 16,
                borderBottom:
                  index < recommendations.length - 1
                    ? "1px solid var(--border)"
                    : "none",
              }}
            >
              <div className="row" style={{ marginBottom: 8 }}>
                {recommendations.length > 1 ? (
                  <span className="badge badge-neutral">Step {index + 1}</span>
                ) : null}
                <span className="badge badge-neutral mono">
                  {recommendation.action_type}
                </span>
                <span className="mono muted">
                  {recommendation.current_configuration} &rarr;{" "}
                  {recommendation.recommended_configuration}
                </span>
              </div>

              <p className="muted" style={{ marginTop: 0 }}>
                {recommendation.rationale}
              </p>

              {recommendation.simulation ? (
                <>
                  <h3 style={{ marginTop: 14 }}>Simulation</h3>
                  <dl className="kv">
                    <dt>Current cost</dt>
                    <dd>
                      {money(recommendation.simulation.current_monthly_cost)}/mo
                    </dd>
                    <dt>Projected cost</dt>
                    <dd>
                      {money(recommendation.simulation.projected_monthly_cost)}/mo
                    </dd>
                    <dt>Saving</dt>
                    <dd style={{ color: "var(--save)" }}>
                      {money(recommendation.simulation.monthly_savings)}/mo (
                      {money(recommendation.simulation.annual_savings)}/yr,{" "}
                      {percent(recommendation.simulation.savings_percent, 1)})
                    </dd>
                    <dt>Restart required</dt>
                    <dd>{recommendation.simulation.restart_required ? "Yes" : "No"}</dd>
                    <dt>Estimated downtime</dt>
                    <dd>
                      {recommendation.simulation.downtime_estimate_seconds === 0
                        ? "None"
                        : `up to ${recommendation.simulation.downtime_estimate_seconds}s`}
                    </dd>
                    <dt>Rollback</dt>
                    <dd>
                      {recommendation.simulation.rollback_possible ? (
                        <span className="mono">
                          {recommendation.simulation.rollback_method}
                        </span>
                      ) : (
                        <span style={{ color: "var(--risk-critical)" }}>
                          Not possible &mdash; this cannot be undone
                        </span>
                      )}
                    </dd>
                  </dl>

                  <h3 style={{ marginTop: 14 }}>Performance impact</h3>
                  <p className="muted" style={{ margin: 0 }}>
                    {recommendation.simulation.performance_impact}
                  </p>

                  {recommendation.simulation.assumptions.length > 0 ? (
                    <>
                      <h3 style={{ marginTop: 14 }}>Assumptions</h3>
                      <ul
                        style={{
                          margin: 0,
                          paddingLeft: 18,
                          color: "var(--text-muted)",
                          fontSize: 13,
                        }}
                      >
                        {recommendation.simulation.assumptions.map((note, i) => (
                          <li key={i} style={{ marginBottom: 4 }}>
                            {note}
                          </li>
                        ))}
                      </ul>
                    </>
                  ) : null}
                </>
              ) : null}

              <div style={{ marginTop: 14 }}>
                <ProposeButton
                  recommendationId={recommendation.recommendation_id}
                  actionType={recommendation.action_type}
                />
              </div>
            </div>
          ))}
        </div>
      ) : (
        <div className="card" style={{ marginBottom: 18 }}>
          <h2>No automatic action proposed</h2>
          <p className="muted" style={{ margin: 0 }}>
            CloudWaste has not proposed a remediation for this finding. That is
            deliberate: some findings, such as a low-traffic NAT gateway or a
            cost anomaly, do not have a safe generic fix and need a person to
            decide what the right change is. The evidence above is the input to
            that decision.
          </p>
        </div>
      )}

      <ExplainPanel findingId={finding.finding_id} />
    </>
  );
}
