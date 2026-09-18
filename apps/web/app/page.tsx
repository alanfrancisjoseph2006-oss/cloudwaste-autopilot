import Link from "next/link";
import { api, compactMoney, money, percent, titleCase } from "@/lib/api";
import {
  ConfidenceBar,
  EmptyState,
  ErrorState,
  RiskBadge,
  SavingsCell,
  ScoreBar,
  StatCard,
} from "@/components/ui";
import { ScanButton } from "./scan-button";

export const dynamic = "force-dynamic";

export default async function DashboardPage() {
  let dashboard, findings, anomalies;
  try {
    [dashboard, findings, anomalies] = await Promise.all([
      api.dashboard(),
      api.findings("?limit=8"),
      api.anomalies(),
    ]);
  } catch (error) {
    return <ErrorState error={error} />;
  }

  if (dashboard.resources_tracked === 0) {
    return (
      <>
        <div className="page-head">
          <div>
            <h1>Dashboard</h1>
            <p className="subtitle">Account {dashboard.account_id}</p>
          </div>
        </div>
        <EmptyState
          title="This account has not been scanned yet."
          hint="A scan reads cost, inventory, utilization, AWS recommendations and CloudTrail, then produces findings."
          action={<ScanButton />}
        />
      </>
    );
  }

  const wasteShare =
    dashboard.monthly_spend > 0
      ? (dashboard.potential_monthly_savings / dashboard.monthly_spend) * 100
      : 0;

  const topServices = Object.entries(dashboard.cost_by_service).slice(0, 6);
  const maxService = Math.max(...topServices.map(([, v]) => v), 1);

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Dashboard</h1>
          <p className="subtitle">
            Account {dashboard.account_id} &middot;{" "}
            {dashboard.resources_tracked} resources tracked
          </p>
        </div>
        <ScanButton />
      </div>

      {dashboard.pending_approvals > 0 ? (
        <div className="banner banner-warn">
          <div>
            <strong>
              {dashboard.pending_approvals} action
              {dashboard.pending_approvals === 1 ? "" : "s"} awaiting approval.
            </strong>{" "}
            <Link href="/actions" style={{ textDecoration: "underline" }}>
              Review them
            </Link>{" "}
            &mdash; approvals expire, and an expired approval has to be sought again.
          </div>
        </div>
      ) : null}

      <div className="grid grid-4" style={{ marginBottom: 18 }}>
        <StatCard
          label="Monthly spend"
          value={money(dashboard.monthly_spend, 0)}
          sub={`${money(dashboard.forecast_next_30_days, 0)} forecast next 30 days`}
        />
        <StatCard
          label="Potential savings"
          value={money(dashboard.potential_monthly_savings, 0)}
          sub={`${money(dashboard.potential_annual_savings, 0)} per year`}
          tone="save"
        />
        <StatCard
          label="Waste score"
          value={`${dashboard.waste_score}`}
          sub={`${percent(wasteShare)} of spend is under an open finding`}
        />
        <StatCard
          label="Active findings"
          value={`${dashboard.active_findings}`}
          sub={
            dashboard.realized_monthly_savings > 0
              ? `${money(dashboard.realized_monthly_savings, 0)}/mo already realized`
              : "None remediated yet"
          }
        />
      </div>

      <div className="grid grid-2" style={{ marginBottom: 18 }}>
        <div className="card">
          <h3>Spend by service</h3>
          {topServices.map(([service, amount]) => (
            <div key={service} style={{ marginBottom: 9 }}>
              <div className="spread" style={{ fontSize: 13, marginBottom: 4 }}>
                <span className="muted">{service}</span>
                <span className="mono">{compactMoney(amount)}</span>
              </div>
              <div className="bar">
                <div
                  className="bar-fill"
                  style={{
                    width: `${(amount / maxService) * 100}%`,
                    background: "#4f9cf9",
                  }}
                />
              </div>
            </div>
          ))}
        </div>

        <div className="card">
          <h3>Waste by category</h3>
          {Object.entries(dashboard.findings_by_type)
            .sort((a, b) => b[1].monthly_savings - a[1].monthly_savings)
            .map(([type, bucket]) => (
              <div
                key={type}
                className="spread"
                style={{ marginBottom: 8, fontSize: 13 }}
              >
                <span className="muted">{titleCase(type)}</span>
                <span className="row">
                  <span className="faint">{bucket.count}</span>
                  <SavingsCell value={bucket.monthly_savings} />
                </span>
              </div>
            ))}
          {anomalies.count > 0 ? (
            <div
              style={{
                marginTop: 12,
                paddingTop: 11,
                borderTop: "1px solid var(--border)",
              }}
            >
              <h3 style={{ marginBottom: 6 }}>Cost anomalies</h3>
              {anomalies.anomalies.map((anomaly) => (
                <div key={anomaly.anomaly_id} style={{ fontSize: 13 }}>
                  <strong>{anomaly.service}</strong>{" "}
                  <span style={{ color: "var(--risk-high)" }}>
                    +{percent(anomaly.increase_percent, 1)}
                  </span>{" "}
                  <span className="faint">
                    ({money(anomaly.excess)} above forecast since{" "}
                    {anomaly.start.slice(0, 10)})
                  </span>
                </div>
              ))}
              <p className="faint" style={{ marginTop: 6 }}>
                A deviation from forecast, not proof of waste. Carries no
                automatic remediation.
              </p>
            </div>
          ) : null}
        </div>
      </div>

      <div className="spread" style={{ marginBottom: 12 }}>
        <h2 style={{ margin: 0 }}>Largest findings</h2>
        <Link href="/findings" style={{ color: "var(--accent)", fontSize: 13 }}>
          All {findings.count} findings &rarr;
        </Link>
      </div>

      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Resource</th>
              <th>Waste type</th>
              <th style={{ width: 110 }}>Score</th>
              <th style={{ width: 120 }}>Confidence</th>
              <th className="num">Monthly cost</th>
              <th className="num">Savings</th>
              <th>Risk</th>
            </tr>
          </thead>
          <tbody>
            {findings.findings.map((finding) => (
              <tr key={finding.finding_id}>
                <td>
                  <Link
                    href={`/findings/${finding.finding_id}`}
                    style={{ color: "var(--accent)" }}
                  >
                    <span className="mono">{finding.resource_id}</span>
                  </Link>
                  <div className="faint">{finding.resource_type}</div>
                </td>
                <td className="muted">{titleCase(finding.waste_type)}</td>
                <td>
                  <ScoreBar value={finding.waste_score} />
                </td>
                <td>
                  <ConfidenceBar value={finding.confidence} />
                </td>
                <td className="num mono">{money(finding.monthly_cost)}</td>
                <td className="num">
                  <SavingsCell value={finding.potential_monthly_savings} />
                </td>
                <td>
                  <RiskBadge risk={finding.risk} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  );
}
