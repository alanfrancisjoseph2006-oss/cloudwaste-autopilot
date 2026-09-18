import Link from "next/link";
import { api, money, percent } from "@/lib/api";
import { EmptyState, ErrorState, RiskBadge, SavingsCell } from "@/components/ui";

export const dynamic = "force-dynamic";

export default async function RecommendationsPage() {
  let data;
  try {
    data = await api.recommendations("?limit=200");
  } catch (error) {
    return <ErrorState error={error} />;
  }

  const reversible = data.recommendations.filter((r) => r.rollback_possible).length;
  const noRestart = data.recommendations.filter((r) => !r.restart_required).length;

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Recommendations</h1>
          <p className="subtitle">
            {data.count} proposed changes worth{" "}
            {money(data.total_monthly_savings, 0)}/month &middot; {reversible}{" "}
            reversible &middot; {noRestart} need no restart
          </p>
        </div>
      </div>

      {data.count === 0 ? (
        <EmptyState
          title="No recommendations yet."
          hint="Run a scan from the dashboard. Note that some findings deliberately produce no recommendation."
        />
      ) : (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Resource</th>
                <th>Action</th>
                <th>Change</th>
                <th className="num">Savings / mo</th>
                <th className="num">Savings / yr</th>
                <th>Risk</th>
                <th>Restart</th>
                <th>Rollback</th>
              </tr>
            </thead>
            <tbody>
              {data.recommendations.map((recommendation) => (
                <tr key={recommendation.recommendation_id}>
                  <td>
                    <Link
                      href={`/findings/${recommendation.finding_id}`}
                      style={{ color: "var(--accent)" }}
                    >
                      <span className="mono">{recommendation.resource_id}</span>
                    </Link>
                    <div className="faint">{recommendation.resource_type}</div>
                  </td>
                  <td>
                    <span className="badge badge-neutral mono">
                      {recommendation.action_type}
                    </span>
                  </td>
                  <td className="mono muted" style={{ fontSize: 12 }}>
                    {recommendation.current_configuration}
                    <br />
                    <span style={{ color: "var(--accent)" }}>
                      &rarr; {recommendation.recommended_configuration}
                    </span>
                  </td>
                  <td className="num">
                    <SavingsCell value={recommendation.monthly_savings} />
                  </td>
                  <td className="num mono muted">
                    {recommendation.annual_savings > 0
                      ? money(recommendation.annual_savings, 0)
                      : "-"}
                  </td>
                  <td>
                    <RiskBadge risk={recommendation.risk} />
                  </td>
                  <td>
                    {recommendation.restart_required ? (
                      <span className="badge badge-medium">Yes</span>
                    ) : (
                      <span className="faint">No</span>
                    )}
                  </td>
                  <td>
                    {recommendation.rollback_possible ? (
                      <span className="faint">Yes</span>
                    ) : (
                      <span className="badge badge-critical">None</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <p className="faint" style={{ marginTop: 14 }}>
        Savings are computed by simulating each change against the resource&apos;s
        current cost. Where the cost comes from list pricing rather than observed
        billing, Savings Plan and Reserved Instance coverage will reduce the real
        figure. Open a finding to see the assumptions behind its number.
      </p>
    </>
  );
}
