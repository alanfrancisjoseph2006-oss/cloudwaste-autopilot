"""Agent runtime.

Runs the tool-use loop against Amazon Bedrock. Two deployment shapes are
supported by the same code:

  * **Direct Bedrock** (`bedrock_enabled=true`): this process runs the loop via
    the Converse API.
  * **Bedrock AgentCore**: the same `ToolRegistry` is exposed to a managed
    agent runtime, which drives the loop instead. `tool_definitions()` and
    `invoke_tool()` are the integration points; the safety properties live in
    the tools, not in the loop, so they hold either way.

When Bedrock is unavailable the runtime falls back to a deterministic local
analyst that answers from the same tools. That fallback is not a language model
and does not pretend to be: it recognizes a handful of intents and otherwise
says what it cannot do. It exists so the product demonstrates without model
access, and so tests never depend on a network call.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any

from ..config import Settings, get_settings
from ..models.domain import Account
from .prompts import SYSTEM_PROMPT
from .tools import ToolError, ToolRegistry, build_registry

logger = logging.getLogger(__name__)


@dataclass
class ToolCall:
    name: str
    arguments: dict
    result: Any = None
    error: str | None = None


@dataclass
class AgentResponse:
    text: str
    tool_calls: list[ToolCall] = field(default_factory=list)
    model_id: str | None = None
    stop_reason: str | None = None
    turns: int = 0
    backend: str = "bedrock"

    def to_dict(self) -> dict:
        return {
            "text": self.text,
            "backend": self.backend,
            "model_id": self.model_id,
            "stop_reason": self.stop_reason,
            "turns": self.turns,
            "tool_calls": [
                {
                    "name": c.name,
                    "arguments": c.arguments,
                    "error": c.error,
                    # Results can be large; the UI shows them on demand.
                    "result_preview": _preview(c.result),
                }
                for c in self.tool_calls
            ],
        }


def _preview(value: Any, limit: int = 600) -> str | None:
    if value is None:
        return None
    text = json.dumps(value, default=str)
    return text if len(text) <= limit else text[:limit] + "...(truncated)"


class CloudWasteAgent:
    def __init__(self, service, account: Account, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()
        self.service = service
        self.account = account
        self.registry: ToolRegistry = build_registry(service, account)

    # ------------------------------------------------------------------
    # AgentCore integration points
    # ------------------------------------------------------------------

    def tool_definitions(self) -> list[dict]:
        """Tool specs, for handing to AgentCore or another agent framework."""
        return self.registry.specs()

    def invoke_tool(self, name: str, arguments: dict) -> dict:
        """Single tool invocation, for an external agent runtime."""
        try:
            return {"ok": True, "result": self.registry.call(name, arguments)}
        except ToolError as exc:
            return {"ok": False, "error": str(exc)}
        except Exception as exc:  # noqa: BLE001
            logger.exception("tool %s failed", name)
            return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}

    # ------------------------------------------------------------------

    def chat(self, message: str, history: list[dict] | None = None) -> AgentResponse:
        if not self.settings.bedrock_enabled:
            return LocalAnalyst(self.registry).answer(message)
        try:
            return self._bedrock_chat(message, history)
        except Exception as exc:  # noqa: BLE001
            logger.warning("bedrock unavailable, falling back to local analyst: %s", exc)
            response = LocalAnalyst(self.registry).answer(message)
            response.text = (
                f"_Bedrock was unavailable ({type(exc).__name__}), so this answer "
                f"comes from the local deterministic analyst._\n\n" + response.text
            )
            return response

    # ------------------------------------------------------------------

    def _bedrock_chat(self, message: str, history: list[dict] | None) -> AgentResponse:
        import boto3
        from botocore.config import Config

        client = boto3.client(
            "bedrock-runtime",
            region_name=self.settings.bedrock_region,
            config=Config(retries={"max_attempts": 3, "mode": "adaptive"}),
        )

        messages: list[dict] = list(history or [])
        messages.append({"role": "user", "content": [{"text": message}]})

        collected: list[ToolCall] = []
        stop_reason = None

        for turn in range(self.settings.agent_max_turns):
            response = client.converse(
                modelId=self.settings.bedrock_model_id,
                messages=messages,
                system=[{"text": SYSTEM_PROMPT}],
                inferenceConfig={
                    "maxTokens": self.settings.bedrock_max_tokens,
                    "temperature": 0.2,
                },
                toolConfig={"tools": self.registry.specs()},
            )

            stop_reason = response.get("stopReason")
            output_message = response["output"]["message"]
            messages.append(output_message)

            if stop_reason != "tool_use":
                text = "".join(
                    block.get("text", "") for block in output_message.get("content", [])
                )
                return AgentResponse(
                    text=text.strip(),
                    tool_calls=collected,
                    model_id=self.settings.bedrock_model_id,
                    stop_reason=stop_reason,
                    turns=turn + 1,
                    backend="bedrock",
                )

            tool_results = []
            for block in output_message.get("content", []):
                if "toolUse" not in block:
                    continue
                use = block["toolUse"]
                call = ToolCall(name=use["name"], arguments=use.get("input", {}))
                try:
                    call.result = self.registry.call(call.name, call.arguments)
                    content = [{"json": _jsonable(call.result)}]
                    status = "success"
                except Exception as exc:  # noqa: BLE001
                    call.error = str(exc)
                    # Hand the error back to the model rather than failing the
                    # turn: a wrong resource id should produce a corrected
                    # second attempt, not a stack trace.
                    content = [{"text": f"Error: {exc}"}]
                    status = "error"
                collected.append(call)
                tool_results.append(
                    {
                        "toolResult": {
                            "toolUseId": use["toolUseId"],
                            "content": content,
                            "status": status,
                        }
                    }
                )

            messages.append({"role": "user", "content": tool_results})

        return AgentResponse(
            text=(
                f"I reached the {self.settings.agent_max_turns}-step limit for a "
                f"single question without finishing. The tool results gathered so "
                f"far are attached. Try narrowing the question to one resource."
            ),
            tool_calls=collected,
            model_id=self.settings.bedrock_model_id,
            stop_reason="max_turns",
            turns=self.settings.agent_max_turns,
            backend="bedrock",
        )


def _jsonable(value: Any) -> Any:
    return json.loads(json.dumps(value, default=str))


# --------------------------------------------------------------------------
# Deterministic fallback
# --------------------------------------------------------------------------


class LocalAnalyst:
    """Answers a narrow set of questions from the same tools, with no model.

    This is keyword routing, not understanding, and it says so when it does not
    recognize a question rather than guessing. Its purpose is to keep the
    product demonstrable and the tests hermetic.
    """

    def __init__(self, registry: ToolRegistry) -> None:
        self.registry = registry

    def answer(self, message: str) -> AgentResponse:
        text = message.lower()
        calls: list[ToolCall] = []

        def run(name: str, **arguments):
            call = ToolCall(name=name, arguments=arguments)
            try:
                call.result = self.registry.call(name, arguments)
            except Exception as exc:  # noqa: BLE001
                call.error = str(exc)
            calls.append(call)
            return call.result

        anomaly_words = (
            "anomaly", "anomalies", "spike", "went up", "go up", "going up",
            "gone up", "increase", "increased", "rise", "risen", "jumped",
            "higher", "more expensive",
        )
        if any(word in text for word in anomaly_words):
            body = self._anomalies(run)
        elif any(word in text for word in ("save", "saving", "waste", "finding", "optimi")):
            body = self._savings(run)
        elif any(word in text for word in ("spend", "cost", "bill", "expensive")):
            body = self._spend(run)
        elif any(word in text for word in ("idle", "unused", "underutil")):
            body = self._idle(run)
        else:
            body = (
                "The local analyst handles a narrow set of questions: current "
                "spend, potential savings, idle or underutilized resources, and "
                "cost anomalies. For anything else, enable Bedrock "
                "(`CLOUDWASTE_BEDROCK_ENABLED=true`) so the full agent can "
                "answer.\n\nAvailable tools: "
                + ", ".join(self.registry.names())
            )

        return AgentResponse(
            text=body, tool_calls=calls, backend="local_analyst", turns=1,
            stop_reason="end_turn",
        )

    def _spend(self, run) -> str:
        summary = run("get_cost_summary", days=30)
        if not summary:
            return "Cost data is unavailable for this account."
        lines = [
            f"**${summary['total_cost']:,.2f}** over the last {summary['period_days']} days, "
            f"with **${summary['forecast_next_30_days']:,.2f}** forecast for the next 30.",
            "",
            "Largest services:",
        ]
        for service, amount in list(summary["cost_by_service"].items())[:5]:
            share = amount / summary["total_cost"] * 100 if summary["total_cost"] else 0
            lines.append(f"- {service}: ${amount:,.2f} ({share:.0f}%)")
        lines.append("")
        lines.append("_Source: Cost Explorer, unblended cost._")
        return "\n".join(lines)

    def _savings(self, run) -> str:
        findings = run("list_findings", status="OPEN", limit=8)
        if not findings or not findings["count"]:
            return "No open findings. Run a scan first if the account has not been scanned."

        total = findings["total_potential_monthly_savings"]
        lines = [
            f"**${total:,.2f}/month** (${total * 12:,.2f}/year) across "
            f"{findings['count']} open findings.",
            "",
        ]
        for f in findings["findings"]:
            lines.append(
                f"- **{f['resource_id']}** - {f['waste_type'].replace('_', ' ')}: "
                f"${f['potential_monthly_savings']:,.2f}/month "
                f"(waste {f['waste_score']:.0f}, confidence {f['confidence']:.0f}%, "
                f"risk {f['risk']})"
            )
        low_confidence = [f for f in findings["findings"] if f["confidence"] < 70]
        if low_confidence:
            lines.append("")
            lines.append(
                f"_{len(low_confidence)} of these are below 70% confidence and need "
                f"a human to look at the evidence before acting._"
            )
        return "\n".join(lines)

    def _idle(self, run) -> str:
        findings = run("list_findings", status="OPEN", limit=25)
        if not findings:
            return "No findings available."
        idle = [
            f
            for f in findings["findings"]
            if f["waste_type"] in ("idle_resource", "underutilized_resource")
        ]
        if not idle:
            return "No idle or underutilized resources are currently flagged."
        lines = [f"{len(idle)} idle or underutilized resource(s):", ""]
        for f in idle:
            lines.append(
                f"- **{f['resource_id']}** ({f['resource_type']}): {f['title']} - "
                f"${f['potential_monthly_savings']:,.2f}/month, "
                f"confidence {f['confidence']:.0f}%"
            )
        return "\n".join(lines)

    def _anomalies(self, run) -> str:
        anomalies = run("get_cost_anomalies", days=30)
        comparison = run("compare_cost_periods", window_days=7)
        if not anomalies or not anomalies["count"]:
            lines = ["AWS Cost Anomaly Detection has raised nothing in the last 30 days."]
        else:
            lines = [f"{anomalies['count']} anomaly(ies) in the last 30 days:", ""]
            for a in anomalies["anomalies"]:
                lines.append(
                    f"- **{a['service']}** from {a['start']}: "
                    f"${a['actual_spend']:,.2f} against an expected "
                    f"${a['expected_spend']:,.2f} "
                    f"(+${a['excess']:,.2f}, {a['increase_percent']:+.1f}%)"
                )
                for cause in a["root_causes"][:2]:
                    detail = ", ".join(f"{k}={v}" for k, v in cause.items() if v)
                    lines.append(f"  - AWS attributes this to {detail}")

        if comparison and comparison.get("by_service"):
            lines.append("")
            lines.append("Largest week-over-week movements:")
            for entry in comparison["by_service"][:3]:
                pct = f"{entry['percentage']:+.1f}%" if entry["percentage"] is not None else "n/a"
                lines.append(
                    f"- {entry['service']}: ${entry['previous']:,.2f} to "
                    f"${entry['current']:,.2f} ({pct})"
                )
        lines.append("")
        lines.append(
            "_An anomaly is a deviation from forecast, not proof of waste. "
            "A deployment or genuine traffic growth looks identical._"
        )
        return "\n".join(lines)
