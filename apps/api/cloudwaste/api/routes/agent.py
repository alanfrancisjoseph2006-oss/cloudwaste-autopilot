"""Agent endpoints: chat, investigate, explain."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from ...agent.prompts import EXPLAIN_PROMPT, INVESTIGATE_PROMPT
from ...agent.runtime import CloudWasteAgent
from ...models.domain import Account
from ...services import CloudWasteService
from ..deps import default_account, service

router = APIRouter()


def _agent(svc: CloudWasteService, account: Account) -> CloudWasteAgent:
    return CloudWasteAgent(svc, account, svc.settings)


class ChatRequest(BaseModel):
    message: str = Field(min_length=1)
    history: list[dict] | None = Field(
        default=None,
        description="Prior Bedrock Converse messages, for a multi-turn conversation.",
    )


@router.post("/agent/chat", tags=["agent"])
def chat(
    payload: ChatRequest,
    account: Account = Depends(default_account),
    svc: CloudWasteService = Depends(service),
):
    response = _agent(svc, account).chat(payload.message, payload.history)
    return response.to_dict()


class InvestigateRequest(BaseModel):
    resource_id: str


@router.post("/agent/investigate", tags=["agent"])
def investigate(
    payload: InvestigateRequest,
    account: Account = Depends(default_account),
    svc: CloudWasteService = Depends(service),
):
    if svc.repos.resources.get(payload.resource_id) is None:
        raise HTTPException(
            404,
            f"Resource {payload.resource_id} is not in the inventory. "
            f"Run POST /findings/scan first.",
        )
    response = _agent(svc, account).chat(
        INVESTIGATE_PROMPT.format(resource_id=payload.resource_id)
    )
    return response.to_dict()


class ExplainRequest(BaseModel):
    finding_id: str


@router.post("/agent/explain", tags=["agent"])
def explain(
    payload: ExplainRequest,
    account: Account = Depends(default_account),
    svc: CloudWasteService = Depends(service),
):
    finding = svc.repos.findings.get(payload.finding_id)
    if finding is None:
        raise HTTPException(404, f"Finding {payload.finding_id} not found")

    agent = _agent(svc, account)
    response = agent.chat(EXPLAIN_PROMPT.format(finding_id=payload.finding_id))
    return {
        **response.to_dict(),
        # The structured evidence travels with the prose so the UI can show
        # both, and so a reader can check the narrative against the sources.
        "finding": finding.model_dump(mode="json"),
        "evidence": [e.model_dump(mode="json") for e in finding.evidence],
        "score_contributions": finding.score_breakdown.as_contributions(),
        "confidence_reasons": finding.confidence_reasons,
    }


@router.get("/agent/tools", tags=["agent"])
def list_tools(
    account: Account = Depends(default_account), svc: CloudWasteService = Depends(service)
):
    """The tool surface, for inspection and for AgentCore registration."""
    agent = _agent(svc, account)
    specs = agent.tool_definitions()
    return {
        "count": len(specs),
        "tools": [
            {
                "name": s["toolSpec"]["name"],
                "description": s["toolSpec"]["description"],
                "input_schema": s["toolSpec"]["inputSchema"]["json"],
                "mutates_aws": False,
            }
            for s in specs
        ],
        "note": (
            "No tool mutates an AWS resource. propose_action creates a pending "
            "action that requires human approval; the agent has no tool that can "
            "approve or execute one."
        ),
    }
