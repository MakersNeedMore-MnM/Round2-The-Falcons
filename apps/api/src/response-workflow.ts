import { randomUUID } from "node:crypto";
import type { ResponseDecisionRequest, ResponseScenario, UserRole } from "@cascadia/contracts";
import type { Clock } from "./store.js";
import { ConflictError, NotFoundError, ValidationError } from "./store.js";

export function applyResponseDecision(
  scenario: ResponseScenario,
  request: ResponseDecisionRequest,
  actorUserId: string,
  actorRole: UserRole,
  clock: Clock,
): ResponseScenario {
  const option = scenario.options.find((item) => item.id === request.optionId);
  if (!option) throw new NotFoundError("Response option does not exist in this scenario.");
  if (!option.eligible) throw new ValidationError("This response option failed policy checks.");
  if (scenario.selectedOptionId && scenario.selectedOptionId !== option.id) throw new ConflictError("A different response option has already been selected.");
  if (scenario.decisions.some((decision) => decision.optionId === option.id && decision.actorUserId === actorUserId)) throw new ConflictError("This operator has already decided on the selected option.");
  if (!option.allowedApprovalRoles.includes(actorRole)) throw Object.assign(new Error("This role cannot approve or reject the selected option."), { statusCode: 403 });
  if (request.decision === "approve" && option.approvalMode !== "operator_approved") throw new ValidationError("This option is recommendation-only and cannot be approved for execution.");
  if (["approved", "rejected"].includes(scenario.status)) throw new ConflictError("The response scenario is already final.");

  const decision = {
    id: randomUUID(), scenarioId: scenario.id, optionId: option.id, actorUserId, actorRole,
    decision: request.decision, comment: request.comment, decidedAt: clock.now().toISOString(),
  } as const;
  const decisions = [...scenario.decisions, decision];
  const optionDecisions = decisions.filter((item) => item.optionId === option.id);
  const rejected = optionDecisions.some((item) => item.decision === "reject");
  const approvals = new Set(optionDecisions.filter((item) => item.decision === "approve").map((item) => item.actorUserId)).size;
  const status = rejected ? "rejected" as const : approvals >= option.requiredApprovals ? "approved" as const : "awaiting_approval" as const;
  return { ...scenario, selectedOptionId: option.id, decisions, status, executionAuthorized: false };
}
