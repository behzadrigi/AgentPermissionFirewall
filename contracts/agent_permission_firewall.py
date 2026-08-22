# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }

from genlayer import *
from dataclasses import dataclass


@allow_storage
@dataclass
class Policy:
    max_spending: u256
    allowed_actions: DynArray[str]
    requires_human_review: bool
    version: u32


@allow_storage
@dataclass
class AgentIdentity:
    owner: Address
    status: str
    created_version: u32


@allow_storage
@dataclass
class PermissionScope:
    name: str
    enabled: bool
    risk_level: u32


@allow_storage
@dataclass
class PolicyBinding:
    agent_id: str
    active: bool


@allow_storage
@dataclass
class RateLimit:
    max_requests: u32
    current_requests: u32


@allow_storage
@dataclass
class EmergencyControl:
    paused: bool
    reason: str


@allow_storage
@dataclass
class ActionRequest:
    agent_id: str
    action: str
    amount: u256
    policy_version: u32
    scope_id: str


@allow_storage
@dataclass
class ActionStatus:
    current: str


@allow_storage
@dataclass
class Decision:
    result: str
    reason: str
    requires_review: bool


@allow_storage
@dataclass
class HumanApproval:
    action_id: str
    approver: Address
    decision: str
    reason: str


@allow_storage
@dataclass
class Reviewer:
    account: Address
    role: str
    active: bool


@allow_storage
@dataclass
class ReviewerVote:
    action_id: str
    reviewer: Address
    result: str
    reason: str


@allow_storage
@dataclass
class ConsensusConfig:
    minimum_votes: u32


@allow_storage
@dataclass
class ExecutionGuard:
    allowed: bool
    reason: str


@allow_storage
@dataclass
class ExecutionReceipt:
    action_id: str
    executor: Address
    result: str
    proof: str


@allow_storage
@dataclass
class AuditEvent:
    action_id: str
    event_type: str
    message: str


@allow_storage
@dataclass
class SecurityCheck:
    passed: bool
    reason: str


class AgentPermissionFirewall(gl.Contract):
    # 01 Admin / authority
    admin: Address

    # 02 Agent identity
    agents: TreeMap[str, AgentIdentity]

    # 03 Policy registry
    policies: TreeMap[str, Policy]

    # 04 Policy binding
    policy_bindings: TreeMap[str, PolicyBinding]

    # 05 Permission scopes
    permission_scopes: TreeMap[str, PermissionScope]

    # 06 Rate limiting
    rate_limits: TreeMap[str, RateLimit]

    # 07 Action registry
    actions: TreeMap[str, ActionRequest]

    # 08 Action lifecycle
    action_status: TreeMap[str, ActionStatus]

    # 09 Risk decisions
    decisions: TreeMap[str, Decision]

    # 10 Human approvals
    human_approvals: TreeMap[str, HumanApproval]

    # 11 Reviewers
    reviewers: TreeMap[str, Reviewer]

    # 12 Reviewer votes
    votes: TreeMap[str, ReviewerVote]

    # 13 Consensus
    consensus: ConsensusConfig

    # 14 Execution guard
    execution_checks: TreeMap[str, ExecutionGuard]

    # 15 Execution receipts
    execution_receipts: TreeMap[str, ExecutionReceipt]

    # 16 Audit events
    audit_events: TreeMap[str, AuditEvent]

    # 17 Security checks
    security_checks: TreeMap[str, SecurityCheck]

    # 18 Emergency control
    emergency: EmergencyControl

    def __init__(self):
        self.admin = gl.message.sender_address

        # TreeMap storage fields are zero-initialized by GenLayer.
        self.consensus = ConsensusConfig(minimum_votes=2)

        self.emergency = EmergencyControl(
            paused=False,
            reason=""
        )

    # --------------------------------------------------
    # 19 AUTHORITY
    # --------------------------------------------------

    def _is_admin(self) -> bool:
        return gl.message.sender_address == self.admin

    def _is_agent_owner(self, agent_id: str) -> bool:
        if agent_id not in self.agents:
            return False
        return self.agents[agent_id].owner == gl.message.sender_address

    def _require_admin(self):
        assert self._is_admin()

    def _require_owner(self, agent_id: str):
        assert self._is_agent_owner(agent_id)

    # --------------------------------------------------
    # 20 AGENT MANAGEMENT
    # --------------------------------------------------

    @gl.public.write
    def register_agent(self, agent_id: str):
        self._require_admin()
        assert agent_id != ""
        assert agent_id not in self.agents

        self.agents[agent_id] = AgentIdentity(
            owner=gl.message.sender_address,
            status="ACTIVE",
            created_version=1
        )

        self.audit_events[agent_id + ":register"] = AuditEvent(
            action_id=agent_id,
            event_type="AGENT_REGISTERED",
            message="Agent registered"
        )

    @gl.public.write
    def disable_agent(self, agent_id: str):
        self._require_admin()
        assert agent_id in self.agents

        agent = self.agents[agent_id]
        agent.status = "DISABLED"
        self.agents[agent_id] = agent

    @gl.public.write
    def enable_agent(self, agent_id: str):
        self._require_admin()
        assert agent_id in self.agents

        agent = self.agents[agent_id]
        agent.status = "ACTIVE"
        self.agents[agent_id] = agent

    # --------------------------------------------------
    # 21 POLICY
    # --------------------------------------------------

    @gl.public.write
    def set_policy(
        self,
        agent_id: str,
        max_spending: u256,
        requires_human_review: bool,
        version: u32
    ):
        self._require_admin()
        assert agent_id in self.agents
        assert version > 0

        actions: DynArray[str] = DynArray()

        self.policies[agent_id] = Policy(
            max_spending=max_spending,
            allowed_actions=actions,
            requires_human_review=requires_human_review,
            version=version
        )

        self.policy_bindings[agent_id] = PolicyBinding(
            agent_id=agent_id,
            active=True
        )

    @gl.public.write
    def add_allowed_action(self, agent_id: str, action: str):
        self._require_admin()
        assert agent_id in self.policies
        assert action != ""

        policy = self.policies[agent_id]
        policy.allowed_actions.append(action)
        self.policies[agent_id] = policy

    @gl.public.write
    def disable_policy(self, agent_id: str):
        self._require_admin()
        assert agent_id in self.policy_bindings

        binding = self.policy_bindings[agent_id]
        binding.active = False
        self.policy_bindings[agent_id] = binding

    @gl.public.write
    def enable_policy(self, agent_id: str):
        self._require_admin()
        assert agent_id in self.policy_bindings

        binding = self.policy_bindings[agent_id]
        binding.active = True
        self.policy_bindings[agent_id] = binding

    # --------------------------------------------------
    # 22 PERMISSION SCOPE
    # --------------------------------------------------

    @gl.public.write
    def create_scope(
        self,
        scope_id: str,
        name: str,
        risk_level: u32
    ):
        self._require_admin()
        assert scope_id != ""
        assert scope_id not in self.permission_scopes
        assert name != ""

        self.permission_scopes[scope_id] = PermissionScope(
            name=name,
            enabled=True,
            risk_level=risk_level
        )

    @gl.public.write
    def disable_scope(self, scope_id: str):
        self._require_admin()
        assert scope_id in self.permission_scopes

        scope = self.permission_scopes[scope_id]
        scope.enabled = False
        self.permission_scopes[scope_id] = scope

    @gl.public.write
    def enable_scope(self, scope_id: str):
        self._require_admin()
        assert scope_id in self.permission_scopes

        scope = self.permission_scopes[scope_id]
        scope.enabled = True
        self.permission_scopes[scope_id] = scope

    # --------------------------------------------------
    # 23 RATE LIMIT
    # --------------------------------------------------

    @gl.public.write
    def set_rate_limit(self, agent_id: str, max_requests: u32):
        self._require_admin()
        assert agent_id in self.agents
        assert max_requests > 0

        self.rate_limits[agent_id] = RateLimit(
            max_requests=max_requests,
            current_requests=0
        )

    @gl.public.write
    def reset_rate_limit(self, agent_id: str):
        self._require_admin()
        assert agent_id in self.rate_limits

        limit = self.rate_limits[agent_id]
        limit.current_requests = 0
        self.rate_limits[agent_id] = limit

    # --------------------------------------------------
    # 24 ACTION SUBMISSION
    # --------------------------------------------------

    @gl.public.write
    def submit_action(
        self,
        action_id: str,
        agent_id: str,
        action: str,
        amount: u256,
        scope_id: str
    ):
        assert not self.emergency.paused
        assert action_id != ""
        assert action_id not in self.actions

        assert agent_id in self.agents
        assert self.agents[agent_id].status == "ACTIVE"

        assert agent_id in self.policies
        assert agent_id in self.policy_bindings
        assert self.policy_bindings[agent_id].active

        assert agent_id in self.rate_limits
        limit = self.rate_limits[agent_id]
        assert limit.current_requests < limit.max_requests

        assert scope_id in self.permission_scopes
        scope = self.permission_scopes[scope_id]
        assert scope.enabled

        policy = self.policies[agent_id]
        assert amount <= policy.max_spending
        assert action != ""

        allowed = False
        for allowed_action in policy.allowed_actions:
            if allowed_action == action:
                allowed = True

        assert allowed

        self.actions[action_id] = ActionRequest(
            agent_id=agent_id,
            action=action,
            amount=amount,
            policy_version=policy.version,
            scope_id=scope_id
        )

        self.action_status[action_id] = ActionStatus(
            current="SUBMITTED"
        )

        limit.current_requests += 1
        self.rate_limits[agent_id] = limit

        self.audit_events[action_id + ":submit"] = AuditEvent(
            action_id=action_id,
            event_type="ACTION_SUBMITTED",
            message="Action submitted"
        )

    # --------------------------------------------------
    # 25 ACTION LIFECYCLE
    # --------------------------------------------------

    @gl.public.write
    def update_action_status(
        self,
        action_id: str,
        new_status: str
    ):
        self._require_admin()
        assert action_id in self.actions
        assert action_id in self.action_status

        current = self.action_status[action_id].current
        valid = False

        if current == "SUBMITTED":
            if new_status == "VALIDATING":
                valid = True
        elif current == "VALIDATING":
            if new_status == "REVIEW":
                valid = True
            elif new_status == "REJECTED":
                valid = True
        elif current == "REVIEW":
            if new_status == "APPROVED":
                valid = True
            elif new_status == "REJECTED":
                valid = True
        elif current == "APPROVED":
            if new_status == "EXECUTED":
                valid = True

        assert valid

        self.action_status[action_id] = ActionStatus(
            current=new_status
        )

    # --------------------------------------------------
    # 26 RISK DECISION
    # --------------------------------------------------

    @gl.public.write
    def evaluate_action(self, action_id: str):
        self._require_admin()
        assert action_id in self.actions

        action = self.actions[action_id]
        assert action.agent_id in self.policies

        policy = self.policies[action.agent_id]
        assert action.policy_version == policy.version

        scope = self.permission_scopes[action.scope_id]

        requires_review = policy.requires_human_review
        if scope.risk_level >= 7:
            requires_review = True

        if requires_review:
            result = "REVIEW_REQUIRED"
            reason = "Human review required"
            next_status = "REVIEW"
        else:
            result = "APPROVED"
            reason = "Policy checks passed"
            next_status = "APPROVED"

        self.decisions[action_id] = Decision(
            result=result,
            reason=reason,
            requires_review=requires_review
        )

        self.action_status[action_id] = ActionStatus(
            current=next_status
        )

    # --------------------------------------------------
    # 27 HUMAN APPROVAL
    # --------------------------------------------------

    @gl.public.write
    def submit_human_approval(
        self,
        action_id: str,
        decision: str,
        reason: str
    ):
        assert action_id in self.actions
        assert action_id in self.decisions
        assert self.action_status[action_id].current == "REVIEW"

        assert decision in ["APPROVED", "REJECTED"]
        assert reason != ""

        self.human_approvals[action_id] = HumanApproval(
            action_id=action_id,
            approver=gl.message.sender_address,
            decision=decision,
            reason=reason
        )

        if decision == "APPROVED":
            self.decisions[action_id] = Decision(
                result="APPROVED",
                reason=reason,
                requires_review=False
            )
            self.action_status[action_id] = ActionStatus(
                current="APPROVED"
            )
        else:
            self.decisions[action_id] = Decision(
                result="REJECTED",
                reason=reason,
                requires_review=False
            )
            self.action_status[action_id] = ActionStatus(
                current="REJECTED"
            )

    # --------------------------------------------------
    # 28 REVIEWER / CONSENSUS
    # --------------------------------------------------

    @gl.public.write
    def register_reviewer(self, reviewer_id: str, role: str):
        self._require_admin()
        assert reviewer_id != ""
        assert reviewer_id not in self.reviewers

        self.reviewers[reviewer_id] = Reviewer(
            account=gl.message.sender_address,
            role=role,
            active=True
        )

    @gl.public.write
    def submit_reviewer_vote(
        self,
        action_id: str,
        reviewer_id: str,
        result: str,
        reason: str
    ):
        assert action_id in self.actions
        assert action_id in self.decisions
        assert reviewer_id in self.reviewers
        assert self.action_status[action_id].current == "REVIEW"

        reviewer = self.reviewers[reviewer_id]
        assert reviewer.active
        assert reviewer.account == gl.message.sender_address

        assert result in ["APPROVE", "REJECT"]
        assert reason != ""

        vote_key = action_id + ":" + reviewer_id
        assert vote_key not in self.votes

        self.votes[vote_key] = ReviewerVote(
            action_id=action_id,
            reviewer=gl.message.sender_address,
            result=result,
            reason=reason
        )

    @gl.public.write
    def evaluate_consensus(self, action_id: str):
        self._require_admin()
        assert action_id in self.actions
        assert self.action_status[action_id].current == "REVIEW"

        approve_count: u32 = 0
        reject_count: u32 = 0

        for reviewer_id in self.reviewers:
            vote_key = action_id + ":" + reviewer_id

            if vote_key in self.votes:
                vote = self.votes[vote_key]

                if vote.result == "APPROVE":
                    approve_count += 1
                elif vote.result == "REJECT":
                    reject_count += 1

        total_votes = approve_count + reject_count
        assert total_votes >= self.consensus.minimum_votes

        if approve_count > reject_count:
            self.decisions[action_id] = Decision(
                result="APPROVED",
                reason="Reviewer consensus approved action",
                requires_review=False
            )
            self.action_status[action_id] = ActionStatus(
                current="APPROVED"
            )
        else:
            self.decisions[action_id] = Decision(
                result="REJECTED",
                reason="Reviewer consensus rejected action",
                requires_review=False
            )
            self.action_status[action_id] = ActionStatus(
                current="REJECTED"
            )

    # --------------------------------------------------
    # 29 EXECUTION GUARD
    # --------------------------------------------------

    @gl.public.write
    def check_execution_guard(self, action_id: str):
        self._require_admin()
        assert action_id in self.actions
        assert action_id in self.decisions

        action = self.actions[action_id]
        agent = self.agents[action.agent_id]
        binding = self.policy_bindings[action.agent_id]
        scope = self.permission_scopes[action.scope_id]
        decision = self.decisions[action_id]

        allowed = True
        reason = "Execution allowed"

        if self.emergency.paused:
            allowed = False
            reason = "Emergency pause active"
        elif agent.status != "ACTIVE":
            allowed = False
            reason = "Agent disabled"
        elif not binding.active:
            allowed = False
            reason = "Policy inactive"
        elif not scope.enabled:
            allowed = False
            reason = "Permission scope disabled"
        elif decision.result != "APPROVED":
            allowed = False
            reason = "Action not approved"

        self.execution_checks[action_id] = ExecutionGuard(
            allowed=allowed,
            reason=reason
        )

    # --------------------------------------------------
    # 30 EXECUTION RECEIPT
    # --------------------------------------------------

    @gl.public.write
    def create_execution_receipt(
        self,
        action_id: str,
        executor: str,
        result: str,
        proof: str
    ):
        self._require_admin()
        assert action_id in self.actions
        assert action_id in self.execution_checks
        assert action_id not in self.execution_receipts

        guard = self.execution_checks[action_id]
        assert guard.allowed
        assert self.action_status[action_id].current == "APPROVED"
        assert executor != ""
        assert result != ""
        assert proof != ""

        self.execution_receipts[action_id] = ExecutionReceipt(
            action_id=action_id,
            executor=Address(executor),
            result=result,
            proof=proof
        )

        self.action_status[action_id] = ActionStatus(
            current="EXECUTED"
        )

        self.audit_events[action_id + ":receipt"] = AuditEvent(
            action_id=action_id,
            event_type="EXECUTION_RECEIPT",
            message=result
        )

    # --------------------------------------------------
    # 31 EMERGENCY / SECURITY / AUDIT
    # --------------------------------------------------

    @gl.public.write
    def pause_system(self, reason: str):
        self._require_admin()
        assert reason != ""

        self.emergency = EmergencyControl(
            paused=True,
            reason=reason
        )

    @gl.public.write
    def resume_system(self):
        self._require_admin()

        self.emergency = EmergencyControl(
            paused=False,
            reason=""
        )

    @gl.public.write
    def security_validate_action(self, action_id: str):
        self._require_admin()
        assert action_id != ""

        if action_id in self.actions:
            self.security_checks[action_id] = SecurityCheck(
                passed=False,
                reason="Duplicate action id"
            )
        else:
            self.security_checks[action_id] = SecurityCheck(
                passed=True,
                reason="Action id available"
            )

    # --------------------------------------------------
    # AUDIT READ METHODS
    # --------------------------------------------------

    @gl.public.view
    def get_action_status(self, action_id: str) -> str:
        if action_id not in self.action_status:
            return "NOT_FOUND"
        return self.action_status[action_id].current

    @gl.public.view
    def get_decision(self, action_id: str) -> str:
        if action_id not in self.decisions:
            return "NOT_FOUND"
        return self.decisions[action_id].result

    @gl.public.view
    def get_execution_result(self, action_id: str) -> str:
        if action_id not in self.execution_receipts:
            return "NO_RECEIPT"
        return self.execution_receipts[action_id].result

    @gl.public.view
    def get_execution_proof(self, action_id: str) -> str:
        if action_id not in self.execution_receipts:
            return ""
        return self.execution_receipts[action_id].proof

    @gl.public.view
    def get_emergency_state(self) -> str:
        if self.emergency.paused:
            return "PAUSED: " + self.emergency.reason
        return "ACTIVE"

    @gl.public.view
    def get_agent_status(self, agent_id: str) -> str:
        if agent_id not in self.agents:
            return "NOT_FOUND"
        return self.agents[agent_id].status
