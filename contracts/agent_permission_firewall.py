from genlayer import *


class Policy:
    max_spending: int
    allowed_actions: list[str]
    requires_human_review: bool
    version: int


class AgentIdentity:
    owner: str
    status: str
    created_version: int


class PermissionScope:
    name: str
    enabled: bool
    risk_level: int


class PolicyBinding:
    agent_id: str
    active: bool


class RateLimit:
    max_requests: int
    current_requests: int


class EmergencyControl:
    paused: bool
    reason: str


class ActionRequest:
    agent_id: str
    action: str
    amount: int
    policy_version: int
    scope_id: str


class ActionStatus:
    current: str


class Decision:
    result: str
    reason: str
    requires_review: bool


class HumanApproval:
    action_id: str
    approver: str
    decision: str
    reason: str


class Reviewer:
    role: str


class ReviewerVote:
    action_id: str
    reviewer: str
    result: str
    reason: str


class ConsensusConfig:
    minimum_votes: int


class ExecutionGuard:
    allowed: bool
    reason: str


class ExecutionReceipt:
    action_id: str
    executor: str
    result: str
    proof: str


class AuditEvent:
    action_id: str
    event_type: str
    message: str


class AuditQuery:
    exists: bool
    status: str
    message: str


class SecurityCheck:
    passed: bool
    reason: str

class AgentPermissionFirewall(gl.Contract):

    agents: TreeMap[str, AgentIdentity]

    policies: TreeMap[str, Policy]

    policy_bindings: TreeMap[str, PolicyBinding]

    permission_scopes: TreeMap[str, PermissionScope]


    rate_limits: TreeMap[str, RateLimit]


    actions: TreeMap[str, ActionRequest]

    action_status: TreeMap[str, ActionStatus]


    decisions: TreeMap[str, Decision]


    human_approvals: TreeMap[str, HumanApproval]


    reviewers: TreeMap[str, Reviewer]

    votes: TreeMap[str, ReviewerVote]

    consensus: ConsensusConfig


    execution_checks: TreeMap[str, ExecutionGuard]

    execution_receipts: TreeMap[str, ExecutionReceipt]


    audit_events: TreeMap[str, AuditEvent]

    audit_queries: TreeMap[str, AuditQuery]


    security_checks: TreeMap[str, SecurityCheck]


    emergency: EmergencyControl

    def __init__(self):

        self.agents = TreeMap()

        self.policies = TreeMap()

        self.policy_bindings = TreeMap()

        self.permission_scopes = TreeMap()


        self.rate_limits = TreeMap()


        self.actions = TreeMap()

        self.action_status = TreeMap()


        self.decisions = TreeMap()


        self.human_approvals = TreeMap()


        self.reviewers = TreeMap()

        self.votes = TreeMap()


        self.consensus = ConsensusConfig(
            minimum_votes=3
        )


        self.execution_checks = TreeMap()

        self.execution_receipts = TreeMap()


        self.audit_events = TreeMap()

        self.audit_queries = TreeMap()


        self.security_checks = TreeMap()


        self.emergency = EmergencyControl(
            paused=False,
            reason=""
        )

    @gl.public.write
    def register_agent(
        self,
        agent_id: str,
        owner: str
    ):

        assert agent_id != ""

        assert owner != ""

        assert agent_id not in self.agents


        self.agents[agent_id] = AgentIdentity(
            owner=owner,
            status="ACTIVE",
            created_version=1
        )


    @gl.public.write
    def disable_agent(
        self,
        agent_id: str
    ):

        assert agent_id in self.agents


        agent = self.agents[agent_id]

        agent.status = "DISABLED"


        self.agents[agent_id] = agent


    @gl.public.write
    def set_policy(
        self,
        agent_id: str,
        policy: Policy
    ):

        assert agent_id in self.agents


        self.policies[agent_id] = policy


        self.policy_bindings[agent_id] = PolicyBinding(
            agent_id=agent_id,
            active=True
        )


    @gl.public.write
    def disable_policy(
        self,
        agent_id: str
    ):

        assert agent_id in self.policy_bindings


        binding = self.policy_bindings[agent_id]

        binding.active = False


        self.policy_bindings[agent_id] = binding


    @gl.public.write
    def create_scope(
        self,
        scope_id: str,
        name: str,
        risk_level: int
    ):

        assert scope_id != ""

        assert name != ""


        self.permission_scopes[scope_id] = PermissionScope(
            name=name,
            enabled=True,
            risk_level=risk_level
    )

    @gl.public.write
    def set_rate_limit(
        self,
        agent_id: str,
        max_requests: int
    ):

        assert agent_id in self.agents

        assert max_requests > 0


        self.rate_limits[agent_id] = RateLimit(
            max_requests=max_requests,
            current_requests=0
        )


    @gl.public.write
    def pause_system(
        self,
        reason: str
    ):

        assert reason != ""


        self.emergency = EmergencyControl(
            paused=True,
            reason=reason
        )


        self.audit_events["system_pause"] = AuditEvent(
            action_id="SYSTEM",
            event_type="EMERGENCY_PAUSE",
            message=reason
        )


    @gl.public.write
    def resume_system(
        self
    ):

        self.emergency = EmergencyControl(
            paused=False,
            reason=""
        )


        self.audit_events["system_resume"] = AuditEvent(
            action_id="SYSTEM",
            event_type="SYSTEM_RESUMED",
            message="Firewall resumed"
        )
