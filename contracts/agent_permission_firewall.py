from genlayer import *

class Policy:
    max_spending: int
    allowed_actions: list[str]
    requires_human_review: bool
    version: int


class ActionRequest:
    agent_id: str
    action: str
    amount: int
    status: str


class Decision:
    result: str
    reason: str


class AgentPermissionFirewall(gl.Contract):
    agents: TreeMap[str, str]
    policies: TreeMap[str, Policy]
    actions: TreeMap[str, ActionRequest]
    decisions: TreeMap[str, Decision]

    def __init__(self):
        self.agents = TreeMap()
        self.policies = TreeMap()
        self.actions = TreeMap()
        self.decisions = TreeMap()

    @gl.public.write
    def register_agent(self, agent_id: str, owner: str):
        assert agent_id != ""
        assert owner != ""
        assert agent_id not in self.agents

        self.agents[agent_id] = owner

    @gl.public.write
    def set_policy(self, agent_id: str, policy: Policy):
        assert agent_id in self.agents

        self.policies[agent_id] = policy

    @gl.public.write
    def submit_action(self, action_id: str, action: ActionRequest):
        assert action_id != ""

        self.actions[action_id] = action

    @gl.public.write
    def evaluate_action(self, action_id: str):
        assert action_id in self.actions

        action = self.actions[action_id]
        policy = self.policies[action.agent_id]

        if action.amount > policy.max_spending:
            self.decisions[action_id] = Decision(
                result="REJECTED",
                reason="Exceeds spending limit"
            )
        elif action.action not in policy.allowed_actions:
            self.decisions[action_id] = Decision(
                result="REJECTED",
                reason="Action not allowed by policy"
            )
        else:
            self.decisions[action_id] = Decision(
                result="APPROVED",
                reason="Action matches policy"
            )
