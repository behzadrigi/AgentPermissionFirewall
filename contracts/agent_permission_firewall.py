from genlayer import *

class Policy:
    max_spending: int
    allowed_actions: str
    requires_human_review: bool
    version: int


class AgentPermissionFirewall(gl.Contract):
    agents: TreeMap[str, str]
    policies: TreeMap[str, Policy]

    def __init__(self):
        self.agents = TreeMap()
        self.policies = TreeMap()

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
