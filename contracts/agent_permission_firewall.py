from genlayer import *

class AgentPermissionFirewall(gl.Contract):
    agents: TreeMap[str, str]

    def __init__(self):
        self.agents = TreeMap()

    @gl.public.write
    def register_agent(self, agent_id: str, owner: str):
        assert agent_id != ""
        assert owner != ""
        assert agent_id not in self.agents

        self.agents[agent_id] = owner
