from genlayer import *

class AgentPermissionFirewall(gl.Contract):
    agents: TreeMap[str, str]

    def __init__(self):
        self.agents = TreeMap()

    @gl.public.write
    def register_agent(self, agent_id: str, owner: str):
        self.agents[agent_id] = owner
