from genlayer import *

class AgentPermissionFirewall(gl.Contract):
    agents: TreeMap[str, str]

    def __init__(self):
        self.agents = TreeMap()
