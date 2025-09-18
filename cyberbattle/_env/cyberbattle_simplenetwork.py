from ..networks import simple_network
from . import cyberbattle_env


class SimpleNetwork(cyberbattle_env.CyberBattleEnv):

    def __init__(self, **kwargs):
        super().__init__(initial_environment=simple_network.new_environment(), **kwargs)
