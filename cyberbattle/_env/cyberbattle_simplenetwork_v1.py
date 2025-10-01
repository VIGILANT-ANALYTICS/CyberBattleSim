from ..networks import simple_network_v1
from . import cyberbattle_env


class SimpleNetworkV1(cyberbattle_env.CyberBattleEnv):

    def __init__(self, **kwargs):
        super().__init__(initial_environment=simple_network_v1.new_environment(), **kwargs)
