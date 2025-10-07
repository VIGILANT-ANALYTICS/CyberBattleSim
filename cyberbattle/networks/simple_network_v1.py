from cyberbattle.simulation import model as m
from cyberbattle.simulation.model import (
    NodeID,
    NodeInfo,
    VulnerabilityID,
    VulnerabilityInfo,
)
from typing import Dict, Iterator, cast, Tuple

default_allow_rules = [
    # m.FirewallRule("RDP", m.RulePermission.ALLOW),
    m.FirewallRule("SSH", m.RulePermission.ALLOW),
]

nodes = {
    "Starting_Client": m.NodeInfo(
        services=[m.ListeningService("SSH")],
        firewall=m.FirewallConfiguration(
            incoming=default_allow_rules, outgoing=default_allow_rules
        ),
        agent_installed=True,
        reimagable=False,
        properties=["Win11"],
        value=0,
        vulnerabilities=dict(
            ReadSourceCode_LeakedNode=m.VulnerabilityInfo(
                description="Source code of a backup script that reveals the backup server reference",
                type=m.VulnerabilityType.LOCAL,
                outcome=m.LeakedNodesId(["Backup_Server"]),
                cost=1,
                reward_string="The source code contains a reference to the backup server",
            ),
            GetBackUpCredentials=m.VulnerabilityInfo(
                description="Attack that gives you backup credentials",
                type=m.VulnerabilityType.LOCAL,
                outcome=m.LeakedCredentials(
                    credentials=[
                        m.CachedCredential(
                            node="Backup_Server", port="SSH", credential="BckUserCreds"
                        )
                    ]
                ),
                cost=2,
                reward_string="You got backup credentials",
            ),
            Trap=m.VulnerabilityInfo(
                description="Just a trap",
                type=m.VulnerabilityType.LOCAL,
                outcome=m.ExploitFailed(),
                cost=10000000000,
                reward_string="You got trapped",
            ),
        ),
    ),
    "Backup_Server": m.NodeInfo(
        services=[m.ListeningService("SSH")],
        firewall=m.FirewallConfiguration(
            incoming=default_allow_rules, outgoing=default_allow_rules
        ),
        reimagable=False,
        value=100,
        properties=["LinuxServer"],
        vulnerabilities=dict(
            Remote=m.VulnerabilityInfo(
                description="Remote",
                type=m.VulnerabilityType.REMOTE,
                outcome=m.SystemEscalation(),
                cost=1,
                reward_string="Remote",
            ),
        ),
    ),
}

global_vulnerability_library: Dict[VulnerabilityID, VulnerabilityInfo] = dict([])
print(global_vulnerability_library)
# Environment constants
ENV_IDENTIFIERS = m.infer_constants_from_nodes(
    cast(Iterator[Tuple[NodeID, NodeInfo]], list(nodes.items())),
    global_vulnerability_library,
)


def new_environment() -> m.Environment:
    return m.Environment(
        network=m.create_network(nodes),
        vulnerability_library=global_vulnerability_library,
        identifiers=ENV_IDENTIFIERS,
    )
