from cyberbattle.simulation import model as m
from cyberbattle.simulation.model import NodeID, NodeInfo, VulnerabilityID, VulnerabilityInfo
from typing import Dict, Iterator, cast, Tuple

default_allow_rules = [
    m.FirewallRule("RDP", m.RulePermission.ALLOW),
    m.FirewallRule("SSH", m.RulePermission.ALLOW),
]

nodes = {
    "Starting_Client": m.NodeInfo(
        services=[m.ListeningService("SSH")],
        firewall=m.FirewallConfiguration(incoming=default_allow_rules, outgoing=default_allow_rules),
        agent_installed=True,
        reimagable=False,
        properties=["Win11"],
        value=0,
        vulnerabilities=dict(
            ReadSourceCode_LeakedNode = m.VulnerabilityInfo(
                description="Source code of a backup script that reveals the backup server reference",
                type=m.VulnerabilityType.LOCAL,
                outcome=m.LeakedNodesId(["Backup_Server"]),
                reward_string="The source code contains a reference to the backup server"
            ),
            ReadSourceCode_LeakedCreds = m.VulnerabilityInfo(
                description="Source code of a backup script that contains hard-coded credentials",
                type=m.VulnerabilityType.LOCAL,
                outcome=m.LeakedCredentials(credentials=[m.CachedCredential(node="Backup_Server", port="SSH", credential="BckUserCreds")]),
                reward_string="The source code contains hard-coded credentials to the backup server"
            ),
        )
    ),
    "Backup_Server": m.NodeInfo(
        services=[m.ListeningService("SSH", allowedCredentials=["BckUserCreds"])],
        firewall=m.FirewallConfiguration(incoming=default_allow_rules, outgoing=default_allow_rules),
        reimagable=False,
        value=100,
        properties=["LinuxServer"],
        vulnerabilities=dict(
            WritableBackupScript = m.VulnerabilityInfo(
                description="The backup script is writable and executed by root.",
                type=m.VulnerabilityType.LOCAL,
                outcome=m.SystemEscalation(),
                reward_string="Overwrite the world-writable backup script to get a root shell"
            ),
            ReadScriptLogs = m.VulnerabilityInfo(
                description="With a root shell the logs of the backup script can be read",
                type=m.VulnerabilityType.LOCAL,
                precondition=m.Precondition(f"privilege_{m.PrivilegeLevel.System}"),
                outcome=m.LeakedNodesId(["Active_Directory"]),
                reward_string="The logs contain information about an Active Directory server"
            )
        )
    ),
    "Active_Directory": m.NodeInfo(
        services=[m.ListeningService("RDP")],
        firewall=m.FirewallConfiguration(incoming=default_allow_rules, outgoing=default_allow_rules),
        reimagable=False,
        value=500,
        properties=["WindowsServer"],
        vulnerabilities=dict(
            Remote_RDP_Exploit = m.VulnerabilityInfo(
                description=("Using SYSTEM/root privileges on Backup_Server, the attacker can remotely exploit misconfigured RDP on Active_Directory to gain system privilages."),
                type=m.VulnerabilityType.REMOTE,
                outcome=m.SystemEscalation(),
                reward_string="Exploit Active_Directory remotely using Backup_Server root privileges"
            )
        )
    )
}

global_vulnerability_library: Dict[VulnerabilityID, VulnerabilityInfo] = dict([])
print(global_vulnerability_library)
# Environment constants
ENV_IDENTIFIERS = m.infer_constants_from_nodes(cast(Iterator[Tuple[NodeID, NodeInfo]], list(nodes.items())), global_vulnerability_library)

def new_environment() -> m.Environment:
    return m.Environment(network=m.create_network(nodes), vulnerability_library=global_vulnerability_library, identifiers=ENV_IDENTIFIERS)
