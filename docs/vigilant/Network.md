## Boilerplate
To create a network you start by creating a folder and a python file inside of the cyberbattle folder, in this example 'cyberbattle/networks/simple_network.py'. After that there are some necessary imports to add.

```python
from cyberbattle.simulation import model as m

from cyberbattle.simulation.model import NodeID, NodeInfo, VulnerabilityID, VulnerabilityInfo

from typing import Dict, Iterator, cast, Tuple
```
## Firewall
Next step is to define the default firewall rules that can be applied to a machine, here you can set which protocols are allowed and which are blocked. A firewall rule can have:
- Port name (Ex. "SSH")
- Permission (ALLOW, BLOCK)
- Reason for the block/allow rule

with multiple rules in a firewall configuration they are processed in order, the first one that matches a given port is applied and the rest are ignored.

```python
default_allow_rules = [
    m.FirewallRule("RDP", m.RulePermission.ALLOW),
    m.FirewallRule("SSH", m.RulePermission.ALLOW),
    m.FirewallRule("HTTPS", m.RulePermission.ALLOW),
    m.FirewallRule("HTTP", m.RulePermission.ALLOW, reason="We need it for old web server"),
]
```
## Nodes

The next step is to define the nodes of the network. Each node can have this data:

```python
class NodeInfo:
    """A computer node in the enterprise network"""
    # List of port/protocol the node is listening to
    services: List[ListeningService]
    # List of known vulnerabilities for the node
    vulnerabilities: VulnerabilityLibrary = dataclasses.field(default_factory=dict)
    # Intrinsic value of the node (translates into a reward if the node gets owned)
    value: NodeValue = 0
    # Properties of the nodes, some of which can imply further vulnerabilities
    properties: List[PropertyName] = dataclasses.field(default_factory=list)
    # Fireall configuration of the node
    firewall: FirewallConfiguration = dataclasses.field(default_factory=FirewallConfiguration)
    # Attacker agent installed on the node? (aka the node is 'pwned')
    agent_installed: bool = False
    # Esclation level
    privilege_level: PrivilegeLevel = PrivilegeLevel.NoAccess
    # Can the node be re-imaged by a defender agent?
    reimagable: bool = True
    # Last time the node was reimaged
    last_reimaging: Optional[datetime] = None
    # String displayed when the node gets owned
    owned_string: str = ""
    # Machine status: running or stopped
    status = MachineStatus.Running
    # Relative node weight used to calculate the cost of stopping this machine
    # or its services
    sla_weight: float = 1.0
```

So a node would look like this:

```python
nodes = {
    "Website": m.NodeInfo(
	    # The protocols exposed by the machines, notice how ssh requires to know some credentials
        services=[m.ListeningService("HTTPS"), m.ListeningService("SSH", allowedCredentials=["ReusedMySqlCred-web"])], 
        # Firewall rules, we use the defaults we set at the start for the incoming traffic, but we add some new rules for the outgoing traffic, this is an exaple of privilage escalation
        firewall=m.FirewallConfiguration(incoming=default_allow_rules, outgoing=default_allow_rules + [m.FirewallRule("su", m.RulePermission.ALLOW), m.FirewallRule("sudo", m.RulePermission.ALLOW)]),
        # The reward the attacker agent will get if he owns this machine
        value=100,
        # What is the machine is running
        properties=["MySql", "Ubuntu", "nginx/1.10.3"],
        # Message for when the machine gets owned
        owned_string="FLAG: Login using insecure SSH user/password",
        # Vulnerabilites of the machine
        vulnerabilities=dict(
            ScanPageContent=m.VulnerabilityInfo(
                description="LeakedGitHubProjectUrl: Website page content shows a link to GitHub " "repo",
                type=m.VulnerabilityType.REMOTE,
                outcome=m.LeakedNodesId(["GitHubProject"]),
                reward_string="WEBSITE page content has a link to github -> Github project discovered!",
                cost=1.0,
            ),

            ScanPageSource=m.VulnerabilityInfo(
                description="Website page source contains refrence to browseable " "relative web directory",
                type=m.VulnerabilityType.REMOTE,
                outcome=m.LeakedNodesId(["Website.Directory"]),
                reward_string="Viewing the web page source reveals a URL to a .txt file and directory on the website",
                cost=1.0,
            ),

            CredScanBashHistory=m.VulnerabilityInfo(
                description="bash history leaking creds - FLAG Stealing " "credentials for the monitoring user",
                type=m.VulnerabilityType.LOCAL,
                outcome=m.LeakedCredentials(credentials=[m.CachedCredential(node="Website[user=monitor]", port="SSH", credential="monitorBashCreds")]),
                reward_string="FLAG: SSH history revealed credentials for the monitoring user (monitor)",
                cost=1.0,
            ),

        ),

    ),
}
```

## Vulnerabilities

 To define vulnerabilities we use a dict inside of the machine declaration:

```python
vulnerabilities=dict(
	ScanPageContent=m.VulnerabilityInfo(
		description="LeakedGitHubProjectUrl: Website page content shows a link to GitHub " "repo",
		type=m.VulnerabilityType.REMOTE,
		outcome=m.LeakedNodesId(["GitHubProject"]),
		reward_string="WEBSITE page content has a link to github -> Github project discovered!",
		cost=1.0,
	),
)
```

In this example "ScanPageContent" is the type of vulnerability. Each vulnerability has these informations:

```python
class VulnerabilityInfo(NamedTuple):
    """Definition of a known vulnerability"""
    # an optional description of what the vulnerability is
    description: str
    # type of vulnerability
    type: VulnerabilityType
    # what happens when successfully exploiting the vulnerability
    outcome: VulnerabilityOutcome
    # a boolean expression over a node's properties determining if the
    # vulnerability is present or not
    precondition: Precondition = Precondition("true")
    # rates of success/failure associated with this vulnerability
    rates: Rates = Rates()
    # points to information about the vulnerability
    URL: str = ""
    # some cost associated with exploiting this vulnerability (e.g.
    # brute force more costly than dumping credentials)
    cost: float = 1.0
    # a string displayed when the vulnerability is successfully exploited
    reward_string: str = ""
```

### Vulnerability Type
The possible VulnerabilityType are:
- LOCAL: The attacking agent needs to be in the same machine as the vulnerability for it to be exploited
- REMOTE: The attacker can exploit the vulnerability from another machine connected to this one as long as he knows of the machine's existance
### Precondition
Preconditions are used to say when a vulnerability is available to be used by the attacker, for example, you need a certain privilege level:

```python
vulnerabilities=dict(
	ReadScriptLogs = m.VulnerabilityInfo(
		description="With a root shell the logs of the backup script can be read",
		type=m.VulnerabilityType.LOCAL,
		precondition=m.Precondition(f"privilege_{m.PrivilegeLevel.System}"),
		outcome=m.LeakedNodesId(["Active_Directory"]),
		reward_string="The logs contain information about an Active Directory server"
	)
)
```
