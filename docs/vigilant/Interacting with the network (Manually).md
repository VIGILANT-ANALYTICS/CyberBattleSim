First step is to setup in a notebook the network:

```python
import sys, logging
import cyberbattle.simulation.model as model
import cyberbattle.simulation.commandcontrol as commandcontrol
import cyberbattle.networks.simple_network as sn
import plotly.offline as plo


plo.init_notebook_mode(connected=True) # type: ignore
logging.basicConfig(stream=sys.stdout, level=logging.INFO, format="%(levelname)s: %(message)s")
%matplotlib inline

network = model.create_network(sn.nodes)
env = model.Environment(network=network, vulnerability_library=dict([]), identifiers=sn.ENV_IDENTIFIERS)

c2 = commandcontrol.CommandControl(env)
dbg = commandcontrol.EnvironmentDebugging(c2)
```

from here all actions are taken using the command and control (c2) variable.

## Running a local attack

```python
c2.run_attack("Starting_Client", "ReadSourceCode_LeakedNode")
```
where "Starting_Client" is the name of the infected machine we want to run the attack on and "ReadSourceCode_LeakedNode" is the name of the vulnerability

## Running a remote attack

```python
c2.run_remote_attack("Backup_Server", "Active_Directory", "Remote_RDP_Exploit")
```
where "Backup_Server" is the name of the already infected machine we want to run the attack from, "Active_Directory" is the target machine and "ReadSourceCode_LeakedNode" is the name of the vulnerability

## Connecting to a machine using credentials
If we got some credentials for a machine using an exploit and now we want to connect to it we will not use an attack (since we have the credentials) but we will use the connect_and_infect function.

```python
backup_server = c2.connect_and_infect(
    source_node_id="Starting_Client",
    target_node_id="Backup_Server",
    credentials="BckUserCreds",
    port_name="SSH"
)
```

## Visualizing the network

### Plot the whole network

```python
env.plot_environment_graph()
```

Using this code we show all the nodes of the network, also the ones not discovered yet

### Plot the discovered network

Using this code we show only the discovered or owned nodes of the network

```python
    dbg.plot_discovered_network()
```

### Print all available attacks

This code prints a table containing all available attacks at that moment, meaning if an attack has [Precondition](Network#Precondition) or is on a node that is not yet discovered it will not be shown.

```python
    c2.print_all_attacks()
```

### Print all credentials gathered

```python
c2.credentials_gathered_so_far
```
