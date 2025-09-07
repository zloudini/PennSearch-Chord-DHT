# PennSearch: Chord DHT and Distributed Search Engine

This project was developed as part of CIS 553: Networked Systems at the University of Pennsylvania. I worked with a team to design and implement a Chord Distributed Hash Table (DHT) on top of the NS3 simulator, and then extend it with PennSearch, a distributed search layer that supports multi-keyword queries across nodes. The system simulates real peer-to-peer networking, allowing us to test and analyze distributed protocols in a controlled environment.

## Key Contributions
- Implemented the Chord DHT protocol, including consistent hashing, finger table initialization, stabilization, and node join/leave functionality.
- Built PennSearch, a distributed search layer that forwards and aggregates multi-keyword queries across responsible nodes to return complete results.
- Worked with Distance Vector (DV) and Link State (LS) routing protocols in NS3 to compare performance under different topologies.
- Designed simulation scenarios and network topologies to test correctness, scalability, and resilience.

## Tech Stack
- Language: C++
- Simulator: NS3 with the WAF build system
- Concepts: Distributed Hash Tables, Peer-to-Peer Search, Routing Protocols, Consistent Hashing

## Repository Structure
- `contrib/upenn-cis553/` – project code including DV/LS routing, Chord DHT, PennSearch, and helper classes
- `scratch/` – scenarios, topologies, and results used for simulation runs
- `src/` – NS3 source code (unmodified)
- `waf` – build system files

## Building and Running

### Compile
```bash
./waf configure    # first-time setup
chmod u+x waf      # if waf does not have execution permissions
./waf              # build (may take a few minutes)
```

### Run
```bash
./waf --run "simulator-main --routing=<NS3|LS|DV> \
  --scenario=./scratch/scenarios/<SCENARIO_FILE_NAME>.sce \
  --inet-topo=./scratch/topologies/<TOPOLOGY_FILE_NAME>.topo \
  --project=<1|2>"
```

### Examples
Run PennSearch with the m2 scenario and topology:
```bash
./waf --run "simulator-main --routing=NS3 --scenario=./scratch/scenarios/m2.sce --inet-topo=./scratch/topologies/m2.topo --project=2"
```

## Learning Outcomes
This project gave me practical experience in:
- Designing and debugging distributed systems  
- Implementing distributed hash tables and routing protocols in C++  
- Building on top of a network simulator (NS3) and using its build system  
- Evaluating scalability, correctness, and performance in simulated peer-to-peer networks
