# Attribute-Authenticated Continuous Group Key Agreement

This is a Rust implementation of the Attribute-Authenticated Continuous Group Key Agreement (AA-CGKA) protocol, as specified in [this paper](https://arxiv.org/abs/2405.12042) 

Our implementation builds upon the following libraries:

- [OpenMLS](https://github.com/openmls/openmls): implementation of the Messaging Layer Security (MLS) protocol, as specified in [RFC 9420](https://datatracker.ietf.org/doc/html/rfc9420).
- [SSI](https://github.com/spruceid/ssi): implementation of Self-Sovereign Identity (SSI) protocols, including W3C's Verifiable Credentials and Decentralized Identifiers (DIDs). We use the branch "feat/bbs-sig-2" for its BBS+ signature support. 

# Execution

We employ the MLS simulation environment from [this work](https://github.com/SDABIS/mls_experimental_analysis) to test our implementation. The simulation environment allows us to run multiple clients, simulating a real-world scenario where clients communicate through a Delivery Service (DS).

This project is divided into 2 folders:
- [*/simulated_client*](./simulated_client): Contains the Rust project for the simulated MLS client and its interaction with the Delivery Services. 
- [*/environment*](./environment): Contains scripts to build and deploy the simulation environment, as well as the configuration files

## Dependencies

- Rust (nightly)
- Docker

## Deployment

- Configure the simulation parameters in */environment/client/Settings.toml*. Each parameter and its possible values are explained in the configuration file. Of particular interest for the AA-CGKA scheme is "credential_type", which can be set to "basic", "sdjwt" or "bbsvc". 
- Build the Docker environment: 
```
cd environment
./build.sh
```
It is necessary to execute the *build.sh* script every time the */environment/client/Settings.toml* configuration file is modified. Otherwise, the changes will not be applied.

- Use the *deploy.sh* script to launch the clients (*-c N*) and/or the server (*-s*).  
    - It is recommended that clients and server are located in different machines.
- To finish the simulation, remove the Docker swarm with the following command:
```
docker service rm mls-client mls-rendezvous
```

## Analysis

Each client generates a log file with its name in the folder *environment/client/logs*. These log files can be analysed and structured into a CSV using the *environment/log_scripts/log_parser.sh* script. Other executables in the same folder help in the creation of plots to visualize the results.

IMPORTANT: the *log_parser.sh* script will read every log file in the folder. Remember to delete the logs of previous executions so that they do not interfere.
