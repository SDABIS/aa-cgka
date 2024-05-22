# Attribute-Authenticated Continuous Group Key Agreement

This is a Rust implementation of the Attribute-Authenticated Continuous Group Key Agreement (AA-CGKA) protocol, as specified in [our paper](https://arxiv.org/abs/2405.12042) 

Our implementation builds upon the following libraries:

- [OpenMLS](https://github.com/openmls/openmls): implementation of the Messaging Layer Security (MLS) protocol, as specified in [RFC 9420](https://datatracker.ietf.org/doc/html/rfc9420).
- [SSI](https://github.com/spruceid/ssi): implementation of Self-Sovereign Identity (SSI) protocols, including W3C's Verifiable Credentials and Decentralized Identifiers (DIDs). We use the branch "feat/bbs-sig-2" for its BBS+ signature support. 

# Examples

The ["main" file](openmls/src/main.rs) contains an example of how to use the AA-CGKA protocol.

A more advanced simulation is available with the crates ["delivery-service"](delivery-service) and ["cli"](cli). Respectively, they provide an implementation for a web server that distributes protocol messages and a program for simulating a number of clients with different credential types.
