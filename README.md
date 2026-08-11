# pcap-reader

Homegrown PCAP file decoder from scratch:

Ethernet → IP/ARP (with reassembly) → TCP/UDP → TCP streams.

## Run

One may use nix + direnv, but any Rust toolchain should work:

```bash
cargo run -- path/to/capture.pcap
```

## Layout


| Module      | Role                                 |
| ----------- | ------------------------------------ |
| `pcap`      | Classic PCAP headers & frames        |
| `ethernet`  | Link layer                           |
| `ip`        | IPv4/IPv6 + ARP, fragment reassembly |
| `transport` | TCP/UDP + stream reassembly          |
| `event`     | Stack decoder → printable events     |


`docker-compose.yaml` / `valkey.docker-compose.yaml` spin up sample traffic worth sniffing. Sample captures live under `examples/`.
