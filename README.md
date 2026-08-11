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

Example output from valkey + cli client echoing some keys.
Each `SET` and `GET` operation creates a new TCP connection, client and server exchange data independently in tcp streams, OS does socket buffering and reassembly for OOO (Out-Of-Order) segments:

```shell
parsed header: PcapHeader { version: Version { major: 2, minor: 4 }, endianess: Little, ts_format: SecondsAndMicroseconds, snapshot_len: 262144, fcs_and_link_type: 1 }
PcapFrame[0]:[2026-08-09 16:06:14.901827 +00, captured=42, original=42]:
	Ethernet: [2e:21:90:ad:4c:ac => ff:ff:ff:ff:ff:ff] proto: Arp
	Arp[172.18.0.2 -> 172.18.0.2] operation: Request, proto: Ipv4
PcapFrame[1]:[2026-08-09 16:06:14.904059 +00, captured=110, original=110]:
	Ethernet: [ce:f0:5e:79:b3:c5 => 33:33:00:00:00:16] proto: Ipv6
	Error: transport proto not supported: ICMPv6
PcapFrame[2]:[2026-08-09 16:06:14.952056 +00, captured=86, original=86]:
	Ethernet: [ce:f0:5e:79:b3:c5 => 33:33:ff:79:b3:c5] proto: Ipv6
	Error: transport proto not supported: ICMPv6
PcapFrame[3]:[2026-08-09 16:06:14.968849 +00, captured=42, original=42]:
	Ethernet: [96:8f:0f:91:70:2f => ff:ff:ff:ff:ff:ff] proto: Arp
	Arp[172.18.0.3 -> 172.18.0.3] operation: Request, proto: Ipv4
PcapFrame[4]:[2026-08-09 16:06:14.979619 +00, captured=42, original=42]:
	Ethernet: [96:8f:0f:91:70:2f => ff:ff:ff:ff:ff:ff] proto: Arp
	Arp[172.18.0.3 -> 172.18.0.2] operation: Request, proto: Ipv4
PcapFrame[5]:[2026-08-09 16:06:14.979633 +00, captured=42, original=42]:
	Ethernet: [2e:21:90:ad:4c:ac => 96:8f:0f:91:70:2f] proto: Arp
	Arp[172.18.0.2 -> 172.18.0.3] operation: Reply, proto: Ipv4
PcapFrame[6]:[2026-08-09 16:06:14.979646 +00, captured=74, original=74]:
	Ethernet: [96:8f:0f:91:70:2f => 2e:21:90:ad:4c:ac] proto: Ipv4
	TCP: stream: opened (forward)
PcapFrame[7]:[2026-08-09 16:06:14.979658 +00, captured=74, original=74]:
	Ethernet: [2e:21:90:ad:4c:ac => 96:8f:0f:91:70:2f] proto: Ipv4
	TCP: stream: opened (reverse)
PcapFrame[8]:[2026-08-09 16:06:14.979666 +00, captured=66, original=66]:
	Ethernet: [96:8f:0f:91:70:2f => 2e:21:90:ad:4c:ac] proto: Ipv4
PcapFrame[9]:[2026-08-09 16:06:14.979696 +00, captured=106, original=106]:
	Ethernet: [96:8f:0f:91:70:2f => 2e:21:90:ad:4c:ac] proto: Ipv4
	TCP: stream: data (forward) len: 40, payload: *3
$3
SET
$8
talker:0
$7
hello-0

PcapFrame[10]:[2026-08-09 16:06:14.979701 +00, captured=66, original=66]:
	Ethernet: [2e:21:90:ad:4c:ac => 96:8f:0f:91:70:2f] proto: Ipv4
PcapFrame[11]:[2026-08-09 16:06:14.979774 +00, captured=71, original=71]:
	Ethernet: [2e:21:90:ad:4c:ac => 96:8f:0f:91:70:2f] proto: Ipv4
	TCP: stream: data (reverse) len: 5, payload: +OK

PcapFrame[12]:[2026-08-09 16:06:14.979782 +00, captured=66, original=66]:
	Ethernet: [96:8f:0f:91:70:2f => 2e:21:90:ad:4c:ac] proto: Ipv4
PcapFrame[13]:[2026-08-09 16:06:14.979851 +00, captured=66, original=66]:
	Ethernet: [96:8f:0f:91:70:2f => 2e:21:90:ad:4c:ac] proto: Ipv4
	TCP: stream: half-closed (forward)
PcapFrame[14]:[2026-08-09 16:06:14.979862 +00, captured=66, original=66]:
	Ethernet: [2e:21:90:ad:4c:ac => 96:8f:0f:91:70:2f] proto: Ipv4
	TCP: stream: half-closed (reverse)
	TCP: stream: closed
PcapFrame[15]:[2026-08-09 16:06:14.97987 +00, captured=66, original=66]:
	Ethernet: [96:8f:0f:91:70:2f => 2e:21:90:ad:4c:ac] proto: Ipv4
PcapFrame[16]:[2026-08-09 16:06:14.980688 +00, captured=74, original=74]:
	Ethernet: [96:8f:0f:91:70:2f => 2e:21:90:ad:4c:ac] proto: Ipv4
	TCP: stream: opened (forward)
PcapFrame[17]:[2026-08-09 16:06:14.980696 +00, captured=74, original=74]:
	Ethernet: [2e:21:90:ad:4c:ac => 96:8f:0f:91:70:2f] proto: Ipv4
	TCP: stream: opened (reverse)
PcapFrame[18]:[2026-08-09 16:06:14.9807 +00, captured=66, original=66]:
	Ethernet: [96:8f:0f:91:70:2f => 2e:21:90:ad:4c:ac] proto: Ipv4
PcapFrame[19]:[2026-08-09 16:06:14.980718 +00, captured=93, original=93]:
	Ethernet: [96:8f:0f:91:70:2f => 2e:21:90:ad:4c:ac] proto: Ipv4
	TCP: stream: data (forward) len: 27, payload: *2
$3
GET
$8
talker:0

PcapFrame[20]:[2026-08-09 16:06:14.980721 +00, captured=66, original=66]:
	Ethernet: [2e:21:90:ad:4c:ac => 96:8f:0f:91:70:2f] proto: Ipv4
PcapFrame[21]:[2026-08-09 16:06:14.980744 +00, captured=79, original=79]:
	Ethernet: [2e:21:90:ad:4c:ac => 96:8f:0f:91:70:2f] proto: Ipv4
	TCP: stream: data (reverse) len: 13, payload: $7
hello-0

PcapFrame[22]:[2026-08-09 16:06:14.980749 +00, captured=66, original=66]:
	Ethernet: [96:8f:0f:91:70:2f => 2e:21:90:ad:4c:ac] proto: Ipv4
PcapFrame[23]:[2026-08-09 16:06:14.980815 +00, captured=66, original=66]:
	Ethernet: [96:8f:0f:91:70:2f => 2e:21:90:ad:4c:ac] proto: Ipv4
	TCP: stream: half-closed (forward)
PcapFrame[24]:[2026-08-09 16:06:14.980824 +00, captured=66, original=66]:
	Ethernet: [2e:21:90:ad:4c:ac => 96:8f:0f:91:70:2f] proto: Ipv4
	TCP: stream: half-closed (reverse)
	TCP: stream: closed
PcapFrame[25]:[2026-08-09 16:06:14.980829 +00, captured=66, original=66]:
	Ethernet: [96:8f:0f:91:70:2f => 2e:21:90:ad:4c:ac] proto: Ipv4
PcapFrame[26]:[2026-08-09 16:06:15.406056 +00, captured=110, original=110]:
	Ethernet: [ce:f0:5e:79:b3:c5 => 33:33:00:00:00:16] proto: Ipv6
	Error: transport proto not supported: ICMPv6
PcapFrame[27]:[2026-08-09 16:06:15.902125 +00, captured=42, original=42]:
	Ethernet: [2e:21:90:ad:4c:ac => ff:ff:ff:ff:ff:ff] proto: Arp
	Arp[172.18.0.2 -> 172.18.0.2] operation: Request, proto: Ipv4
PcapFrame[28]:[2026-08-09 16:06:15.966143 +00, captured=110, original=110]:
	Ethernet: [ce:f0:5e:79:b3:c5 => 33:33:00:00:00:16] proto: Ipv6
	Error: transport proto not supported: ICMPv6
```

Example of UDP DDS traffic between `talker` and `listener` ROS2 nodes.
ROS2 implements custom application-level QoS (at least once, at most once delivery) with UDP transport, splitting payloads by maximum datagram size:

```shell
PcapFrame[0]:[2026-06-07 11:51:47.777815 +00, captured=42, original=42]:
        Ethernet: [8e:25:e4:87:05:a2 => ff:ff:ff:ff:ff:ff] proto: Arp
        Arp[172.19.0.2 -> 172.19.0.2] operation: Request, proto: Ipv4
PcapFrame[1]:[2026-06-07 11:51:47.780014 +00, captured=110, original=110]:
        Ethernet: [76:92:fc:80:d0:11 => 33:33:00:00:00:16] proto: Ipv6
        Error: transport proto not supported: ICMPv6
PcapFrame[2]:[2026-06-07 11:51:47.818034 +00, captured=110, original=110]:
        Ethernet: [76:92:fc:80:d0:11 => 33:33:00:00:00:16] proto: Ipv6
        Error: transport proto not supported: ICMPv6
PcapFrame[3]:[2026-06-07 11:51:48.274641 +00, captured=610, original=610]:
        Ethernet: [8e:25:e4:87:05:a2 => 01:00:5e:7f:00:01] proto: Ipv4
        UDP: [172.19.0.2:52113 -> 239.255.0.1:7400] len: 568, payload: non-utf8: 52:54:50:53:02:03:01:0f:01:0f:3d:ea:1d:00:e7:3e:00:00:00:00:09:01:08:00:54:5b:25:6a:67:15:4a:46:15:05:d8:01:00:00:10:00:00:01:00:c7:00:01:00:c2:00:00:00:00:01:00:00:00:00:03:00:00:15:00:04:00:02:03:00:00:16:00:04:00:01:0f:00:00:00:80:04:00:03:06:01:00:0f:00:04:00:00:00:00:00:50:00:10:00:01:0f:3d:ea:1d:00:e7:3e:00:00:00:00:00:00:01:c1:07:80:04:00:01:00:00:00:03:80:28:00:21:00:00:00:31:63:33:30:31:31:31:66:34:36:65:65:34:64:62:39:61:33:31:65:35:32:33:34:30:35:30:31:35:62:30:62:00:00:00:00:32:00:18:00:01:00:00:00:f2:1c:00:00:00:00:00:00:00:00:00:00:00:00:00:00:ac:13:00:02:31:00:18:00:13:00:00:00:f3:1c:00:00:55:3d:ea:00:00:00:00:00:00:00:00:00:00:00:00:00:31:00:18:00:01:00:00:00:f3:1c:00:00:00:00:00:00:00:00:00:00:00:00:00:00:ac:13:00:02:02:00:08:00:14:00:00:00:00:00:00:00:58:00:04:00:3f:fc:0f:00:62:00:08:00:02:00:00:00:2f:00:00:00:2c:00:10:00:0b:00:00:00:65:6e:63:6c:61:76:65:3d:2f:3b:00:00:59:00:c8:00:04:00:00:00:11:00:00:00:50:41:52:54:49:43:49:50:41:4e:54:5f:54:59:50:45:00:00:00:00:07:00:00:00:53:49:4d:50:4c:45:00:00:1b:00:00:00:66:61:73:74:64:64:73:2e:70:68:79:73:69:63:61:6c:5f:64:61:74:61:2e:68:6f:73:74:00:00:21:00:00:00:31:63:33:30:31:31:31:66:34:36:65:65:34:64:62:39:61:33:31:65:35:32:33:34:30:35:30:31:35:62:30:62:00:00:00:00:1b:00:00:00:66:61:73:74:64:64:73:2e:70:68:79:73:69:63:61:6c:5f:64:61:74:61:2e:75:73:65:72:00:00:05:00:00:00:72:6f:6f:74:00:00:00:00:1e:00:00:00:66:61:73:74:64:64:73:2e:70:68:79:73:69:63:61:6c:5f:64:61:74:61:2e:70:72:6f:63:65:73:73:00:00:00:03:00:00:00:32:39:00:00:01:00:00:00:80:01:38:00:01:00:00:00:e8:1c:00:00:00:00:00:00:00:00:00:00:00:00:00:00:ef:ff:00:01:54:5b:25:6a:c1:52:4e:46:02:00:00:00:00:00:00:00:70:04:00:00:00:00:00:00:00:00:00:00:00:00:00:00
PcapFrame[4]:[2026-06-07 11:51:48.276005 +00, captured=54, original=54]:
        Ethernet: [8e:25:e4:87:05:a2 => 01:00:5e:00:00:16] proto: Ipv4
        Error: transport proto not supported: IGMP
PcapFrame[5]:[2026-06-07 11:51:48.374802 +00, captured=610, original=610]:
        Ethernet: [8e:25:e4:87:05:a2 => 01:00:5e:7f:00:01] proto: Ipv4
        UDP: [172.19.0.2:52113 -> 239.255.0.1:7400] len: 568, payload: non-utf8: 52:54:50:53:02:03:01:0f:01:0f:3d:ea:1d:00:e7:3e:00:00:00:00:09:01:08:00:54:5b:25:6a:67:15:4a:46:15:05:d8:01:00:00:10:00:00:01:00:c7:00:01:00:c2:00:00:00:00:01:00:00:00:00:03:00:00:15:00:04:00:02:03:00:00:16:00:04:00:01:0f:00:00:00:80:04:00:03:06:01:00:0f:00:04:00:00:00:00:00:50:00:10:00:01:0f:3d:ea:1d:00:e7:3e:00:00:00:00:00:00:01:c1:07:80:04:00:01:00:00:00:03:80:28:00:21:00:00:00:31:63:33:30:31:31:31:66:34:36:65:65:34:64:62:39:61:33:31:65:35:32:33:34:30:35:30:31:35:62:30:62:00:00:00:00:32:00:18:00:01:00:00:00:f2:1c:00:00:00:00:00:00:00:00:00:00:00:00:00:00:ac:13:00:02:31:00:18:00:13:00:00:00:f3:1c:00:00:55:3d:ea:00:00:00:00:00:00:00:00:00:00:00:00:00:31:00:18:00:01:00:00:00:f3:1c:00:00:00:00:00:00:00:00:00:00:00:00:00:00:ac:13:00:02:02:00:08:00:14:00:00:00:00:00:00:00:58:00:04:00:3f:fc:0f:00:62:00:08:00:02:00:00:00:2f:00:00:00:2c:00:10:00:0b:00:00:00:65:6e:63:6c:61:76:65:3d:2f:3b:00:00:59:00:c8:00:04:00:00:00:11:00:00:00:50:41:52:54:49:43:49:50:41:4e:54:5f:54:59:50:45:00:00:00:00:07:00:00:00:53:49:4d:50:4c:45:00:00:1b:00:00:00:66:61:73:74:64:64:73:2e:70:68:79:73:69:63:61:6c:5f:64:61:74:61:2e:68:6f:73:74:00:00:21:00:00:00:31:63:33:30:31:31:31:66:34:36:65:65:34:64:62:39:61:33:31:65:35:32:33:34:30:35:30:31:35:62:30:62:00:00:00:00:1b:00:00:00:66:61:73:74:64:64:73:2e:70:68:79:73:69:63:61:6c:5f:64:61:74:61:2e:75:73:65:72:00:00:05:00:00:00:72:6f:6f:74:00:00:00:00:1e:00:00:00:66:61:73:74:64:64:73:2e:70:68:79:73:69:63:61:6c:5f:64:61:74:61:2e:70:72:6f:63:65:73:73:00:00:00:03:00:00:00:32:39:00:00:01:00:00:00:80:01:38:00:01:00:00:00:e8:1c:00:00:00:00:00:00:00:00:00:00:00:00:00:00:ef:ff:00:01:54:5b:25:6a:48:eb:f1:5f:04:00:00:00:00:00:00:00:e0:08:00:00:00:00:00:00:00:00:00:00:00:00:00:00
PcapFrame[6]:[2026-06-07 11:51:48.47484 +00, captured=610, original=610]:
        Ethernet: [8e:25:e4:87:05:a2 => 01:00:5e:7f:00:01] proto: Ipv4
        UDP: [172.19.0.2:52113 -> 239.255.0.1:7400] len: 568, payload: non-utf8: 52:54:50:53:02:03:01:0f:01:0f:3d:ea:1d:00:e7:3e:00:00:00:00:09:01:08:00:54:5b:25:6a:67:15:4a:46:15:05:d8:01:00:00:10:00:00:01:00:c7:00:01:00:c2:00:00:00:00:01:00:00:00:00:03:00:00:15:00:04:00:02:03:00:00:16:00:04:00:01:0f:00:00:00:80:04:00:03:06:01:00:0f:00:04:00:00:00:00:00:50:00:10:00:01:0f:3d:ea:1d:00:e7:3e:00:00:00:00:00:00:01:c1:07:80:04:00:01:00:00:00:03:80:28:00:21:00:00:00:31:63:33:30:31:31:31:66:34:36:65:65:34:64:62:39:61:33:31:65:35:32:33:34:30:35:30:31:35:62:30:62:00:00:00:00:32:00:18:00:01:00:00:00:f2:1c:00:00:00:00:00:00:00:00:00:00:00:00:00:00:ac:13:00:02:31:00:18:00:13:00:00:00:f3:1c:00:00:55:3d:ea:00:00:00:00:00:00:00:00:00:00:00:00:00:31:00:18:00:01:00:00:00:f3:1c:00:00:00:00:00:00:00:00:00:00:00:00:00:00:ac:13:00:02:02:00:08:00:14:00:00:00:00:00:00:00:58:00:04:00:3f:fc:0f:00:62:00:08:00:02:00:00:00:2f:00:00:00:2c:00:10:00:0b:00:00:00:65:6e:63:6c:61:76:65:3d:2f:3b:00:00:59:00:c8:00:04:00:00:00:11:00:00:00:50:41:52:54:49:43:49:50:41:4e:54:5f:54:59:50:45:00:00:00:00:07:00:00:00:53:49:4d:50:4c:45:00:00:1b:00:00:00:66:61:73:74:64:64:73:2e:70:68:79:73:69:63:61:6c:5f:64:61:74:61:2e:68:6f:73:74:00:00:21:00:00:00:31:63:33:30:31:31:31:66:34:36:65:65:34:64:62:39:61:33:31:65:35:32:33:34:30:35:30:31:35:62:30:62:00:00:00:00:1b:00:00:00:66:61:73:74:64:64:73:2e:70:68:79:73:69:63:61:6c:5f:64:61:74:61:2e:75:73:65:72:00:00:05:00:00:00:72:6f:6f:74:00:00:00:00:1e:00:00:00:66:61:73:74:64:64:73:2e:70:68:79:73:69:63:61:6c:5f:64:61:74:61:2e:70:72:6f:63:65:73:73:00:00:00:03:00:00:00:32:39:00:00:01:00:00:00:80:01:38:00:01:00:00:00:e8:1c:00:00:00:00:00:00:00:00:00:00:00:00:00:00:ef:ff:00:01:54:5b:25:6a:f6:42:8e:79:06:00:00:00:00:00:00:00:50:0d:00:00:00:00:00:00:00:00:00:00:00:00:00:00
```
