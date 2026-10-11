# DPI Engine 

## Project structure

```text
dpi-engine-java/
├── src/main/java/
│   ├── model/
│   │   ├── Config.java
│   │   ├── PacketJob.java
│   │   ├── FiveTuple.java
│   │   └── PacketAction.java
│   ├── pcap/
│   │   ├── PcapReader.java
│   │   └── PcapWriter.java
│   ├── parser/
│   │   ├── PacketParser.java
│   │   └── SniExtractor.java
│   ├── connection/
│   │   ├── ConnectionTracker.java
│   │   └── GlobalConnectionTable.java
│   ├── rules/
│   │   └── RuleManager.java
│   ├── pipeline/
│   │   ├── FastPath.java
│   │   ├── LoadBalancer.java
│   │   └── BlockingPacketQueue.java
│   ├── core/
│   │   ├── DPIEngine.java
│   │   └── DPIStats.java
│   └── Main.java
├── samples/test_dpi.pcap
├── pom.xml
├── build.sh / build.bat
└── run.sh / run.bat
```

## What the classes do

- `model`: the configuration and packet data shared between components.
- `pcap`: reads the PCAP header and raw packets, then writes forwarded packets to a new PCAP file.
- `parser`: interprets Ethernet/IPv4/TCP/UDP bytes and extracts TLS SNI, HTTP Host and DNS query names.
- `connection`: remembers basic details about each network flow.
- `rules`: stores IP, application, domain and port blocking rules.
- `pipeline`: uses bounded thread-safe queues, load-balancer threads and fast-path worker threads.
- `core`: starts and joins the pipeline, records statistics and coordinates output.
- `Main.java`: reads command-line arguments and starts processing.

## Build

Install a JDK 17 or newer.

On Windows:

```bat
build.bat
```

On Linux/macOS:

```sh
./build.sh
```

The build creates `target/dpi-engine-java.jar`.

## Run

Windows:

```bat
run.bat samples\test_dpi.pcap samples\filtered.pcap
```

Linux/macOS:

```sh
./run.sh samples/test_dpi.pcap samples/filtered.pcap
```

Or invoke the JAR directly after building:

```sh
java -jar target/dpi-engine-java.jar samples/test_dpi.pcap samples/filtered.pcap
```

## Blocking rules from the command line

```sh
java -jar target/dpi-engine-java.jar input.pcap output.pcap --block-ip=192.0.2.10
java -jar target/dpi-engine-java.jar input.pcap output.pcap --block-domain=example.com
java -jar target/dpi-engine-java.jar input.pcap output.pcap --block-app=Google
java -jar target/dpi-engine-java.jar input.pcap output.pcap --block-port=443
```

You can combine options. A domain rule also matches its subdomains; an IP or port rule matches either side of a packet. To choose the worker count:

```sh
java -jar target/dpi-engine-java.jar input.pcap output.pcap --lbs=2 --workers=2
```

A text rules file can use the same section-based format as the original C++ project:

```text
[BLOCKED_IPS]
192.0.2.10

[BLOCKED_APPS]
Google

[BLOCKED_DOMAINS]
example.com

[BLOCKED_PORTS]
443
```

For convenience, the loader also accepts one `block-type=value` rule per line, such as `block-domain=example.com`. Run it with `--rules=rules.txt`.

## Processing flow

1. `PcapReader` reads one packet from the capture file.
2. `PacketParser` checks the Ethernet, IPv4 and TCP/UDP headers.
3. `DPIEngine` creates a `PacketJob` and sends it to a load balancer using the flow hash.
4. `LoadBalancer` sends the packet to a worker. The same flow direction pair is routed to the same worker.
5. `FastPath` attempts to recognize a hostname/application and checks the blocking rules.
6. `DPIEngine` receives the `FORWARD` or `DROP` result. Forwarded packet bytes are written by one output thread.
7. Worker results enter one output thread. It uses the packet IDs to write forwarded packets in original capture order, skipping packets marked `DROP`.
8. Workers and queues drain before the output file is closed.

## Scope and limitations

- Supports classic PCAP files with Ethernet link-layer headers, IPv4, TCP and UDP. IPv6, VLAN-tagged frames and non-IP traffic are skipped by this simple implementation.
- Packet bytes are not modified. When no rules match, accepted IPv4 TCP/UDP packets are written to the output PCAP.
- TLS SNI extraction works when a complete ClientHello is present in an individual packet payload. TCP stream reassembly is not implemented.
- DNS query names and plaintext HTTP Host headers can be detected from packet payloads.
- QUIC is labelled based on UDP port 443; this beginner version does not decrypt QUIC or extract QUIC SNI.
- This is a teaching implementation, not a production firewall. Real deployments need additional parser hardening, IPv6 support, stream reassembly, queue/backpressure design, extensive tests, and performance/security review.

## Validation performed

The project compiles with `javac --release 17`. The included 77-packet sample was processed successfully: without rules, 77 packets were written to a valid output PCAP; with `--block-app=Google`, the sample run dropped a matching packet and wrote a valid PCAP with 76 packets. These checks validate this included sample, not every possible PCAP variant.
=======
# dpi-engine
>>>>>>> 5191f1ce16ae5c2c9e5f4d830b5fb4b8bc052914
