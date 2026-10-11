# C++ to Java conversion map

Java does not use C++ header files (`.h`). In C++, the header usually declares a class and its methods while the `.cpp` file contains the method implementations. In this Java version, the class fields and method implementations live together in a `.java` file.

| Original C++ area | Java file |
|---|---|
| `types.h`, `types.cpp` | `model/Config.java`, `model/FiveTuple.java`, `model/PacketJob.java`, `model/PacketAction.java` |
| `pcap_reader.h`, `pcap_reader.cpp` | `pcap/PcapReader.java`, `pcap/PcapWriter.java` |
| `packet_parser.h`, `packet_parser.cpp` | `parser/PacketParser.java` |
| `sni_extractor.h`, `sni_extractor.cpp` | `parser/SniExtractor.java` |
| `connection_tracker.h`, `connection_tracker.cpp` | `connection/ConnectionTracker.java` |
| `dpi_engine.h`, `dpi_engine.cpp` | `core/DPIEngine.java`, `core/DPIStats.java` |
| `rule_manager.h`, `rule_manager.cpp` | `rules/RuleManager.java` |
| `thread_safe_queue.h` | `pipeline/BlockingPacketQueue.java` |
| `fast_path.h`, `fast_path.cpp` | `pipeline/FastPath.java` |
| `load_balancer.h`, `load_balancer.cpp` | `pipeline/LoadBalancer.java` |
| `main*.cpp`, `dpi_mt.cpp` | `Main.java` (one beginner-friendly command-line entry point) |
| shared connection lookup in the engine | `connection/GlobalConnectionTable.java` |

To keep the requested exact source layout, helper types such as connection details and packet-processing callbacks are nested inside the listed classes instead of becoming additional source files. Some advanced behavior has been simplified for clarity; the limitations are listed in `README.md`.
