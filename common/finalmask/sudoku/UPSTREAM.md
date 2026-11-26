# Xray Sudoku provenance

Upstream: https://github.com/XTLS/Xray-core/tree/676eaf66f8f05d4d558ee7a74b4736623d3feeb9/transport/internet/finalmask/sudoku (v26.11.9), MPL-2.0. The original upstream LICENSE is retained as LICENSE.MPL-2.0 in this directory. The files table.go, codec.go and packed.go contain adapted upstream source; retain their notices.

Adaptations: replaced generated protobuf settings with a local configuration, removed unbounded caches, shared group-to-grid index and clue arrays across layouts/passwords, transformed clues at encode/decode boundaries, and separated the packed codec from upstream connection constructors. New bounded directional net.Conn adapter and tests are local. No upstream source license change is asserted. Distribution remains subject to MPL and repository GPL terms as applicable.

Wire compatibility is the intent; current tests are not a substitute for an actual pinned Xray peer. Mobile memory/CPU measurements are still required.

UDP adapter adapted from upstream conn_udp.go; connected socket, bounded buffers and explicit write errors. Original codec retained.
