# XMC provenance

Port of Xray-core v26.11.9, commit 676eaf66f8f05d4d558ee7a74b4736623d3feeb9, https://github.com/XTLS/Xray-core/tree/676eaf66f8f05d4d558ee7a74b4736623d3feeb9/transport/internet/finalmask/xmc under MPL-2.0. Original license retained. Client, protocol, stream, padding, derivation, profile and deadline implementation retain notices. Local configuration replaces protobuf types and derives the reference RSA key once per mask, retaining only the public key. Added bounds and terminal handshake failure cleanup. No external dependencies or online profile retrieval.

XMC requires a corresponding configured server. Its inherited RSA-1024/PKCS#1 v1.5 and CFB8 are protocol compatibility mechanisms, not a recommendation for standalone modern encryption. Preserve application end-to-end protection. Actual Xray binary interoperability and mobile performance measurements remain required.

The CFB8 implementation also includes code from Tnze/go-mc at commit 539b4a3a7f030332eb58b8a946116ae7907630d2 (MIT). Its original copyright and license are retained in LICENSE.go-mc.MIT.
