# OSTP documentation

Each document exists in English (`en/`) and Russian (`ru/`) with the same content. Installation and a quick start are in the [README](../README.md).

| Topic | English | Русский | What is in it |
|---|---|---|---|
| Client | [client.md](en/client.md) | [client.md](ru/client.md) | Proxy and TUN modes, transports, recovery and roaming, exclusions, multiplexing |
| Server | [server.md](en/server.md) | [server.md](ru/server.md) | Dispatcher, attack mitigation, roaming, management API and web panel, `ostp manage`, server key, key expiry, server info, log privacy, DNS, fallback listener, outbound proxy, WARP, overnet, relay node |
| Domains and TLS | [tls.md](en/tls.md) | [tls.md](ru/tls.md) | TLS on 443, how the server tells connections apart, `ostp cert`, web servers, renewal, subscriptions |
| Protocol specification | [specification.md](en/specification.md) | [specification.md](ru/specification.md) | Wire format, header masking, key derivation and handshake, frames, ARQ, congestion control, roaming; the specification still describes v5, v6 is in the two pages above |
| Protocol v6: handshake | [v6-design.md](en/v6-design.md) | [v6-design.md](ru/v6-design.md) | Implemented in 0.5.0: server key pinning (NKpsk0, `pk=` in links), a handshake that looks random, key derivation, the transitional mode (`accept_v5`); open questions at the end |
| Protocol v6: session layer | [v6-session-design.md](en/v6-session-design.md) | [v6-session-design.md](ru/v6-session-design.md) | Implemented in 0.5.0 after the handshake: per-stream ordering, half-close, UDP without retransmission, session Close with a reason, 16-byte header |
| Carriers (draft, not implemented) | [carriers-design.md](en/carriers-design.md) | [carriers-design.md](ru/carriers-design.md) | Plan only, no code: carrying OSTP inside WebSocket, QUIC/HTTP3, WebRTC, ICMP and HTTPS long-poll: what a carrier is, what censors see, cost, recommended order |
| Cloudflare WARP | [warp-design.md](en/warp-design.md) | [warp-design.md](ru/warp-design.md) | Design of `ostp warp` (implemented): WireGuard in the server with a local SOCKS5 (TCP and UDP) as the server's exit, differences from the plan, what is checked |
| Obfuscation | [obfuscation.md](en/obfuscation.md) | [obfuscation.md](ru/obfuscation.md) | Kerckhoffs's principle (what is public, what is secret), secret derivation, masking, padding, TTL-desync decoys |
| Architecture | [architecture.md](en/architecture.md) | [architecture.md](ru/architecture.md) | How the crates fit together, envelope vs. frame, multiplexing, ARQ, roaming, server subsystems |
| Integrations | [integrations.md](en/integrations.md) | [integrations.md](ru/integrations.md) | Android app and JNI, desktop GUI, first-run screen, installing and managing your own server over SSH, system interfaces |
| Test protocol | [testing.md](en/testing.md) | [testing.md](ru/testing.md) | Checklist run before every beta and stable release |

Also here:

- [CHANGELOG.md](../CHANGELOG.md) / [CHANGELOG.ru.md](../CHANGELOG.ru.md): what changed in each release, also shown by `ostp changelog`.
- [CONTRIBUTING.md](../CONTRIBUTING.md) / [CONTRIBUTING.ru.md](../CONTRIBUTING.ru.md): repository layout, branches, CI on GitHub Actions, releases, how to send changes.
- [SECURITY.md](../SECURITY.md) / [SECURITY.ru.md](../SECURITY.ru.md): supported versions and how to report a vulnerability.
- The [wiki](https://github.com/ospab/ostp/wiki): installation, configuration reference, share links, FAQ.

---

# Документация OSTP

Каждый документ есть на английском (`en/`) и русском (`ru/`) с одинаковым содержанием. Установка и быстрый старт — в [README](../README.ru.md).
Таблица документов выше общая для обоих языков; в ней описано, что есть в каждом документе, и помечено, какие страницы ещё только планы (носители). Кроме неё:

- [CHANGELOG.ru.md](../CHANGELOG.ru.md): что изменилось в каждом выпуске; то же показывает `ostp changelog`.
- [CONTRIBUTING.ru.md](../CONTRIBUTING.ru.md): устройство репозитория, ветки, CI на GitHub Actions, выпуски, как присылать изменения.
- [SECURITY.ru.md](../SECURITY.ru.md): поддерживаемые версии и как сообщить об уязвимости.
- [Wiki](https://github.com/ospab/ostp/wiki): установка, справочник по конфигу, ссылки для подключения, FAQ.
