# Security policy

Русская версия: [SECURITY.ru.md](SECURITY.ru.md).

OSTP is used to get around network censorship, so a vulnerability can put users at risk: not only their data, but the fact that they use a tunnel
at all. Please report problems privately so they can be fixed before they are public.

## What counts

- Anything that breaks confidentiality or integrity of the tunnel: decrypting, forging or replaying traffic, weakening the handshake or the keys.
- Anything that lets an observer or an active prober **identify** OSTP traffic or an OSTP server reliably: a constant on the wire, a
  distinguishable answer to probes, a fingerprint in sizes or timing.
- Server problems: authentication bypass in the panel or API, access to other users' traffic, remote crashes, resource exhaustion from
  unauthenticated packets.
- Client problems: traffic leaking outside the tunnel when it should not (DNS, IPv6, kill switch), local privilege escalation through the
  desktop helper.

Bugs without a security impact (a feature not working, a crash you caused yourself with a broken config) go to the normal
[issues](https://github.com/ospab/ostp/issues).

## How to report

Email **gvoprgrg@gmail.com** or write to **[@ospab0](https://t.me/ospab0)** on Telegram. Include:

- the version (`ostp -V`, which includes the channel, or the app's About screen) and platform;
- what an attacker needs (network position, a valid key or not, local access);
- steps or a proof of concept, and what you observed.

Remove access keys, tokens and your own server's address from logs before sending. This is a small project run by one person: expect an
answer within days, not hours. You will be told when the fix ships and credited in the changelog unless you prefer not to be.

## Supported versions

| Version | Fixes |
|---|---|
| 0.5.x (protocol v6) | Yes. |
| 0.4.x and older | No. |

Fixes go into `alpha`, then the next beta and the next stable release. A server updated to 0.5.0 can keep serving 0.4.x clients
for a while (`ostp key legacy on`), but those clients get none of the v6 protections, such as checking the server's key. Update with `ostp update`
or from the [Releases](https://github.com/ospab/ostp/releases) page.
