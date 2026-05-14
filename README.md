# OSTP (Ospab Stealth Transport Protocol)

OSTP is a high-throughput, robust, and multiplexed transport protocol engineered for secure, distributed industrial telemetry replication and real-time metric synchronization over unreliable, lossy networks. By implementing granular keystream scrambling and adaptive block framing, OSTP ensures absolute structural integrity and uniform entropy across all transmitted grid data, eliminating distinct traffic signatures and protecting assets against unauthorized analysis.

---

## Industrial Architecture

The pipeline utilizes a highly optimized modular framework:
- **ostp-core**: The foundational grid synchronization library hosting core transport primitives, keystream scrambling pipelines, Noise Protocol Framework cryptography, and zero-copy framed processing.
- **ostp**: The consolidated cross-platform node daemon configured either as a telemetry collector (`server`) or relay bridge (`client`).
- **ostp-jni**: Consolidated bindings allowing secure deployment of telemetry nodes across Android-embedded field equipment.

---

## Feature Specification

- **Keystream Scrambling (Entropy Masking)**: Internal packet fields are processed via high-entropy masking derived dynamically per session, ensuring absolute payload uniformity. This makes active traffic fully transparent to statistical network analyzers.
- **Persistent Connection Multiplexing**: Enables high-fidelity continuous data channels, supporting parallel session structures and maintaining state persistence across volatile network interface rotations.
- **Resilient Network Handoff**: Automatically detects and preserves active TCP pipelines when node endpoints experience topological shifts (e.g., cellular to fiber gateways) without interrupting upper-tier protocols.
- **Pre-Shared Cryptographic Handshake**: Employs `Noise_NNpsk0_25519_ChaChaPoly_BLAKE2s` to validate remote nodes, establishing authentic channels instantly with post-quantum grade forward secrecy.
- **Gateway Routing Protocol Support**: Standard dual-mode interfaces for legacy application routing via industrial SOCKS5/HTTP-CONNECT translation models.
- **Static/Adaptive Block Shaping**: Eliminates behavioral data leaks through cryptographically randomized block-alignment schemes to maintain constant channel densities.

---

## Provisioning and Configuration

### Automated Linux Server Deployment (Recommended)

For rapid, interactive provisioning on standard Linux host environments, execute the unified installer via a single terminal command:

```bash
bash <(curl -Ls https://raw.githubusercontent.com/ospab/ostp/master/scripts/install.sh)
```

*This routine autonomously fetches correct binary releases, registers a resilient system daemon, and interactively initializes configuration templates utilizing the binary's native compiler.*

### Manual Node Initialization

The consolidated `ostp` daemon automates node certificate generation and base configuration templating.

**Provision Collector Node (Server):**
```bash
./ostp --init server
```
*This provisions `config.json` bound to an automated listening grid port with randomized secure node validation keys.*

**Provision Relay Node (Client):**
```bash
./ostp --init client
```

### Node Integration Config

Configuration parameters are defined within `config.json` aligned adjacent to the service binary.

#### Telemetry Collector Configuration (`config.json`)
```json
{
  "mode": "server",
  "listen": "0.0.0.0:50000",
  "access_keys": [
    "secure_node_registration_key_here"
  ],
  "debug": false
}
```

#### Relay Bridge Configuration (`config.json`)
```json
{
  "mode": "client",
  "server": "COLLECTOR_ENDPOINT_IP:50000",
  "access_key": "secure_node_registration_key_here",
  "socks5_bind": "127.0.0.1:1088",
  "tun": {
    "enable": false,
    "wintun_path": "./wintun.dll",
    "ipv4_address": "10.1.0.2/24"
  },
  "exclude": {
    "domains": [
      "internal-system.lan",
      "local.lan"
    ],
    "ips": [
      "192.168.1.0/24",
      "10.0.0.0/8"
    ],
    "processes": [
      "local_monitoring.exe"
    ]
  },
  "mux": {
    "enabled": true,
    "sessions": 2
  }
}
```

### Execution Parameters

Initiate telemetry processing by assigning the active configuration target:

```bash
./ostp --config config.json
```

---

## Operation & Reliability Metrics

### Stream Multiplexing (Mux)
> [!IMPORTANT]
> **Parallel multiplexing is fully supported.**
> The pipeline executes parallel handshake processes seamlessly, routing independent stream structures via separate cryptographic tunnels to maximize throughput.

### Exclusion Engines (Bypass Modules)
> [!NOTE]
> Real-time exclusion engines are fully operational. Configured IP subnets, local domains, and internal processes correctly route traffic natively to prevent local loop latencies.

---

## License

OSTP is published under the Business Source License 1.1 (BSL), permitting unrestricted personal, non-commercial, and private utility deployments. This license automatically transitions to the permissive MIT License on May 14, 2030.

For full licensing terms, refer to the accompanying [LICENSE](LICENSE) file or the official repository at [https://github.com/ospab/ostp](https://github.com/ospab/ostp).
