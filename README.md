# protovakt

**protovakt** (from "protocol" + "vakt" - guard/watch) - a system for analysis and fuzzing of modern network protocols.

## Description

protovakt is a universal tool for ensuring security, correctness, and performance of modern protocol implementations through deep analysis and automated testing.

## Current Status

### Implemented

- ✅ CLI interface with commands: `analyze`, `fuzz`, `ci`, `plugin`, `config`
- ✅ Basic module architecture (core, analyzer, fuzzer)
- ✅ Basic decoders for TCP, TLS, HTTP
- ✅ Session management system with bidirectional matching
- ✅ State machine engine for protocols
- ✅ Protocol dispatcher for packet routing
- ✅ Configuration file (.protovakt.yml)
- ✅ PCAP file analysis with packet parsing
- ✅ Live capture from network interfaces with BPF filters
- ✅ Statistics collection and findings tracking
- ✅ Report generation (JSON, HTML)
- ✅ Basic fuzzing strategies (structure ready)

### In Development

- ⏳ QUIC/HTTP3 support
- ⏳ gRPC/gRPC-Web analysis
- ⏳ Coverage-guided fuzzing
- ⏳ Performance analysis
- ⏳ Web UI

## Installation

```bash
git clone <repository-url>
cd protovakt
cargo build --release
```

## Usage

### Generate Configuration File

```bash
protovakt config generate
```

### Traffic Analysis

```bash
# Analyze PCAP file
protovakt analyze --input capture.pcap --protocol quic

# Live capture
protovakt analyze --live eth0 --filter "port 443"
```

### Fuzzing

```bash
# Fuzzing with target specification
protovakt fuzz --target tcp://server:443 --protocol grpc --duration 1h

# Fuzzing with corpus
protovakt fuzz --target tcp://server:443 --protocol http3 --corpus ./traffic/ --strategy mutation
```

### CI/CD Mode

```bash
protovakt ci --fail-on critical --output sarif
```

### Plugin Management

```bash
# Install plugin
protovakt plugin install quic-analyzer

# List plugins
protovakt plugin list

# Remove plugin
protovakt plugin remove quic-analyzer
```

### Configuration

```bash
# Validate configuration
protovakt config validate

# Show current configuration
protovakt config show

# Generate example
protovakt config generate
```

## Configuration

Configuration file `.protovakt.yml`:

```yaml
version: "1.0"

general:
  log_level: "info"
  output_dir: "./reports"
  temp_dir: "/tmp/protovakt"

analysis:
  enabled_protocols: ["quic", "http3", "grpc"]
  compliance:
    rfc_strict: true
    security_checks: true
  performance:
    metrics: ["throughput", "latency", "jitter"]

fuzzing:
  targets:
    - name: "production-api"
      endpoint: "tcp://api.example.com:443"
      protocol: "grpc"
  
  strategies:
    - type: "stateful"
      max_depth: 15
    - type: "mutation"
      corpus: ["./traffic/*.pcap"]
  
  limits:
    duration: "8h"
    memory_mb: 4096
    requests_per_sec: 1000
    cpu_cores: 4

reporting:
  formats: ["json", "html", "pdf"]
  notifications:
    slack:
      webhook: ${SLACK_WEBHOOK}

ci:
  quality_gates:
    security_critical: 0
    security_high: 5
    coverage_min: 0.85
    performance_regression: 0.10
```

## Supported Protocols

| Protocol | Status | Versions | Features |
|----------|--------|----------|----------|
| TCP | ✅ | - | Basic header analysis |
| TLS | ✅ | 1.0-1.3 | Version checking, security checks |
| HTTP | ✅ | 1.0-2.0 | Request/response analysis |
| QUIC | ⏳ | draft-29, RFC 9000-9002 | In development |
| HTTP/3 | ⏳ | RFC 9114 | In development |
| gRPC/gRPC-Web | ⏳ | v1.0+ | In development |
| WebTransport | ⏳ | draft-ietf-webtrans-http3 | In development |
| MQTT 5.0 | ⏳ | v5.0 | In development |
| Kafka Protocol | ⏳ | v2.0+ | In development |

## Development

### Building

```bash
# Debug build
cargo build

# Release build
cargo build --release

# Run tests
cargo test

# Check code
cargo check
```

## Contributing

The project is under active development. Contributions are welcome!

## Links

- [RFC 9000: QUIC](https://www.rfc-editor.org/rfc/rfc9000.html)
- [RFC 9114: HTTP/3](https://www.rfc-editor.org/rfc/rfc9114.html)
- [gRPC Protocol](https://grpc.io/docs/what-is-grpc/core-concepts/)