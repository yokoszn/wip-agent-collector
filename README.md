# Linux-First eBPF Endpoint Agent:

#### a) **eBPF Programs (C)**
- ✅ `process_monitor.bpf.c` - Tracks execve, fork, exit
  - Full process tree tracking
  - Command line arguments capture
  - Container detection (cgroup-based)
  - Parent-child relationships

- ✅ `network_monitor.bpf.c` - Monitors network activity
  - TCP/UDP connections (IPv4 & IPv6)
  - DNS query capture
  - Connection state tracking
  - Process correlation

#### b) **Rust Userspace Code**
- ✅ `main.rs` - Agent orchestration
  - Component initialization
  - Event processing loop
  - Signal handling
  - Configuration loading

- ✅ `monitors/process.rs` - Process monitor
  - eBPF program loader (libbpf-rs)
  - Process tree reconstruction
  - Behavioral baseline learning
  - Event enrichment

#### c) **Build System**
- ✅ `Cargo.toml` - All dependencies configured
  - libbpf-rs for eBPF loading
  - Tokio for async runtime
  - Serde for serialization
  - Networking libraries
  - And more...


---

### 4. **Quick Start Guide**
📄 `docs/QUICKSTART.md` (25 pages)

**What's inside:**
- Prerequisites checklist
- Installation instructions (Ubuntu, RHEL, Fedora)
- Configuration examples
- Detection rule templates
- Testing procedures
- Troubleshooting guide
- Systemd service setup
- Performance tuning

---


## 🆘 Getting Help

### Documentation
- **Architecture**: `twn-linux-ebpf-agent-architecture.md`
- **Roadmap**: `TWN-IMPLEMENTATION-ROADMAP.md`
- **Quick Start**: `docs/QUICKSTART.md`
- **Code**: Browse `twn-agent/`

### Resources
- **eBPF Learning**: https://ebpf.io/
- **libbpf**: https://github.com/libbpf/libbpf
- **Rust eBPF**: https://github.com/aya-rs/aya
- **Falco (inspiration)**: https://github.com/falcosecurity/falco

### Community (Future)
- Discord: (to be created)
- Documentation site: (to be created)

---
