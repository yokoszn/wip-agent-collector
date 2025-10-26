# TWN Platform - Linux-First Implementation Roadmap

## Executive Summary

This roadmap outlines the path to building an open-source endpoint security and remote management platform with feature parity to **Datto RMM + Sophos Endpoint**, starting with **Linux-first using eBPF**.

**Timeline**: 20 weeks (5 months)
**Team Size**: 2-4 developers
**Tech Stack**: Rust + eBPF (kernel), SvelteKit (frontend)

---

## 📅 Phase 1: Core eBPF Agent (Weeks 1-4)

### Week 1: Project Setup & Process Monitoring
**Goal**: Get basic process monitoring working with eBPF

**Tasks**:
- [ ] Set up development environment (Rust + eBPF toolchain)
- [ ] Create project structure
- [ ] Implement `process_monitor.bpf.c` (execve, fork, exit tracepoints)
- [ ] Implement Rust userspace loader using libbpf-rs
- [ ] Build process tree tracking
- [ ] Test on Ubuntu 22.04, Fedora 38

**Deliverables**:
- ✅ Process execution events captured
- ✅ Process tree visualization
- ✅ Basic event logging

**Success Metrics**:
- Can track all process exec/fork/exit events
- < 2% CPU overhead
- < 100MB memory usage

---

### Week 2: Network Monitoring
**Goal**: Capture all network connections and DNS queries

**Tasks**:
- [ ] Implement `network_monitor.bpf.c`:
  - kprobe on tcp_v4_connect, tcp_v6_connect
  - kprobe on udp_sendmsg
  - Socket filter for DNS queries
- [ ] Parse IPv4 and IPv6 addresses
- [ ] Track connection state (established, closed)
- [ ] Correlate network events with processes
- [ ] Test with various protocols (HTTP, HTTPS, SSH, MySQL)

**Deliverables**:
- ✅ All TCP/UDP connections captured
- ✅ DNS queries logged before resolution
- ✅ Network event correlation with processes

**Success Metrics**:
- 100% connection capture rate
- DNS queries captured with < 50ms latency
- No packet loss

---

### Week 3: File System Monitoring
**Goal**: Monitor file operations for threat detection

**Tasks**:
- [ ] Implement `file_monitor.bpf.c`:
  - LSM hooks: file_open, file_permission
  - kprobe on vfs_write, vfs_unlink
- [ ] Track file access patterns
- [ ] Detect suspicious file operations:
  - Execution from /tmp or /dev/shm
  - Mass file modifications (ransomware indicator)
  - Hidden file creation
- [ ] Build file integrity monitoring

**Deliverables**:
- ✅ File open/write/delete events captured
- ✅ Suspicious file operation detection
- ✅ File integrity baseline

**Success Metrics**:
- Can detect execution from suspicious paths
- Detects ransomware-like patterns (50+ files/min)
- < 5% I/O overhead

---

### Week 4: Security Monitoring
**Goal**: Detect privilege escalation and kernel exploits

**Tasks**:
- [ ] Implement `security_monitor.bpf.c`:
  - LSM hooks: capable, kernel_module_request
  - Tracepoint for setuid/setgid
  - Track capability checks (CAP_SYS_ADMIN, etc.)
- [ ] Container detection (cgroup tracking)
- [ ] Kernel module loading alerts
- [ ] Privilege escalation detection

**Deliverables**:
- ✅ Privilege escalation detection
- ✅ Kernel module loading alerts
- ✅ Container awareness

**Success Metrics**:
- Detects all setuid operations
- Detects suspicious capability usage
- Container ID correctly identified

---

## 📅 Phase 2: Detection Engine (Weeks 5-8)

### Week 5: Rule Engine
**Goal**: YARA-style detection rules

**Tasks**:
- [ ] Design rule format (YAML-based)
- [ ] Implement rule parser
- [ ] Build rule matching engine:
  - Process patterns (regex, args matching)
  - Network patterns (IP, port, protocol)
  - File patterns (path, operation type)
  - Composite rules (AND/OR logic)
- [ ] Write 10 initial rules:
  - Crypto miner detection
  - Reverse shell detection
  - Privilege escalation
  - Suspicious file execution
  - Lateral movement

**Deliverables**:
- ✅ Rule engine with 10+ rules
- ✅ Rule hot-reload (no restart needed)
- ✅ Rule testing framework

**Success Metrics**:
- Rules execute in < 100ms
- 0% false negatives on known threats
- < 1% false positives

---

### Week 6: Behavioral Baselines
**Goal**: Learn normal behavior to detect anomalies

**Tasks**:
- [ ] Implement baseline learning:
  - Process baseline (known executables)
  - Network baseline (normal connections per process)
  - File baseline (typical access patterns)
- [ ] Build anomaly detection:
  - Unknown process execution
  - Unusual network connections
  - Unexpected file modifications
- [ ] Baseline persistence (save/load)
- [ ] Baseline visualization

**Deliverables**:
- ✅ 7-day learning period
- ✅ Anomaly detection with confidence scores
- ✅ Baseline dashboard

**Success Metrics**:
- 95% accuracy in detecting anomalies after learning period
- < 5% false positive rate
- Baseline storage < 50MB

---

### Week 7: Threat Intelligence Integration
**Goal**: Enrich detections with threat intel

**Tasks**:
- [ ] Integrate threat intel feeds:
  - AbuseIPDB (malicious IPs)
  - URLhaus (malicious URLs)
  - MalwareBazaar (file hashes)
  - MISP (optional)
- [ ] Implement feed updater (daily)
- [ ] IP/domain/hash lookup
- [ ] Threat score calculation

**Deliverables**:
- ✅ 3+ threat intel feed integrations
- ✅ Real-time threat lookups
- ✅ Threat score in alerts

**Success Metrics**:
- Threat lookups < 10ms
- 99.9% feed availability
- Automatic feed updates

---

### Week 8: Testing & Hardening
**Goal**: Test against MITRE ATT&CK scenarios

**Tasks**:
- [ ] Test against MITRE ATT&CK techniques:
  - T1059: Command execution
  - T1055: Process injection
  - T1071: Application layer protocol
  - T1486: Data encrypted for impact (ransomware)
  - T1496: Resource hijacking (crypto mining)
- [ ] Performance optimization
- [ ] Fix false positives
- [ ] Documentation

**Deliverables**:
- ✅ Detect 20+ MITRE ATT&CK techniques
- ✅ Performance benchmarks
- ✅ Detection documentation

**Success Metrics**:
- 90%+ detection rate on ATT&CK techniques
- < 3% CPU usage under load
- < 250MB memory usage

---

## 📅 Phase 3: Response & Remediation (Weeks 9-12)

### Week 9: Automated Response Actions
**Goal**: Kill processes, quarantine files, block IPs

**Tasks**:
- [ ] Implement response actions:
  - Process termination (SIGTERM, SIGKILL)
  - File quarantine (move to /var/twn/quarantine)
  - Network blocking (iptables/nftables rules)
  - User session termination
- [ ] Action approval workflow (optional human-in-the-loop)
- [ ] Action logging & audit trail
- [ ] Rollback capability

**Deliverables**:
- ✅ 4+ response action types
- ✅ Approval workflow
- ✅ Audit logging

**Success Metrics**:
- Actions execute in < 500ms
- 100% action success rate
- Full audit trail

---

### Week 10: Network Isolation (eBPF)
**Goal**: Quarantine compromised hosts using eBPF

**Tasks**:
- [ ] Implement eBPF-based isolation:
  - Block all outbound connections (except management)
  - Allow inbound SSH/management
  - Per-process isolation
- [ ] Isolation status tracking
- [ ] Auto-release after investigation
- [ ] Isolation testing

**Deliverables**:
- ✅ eBPF network isolation
- ✅ Whitelist management IPs
- ✅ Per-process isolation

**Success Metrics**:
- Isolation activates in < 1 second
- 0% packet leakage
- Management access maintained

---

### Week 11: Forensic Collection
**Goal**: Capture evidence for investigation

**Tasks**:
- [ ] Implement forensic collectors:
  - Memory dump (process memory)
  - Process snapshot (state, env vars, file descriptors)
  - Network packet capture (via eBPF)
  - File system timeline
  - Registry/config changes
- [ ] Artifact compression & encryption
- [ ] Artifact upload to forensics backend
- [ ] Chain of custody logging

**Deliverables**:
- ✅ 4+ forensic artifact types
- ✅ Encrypted artifact storage
- ✅ Chain of custody

**Success Metrics**:
- Complete artifact collection in < 30 seconds
- Artifacts encrypted with AES-256
- Full chain of custody documentation

---

### Week 12: Playbook Engine (Temporal Workflows)
**Goal**: Orchestrate complex response workflows

**Tasks**:
- [ ] Integrate Temporal for durable workflows
- [ ] Create playbook templates:
  - Ransomware response (isolate → collect → alert)
  - Crypto miner response (kill → hunt → report)
  - Lateral movement (isolate → investigate → remediate)
- [ ] Human-in-the-loop approvals
- [ ] Playbook visualization
- [ ] Playbook versioning

**Deliverables**:
- ✅ 3+ playbook templates
- ✅ Temporal integration
- ✅ Approval workflows

**Success Metrics**:
- Playbooks execute reliably
- Human approval in < 5 minutes
- Playbook state persisted

---

## 📅 Phase 4: Integration Layer (Weeks 13-16)

### Week 13: OTLP Export (SigNoz)
**Goal**: Send telemetry to SigNoz for observability

**Tasks**:
- [ ] Implement OTLP exporter:
  - Metrics (process CPU, network bytes, file I/O)
  - Traces (event timelines)
  - Logs (agent logs, alerts)
- [ ] Batch processing for efficiency
- [ ] Retry logic with exponential backoff
- [ ] TLS support
- [ ] Create SigNoz dashboards

**Deliverables**:
- ✅ OTLP integration
- ✅ SigNoz dashboards
- ✅ Batch processing

**Success Metrics**:
- 99.9% delivery rate
- < 100ms export latency
- Batches of 100 events

---

### Week 14: Wazuh Integration
**Goal**: Send alerts to Wazuh SIEM

**Tasks**:
- [ ] Implement Wazuh agent protocol
- [ ] Map TWN alerts to Wazuh format
- [ ] Wazuh decoder & rules for TWN events
- [ ] Register agent with Wazuh manager
- [ ] Test alert correlation

**Deliverables**:
- ✅ Wazuh agent integration
- ✅ Custom decoders
- ✅ Alert correlation

**Success Metrics**:
- All alerts sent to Wazuh
- Correlation rules working
- < 1 second alert latency

---

### Week 15: Velociraptor VQL Endpoint
**Goal**: Enable forensic hunting via VQL

**Tasks**:
- [ ] Implement VQL query endpoint
- [ ] Map TWN events to VQL-queryable format
- [ ] Support VQL queries:
  - `SELECT * FROM processes WHERE name = 'xmrig'`
  - `SELECT * FROM network WHERE dst_port = 3333`
  - `SELECT * FROM files WHERE path LIKE '/tmp/%'`
- [ ] Response caching
- [ ] Query performance optimization

**Deliverables**:
- ✅ VQL endpoint
- ✅ 10+ VQL query types supported
- ✅ Query caching

**Success Metrics**:
- VQL queries execute in < 2 seconds
- 100% compatibility with Velociraptor
- Cache hit rate > 80%

---

### Week 16: MeshCentral Coordination
**Goal**: Coordinate with MeshCentral for remote access

**Tasks**:
- [ ] Install MeshCentral agent alongside TWN agent
- [ ] Share device inventory
- [ ] Trigger security scans from remote sessions
- [ ] Log remote access sessions in TWN
- [ ] Alert on suspicious remote activity

**Deliverables**:
- ✅ MeshCentral integration
- ✅ Shared inventory
- ✅ Remote session logging

**Success Metrics**:
- Remote access fully logged
- Device inventory synced
- Security scans triggered from MeshCentral

---

## 📅 Phase 5: Deployment & Hardening (Weeks 17-20)

### Week 17: Fleet Deployment Tools
**Goal**: Deploy TWN agent across hundreds/thousands of hosts

**Tasks**:
- [ ] Create deployment packages:
  - .deb (Debian/Ubuntu)
  - .rpm (RHEL/Fedora)
  - .tar.gz (generic)
- [ ] Ansible playbook for deployment
- [ ] Salt states
- [ ] Docker/Podman image
- [ ] Kubernetes DaemonSet
- [ ] Auto-update mechanism

**Deliverables**:
- ✅ 5+ deployment methods
- ✅ Auto-update
- ✅ Deployment automation

**Success Metrics**:
- Deploy to 100 hosts in < 10 minutes
- 99% successful deployments
- Auto-update without downtime

---

### Week 18: Dashboard (SvelteKit)
**Goal**: Build TWN control panel

**Tasks**:
- [ ] SvelteKit app scaffolding
- [ ] Device inventory view
- [ ] Real-time alerts dashboard
- [ ] Remote access launcher (MeshCentral)
- [ ] Detection rule management
- [ ] Forensic investigation UI
- [ ] Response action history

**Deliverables**:
- ✅ SvelteKit dashboard
- ✅ 7+ key views
- ✅ Real-time updates (SSE/WebSocket)

**Success Metrics**:
- Dashboard loads in < 2 seconds
- Real-time updates in < 500ms
- Mobile-responsive

---

### Week 19: Performance Optimization
**Goal**: Optimize for production workloads

**Tasks**:
- [ ] Profile CPU usage (perf, flamegraphs)
- [ ] Optimize hot paths
- [ ] Reduce memory allocations
- [ ] eBPF program optimization
- [ ] Batch processing tuning
- [ ] Load testing (1000+ agents)

**Deliverables**:
- ✅ Performance report
- ✅ Optimization patches
- ✅ Load test results

**Success Metrics**:
- < 2% CPU usage (idle)
- < 7% CPU usage (active)
- < 200MB memory usage
- Supports 10,000+ agents per control plane

---

### Week 20: Security Hardening & Launch
**Goal**: Production-ready security

**Tasks**:
- [ ] Security audit
- [ ] Penetration testing
- [ ] TLS everywhere (mTLS for agent ↔ backend)
- [ ] Secrets management (Vault integration)
- [ ] Rate limiting & DDoS protection
- [ ] Compliance documentation (SOC 2, ISO 27001)
- [ ] Launch 🚀

**Deliverables**:
- ✅ Security audit report
- ✅ Pentest results
- ✅ Hardening checklist
- ✅ Compliance docs

**Success Metrics**:
- 0 critical vulnerabilities
- TLS 1.3 everywhere
- Secrets encrypted at rest
- Ready for production deployment

---

## 🛠️ Tech Stack Summary

### Agent (Linux)
- **Language**: Rust (userspace), C (eBPF programs)
- **eBPF**: libbpf + libbpf-rs OR aya (pure Rust)
- **Detection**: Custom engine + YARA (optional)
- **Storage**: SQLite (events), RocksDB (optional)
- **Communication**: OTLP (gRPC), Wazuh protocol, VQL endpoint

### Backend Services (Existing)
- **SIEM**: Wazuh
- **Forensics**: Velociraptor
- **Remote Access**: MeshCentral
- **Observability**: SigNoz + OpenObserve + Pyroscope

### Orchestration Layer
- **Workflows**: Temporal
- **AI**: obot + litellm + goose
- **Inventory**: Netbox

### Dashboard
- **Framework**: SvelteKit
- **UI**: Tailwind CSS + shadcn-svelte
- **Charts**: Chart.js or Apache ECharts
- **Real-time**: SSE or WebSocket

---

## 📊 Resource Requirements

### Development Team
- **2 Backend/eBPF Engineers** (Rust + C + Linux kernel)
- **1 Frontend Engineer** (SvelteKit)
- **1 DevOps Engineer** (deployment, infrastructure)

### Infrastructure
- **Development**: 4-8 vCPU, 16-32GB RAM
- **Testing**: 100+ VMs for fleet testing
- **Production (per 1000 agents)**: 8 vCPU, 16GB RAM (control plane)

### Budget (Self-Hosted)
- **Cloud costs**: $0 (self-hosted) to $500/mo (cloud development)
- **Developer time**: ~$200k for 5 months (2-4 devs)
- **Total**: ~$200-250k for MVP

---

## 🎯 Success Criteria

### MVP (End of Week 20)
✅ Detects 20+ MITRE ATT&CK techniques  
✅ < 2% CPU, < 250MB memory per agent  
✅ 99.9% uptime  
✅ Supports 10,000+ agents per control plane  
✅ < 1% false positive rate  
✅ Real-time detection (< 500ms latency)  
✅ Automated response actions  
✅ Complete forensics collection  
✅ Integration with Wazuh, Velociraptor, MeshCentral  
✅ SvelteKit dashboard  

### V1.0 (6 months post-MVP)
- Windows support (ETW-based monitoring)
- macOS support (Endpoint Security Framework)
- ML-based anomaly detection
- Advanced threat hunting
- Compliance reporting (PCI-DSS, HIPAA, etc.)

---

## 🚀 Getting Started NOW

### This Week
1. **Set up development environment** (see QUICKSTART.md)
2. **Build first eBPF program** (process_monitor.bpf.c)
3. **Load with libbpf-rs**
4. **Capture first process event** 🎉

### Next Steps
- Join our [Discord](https://discord.gg/twn-security)
- Read the [architecture docs](twn-linux-ebpf-agent-architecture.md)
- Check the [code examples](twn-agent/)
- Start building!

---

## 📞 Support & Community

- **Documentation**: https://docs.twn.io
- **Discord**: https://discord.gg/twn-security
- **GitHub**: https://github.com/your-org/twn-agent
- **Email**: hello@twn.io

**Let's build the future of open-source endpoint security together! 🚀**
