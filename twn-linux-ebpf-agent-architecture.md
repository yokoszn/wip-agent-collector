# TWN Linux Agent Architecture (eBPF-First)
## Feature Parity: Datto RMM + Sophos Endpoint

> **Philosophy**: All-in on Linux first, eBPF for deep visibility, OSS for self-hosting

---

## Core Agent Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    TWN Agent (Rust)                      │
├─────────────────────────────────────────────────────────┤
│                                                          │
│  ┌────────────────────────────────────────────┐        │
│  │         eBPF Subsystem (Kernel Space)      │        │
│  ├────────────────────────────────────────────┤        │
│  │                                             │        │
│  │  Process Monitoring (execve, fork, exit)   │        │
│  │  - Full process tree tracking              │        │
│  │  - Command line arguments                  │        │
│  │  - Parent-child relationships              │        │
│  │  - Process credentials (UID/GID)           │        │
│  │  - Container awareness (cgroups)           │        │
│  │                                             │        │
│  │  Network Monitoring (tcp, udp, dns)        │        │
│  │  - All connections (established + attempts)│        │
│  │  - DNS queries (before resolution)         │        │
│  │  - TLS/SSL inspection (SNI)                │        │
│  │  - Port scanning detection                 │        │
│  │  - Lateral movement tracking               │        │
│  │                                             │        │
│  │  File System Monitoring (openat, write)    │        │
│  │  - File access patterns                    │        │
│  │  - Suspicious file operations              │        │
│  │  - Ransomware indicators                   │        │
│  │  - Config file tampering                   │        │
│  │  - Binary execution from /tmp              │        │
│  │                                             │        │
│  │  Security Events (LSM hooks)               │        │
│  │  - Privilege escalation attempts           │        │
│  │  - Capability changes                      │        │
│  │  - Module loading                          │        │
│  │  - Kernel exploitation attempts            │        │
│  │                                             │        │
│  │  Performance Monitoring                     │        │
│  │  - CPU usage per process                   │        │
│  │  - Memory allocation patterns              │        │
│  │  - I/O operations                          │        │
│  │  - Syscall latency                         │        │
│  │                                             │        │
│  └────────────────────────────────────────────┘        │
│                        ↓                                 │
│  ┌────────────────────────────────────────────┐        │
│  │      Event Processing (User Space)          │        │
│  ├────────────────────────────────────────────┤        │
│  │                                             │        │
│  │  Real-time Analysis Engine                 │        │
│  │  ├─ Pattern matching (YARA-style)          │        │
│  │  ├─ Behavioral anomaly detection           │        │
│  │  ├─ Threat intelligence correlation        │        │
│  │  └─ Machine learning inference (optional)  │        │
│  │                                             │        │
│  │  Event Enrichment                          │        │
│  │  ├─ Process context (user, path, hashes)   │        │
│  │  ├─ Network context (DNS, GeoIP, threat)   │        │
│  │  ├─ File context (hashes, signatures)      │        │
│  │  └─ Timeline reconstruction                │        │
│  │                                             │        │
│  │  Local Intelligence                         │        │
│  │  ├─ Process baseline (normal behavior)     │        │
│  │  ├─ Network baseline (known-good)          │        │
│  │  ├─ File integrity database                │        │
│  │  └─ Custom detection rules                 │        │
│  │                                             │        │
│  └────────────────────────────────────────────┘        │
│                        ↓                                 │
│  ┌────────────────────────────────────────────┐        │
│  │       Response & Remediation                │        │
│  ├────────────────────────────────────────────┤        │
│  │                                             │        │
│  │  Automated Actions                          │        │
│  │  ├─ Process termination                     │        │
│  │  ├─ Network isolation (iptables/nftables)  │        │
│  │  ├─ File quarantine                         │        │
│  │  ├─ User session termination                │        │
│  │  └─ Container isolation                     │        │
│  │                                             │        │
│  │  Forensic Collection                        │        │
│  │  ├─ Memory dumps                            │        │
│  │  ├─ Process snapshots                       │        │
│  │  ├─ Network packet capture (via eBPF)      │        │
│  │  ├─ File system artifacts                   │        │
│  │  └─ Timeline export                         │        │
│  │                                             │        │
│  └────────────────────────────────────────────┘        │
│                        ↓                                 │
│  ┌────────────────────────────────────────────┐        │
│  │      Communication Layer                    │        │
│  ├────────────────────────────────────────────┤        │
│  │                                             │        │
│  │  ├─ OTLP Export (metrics, traces, logs)    │        │
│  │  ├─ Wazuh Agent Protocol                    │        │
│  │  ├─ Velociraptor VQL endpoint               │        │
│  │  ├─ MeshCentral Agent                       │        │
│  │  └─ TWN Control Plane (custom protocol)    │        │
│  │                                             │        │
│  └────────────────────────────────────────────┘        │
│                                                          │
└─────────────────────────────────────────────────────────┘
```

---

## Feature Parity Matrix

### Datto RMM Features → TWN Implementation

| Datto RMM Feature | TWN Linux Implementation | Status |
|-------------------|-------------------------|--------|
| **Remote Desktop** | MeshCentral + Guacamole | ✅ Use existing |
| **Command Execution** | SSH + Wazuh remote commands | ✅ Use existing |
| **File Transfer** | MeshCentral file manager | ✅ Use existing |
| **Process Management** | eBPF process monitor + kill | 🔨 Build |
| **Service Management** | systemd/sysvinit control | 🔨 Build |
| **Software Inventory** | dpkg/rpm/snap enumeration | 🔨 Build |
| **Patch Management** | apt/yum/dnf orchestration | 🔨 Build |
| **Performance Monitoring** | eBPF perf counters | 🔨 Build |
| **Network Discovery** | eBPF network tracking | 🔨 Build |
| **Asset Inventory** | Hardware detection + netbox | 🔨 Build |
| **Alerting** | Event correlation → Wazuh | ✅ Use existing |
| **Reporting** | Temporal workflows | ✅ Use existing |
| **Scripting** | Remote execution engine | 🔨 Build |
| **Backup Management** | Integration with restic/borg | 🔨 Future |

### Sophos Endpoint Features → TWN Implementation

| Sophos Feature | TWN Linux Implementation | Status |
|----------------|-------------------------|--------|
| **Real-time File Scanning** | eBPF file monitor + YARA | 🔨 Build |
| **Behavioral Analysis** | eBPF syscall patterns | 🔨 Build |
| **Exploit Prevention** | eBPF LSM hooks | 🔨 Build |
| **Ransomware Protection** | eBPF file entropy detection | 🔨 Build |
| **Web Filtering** | eBPF DNS/HTTP tracking | 🔨 Build |
| **Application Control** | eBPF exec whitelisting | 🔨 Build |
| **Device Control** | USB/device monitoring | 🔨 Build |
| **Firewall** | eBPF network filtering | 🔨 Build |
| **IPS/IDS** | Falco + custom rules | ✅ Use Falco |
| **EDR** | Velociraptor + eBPF telemetry | ✅ Use Velociraptor |
| **Threat Hunting** | Velociraptor VQL | ✅ Use existing |
| **Forensics** | eBPF event recording | 🔨 Build |
| **Isolation** | Network quarantine | 🔨 Build |
| **Root Cause Analysis** | Event timeline reconstruction | 🔨 Build |
| **Threat Intelligence** | TI feed integration | 🔨 Build |

---

## Phase 1: Core eBPF Agent (Linux-First)

### 1.1 Process Monitoring (Week 1-2)

**eBPF Programs to Build:**

```rust
// programs/process_monitor.bpf.c
SEC("tracepoint/sched/sched_process_exec")
int trace_exec(struct trace_event_raw_sched_process_exec *ctx) {
    struct process_event event = {};
    
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.ppid = ctx->old_pid;  // Parent process
    event.uid = bpf_get_current_uid_gid() >> 32;
    event.gid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    
    // Get command line (filename)
    bpf_probe_read_str(&event.comm, sizeof(event.comm), ctx->filename);
    
    // Get full path
    struct task_struct *task = (void *)bpf_get_current_task();
    bpf_probe_read_str(&event.path, sizeof(event.path), 
                       BPF_CORE_READ(task, mm, exe_file, f_path.dentry, d_name.name));
    
    // Container detection (cgroup)
    event.container_id = get_container_id(task);
    
    // Send to userspace
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, 
                          &event, sizeof(event));
    return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int trace_exit(struct trace_event_raw_sched_process_template *ctx) {
    // Track process termination
    struct process_exit_event event = {};
    event.pid = ctx->pid;
    event.exit_code = ctx->exit_code;
    
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
                          &event, sizeof(event));
    return 0;
}
```

**Rust Userspace Handler:**

```rust
// src/monitors/process.rs
pub struct ProcessMonitor {
    process_tree: ProcessTree,
    baseline: ProcessBaseline,
    rules: Vec<DetectionRule>,
}

impl ProcessMonitor {
    pub async fn handle_exec_event(&mut self, event: ProcessExecEvent) {
        // 1. Update process tree
        self.process_tree.add_process(event);
        
        // 2. Check against baseline
        if !self.baseline.is_known_process(&event.path) {
            self.alert(Alert::UnknownProcess(event.clone()));
        }
        
        // 3. Check suspicious patterns
        if event.path.starts_with("/tmp") || event.path.starts_with("/dev/shm") {
            self.alert(Alert::SuspiciousExecution(event.clone()));
        }
        
        // 4. Check privilege escalation
        if event.uid == 0 && event.ppid_uid != 0 {
            self.alert(Alert::PrivilegeEscalation(event.clone()));
        }
        
        // 5. Run custom rules
        for rule in &self.rules {
            if rule.matches(&event) {
                self.alert(Alert::RuleMatch(rule.name.clone(), event.clone()));
            }
        }
        
        // 6. Send to backend
        self.send_telemetry(event).await;
    }
}
```

### 1.2 Network Monitoring (Week 2-3)

**eBPF Programs:**

```c
// programs/network_monitor.bpf.c
SEC("kprobe/tcp_v4_connect")
int trace_tcp_connect(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    struct network_event event = {};
    
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.protocol = IPPROTO_TCP;
    
    // Get destination IP and port
    struct inet_sock *inet = inet_sk(sk);
    event.daddr = BPF_CORE_READ(inet, inet_daddr);
    event.dport = bpf_ntohs(BPF_CORE_READ(inet, inet_dport));
    
    // Get source port
    event.sport = BPF_CORE_READ(inet, inet_sport);
    
    // Get process info
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
                          &event, sizeof(event));
    return 0;
}

SEC("kprobe/udp_sendmsg")
int trace_udp_send(struct pt_regs *ctx) {
    // Similar for UDP...
}

SEC("kprobe/__x64_sys_connect")
int trace_connect(struct pt_regs *ctx) {
    // Catch all connect() calls
}
```

**DNS Monitoring:**

```c
// programs/dns_monitor.bpf.c
SEC("socket/dns")
int trace_dns(struct __sk_buff *skb) {
    // Parse DNS queries from network packets
    struct dns_query query = {};
    
    // Extract DNS question
    if (parse_dns_packet(skb, &query) == 0) {
        bpf_perf_event_output(skb, &dns_events, BPF_F_CURRENT_CPU,
                              &query, sizeof(query));
    }
    return 0;
}
```

### 1.3 File System Monitoring (Week 3-4)

**eBPF Programs:**

```c
// programs/file_monitor.bpf.c
SEC("lsm/file_open")
int BPF_PROG(trace_file_open, struct file *file, int ret) {
    if (ret != 0) return 0;  // Only track successful opens
    
    struct file_event event = {};
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.operation = FILE_OP_OPEN;
    
    // Get file path
    struct dentry *dentry = BPF_CORE_READ(file, f_path.dentry);
    bpf_probe_read_str(&event.path, sizeof(event.path),
                       BPF_CORE_READ(dentry, d_name.name));
    
    // Get flags (read/write/append)
    event.flags = BPF_CORE_READ(file, f_flags);
    
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
                          &event, sizeof(event));
    return 0;
}

SEC("lsm/file_permission")
int BPF_PROG(trace_file_permission, struct file *file, int mask) {
    // Track file access attempts
}

SEC("kprobe/vfs_write")
int trace_file_write(struct pt_regs *ctx) {
    // Track file modifications
}
```

**Ransomware Detection:**

```rust
// src/monitors/ransomware.rs
pub struct RansomwareDetector {
    file_entropy_tracker: HashMap<PathBuf, f64>,
    rapid_rename_tracker: HashMap<u32, Vec<FileEvent>>,
}

impl RansomwareDetector {
    pub async fn analyze_file_event(&mut self, event: FileEvent) {
        // 1. Rapid file encryption pattern
        if self.is_rapid_encryption_pattern(event.pid) {
            self.alert(Alert::RansomwareDetected {
                pid: event.pid,
                reason: "Rapid file encryption pattern detected"
            });
            self.isolate_process(event.pid).await;
        }
        
        // 2. Suspicious extensions
        if event.path.extension().map_or(false, |ext| {
            ext.to_str().map_or(false, |s| 
                s.len() > 5 || RANSOMWARE_EXTENSIONS.contains(&s))
        }) {
            self.alert(Alert::SuspiciousFileExtension(event));
        }
        
        // 3. Mass file modification
        let recent_writes = self.rapid_rename_tracker
            .entry(event.pid)
            .or_insert_with(Vec::new);
        recent_writes.push(event.clone());
        recent_writes.retain(|e| e.timestamp > now() - Duration::from_secs(60));
        
        if recent_writes.len() > 50 {
            self.alert(Alert::MassFileModification(event.pid));
        }
    }
}
```

### 1.4 Security Monitoring (Week 4-5)

**Privilege Escalation Detection:**

```c
// programs/security_monitor.bpf.c
SEC("lsm/capable")
int BPF_PROG(trace_capable, const struct cred *cred, struct user_namespace *ns,
             int cap, unsigned int opts) {
    struct capability_event event = {};
    
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.capability = cap;
    event.uid = BPF_CORE_READ(cred, uid.val);
    
    // Track privilege escalation attempts
    if (cap == CAP_SYS_ADMIN || cap == CAP_DAC_OVERRIDE) {
        bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
                              &event, sizeof(event));
    }
    
    return 0;
}

SEC("lsm/kernel_module_request")
int BPF_PROG(trace_module_load, char *kmod_name) {
    // Track kernel module loading
    struct module_event event = {};
    event.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_probe_read_str(&event.name, sizeof(event.name), kmod_name);
    
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
                          &event, sizeof(event));
    return 0;
}
```

---

## Phase 2: Threat Detection Engine (Week 6-8)

### 2.1 Detection Rules (YARA-style)

```rust
// src/detection/rules.rs
pub struct DetectionRule {
    pub name: String,
    pub severity: Severity,
    pub condition: RuleCondition,
    pub action: RuleAction,
}

pub enum RuleCondition {
    ProcessPattern {
        path_regex: Regex,
        args_contains: Vec<String>,
        parent_name: Option<String>,
    },
    NetworkPattern {
        dst_ip: Option<IpAddr>,
        dst_port: Option<u16>,
        protocol: Protocol,
        process_name: Option<String>,
    },
    FilePattern {
        path_regex: Regex,
        operation: FileOperation,
        rapid_activity: bool,
    },
    Composite {
        conditions: Vec<RuleCondition>,
        logic: LogicOperator,  // AND/OR
        within_timeframe: Duration,
    },
}

// Example rules
const CRYPTO_MINER_RULE: &str = r#"
rule: crypto_miner_detection
severity: high
conditions:
  - process:
      path_regex: ".*(xmrig|cpuminer|ccminer).*"
  - network:
      dst_port: 3333
      protocol: tcp
  - process:
      cpu_usage: "> 80%"
      duration: "> 60s"
action: alert_and_suggest_kill
"#;

const REVERSE_SHELL_RULE: &str = r#"
rule: reverse_shell_detection
severity: critical
conditions:
  - network:
      direction: outbound
      established: true
  - process:
      args_contains: ["/bin/sh", "/bin/bash"]
      stdin_fd: "socket"
action: alert_and_isolate
"#;
```

### 2.2 Behavioral Baselines

```rust
// src/detection/baseline.rs
pub struct BehavioralBaseline {
    normal_processes: HashSet<ProcessSignature>,
    normal_network: HashMap<ProcessName, Vec<NetworkPattern>>,
    normal_files: HashMap<ProcessName, Vec<PathBuf>>,
}

impl BehavioralBaseline {
    pub fn learn_from_events(&mut self, events: Vec<Event>, duration: Duration) {
        // Build baseline over time (e.g., 7 days)
        for event in events {
            match event {
                Event::ProcessExec(proc) => {
                    self.normal_processes.insert(ProcessSignature {
                        path: proc.path,
                        hash: proc.hash,
                        user: proc.uid,
                    });
                }
                Event::NetworkConnect(net) => {
                    self.normal_network
                        .entry(net.process_name)
                        .or_default()
                        .push(NetworkPattern {
                            dst_ip: net.dst_ip,
                            dst_port: net.dst_port,
                        });
                }
                // ... etc
            }
        }
    }
    
    pub fn is_anomalous(&self, event: &Event) -> Option<Anomaly> {
        // Check if event deviates from baseline
        match event {
            Event::ProcessExec(proc) if !self.is_known_process(proc) => {
                Some(Anomaly::UnknownProcess(proc.clone()))
            }
            Event::NetworkConnect(net) if !self.is_known_connection(net) => {
                Some(Anomaly::UnknownConnection(net.clone()))
            }
            _ => None,
        }
    }
}
```

---

## Phase 3: Response & Remediation (Week 9-10)

### 3.1 Automated Response

```rust
// src/response/actions.rs
pub struct ResponseEngine {
    action_queue: mpsc::Sender<ResponseAction>,
    approved_actions: HashSet<ActionType>,
}

impl ResponseEngine {
    pub async fn execute_action(&self, action: ResponseAction) -> Result<()> {
        match action {
            ResponseAction::KillProcess { pid, signal } => {
                nix::sys::signal::kill(
                    nix::unistd::Pid::from_raw(pid as i32),
                    signal
                )?;
                
                // Log action
                self.audit_log(AuditEvent::ProcessKilled { pid, signal }).await;
            }
            
            ResponseAction::IsolateHost { reason } => {
                // Block all outbound connections except to management
                self.apply_network_isolation().await?;
                self.alert_admin(AlertType::HostIsolated { reason }).await;
            }
            
            ResponseAction::QuarantineFile { path } => {
                let quarantine_path = format!("/var/twn/quarantine/{}", 
                                              path.file_name().unwrap());
                tokio::fs::rename(&path, &quarantine_path).await?;
                
                // Store metadata
                self.store_quarantine_metadata(&path, &quarantine_path).await?;
            }
            
            ResponseAction::BlockNetwork { ip, port, duration } => {
                // Add iptables/nftables rule
                Command::new("iptables")
                    .args(&["-A", "OUTPUT", "-d", &ip.to_string(), 
                            "-p", "tcp", "--dport", &port.to_string(), 
                            "-j", "DROP"])
                    .output()
                    .await?;
                
                // Schedule removal after duration
                tokio::spawn(async move {
                    tokio::time::sleep(duration).await;
                    // Remove rule...
                });
            }
            
            ResponseAction::CollectForensics { pid, artifacts } => {
                self.collect_memory_dump(pid).await?;
                self.collect_process_snapshot(pid).await?;
                self.collect_network_pcap(pid, Duration::from_secs(60)).await?;
            }
        }
        
        Ok(())
    }
}
```

### 3.2 Network Isolation (eBPF-based)

```c
// programs/network_isolation.bpf.c
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, u32);  // PID
    __type(value, u8);  // isolated=1
} isolated_processes SEC(".maps");

SEC("cgroup/sock_create")
int block_socket_create(struct bpf_sock *sk) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u8 *isolated = bpf_map_lookup_elem(&isolated_processes, &pid);
    
    if (isolated && *isolated == 1) {
        // Block socket creation for isolated processes
        return 0;  // Deny
    }
    
    return 1;  // Allow
}
```

---

## Phase 4: Integration Layer (Week 11-12)

### 4.1 OTLP Export

```rust
// src/export/otlp.rs
pub struct OtlpExporter {
    client: tonic::Client,
    batch_buffer: Vec<Span>,
}

impl OtlpExporter {
    pub async fn export_process_event(&mut self, event: ProcessExecEvent) {
        let span = Span {
            trace_id: generate_trace_id(),
            span_id: generate_span_id(),
            name: "process.exec".to_string(),
            kind: SpanKind::Internal,
            start_time: event.timestamp,
            end_time: event.timestamp,
            attributes: vec![
                KeyValue { key: "process.pid".into(), value: event.pid.into() },
                KeyValue { key: "process.executable.path".into(), value: event.path.into() },
                KeyValue { key: "process.command_line".into(), value: event.args.join(" ").into() },
                KeyValue { key: "process.parent.pid".into(), value: event.ppid.into() },
            ],
            ..Default::default()
        };
        
        self.batch_buffer.push(span);
        
        if self.batch_buffer.len() >= 100 {
            self.flush().await?;
        }
    }
}
```

### 4.2 Wazuh Integration

```rust
// src/export/wazuh.rs
pub struct WazuhExporter {
    agent: WazuhAgent,
}

impl WazuhExporter {
    pub async fn send_alert(&self, alert: Alert) {
        let wazuh_alert = json!({
            "timestamp": alert.timestamp.to_rfc3339(),
            "rule": {
                "level": alert.severity.to_wazuh_level(),
                "description": alert.description,
                "id": alert.rule_id,
            },
            "agent": {
                "id": self.agent.id,
                "name": self.agent.name,
                "ip": self.agent.ip,
            },
            "data": alert.data,
        });
        
        self.agent.send_event(wazuh_alert).await?;
    }
}
```

### 4.3 Velociraptor VQL Endpoint

```rust
// src/export/velociraptor.rs
pub struct VelociraptorEndpoint {
    event_store: EventStore,
}

impl VelociraptorEndpoint {
    // Expose VQL-queryable interface
    pub async fn query(&self, vql: &str) -> Result<Vec<serde_json::Value>> {
        // Parse VQL and execute against local event store
        let query = parse_vql(vql)?;
        let results = self.event_store.execute_query(query).await?;
        Ok(results)
    }
    
    // Example VQL queries supported:
    // SELECT * FROM processes WHERE name = 'xmrig'
    // SELECT * FROM network WHERE dst_port = 3333
    // SELECT * FROM files WHERE path LIKE '/tmp/%'
}
```

---

## eBPF Programs Priority Order

### Must-Have (Phase 1)
1. ✅ **Process Execution** (`execve`, `fork`, `exit`)
2. ✅ **Network Connections** (`tcp_connect`, `udp_sendmsg`)
3. ✅ **File Operations** (`openat`, `write`, `unlink`)
4. ✅ **Privilege Escalation** (`setuid`, `capable`)

### Should-Have (Phase 2)
5. ✅ **DNS Queries** (socket filter)
6. ✅ **Kernel Module Loading** (`finit_module`)
7. ✅ **Container Awareness** (cgroup tracking)
8. ✅ **Performance Metrics** (CPU, memory per process)

### Nice-to-Have (Phase 3)
9. ⚠️ **TLS/SSL Inspection** (uprobes on OpenSSL)
10. ⚠️ **USB Device Events** (usb_device_add)
11. ⚠️ **Memory Access Patterns** (page faults)
12. ⚠️ **IPC Monitoring** (pipes, shared memory)

---

## Tech Stack

### Core Agent
- **Language**: Rust (for agent) + C (for eBPF programs)
- **eBPF Framework**: `libbpf` + `libbpf-rs` (Rust bindings)
- **OR**: `aya` (pure Rust eBPF)
- **Kernel Requirements**: Linux 5.8+ (for BPF LSM support)

### Detection
- **Pattern Matching**: Custom YARA-like engine
- **Anomaly Detection**: Statistical baselines + optional ML
- **Threat Intel**: MISP integration

### Storage
- **Local Events**: SQLite or RocksDB (embedded)
- **Forensic Artifacts**: File system + object storage

### Communication
- **OTLP**: OpenTelemetry Protocol (to SigNoz)
- **Wazuh**: Native agent protocol
- **Velociraptor**: VQL query endpoint
- **MeshCentral**: Existing agent

---

## Deployment Model

```yaml
# /etc/twn/agent.yaml
agent:
  mode: full  # full | lightweight | forensics-only
  
  ebpf:
    enabled: true
    programs:
      - process_monitor
      - network_monitor
      - file_monitor
      - security_monitor
    
  detection:
    rules_path: /etc/twn/rules.d/
    baseline_learning: true
    baseline_duration: 7d
    
  response:
    auto_respond: true
    allowed_actions:
      - kill_process
      - quarantine_file
      - block_network
    require_approval:
      - isolate_host
      
  export:
    otlp:
      endpoint: https://signoz.twn.internal:4317
    wazuh:
      server: wazuh.twn.internal
      port: 1514
    velociraptor:
      server: velociraptor.twn.internal
      port: 8000
      
  performance:
    max_cpu_usage: 10%  # Agent CPU limit
    max_memory: 512MB
    event_buffer_size: 10000
```

---

## Performance Targets

| Metric | Target | Notes |
|--------|--------|-------|
| CPU Usage (idle) | < 2% | With all eBPF programs loaded |
| CPU Usage (active) | < 10% | During event processing |
| Memory Usage | < 256MB | Base agent footprint |
| Event Latency | < 100ms | From kernel to userspace |
| Detection Latency | < 500ms | From event to alert |
| Network Overhead | < 1MB/hr | Steady-state telemetry |

---

## What Makes This Better Than Sophos/Datto

### vs. Sophos Endpoint
1. **eBPF = Kernel-level visibility** (Sophos uses userspace hooks)
2. **Open source** (audit the code, no vendor lock-in)
3. **Integrated with RMM** (one agent, not two)
4. **Self-hosted** (data stays on your infrastructure)
5. **Customizable rules** (write your own detections)

### vs. Datto RMM
1. **Real-time security** (not just management)
2. **Behavioral detection** (not just AV signatures)
3. **Forensics built-in** (Datto requires add-ons)
4. **eBPF efficiency** (lower overhead than WMI/CIM)
5. **Linux-first** (proper Linux support, not an afterthought)

---

## Next Steps

### Week 1-2: Foundation
- [ ] Set up Rust + eBPF development environment
- [ ] Implement basic process monitoring eBPF program
- [ ] Build event processing pipeline
- [ ] Test on various kernel versions (5.8+, 5.15, 6.x)

### Week 3-4: Core Monitoring
- [ ] Implement network monitoring (TCP/UDP/DNS)
- [ ] Implement file system monitoring
- [ ] Add process tree reconstruction
- [ ] Build event correlation engine

### Week 5-6: Detection
- [ ] Implement rule engine
- [ ] Add behavioral baselines
- [ ] Build threat detection logic
- [ ] Test against MITRE ATT&CK scenarios

### Week 7-8: Response
- [ ] Implement automated response actions
- [ ] Add network isolation capabilities
- [ ] Build forensic collection
- [ ] Test incident response workflows

### Week 9-10: Integration
- [ ] OTLP export to SigNoz
- [ ] Wazuh agent integration
- [ ] Velociraptor VQL endpoint
- [ ] MeshCentral coordination

### Week 11-12: Hardening
- [ ] Performance optimization
- [ ] Security hardening
- [ ] Documentation
- [ ] Deployment automation

---

## Resources

### eBPF Learning
- https://ebpf.io/ (official docs)
- https://github.com/iovisor/bcc (BCC toolkit)
- https://github.com/libbpf/libbpf-rs (Rust bindings)
- https://github.com/aya-rs/aya (pure Rust eBPF)

### Reference Implementations
- https://github.com/falcosecurity/falco (runtime security)
- https://github.com/cilium/tetragon (eBPF security observability)
- https://github.com/aquasecurity/tracee (eBPF security)
- https://github.com/DataDog/datadog-agent (eBPF monitoring)

### Detection Rules
- https://github.com/SigmaHQ/sigma (detection rules)
- https://attack.mitre.org/ (TTPs)
- https://github.com/elastic/detection-rules

