# Kernel Hardening Reference — sysctl Parameters

This document covers the sysctl hardening parameters identified as remaining issues after the initial 10 remediations. These correspond to CIS Benchmark sections 3.2 and 3.3.

---

## What is sysctl?

`sysctl` allows reading and writing kernel parameters at runtime. Security-relevant parameters are persistent when written to `/etc/sysctl.conf` or `/etc/sysctl.d/*.conf`.

```bash
# Apply all settings immediately
sudo sysctl -p /etc/sysctl.conf

# Verify a specific setting
sysctl net.ipv4.conf.all.rp_filter
```

---

## Network Security Parameters

### Reverse Path Filtering (Anti-Spoofing)

```ini
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
```

**What it does:** Validates that incoming packets have a source address routable back through the same interface. Packets that fail this check are dropped.

**Why it matters:** Prevents IP spoofing attacks where an attacker forges a source IP to bypass access controls or trigger server-to-server communication.

---

### Log Martian Packets

```ini
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
```

**What it does:** Logs packets with impossible source addresses (RFC 1918 private addresses appearing on public interfaces, loopback addresses from external, etc.).

**Why it matters:** These packets are either misconfigurations or active spoofing attempts. Logging them provides visibility into reconnaissance activity.

---

### ICMP Redirect Handling

```ini
# Do not send ICMP redirects
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# Do not accept ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
```

**What it does:** Disables ICMP redirect messages in both directions.

**Why it matters:** ICMP redirects can be used to manipulate routing tables on a host — a classic man-in-the-middle setup technique.

---

### Source Routing

```ini
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
```

**What it does:** Rejects packets that carry routing instructions embedded in the packet header.

**Why it matters:** Source routing was deprecated precisely because it allows attackers to force traffic through arbitrary paths, potentially bypassing firewalls.

---

### TCP SYN Cookies

```ini
net.ipv4.tcp_syncookies = 1
```

**What it does:** Enables SYN cookie generation when the SYN backlog queue is full.

**Why it matters:** Mitigates SYN flood (TCP exhaustion) DoS attacks by handling connection setup without consuming backlog queue entries.

---

### Packet Forwarding

```ini
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0
```

**What it does:** Disables IP packet forwarding between interfaces.

**Why it matters:** Unless this machine is a router or runs containers with bridged networking, forwarding should be off. Enabling it could turn a compromised server into a pivot point within the network.

---

### Broadcast Ping

```ini
net.ipv4.icmp_echo_ignore_broadcasts = 1
```

**What it does:** Ignores ICMP echo requests sent to broadcast addresses.

**Why it matters:** Smurf attacks amplify traffic by sending a spoofed ping to a broadcast address — all hosts on the network reply to the victim. Ignoring broadcasts eliminates this amplification vector.

---

## Kernel Hardening Parameters

### Restrict /proc Access

```ini
kernel.dmesg_restrict = 1
```

**What it does:** Restricts `dmesg` output to root only.

**Why it matters:** Kernel logs contain memory addresses, loaded modules, and hardware information useful for kernel exploit development.

---

### Disable Magic SysRq

```ini
kernel.sysrq = 0
```

**What it does:** Disables the SysRq key combination that allows direct kernel commands.

**Why it matters:** On a server, there is no legitimate reason for physical console SysRq access. An attacker with physical access could use it to reboot or sync filesystems.

---

### PTRACE Scope

```ini
kernel.yama.ptrace_scope = 1
```

**What it does:** Restricts the `ptrace()` system call so that only direct parent processes can trace a child.

**Why it matters:** `ptrace` is used by debuggers but can also be abused by malware to inject code into running processes or read process memory. This setting prevents lateral movement between processes.

---

## Applying These Settings

Create a dedicated file to keep hardening settings organized:

```bash
sudo tee /etc/sysctl.d/99-hardening.conf << 'EOF'
# CIS Section 3.2 — Network Parameters (Host Only)
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# CIS Section 3.3 — Network Parameters (Host and Router)
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv4.tcp_syncookies = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Kernel hardening
kernel.dmesg_restrict = 1
kernel.sysrq = 0
kernel.yama.ptrace_scope = 1
EOF

sudo sysctl --system
```

---

## Verification

After applying, verify each parameter:

```bash
# Check all at once
sysctl -a 2>/dev/null | grep -E "rp_filter|log_martians|send_redirects|accept_redirects|syncookies|sysrq|ptrace"
```

Expected output should show `= 1` for protections and `= 0` for disabled features.

---

*Reference: CIS Debian Linux Benchmark — Sections 3.2 and 3.3*
