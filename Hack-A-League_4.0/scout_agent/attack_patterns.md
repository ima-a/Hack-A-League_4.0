# Attack Patterns Reference

This document catalogs the common network attack patterns that the Scout Agent monitors for in SwarmShield. Each entry includes detection signals, typical traffic signatures, and the Monte Carlo risk weight used during threat estimation.

---

## 1. SYN Flood (DDoS)

**Category:** Denial of Service  
**MITRE ATT&CK:** T1498.001 – Direct Network Flood

### Description
Attacker sends a large volume of TCP SYN packets without completing the three-way handshake, exhausting the target's connection table.

### Detection Signals
- SYN packet rate > 500 pps from a single source
- SYN / SYN-ACK ratio > 5:1 on a given port
- Incomplete TCP connections accumulating on port 80 / 443
- Source IPs with TTL variance (spoofed addresses)

### Traffic Signature
```
TCP flags: SYN only (0x002)
Packet size: 40–60 bytes
Rate: burst, sustained > 30 seconds
Dst port: typically 80 / 443 / 22
```

### Monte Carlo Risk Weight
- Base severity: **0.85**
- Propagation potential: **low** (self-contained)
- Impact score range: 0.60 – 0.95

---

## 2. Port Scan (Reconnaissance)

**Category:** Reconnaissance  
**MITRE ATT&CK:** T1046 – Network Service Scanning

### Description
Systematic probing of sequential or random ports on a target host to enumerate open services.

### Detection Signals
- Single source IP contacting > 20 distinct ports within 10 s
- High proportion of RST or ICMP Port Unreachable responses
- Low bytes-per-packet average (< 80 bytes)
- Stealth scan: FIN / NULL / XMAS flags in use

### Traffic Signature
```
TCP flags: SYN (connect scan), FIN, NULL, or XMAS (stealth)
Packet size: < 80 bytes
Dst port: sequential or random sweep
Rate: 5–200 pps
```

### Monte Carlo Risk Weight
- Base severity: **0.45**
- Propagation potential: **medium** (precursor to exploitation)
- Impact score range: 0.30 – 0.65

---

## 3. Brute Force SSH / Login

**Category:** Credential Access  
**MITRE ATT&CK:** T1110 – Brute Force

### Description
Automated attempts to authenticate with large numbers of passwords or usernames against SSH, FTP, HTTP login endpoints, or RDP.

### Detection Signals
- > 10 authentication failures from single IP within 60 s
- Repeated TCP connections to port 22 / 21 / 3389
- Short-lived sessions (< 2 s) without successful data transfer
- User-agent cycling (for HTTP brute force)

### Traffic Signature
```
Protocol: TCP (SSH port 22, FTP 21, RDP 3389)
Session duration: < 2 s
Failure rate: > 80 % of sessions
Packet cadence: regular interval (bot-driven)
```

### Monte Carlo Risk Weight
- Base severity: **0.70**
- Propagation potential: **high** (credential compromise leads to lateral movement)
- Impact score range: 0.55 – 0.90

---

## 4. DNS Amplification

**Category:** Denial of Service / Amplification  
**MITRE ATT&CK:** T1498.002 – Reflection Amplification

### Description
Attacker sends small DNS queries with a spoofed source IP (victim) to open resolvers that return large responses, amplifying traffic toward the victim.

### Detection Signals
- Unusually large DNS response packets (> 512 bytes, especially ANY queries)
- High UDP traffic from port 53 toward victim
- Response-to-query ratio > 10:1
- Queries for TXT / ANY record types in volume

### Traffic Signature
```
Protocol: UDP
Src port: 53 (DNS)
Packet size: 512–4096 bytes (response)
Query type: ANY, TXT, DNSKEY
Rate: amplified bursts
```

### Monte Carlo Risk Weight
- Base severity: **0.80**
- Propagation potential: **low** (reflected, not self-propagating)
- Impact score range: 0.65 – 0.92

---

## 5. ARP Spoofing / Man-in-the-Middle

**Category:** Credential Access / Collection  
**MITRE ATT&CK:** T1557.002 – ARP Cache Poisoning

### Description
Attacker broadcasts forged ARP replies to associate their MAC address with a legitimate IP address, intercepting traffic.

### Detection Signals
- Multiple ARP replies for the same IP from different MACs
- ARP reply without a preceding ARP request
- Rapid ARP table changes (> 3 changes per minute for a single IP)
- Duplicate IP detections on the local segment

### Traffic Signature
```
Protocol: ARP
Opcode: 2 (reply) without matching request
MAC conflicts: same IP → different MACs
Rate: bursty, < 10 pps but highly targeted
```

### Monte Carlo Risk Weight
- Base severity: **0.75**
- Propagation potential: **high** (enables data exfiltration and credential theft)
- Impact score range: 0.60 – 0.88

---

## 6. ICMP Flood (Ping Flood)

**Category:** Denial of Service  
**MITRE ATT&CK:** T1498.001 – Direct Network Flood

### Description
Attacker overwhelms target with high-rate ICMP Echo Request packets to consume bandwidth and CPU.

### Detection Signals
- ICMP Echo Request rate > 1000 ppm from single source
- ICMP traffic > 20 % of total interface bandwidth
- Large ICMP payload sizes (padding to maximum MTU)

### Traffic Signature
```
Protocol: ICMP type 8 (Echo Request)
Packet size: 64–65535 bytes
Rate: sustained high volume
```

### Monte Carlo Risk Weight
- Base severity: **0.60**
- Propagation potential: **low**
- Impact score range: 0.40 – 0.75

---

## 7. SQL Injection (HTTP-Layer)

**Category:** Initial Access / Exfiltration  
**MITRE ATT&CK:** T1190 – Exploit Public-Facing Application

### Description
An attacker injects malicious SQL statements into HTTP request parameters to manipulate the backend database.

### Detection Signals
- URL or POST body containing SQL keywords: `UNION`, `SELECT`, `DROP`, `INSERT`, `--`, `'`
- Anomalous HTTP response sizes (large data dumps)
- High rate of 500 / 200 alternating responses
- Unusual query strings with encoded characters (`%27`, `%3D`, `%20`)

### Traffic Signature
```
Protocol: HTTP / HTTPS
Dst port: 80 / 443 / 8080
Payload pattern: SQL keywords in URI or body
Response size: abnormal spike
```

### Monte Carlo Risk Weight
- Base severity: **0.90**
- Propagation potential: **very high** (data exfiltration, pivoting)
- Impact score range: 0.75 – 0.98

---

## 8. Command & Control (C2) Beacon

**Category:** Command and Control  
**MITRE ATT&CK:** T1071 – Application Layer Protocol

### Description
Compromised host communicates with attacker-controlled server in a regular, periodic pattern to receive instructions or exfiltrate data.

### Detection Signals
- Highly regular connection intervals (jitter < 5 %)
- Low-volume, consistent outbound connections to rare external IPs
- Unusual protocols on standard ports (e.g., DNS tunneling, HTTPS to non-CDN IPs)
- Long-duration low-bandwidth sessions

### Traffic Signature
```
Protocol: HTTPS / DNS / HTTP
Interval: periodic (e.g., every 30 s ± 1 s)
Payload size: small (< 256 bytes per beacon)
Dst IP: rare / new external host
```

### Monte Carlo Risk Weight
- Base severity: **0.95**
- Propagation potential: **very high** (active compromise)
- Impact score range: 0.80 – 1.00

---

## 9. UDP Flood

**Category:** Denial of Service  
**MITRE ATT&CK:** T1498.001

### Description
Mass UDP packets directed at random ports on target host, forcing it to process and respond to ICMP Port Unreachable messages.

### Detection Signals
- UDP packet rate > 10,000 pps toward single host
- Randomised destination ports
- Spoofed or rapidly rotating source IPs
- High ICMP Port Unreachable response rate

### Traffic Signature
```
Protocol: UDP
Dst port: random (1024–65535)
Packet size: 512–1500 bytes
Rate: massive, sustained
```

### Monte Carlo Risk Weight
- Base severity: **0.72**
- Propagation potential: **low**
- Impact score range: 0.55 – 0.88

---

## 10. Lateral Movement (SMB / Pass-the-Hash)

**Category:** Lateral Movement  
**MITRE ATT&CK:** T1550.002 – Pass the Hash

### Description
Attacker reuses captured NTLM hashes to authenticate to remote services without knowing the plaintext password.

### Detection Signals
- SMB connections from unusual internal hosts
- Failed then immediately successful SMB authentications
- NTLM authentication on port 445 where Kerberos is expected
- Same hash reused across multiple destination IPs within short window

### Traffic Signature
```
Protocol: SMB (TCP 445)
Auth type: NTLM (not Kerberos)
Pattern: failure → rapid success → new target
Spread: multiple internal dest IPs
```

### Monte Carlo Risk Weight
- Base severity: **0.88**
- Propagation potential: **very high** (snowball across internal network)
- Impact score range: 0.72 – 0.97

---

## Threat Level Thresholds

| Combined Risk Score | Threat Level | Scout Action                              |
|---------------------|--------------|-------------------------------------------|
| 0.00 – 0.30         | **LOW**      | Log only, continue monitoring             |
| 0.31 – 0.55         | **MEDIUM**   | Alert Analyzer, increase capture rate     |
| 0.56 – 0.75         | **HIGH**     | Immediate report to Analyzer + Responder  |
| 0.76 – 1.00         | **CRITICAL** | Emergency report, trigger auto-response   |

---

## Pattern Update Policy

- Patterns are versioned in this file; each release should increment the `PATTERN_VERSION` constant in `scout_agent.py`.
- Dynamic updates can be pushed via the Flask config endpoint (`POST /config`) without restarting the agent.
- The Monte Carlo estimator reads base severity weights at runtime from this reference.
