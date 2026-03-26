# Zeek IR Cheat Sheet

Quick reference for incident response with Zeek. Print this out or keep it open during exercises.

---

## Running Zeek

```bash
# Setup alias (suppress checksum warnings)
alias zeek="zeek -C 'FilteredTraceDetection::enable=F'"

# Process a pcap with default scripts
zeek -r capture.pcap local

# Process with a specific script
zeek -r capture.pcap scripts/my-detection.zeek

# Process with default scripts + a custom script
zeek -r capture.pcap local scripts/my-detection.zeek

# Process with file extraction
zeek -r capture.pcap local policy/frameworks/files/extract-all-files

# Process with malware hash lookups
zeek -r capture.pcap local policy/frameworks/files/detect-MHR.zeek
```

---

## zeek-cut: Your Best Friend

`zeek-cut` extracts specific columns from Zeek logs by field name (not position).

```bash
# Basic: extract specific fields
zeek-cut ts uid id.orig_h id.resp_h < conn.log

# Convert timestamps to human-readable
zeek-cut -d ts uid id.orig_h < conn.log

# Pipe into standard Unix tools
zeek-cut id.orig_h < conn.log | sort | uniq -c | sort -rn | head
```

---

## Core Log Files

| Log | What It Records | Key Fields |
|-----|-----------------|------------|
| `conn.log` | Every connection | `uid`, `id.*`, `proto`, `service`, `duration`, `orig_bytes`, `resp_bytes`, `conn_state`, `history` |
| `dns.log` | DNS queries & responses | `uid`, `query`, `qtype_name`, `rcode_name`, `answers` |
| `http.log` | HTTP transactions | `uid`, `method`, `host`, `uri`, `user_agent`, `status_code`, `resp_mime_types` |
| `ssl.log` | TLS/SSL handshakes | `uid`, `version`, `cipher`, `server_name`, `subject`, `issuer`, `ja3`, `ja3s` |
| `files.log` | Files seen in traffic | `fuid`, `uid`, `source`, `mime_type`, `filename`, `md5`, `sha1` |
| `smtp.log` | Email transactions | `uid`, `mailfrom`, `rcptto`, `subject`, `from`, `to` |
| `ssh.log` | SSH connections | `uid`, `version`, `auth_success`, `client`, `server` |
| `notice.log` | Zeek-generated alerts | `note`, `msg`, `src`, `dst`, `p` |
| `weird.log` | Protocol anomalies | `name`, `addl`, `uid` |
| `software.log` | Detected software | `host`, `software_type`, `name`, `version.major/minor` |
| `dhcp.log` | DHCP leases | `mac`, `assigned_addr`, `host_name` |
| `kerberos.log` | Kerberos auth | `client`, `service`, `success` |
| `ntlm.log` | NTLM auth | `username`, `hostname`, `domainname`, `success` |
| `dpd.log` | Protocol detection | `proto`, `analyzer`, `failure_reason` |
| `pe.log` | Windows PE files | `machine`, `compile_ts`, `subsystem` |

---

## conn.log: Connection States

| State | Meaning |
|-------|---------|
| `S0` | SYN sent, no reply (connection attempt, often = scanning) |
| `S1` | SYN-ACK seen, no final ACK from originator |
| `SF` | Normal connection establishment and termination |
| `REJ` | Connection rejected (RST from responder) |
| `S2` | Connection established, close attempt by originator (FIN) |
| `S3` | Connection established, close attempt by responder (FIN) |
| `RSTO` | Connection established, RST from originator |
| `RSTR` | Connection established, RST from responder |
| `RSTOS0` | SYN sent, RST from originator |
| `RSTRH` | RST from responder before SYN-ACK |
| `SH` | SYN+ACK seen, no final ACK (handshake) |
| `SHR` | SYN+ACK seen, then RST |
| `OTH` | No SYN seen, midstream traffic |

## conn.log: History Field

| Letter | Meaning | Case |
|--------|---------|------|
| `S` / `s` | SYN | Uppercase = originator, lowercase = responder |
| `H` / `h` | SYN+ACK | |
| `A` / `a` | ACK | |
| `D` / `d` | Data packet | |
| `F` / `f` | FIN | |
| `R` / `r` | RST | |
| `C` / `c` | Packet with bad checksum | |
| `I` / `i` | Inconsistent packet | |
| `Q` / `q` | Multi-flag packet (SYN+FIN, SYN+RST) | |
| `T` / `t` | Retransmission | |
| `W` / `w` | Zero-window advertisement | |
| `^` | Flipped connection (orig/resp swapped) | |

---

## Common Investigation One-Liners

### Getting Oriented

```bash
# What logs were generated?
ls -la *.log

# Time range of capture
zeek-cut -d ts < conn.log | head -1 && zeek-cut -d ts < conn.log | tail -1

# Overview of services
zeek-cut service < conn.log | sort | uniq -c | sort -rn

# All unique source IPs
zeek-cut id.orig_h < conn.log | sort -u

# All unique destination IPs  
zeek-cut id.resp_h < conn.log | sort -u
```

### Finding Suspicious Activity

```bash
# Scanning: hosts with many S0 (unanswered SYN) connections
grep S0 conn.log | zeek-cut id.orig_h | sort | uniq -c | sort -rn | head

# Top talkers by bytes
zeek-cut id.orig_h orig_ip_bytes < conn.log | \
  awk '{a[$1]+=$2} END {for(i in a) print a[i], i}' | sort -rn | head

# Long-running connections (potential C2 beaconing)
zeek-cut uid id.orig_h id.resp_h duration < conn.log | sort -nrk4 | head

# Connections to unusual ports
zeek-cut id.resp_p < conn.log | sort | uniq -c | sort -rn | head -30

# Everything for a specific IP
grep "10.0.0.1" *.log
```

### HTTP Analysis

```bash
# All user agents
zeek-cut user_agent < http.log | sort | uniq -c | sort -rn

# Executable downloads
zeek-cut host uri resp_mime_types < http.log | grep -i "dosexec\|octet-stream"

# POST requests (potential data exfil or credential submission)
grep POST http.log | zeek-cut host uri

# All unique hosts visited
zeek-cut host < http.log | sort -u
```

### DNS Analysis

```bash
# Most queried domains
zeek-cut query < dns.log | sort | uniq -c | sort -rn | head -20

# NXDOMAIN responses (potential DGA)
grep NXDOMAIN dns.log | zeek-cut query | sort | uniq -c | sort -rn | head

# Query types (look for unusual: AXFR, TXT, ANY, CHAOS)
zeek-cut qtype_name < dns.log | sort | uniq -c | sort -rn

# DNS resolvers in use
zeek-cut id.resp_h < dns.log | sort | uniq -c | sort -rn
```

### File Analysis

```bash
# All files by type
zeek-cut mime_type < files.log | sort | uniq -c | sort -rn

# Executable files
grep "dosexec" files.log | zeek-cut filename md5 source

# Extract MD5 hashes for VirusTotal lookups
zeek-cut md5 < files.log | sort -u

# Files with names
zeek-cut filename mime_type md5 < files.log | grep -v "^-"
```

### Email Analysis

```bash
# Who emailed whom
zeek-cut mailfrom rcptto subject < smtp.log

# Email subjects
zeek-cut subject < smtp.log

# Email attachments (cross-reference with files.log)
zeek-cut fuids < smtp.log
```

### TLS/SSL Analysis

```bash
# Server names (SNI)
zeek-cut server_name < ssl.log | sort | uniq -c | sort -rn

# Certificate subjects
zeek-cut subject < ssl.log | sort -u

# Self-signed certificates (subject == issuer)
awk -F'\t' '$10 == $11' ssl.log | zeek-cut server_name subject

# JA3 fingerprints (client TLS fingerprinting)
zeek-cut ja3 < ssl.log | sort | uniq -c | sort -rn
```

### Cross-Log Correlation

```bash
# Find all logs for a specific connection UID
UID="CneXtI3GzF0GLSGJt7"
grep "$UID" *.log

# Find all activity for a host across all logs
HOST="10.0.0.147"
grep "$HOST" *.log

# Link files to connections
# 1. Get file UID from files.log
# 2. Get connection UID from files.log
# 3. Look up connection in conn.log
zeek-cut fuid uid id.orig_h id.resp_h < files.log
```

---

## Host Identification Techniques

| What You Need | Where to Find It |
|---------------|-----------------|
| IP address | `conn.log` — `id.orig_h`, `id.resp_h` |
| MAC address | `conn.log` — `orig_l2_addr`, `resp_l2_addr` |
| Hostname | `dhcp.log` — `host_name`; `kerberos.log`; `ntlm.log` — `hostname` |
| OS | `http.log` — `user_agent`; `software.log` |
| Username | `kerberos.log` — `client`; `ntlm.log` — `username` |
| Domain | `kerberos.log`; `ntlm.log` — `domainname` |
| Browser | `http.log` — `user_agent` |

---

## Quick Acronyms

| Acronym | Meaning |
|---------|---------|
| UID | Unique Identifier (connection-level) |
| FUID | File Unique Identifier |
| IoC | Indicator of Compromise |
| C2 / C&C | Command and Control |
| DGA | Domain Generation Algorithm |
| NXDOMAIN | Non-Existent Domain (DNS response) |
| AXFR | Authoritative Zone Transfer |
| SNI | Server Name Indication (TLS) |
| JA3 | TLS client fingerprint hash |
| MHR | Malware Hash Registry (Team Cymru) |
| NSM | Network Security Monitoring |
