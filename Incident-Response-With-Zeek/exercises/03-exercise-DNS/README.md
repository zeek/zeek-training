# Exercise 3: DNS Attack Detection

**Duration**: ~30-40 minutes
**Objective**: Analyze DNS traffic for reconnaissance and attack indicators using Zeek logs and custom heuristics.

## Prerequisites

- Completed Exercises 0-2
- Familiarity with `conn.log` and basic Zeek log querying

## Overview

DNS is both essential infrastructure and a rich attack surface. Attackers use DNS for:

- **Reconnaissance**: Version queries, zone transfers, reverse lookups
- **Command & Control**: DNS tunneling, DGA domains
- **Data Exfiltration**: Encoding data in DNS queries

This exercise covers detecting these activities with Zeek.

---

## Part 1: Exploring `dns.log`

```bash
zeek -C -r Traces/01-exercise-hm.edu.dns.pcap local
```

### Questions

1. **How many different query types are there?**
   ```bash
   zeek-cut qtype_name < dns.log | sort | uniq -c | sort -rn
   ```

2. **Are the infrequent query types interesting?**
   - Look for `AXFR`, `TXT`, `ANY`, `SRV`, `CHAOS` — these are often recon indicators

3. **What are the most frequently queried domains?**
   ```bash
   zeek-cut query < dns.log | sort | uniq -c | sort -rn | head -20
   ```

4. **What DNS resolvers are in use?**
   ```bash
   zeek-cut id.resp_h < dns.log | sort | uniq -c | sort -rn
   ```

5. **Any long-lived DNS connections?** (unusual for DNS)

6. **Anything interesting in the NXDOMAIN responses?**
   ```bash
   grep NXDOMAIN dns.log | zeek-cut query | sort | uniq -c | sort -rn | head
   ```
   Random-looking domain names returning NXDOMAIN can indicate DGA (Domain Generation Algorithm) malware.

---

## Part 2: DNS Reconnaissance Techniques

### 2a: Identifying `dig` Commands

Can you identify DNS reconnaissance tool usage (like `dig`) in the logs?

- Look for NS lookups, SOA queries, and AXFR attempts
- These typically come from a single source IP in rapid succession

### 2b: Zone Transfer Attempts (AXFR)

**What it is**: AXFR requests attempt to download the entire DNS zone file from a server. If successful, the attacker gets a complete map of all hosts in the domain.

**What to look for**:
```bash
grep AXFR dns.log
```

Questions:
- Was the zone transfer successful or refused?
- Check the `rcode_name` field — `REFUSED` means the server is properly configured

### 2c: Reverse PTR Lookups

**What it is**: Reverse DNS lookups map IP addresses back to hostnames. Mass PTR queries indicate network reconnaissance (host enumeration).

```bash
grep PTR dns.log | zeek-cut query rcode_name | head -20
```

Questions:
- How many PTR queries were issued?
- How many returned results (`NOERROR`) vs. not found (`NXDOMAIN`)?
- Can you start classifying subnets based on the hostnames returned? (VPN, HPC, production infrastructure)

**Parse PTR results into readable IPs**:
```bash
grep PTR dns.log | awk -F"\t" '{if ($16 == "NOERROR") print $10, $22}' | \
  sed -E 's/^([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+)\.in-addr\.arpa/\4.\3.\2.\1/'
```

### 2d: Version.bind Queries

**What it is**: Querying `version.bind` in the CHAOS class reveals the DNS server software and version — useful for finding vulnerabilities.

```bash
dig @target_dns_server version.bind txt chaos
```

**What to look for in Zeek logs**:
```bash
grep version.bind dns.log
```

- `qclass_name` will show `C_CHAOS` (class 3) instead of the normal `C_INTERNET` (class 1)
- Multiple servers queried from the same source = active reconnaissance

---

## Part 3: Automated Detection with DNS Heuristics

The `dns-heuristics/` package provides automated detection for common DNS attacks.

```bash
zeek -C -r Traces/01-exercise-hm.edu.dns.pcap scripts/dns-heuristics
```

Then check `notice.log`:
```bash
cat notice.log
```

### What the Heuristics Detect

| Script | Detection |
|--------|-----------|
| `dns-threshold.zeek` | Excessive DNS lookups (threshold + spike detection) |
| `dns-hitters.zeek` | Top DNS queriers |
| `version.bind.zeek` | `version.bind` CHAOS queries |
| `zonetransfer.zeek` | AXFR zone transfer attempts |
| `ptr.zeek` | Mass reverse PTR lookups |
| `netbios.zeek` | NetBIOS-related DNS queries |
| `txt.zeek` | Excessive TXT queries (potential tunneling) |

### Understanding `dns-threshold.zeek`

This is the most complex script. It implements two detection strategies:

1. **Daily Threshold**: Alerts when a host exceeds N total lookups per day (configurable: 100K, 200K, 300K, etc.)
2. **Spike Detection**: Alerts when a host does 400+ lookups within 1 second, consistently (3+ times)

The spike detection is designed to catch sudden bursts — like a malware infection triggering rapid DNS lookups.

---

## Bonus: Additional DNS Pcaps

The `Traces/misc-dns-pcaps/` directory has targeted scenarios:

| Pcap | Scenario |
|------|----------|
| `01-HostThreshold.pcap` | High-volume DNS host |
| `02-PTRThreshold.pcap` | Mass PTR lookups |
| `03-QueryThreshold.pcap` | Query flood |
| `04-TxtThreshold.pcap` | Excessive TXT queries |
| `05-VersionBind.pcap` | `version.bind` recon |
| `06-netbios.dns.pcap` | NetBIOS DNS traffic |
| `07-failed-axfr-zone-transfer.pcap` | Failed zone transfer |
| `08-dig-hm.edu.pcap` | `dig` reconnaissance |

Run each with:
```bash
zeek -C -r Traces/misc-dns-pcaps/<pcap-file> scripts/dns-heuristics
```

---

## Key Takeaways

- DNS is one of the **most revealing log sources** for IR — nearly every network activity generates DNS queries
- **NXDOMAIN floods** often indicate DGA malware or misconfigured systems
- **AXFR attempts** are a serious recon indicator — they should always be refused and alerted on
- **Mass PTR lookups** reveal network enumeration
- **`version.bind`** queries in CHAOS class are pure reconnaissance
- **Threshold + spike detection** catches both sustained abuse and sudden bursts
