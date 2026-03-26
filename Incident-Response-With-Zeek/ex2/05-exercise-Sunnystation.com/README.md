# Exercise 5: Security Incident - Windows Compromise (Sunnystation.com)

**Duration**: ~60 minutes
**Objective**: Conduct a full incident response investigation of a Windows host compromise using only Zeek logs.

## Scenario

You are investigating a suspected compromise of a Windows workstation. A packet capture has been provided covering the timeframe of the incident.

Your goal is to reconstruct what happened: who was affected, what the attacker did, and how the attack progressed.

**Source**: [malware-traffic-analysis.net - 2022-02-23](https://www.malware-traffic-analysis.net/2022/02/23/index.html)

---

## Getting Started

```bash
zeek -C -r Traces/2022-02-23-traffic-analysis-exercise.pcap local
```

This generates all standard Zeek logs from the capture.

---

## Investigation Questions

### Phase 1: Host Identification (The "Who")

1. **What are the IP addresses of the internal hosts?**
   ```bash
   zeek-cut id.orig_h local_orig < conn.log | grep T | sort -u
   ```

2. **What are the hostnames?**
   - Check `dhcp.log` for DHCP hostnames
   - Check `kerberos.log` and `ntlm.log` for Windows authentication
   - Check `dns.log` for PTR lookups

3. **What are the domain names in use?**
   - Look in `kerberos.log`, `ntlm.log`, and `dns.log`

4. **What are the MAC addresses?**
   ```bash
   zeek-cut id.orig_h orig_l2_addr < conn.log | sort -u
   ```

5. **What software is running on the hosts?**
   - Check `http.log` user agents
   - Check `ssh.log` client/server versions
   - Check `software.log` if generated

### Phase 2: User Identification (The "Who Else")

6. **What user accounts are active?**
   - Check `kerberos.log` and `ntlm.log` for usernames

7. **Map users to hosts** - which user was on which machine?

### Phase 3: Activity Mapping (The "What")

8. **Map hosts to activity** - what was each host doing?
   ```bash
   # Per-host service breakdown
   for ip in $(zeek-cut id.orig_h local_orig < conn.log | grep T | awk '{print $1}' | sort -u); do
     echo "=== $ip ==="
     grep "$ip" conn.log | zeek-cut service | sort | uniq -c | sort -rn
   done
   ```

9. **What is the timeline of events?**
   - Sort key events by timestamp to reconstruct the attack chain

10. **What indicators of compromise can you identify?**
    - Suspicious domains in `dns.log`
    - Malicious file downloads in `files.log`
    - C2 communication patterns in `conn.log`
    - Alerts in `notice.log`

---

## Investigation Methodology

This exercise illustrates the **iterative nature of IR with Zeek** (slides 29, 102-103):

### Start Broad
```bash
# Overview: what's in this capture?
wc -l *.log
zeek-cut service < conn.log | sort | uniq -c | sort -rn

# Time window
zeek-cut ts < conn.log | sort -n | head -1
zeek-cut ts < conn.log | sort -n | tail -1
```

### Narrow Down
```bash
# Find suspicious connections
grep -v "^#" conn.log | zeek-cut id.orig_h id.resp_h id.resp_p service conn_state | \
  grep S0 | sort | uniq -c | sort -rn | head

# Find external connections
zeek-cut id.orig_h id.resp_h id.resp_p service < conn.log | sort | uniq -c | sort -rn | head -30
```

### Pivot on Findings
```bash
# Once you find a suspicious IP, look at EVERYTHING about it
SUSPECT="<suspicious-ip>"
grep "$SUSPECT" *.log
```

### Reconstruct the Story
Put your findings in chronological order. The attack likely follows this pattern:
1. Initial access (how did the attacker get in?)
2. Execution (what ran on the victim?)
3. C2 establishment (how does the attacker maintain access?)
4. Actions on objectives (what did the attacker do?)

---

## Answers

See `answers/2022-02-23-traffic-analysis-exercise-answers.pdf` for the reference solution.

---

## Why This Exercise Matters

This exercise demonstrates three critical IR principles:

1. **IR with Zeek is iterative** - you learn as you go. Each indicator leads to new ones.
2. **You don't need to know everything upfront** - start with what you have and expand.
3. **Every small discovery helps** - a hostname here, a user agent there, they all build the picture.

The answers to "Who, When, What, Where, How" emerge naturally from systematic log analysis.

---

## Key Takeaways

- Windows environments generate rich authentication logs (`kerberos.log`, `ntlm.log`) that identify users and hosts
- **`conn.log` is always your starting point** - it gives you the network-level overview
- **Cross-log correlation via UIDs** is how you build the full story
- Real incidents are messy - there will be legitimate traffic mixed with malicious activity
- Document your findings as you go - timestamps, IPs, hostnames, and the connections between them
