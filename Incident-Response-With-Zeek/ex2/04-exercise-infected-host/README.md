# Exercise 4: Security Incident — Fake Google Authenticator

**Duration**: ~45-60 minutes
**Objective**: Investigate a real-world infection using Zeek logs, piecing together the full attack chain.

## Scenario

You work as an analyst at a Security Operations Center (SOC). Someone contacts your team to report that a coworker downloaded a suspicious file after searching for "Google Authenticator."

The caller provides information similar to these social media posts:
- [LinkedIn - Unit42](https://www.linkedin.com/posts/unit42_2025-01-22-wednesday-a-malicious-ad-led-activity-7288213662329192450-ky3V/)
- [X/Twitter - Unit42](https://x.com/Unit42_Intel/status/1882448037030584611)

Based on the caller's initial information, you confirm there was an infection. You retrieve a packet capture (pcap) of the associated traffic.

**Source**: [malware-traffic-analysis.net - 2025-01-22](https://www.malware-traffic-analysis.net/2025/01/22/index.html)

---

## Getting Started

```bash
zeek -C -r Traces/2025-01-22-traffic-analysis-exercise.pcap local
```

This generates all standard Zeek logs. Start your investigation.

---

## Investigation Questions

Answer these for your incident report:

### Host Identification

1. **What is the OS of the client?**
   - Hint: Check `http.log` user agents, and look for OS-specific traffic patterns

2. **What is the IP address of the infected client?**
   - Hint: Start with `conn.log` — who is generating the most suspicious traffic?

3. **What is the MAC address of the infected client?**
   - Hint: `zeek-cut orig_l2_addr < conn.log | sort | uniq -c | sort -rn`

4. **What is the hostname of the infected client?**
   - Hint: Check `dhcp.log`, `kerberos.log`, or `ntlm.log`

5. **What is the user account name from the infected client?**
   - Hint: Check `kerberos.log` or `ntlm.log` for authentication events

### Attack Chain

6. **What is the likely domain name for the fake Google Authenticator page?**
   - Hint: Look at `http.log` and `dns.log` around the time of the initial infection
   - What search led the user to this page?

7. **What are the IP addresses used for C2 (Command & Control) servers?**
   - Hint: Look for connections after the initial download — unusual ports, long durations, periodic beaconing

8. **What browser was the user using?**
   - Hint: `zeek-cut user_agent < http.log | sort | uniq -c | sort -rn`

---

## Investigation Approach

### Step 1: Get the Big Picture
```bash
# What time range does this capture cover?
zeek-cut ts < conn.log | head -1 && zeek-cut ts < conn.log | tail -1

# What services are present?
zeek-cut service < conn.log | sort | uniq -c | sort -rn

# How many unique internal hosts?
zeek-cut id.orig_h < conn.log | sort -u | wc -l
```

### Step 2: Find the Infected Host
```bash
# Look for HTTP downloads of executables
zeek-cut host uri resp_mime_types < http.log | grep -i exe

# Check files.log for suspicious downloads
zeek-cut source filename mime_type md5 < files.log | grep dosexec

# Check notice.log for any alerts
cat notice.log
```

### Step 3: Map the Attack Timeline
```bash
# Filter all activity for the infected host IP
INFECTED_IP="<ip-you-found>"
grep $INFECTED_IP conn.log | zeek-cut ts id.resp_h id.resp_p service duration | sort
```

### Step 4: Identify C2
```bash
# Look for connections to unusual ports after the infection timestamp
# Look for periodic connections (beaconing)
# Look for self-signed or unusual TLS certificates in ssl.log
```

---

## Answers

See `answers/2025-01-22-traffic-analysis-exercise-answers.pdf` for the reference solution.

Compare your findings — did you identify the same indicators? Did you find anything additional?

---

## Key Takeaways

- **IR is iterative** — you discover new indicators as you investigate, and each leads to more
- **Start broad, then narrow** — `conn.log` overview first, then dive into protocol-specific logs
- **Correlate across logs** — UIDs connect `conn.log` to `http.log` to `files.log`
- **Timeline is everything** — sort by timestamp to reconstruct the attack chain
- **Don't panic about volume** — `zeek-cut` and standard Unix tools (`grep`, `sort`, `uniq`, `awk`) are all you need
