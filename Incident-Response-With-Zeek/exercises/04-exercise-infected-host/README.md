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
zeek -C -r Traces/2025-01-22-traffic-analysis-exercise.pcap local policy/protocols/conn/mac-logging
```

This generates all standard Zeek logs. Start your investigation.

#### Enabling MAC address logging

By default `conn.log` does not record MAC addresses. The script that adds them,
`policy/protocols/conn/mac-logging`, ships with Zeek but is commented out in the
default `local.zeek`. You can turn it on in one of two ways.

**Option 1 — per run (no config change).** Add the script name to the command line,
as the command above does: `zeek -C -r <pcap> local policy/protocols/conn/mac-logging`.

**Option 2 — permanently.** Uncomment the line in `site/local.zeek`:

```bash
# Find the file (e.g. /usr/local/zeek/share/zeek/site/local.zeek)
LOCAL=$(zeek-config --site_dir)/local.zeek
grep -n mac-logging "$LOCAL"
# Change:   # @load policy/protocols/conn/mac-logging
# to:       @load policy/protocols/conn/mac-logging
```

After that, `zeek -C -r <pcap> local` includes MAC addresses. On a live sensor
managed by `zeekctl`, run `zeekctl deploy` to apply the change.

**Verify** that the new columns are present:

```bash
grep '^#fields' conn.log | tr '\t' '\n' | grep l2_addr
# orig_l2_addr
# resp_l2_addr
```

Each column holds the source MAC of the **first packet Zeek saw from that endpoint**
(`orig_l2_addr` for the originator, `resp_l2_addr` for the responder). For traffic to the internet, `resp_l2_addr` is the gateway's MAC,
not the remote host's. Only local hosts' MAC addresses are meaningful.

---

## Investigation Questions

Answer these for your incident report:

### Host Identification

1. **What is the OS of the client?**
   - Hint: Check `software.log` and `http.log` user agents, and look for OS-specific traffic patterns
   - Note: "Windows NT 10.0" is reported by both Windows 10 and 11; the logs cannot tell them apart

2. **What is the IP address of the infected client?**
   - Hint: Start with `conn.log` — who is generating the most suspicious traffic?

3. **What is the MAC address of the infected client?**
   - Hint: `zeek-cut client_addr mac < dhcp.log`, or `zeek-cut id.orig_h orig_l2_addr < conn.log | sort | uniq -c | sort -rn` (needs `mac-logging`, see above)

4. **What is the hostname of the infected client?**
   - Hint: Check `dhcp.log` (`host_name`), then confirm in `kerberos.log` (machine accounts end in `$`)

5. **What is the user account name from the infected client?**
   - Hint: Check `kerberos.log` for `client` names that do not end in `$` (this capture has no `ntlm.log`)

### Attack Chain

6. **What is the likely domain name for the fake Google Authenticator page?**
   - Hint: Look at `http.log` and `dns.log` around the time of the initial infection
   - What search led the user to this page?

7. **What are the IP addresses used for C2 (Command & Control) servers?**
   - Hint: Look for connections after the initial download — unusual ports, long durations, periodic beaconing

8. **What browser was the user using?**
   - Hint: `zeek-cut user_agent < http.log | sort | uniq -c | sort -rn` — but check which process made each request. The user browsed over HTTPS, so their browser's user agent never reaches `http.log`. Use `server_name` in `ssl.log` and `quic.log` to infer the browser.

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
See `answers/ZEEK-ANSWER-GUIDE.md` for how to derive each answer from the Zeek logs alone, including the OS and browser questions that the PDF does not cover.

Compare your findings — did you identify the same indicators? Did you find anything additional?

---

## Key Takeaways

- **IR is iterative** — you discover new indicators as you investigate, and each leads to more
- **Start broad, then narrow** — `conn.log` overview first, then dive into protocol-specific logs
- **Correlate across logs** — UIDs connect `conn.log` to `http.log` to `files.log`
- **Timeline is everything** — sort by timestamp to reconstruct the attack chain
- **Don't panic about volume** — `zeek-cut` and standard Unix tools (`grep`, `sort`, `uniq`, `awk`) are all you need
