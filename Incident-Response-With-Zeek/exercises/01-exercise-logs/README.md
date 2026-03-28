# Exercise 1: Exploring Zeek Logs

**Duration**: ~30-40 minutes
**Objective**: Get familiar with Zeek's core log files by analyzing packet captures and answering investigative questions.

## Prerequisites

- Completed Exercise 0 (Zeek is installed and working)
- Alias configured: `alias zeek="zeek -C 'FilteredTraceDetection::enable=F'"`

## Overview

This exercise uses four different packet captures, each highlighting different network activity. You'll learn to read and query Zeek's most important log files.

## Traces

| Pcap | Focus |
|------|-------|
| `Traces/01-conn.log.pcap` | General network traffic — connections, HTTP, files, SMTP, MySQL |
| `Traces/02-spamming.pcap` | Email/spam traffic |
| `Traces/03-ssh-bruteforce.pcap` | SSH brute-force attack |
| `Traces/04-http-file-transfer-incorrect-filetype.pcap` | File transfers with mismatched MIME types |

---

## Part A: Connection Log (`conn.log`)

```bash
zeek -r Traces/01-conn.log.pcap local
```

The `conn.log` is your **fundamental starting point** for any investigation. It records every connection Zeek observes.

### Questions

1. **What's the longest running connection?**
   - Hint: `zeek-cut uid duration < conn.log | sort -nrk2 | head`

2. **Which IP sent the most data?**
   - Hint: Look at `orig_ip_bytes` and `resp_ip_bytes` fields

3. **Other than TCP, UDP, ICMP — what protocols are in use?**
   - Hint: `zeek-cut proto service < conn.log | sort | uniq`

4. **Find a UDP flow.** What does it look like compared to TCP?
   - Hint: `grep udp conn.log`

5. **Examine the `history` field.** What do the letters mean?
   - Reference: `S`=SYN, `H`=SYN+ACK, `A`=ACK, `D`=data, `F`=FIN, `R`=RST
   - Uppercase = originator, lowercase = responder

6. **Is there any IPv6 in the sample?**

7. **Can you find hosts scanning the network?**
   - Hint: Look for connections with `conn_state` of `S0` (SYN sent, no reply)

8. **What services are running?**
   - Hint: `zeek-cut service < conn.log | sort | uniq -c | sort -rn`

---

## Part B: HTTP Log (`http.log`)

Using the same pcap (`01-conn.log.pcap`), examine `http.log`:

### Questions

1. **What anti-virus software got updated?**
   - Look at `user_agent` and `host` fields

2. **What did a user search for on Google?**
   - Look at `uri` fields containing search queries

3. **What was the Netgear device being exploited for?**
   - Look for suspicious URIs targeting Netgear

4. **Did any executable get downloaded?**
   - Check `resp_mime_types` for `application/x-dosexec`

5. **Are any web servers running on non-standard ports** (not 80/tcp)?
   - Hint: `zeek-cut id.resp_p < http.log | sort | uniq -c | sort -rn`

---

## Part C: Files Log (`files.log`)

### Questions

1. **What different file types do you see?**
   - Hint: `zeek-cut mime_type < files.log | sort | uniq -c | sort -rn`

2. **Any files that don't match their declared type?**

3. **Any executable files?**

4. **Check some MD5 hashes for malware** on [VirusTotal](https://www.virustotal.com)
   - Hint: `zeek-cut md5 < files.log`

5. **Automate hash lookups** with Zeek's built-in Malware Hash Registry:
   ```bash
   zeek -r Traces/01-conn.log.pcap local policy/frameworks/files/detect-MHR.zeek
   ```
   Then check `notice.log` for any `TeamCymruMalwareHashRegistry::Match` entries.

---

## Part D: SSH Log

```bash
zeek -r Traces/01-conn.log.pcap local
```

### Questions

1. What SSH connections are present?
2. What port was SSH running on?
3. What versions of SSH client/server are in use?
4. How many bytes were transferred?

### Bonus: SSH Brute Force

```bash
zeek -r Traces/03-ssh-bruteforce.pcap local
```

1. **Was the brute force successful?** How can you tell?
   - Hint: Look at `ssh.log` — successful auth shows `auth_success: T`
   - Also check `notice.log` for Zeek's built-in SSH brute-force detection

---

## Part E: SMTP Log

```bash
zeek -r Traces/01-conn.log.pcap local
```

### Questions

1. Who sent email to whom?
2. What was the subject of the email?
3. Where did the email originate from? (check `path`, `first_received` fields)
4. What was the content of the email?

---

## Part F: File Type Mismatch (Bonus)

```bash
zeek -r Traces/04-http-file-transfer-incorrect-filetype.pcap scripts/04-http-file-transfer-incorrect-filetype.zeek
```

This exercise uses a custom script to extract files. Examine the extracted files — do their actual types match what the HTTP headers claimed?

---

## Key Takeaways

- **`conn.log`** is your starting point for every investigation
- **`zeek-cut`** is your best friend for extracting specific fields
- **UIDs** tie related log entries together across different log files
- **`history`** and **`conn_state`** tell you the TCP state machine story
- Zeek logs far more detail than traditional netflow — use it

## Useful One-Liners

```bash
# Top talkers by bytes
zeek-cut id.orig_h orig_ip_bytes < conn.log | sort | awk '{a[$1]+=$2} END {for(i in a) print a[i], i}' | sort -rn | head

# All services detected
zeek-cut service < conn.log | sort | uniq -c | sort -rn

# Failed connections (potential scanning)
grep S0 conn.log | zeek-cut id.orig_h | sort | uniq -c | sort -rn | head

# HTTP user agents
zeek-cut user_agent < http.log | sort | uniq -c | sort -rn
```
