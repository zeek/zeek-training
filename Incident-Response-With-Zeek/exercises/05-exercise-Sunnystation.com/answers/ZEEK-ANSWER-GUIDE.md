# Exercise 5 — Answer Guide Using Only Zeek Logs

This guide shows how to answer each question from the Zeek logs alone, and checks
every result against the reference PDF
(`2022-02-23-traffic-analysis-exercise-answers.pdf`, malware-traffic-analysis.net).
Run the commands from the exercise directory against logs made with:

```bash
zeek -C -r Traces/2022-02-23-traffic-analysis-exercise.pcap local policy/protocols/conn/mac-logging
```

Timestamps are Unix epoch values. Convert them with `date -u -r <ts>` (macOS) or
`date -u -d @<ts>` (Linux). The capture covers 2022-02-23 18:22:24 – 19:07:04 UTC.

## Summary

| Host | IP | MAC | User | Malware | First malicious event (UTC) |
|------|----|-----|------|---------|-----------------------------|
| DESKTOP-VD151O7 | 172.16.0.131 | 2c:27:d7:d2:06:f5 | tricia.becker | Formbook (XLoader) | 18:29:19 |
| DESKTOP-W5TFTQY | 172.16.0.170 | 00:12:f0:64:d1:d9 | everett.french | Emotet | 18:25:44 |
| DESKTOP-KPQ9FDB | 172.16.0.149 | 00:1b:fc:7b:d1:c0 | nick.montgomery | Emotet + spambot | 18:24:34 |

| Server | IP | Evidence |
|--------|----|----------|
| SUNNYSTATION-DC (domain controller) | 172.16.0.52 | `kerberos.log` service names, `ntlm.log` |
| SUNNYFILESERVER (file server) | 172.16.0.53 | `smb_mapping.log` |

Every value in both tables, and every IOC list below, matches the PDF. The PDF's
Emotet C2 list for 172.16.0.170 (33 IPs) is reproduced exactly by the filters in
Q10b.

What Zeek logs **cannot** do on their own is name a malware family. The names
Formbook and Emotet come from matching the observed patterns (URL structure,
TLS behaviour, file hashes) to public threat intelligence. Each section states
which pattern points to which family.

---

## Phase 1: Host Identification

### Q1. What are the IP addresses of the internal hosts?

```bash
zeek-cut host < known_hosts.log
zeek-cut id.orig_h local_orig < conn.log | grep T | sort -u
```

```
known_hosts.log:  172.16.0.52  172.16.0.53  172.16.0.131  172.16.0.149  172.16.0.170
conn.log (T):     0.0.0.0  172.16.0.131  172.16.0.149  172.16.0.170
```

> **Note:** the README's `local_orig` command lists only hosts that **start**
> connections. It misses 172.16.0.52 (DC) and 172.16.0.53 (file server), which only
> respond in this capture. `known_hosts.log` lists both. `0.0.0.0` is the source
> address of a DHCP request, not a host.

**Answer:** clients 172.16.0.131, .149, .170; servers 172.16.0.52, .53.

### Q2. What are the hostnames?

```bash
zeek-cut client_addr mac host_name client_fqdn < dhcp.log
zeek-cut id.orig_h client < kerberos.log | grep '\$' | sort -u     # machine accounts
zeek-cut id.resp_h path < smb_mapping.log | sort -u               # server names
zeek-cut service < kerberos.log | sort | uniq -c | sort -rn | head
```

```
172.16.0.131  2c:27:d7:d2:06:f5  DESKTOP-VD151O7  DESKTOP-VD151O7.sunnystation.com
172.16.0.170  00:12:f0:64:d1:d9  DESKTOP-W5TFTQY  DESKTOP-W5TFTQY.sunnystation.com
172.16.0.149  00:1b:fc:7b:d1:c0  DESKTOP-KPQ9FDB  DESKTOP-KPQ9FDB.sunnystation.com
172.16.0.53   \\SUNNYFILESERVER\everett.french  (and \nick.montgomery, \tricia.becker, \IPC$)
ldap/SUNNYSTATION-DC.sunnystation.com, cifs/SUNNYSTATION-DC.sunnystation.com, ...
```

The Kerberos machine accounts (`DESKTOP-VD151O7$` and so on) confirm the DHCP
hostnames. `ntlm.log` also has `server_nb_computer_name = SUNNYSTATION-DC` for
172.16.0.52. The README's PTR hint gives nothing here: `dns.log` has no PTR
queries (`zeek-cut qtype_name < dns.log | grep -c PTR` returns 0).

### Q3. What are the domain names in use?

```bash
zeek-cut client < kerberos.log | awk -F/ '{print toupper($2)}' | sort | uniq -c
zeek-cut domainname server_dns_computer_name < ntlm.log | sort -u
zeek-cut client_fqdn domain < dhcp.log
```

**Answer:** AD domain `sunnystation.com` (NetBIOS name `SUNNYSTATION`).

`dhcp.log` shows `domain = localdomain` (DHCP option 15, set by the DHCP server).
The FQDN the clients register is `*.sunnystation.com`. The `localdomain` suffix
explains the `wpad.localdomain` / `isatap.localdomain` NXDOMAIN responses in
`dns.log`. Those responses are benign.

### Q4. What are the MAC addresses?

```bash
zeek-cut id.orig_h orig_l2_addr < conn.log | sort | uniq -c | sort -rn
zeek-cut client_addr mac < dhcp.log        # works without mac-logging
```

```
369 172.16.0.149  00:1b:fc:7b:d1:c0
360 172.16.0.170  00:12:f0:64:d1:d9
180 172.16.0.131  2c:27:d7:d2:06:f5
  1 37.44.244.177 00:09:12:96:5d:c9   <- ICMP unreachable from a C2 IP; the MAC is the gateway's
```

The `conn.log` columns exist only when `mac-logging` is loaded (see the exercise 4
README, "Enabling MAC address logging").

### Q5. What software is running on the hosts?

```bash
zeek-cut host software_type unparsed_version < software.log
zeek-cut id.orig_h user_agent < http.log | sort | uniq -c
```

```
172.16.0.131  Microsoft NCSI
172.16.0.149  Mozilla/5.0 (Windows NT 10.0; Win64; x64; Trident/7.0; rv:11.0) like Gecko
172.16.0.149  Microsoft-CryptoAPI/10.0
```

All three clients run Windows. The `Windows NT 10.0` token is reported by both
Windows 10 and 11, so the logs cannot tell them apart. The IE 11 user-agent string
on 172.16.0.149 appears in exactly one request: the Emotet DLL download (Q10c).
Windows download APIs, which macro and script downloaders often call, can also
send this string, so it does not prove the user was browsing with IE.
There is no `ssh.log`; SSH does not appear in this capture.

---

## Phase 2: User Identification

### Q6. What user accounts are active?

User accounts are Kerberos `client` values that do **not** end in `$`:

```bash
zeek-cut id.orig_h client request_type < kerberos.log | grep -v '\$' | awk '$2!~/^(-|\/)/' | sort | uniq -c
zeek-cut id.orig_h username hostname domainname < ntlm.log | sort | uniq -c
```

```
172.16.0.131  tricia.becker/SUNNYSTATION(.COM)    AS, TGS
172.16.0.149  nick.montgomery/SUNNYSTATION(.COM)  AS, TGS
172.16.0.170  everett.french/SUNNYSTATION(.COM)   AS, TGS
ntlm.log:  172.16.0.131  tricia.becker  DESKTOP-VD151O7  SUNNYSTATION
```

**Answer:** `tricia.becker`, `everett.french`, `nick.montgomery`.

### Q7. Map users to hosts

Each user's Kerberos AS request (logon) comes from a single IP:

```bash
zeek-cut ts id.orig_h client request_type < kerberos.log | awk '$4=="AS" && $3!~/\$/' | sort -n
```

| Logon (UTC) | IP | Host | User |
|-------------|----|------|------|
| 18:23:08 | 172.16.0.170 | DESKTOP-W5TFTQY | everett.french |
| 18:23:17 | 172.16.0.131 | DESKTOP-VD151O7 | tricia.becker |
| 18:23:49 | 172.16.0.149 | DESKTOP-KPQ9FDB | nick.montgomery |

The file server's home shares in `smb_mapping.log`
(`\\SUNNYFILESERVER\<username>`) show the same three users.

---

## Phase 3: Activity Mapping

### Q8. Map hosts to activity

For each host, list external connections excluding DNS, broken down by
destination, port, state and service:

```bash
for h in 172.16.0.131 172.16.0.149 172.16.0.170; do
  echo "=== $h ==="
  zeek-cut id.orig_h id.resp_h id.resp_p conn_state service < conn.log |
    awk -v h=$h '$1==h && $2!~/^(172\.16\.|224\.|239\.)/ && $3!=53 {print $3, $4, $5}' |
    sort | uniq -c | sort -rn | head
done
```

| Host | Activity that stands out |
|------|--------------------------|
| .131 | Plain-HTTP GETs to 21 different domains, all with path `/uar3/?<base64-like>`; 21 of the 28 gaps between requests are 5–6 s |
| .170 | Many TLS connections on 443/8080/80 to bare IPs with **no SNI** and **self-signed** certificates; 19 IPs with only refused (REJ) or unanswered (S0) attempts |
| .149 | The same no-SNI TLS pattern on 443/8080 to 3 IPs, **plus outbound SMTP on 25/465/587** to about 25 mail servers at 19:07 |

Port 80 carrying TLS (`168.197.250.14:80`, service `ssl`) is itself an anomaly.
Zeek's dynamic protocol detection identified the protocol from the payload, not
from the port number.

### Q9. What is the timeline of events?

| UTC | Host | Event | Log |
|-----|------|-------|-----|
| 18:22:24 | — | Capture starts | conn.log |
| 18:23:08–49 | all | Kerberos logons of the three users | kerberos.log |
| 18:24:34 | .149 | `GET www.ajaxmatters.com/c7g8t/zbBYgukXYxzAF2hZc/` → PE file (Emotet DLL) | http.log, files.log, pe.log |
| 18:24:43 | .149 | First TLS to 135.148.121.246:8080 (Emotet C2) | conn.log, ssl.log |
| 18:25:44 | .170 | TLS to `dalgahavuzu.com` (178.211.56.194:443), 1.1 MB received (Emotet DLL) | dns.log, ssl.log, conn.log |
| 18:25:53 | .170 | First Emotet C2 TLS (27.254.174.84:8080) | ssl.log |
| 18:29:19 | .131 | `GET 156.96.154.210/Ocklqc.jpg` → 719,872-byte byte-reversed PE (Formbook) | http.log, files.log |
| 18:30:38–18:34:40 | .131 | Formbook C2 `GET /uar3/?...` to 21 domains; 9 more domains fail in DNS | http.log, dns.log |
| 19:07:01–05 | .149 | Spambot: SMTP to 21 mail servers; spam sent with attachment `kenmarefarmersunion.com.xlsm` | smtp.log, files.log, conn.log |
| 19:07:04 | — | Capture ends | conn.log |

### Q10. What indicators of compromise can you identify?

#### 10a. 172.16.0.131 — Formbook (XLoader)

**Payload download:**

```bash
zeek-cut ts host uri status_code resp_mime_types user_agent < http.log | grep Ocklqc
zeek-cut ts mime_type seen_bytes sha256 < files.log | grep -v -E 'x509|ocsp' | head -4
```

```
156.96.154.210  /Ocklqc.jpg  200  -  -        (no MIME type identified, no user agent)
seen_bytes 719872  sha256 2620bf96201e9f328aee98a74ce5b87f221e761a8b2662974b35f90991404337
```

The file is named `.jpg`, but Zeek found no MIME type for it, and the request had
no user agent. To show that the file is byte-reversed (as the PDF says), extract
it with Zeek and look at its last two bytes:

```bash
PCAP=$PWD/Traces/2022-02-23-traffic-analysis-exercise.pcap
cd "$(mktemp -d)"                      # keep extracted malware out of the repo
zeek -C -r "$PCAP" frameworks/files/extract-all-files
F=$(zeek-cut seen_bytes extracted < files.log | awk '$1==719872{print $2}')
tail -c 2 extract_files/$F | xxd        # 5a4d = "ZM" = the PE "MZ" header written backwards
```

**C2 (21 domain/IP pairs, 29 requests):**

```bash
zeek-cut id.resp_h host uri < http.log | awk '$3 ~ /^\/uar3\//{print $1, $2}' | sort -u
```

All 21 pairs match the PDF exactly (23.227.38.74 www.katchybugonsale.com,
72.167.191.69 www.privilegetroissecurity.com, … 66.29.145.216 www.ban-click.com).
The pattern is many unrelated domains, a fixed path `/uar3/`, two parameters (one
carrying a base64-like blob) and a near-fixed interval. The PDF attributes this
pattern to Formbook/XLoader. Zeek shows the pattern; naming the family takes
external threat intelligence.

**C2 domains that failed in DNS (9):**

```bash
zeek-cut id.orig_h query rcode_name < dns.log |
  awk '$1=="172.16.0.131" && $3!="NOERROR" && $3!="-"' | grep -v -E 'wpad|isatap'
```

```
www.32342240.xyz  www.barrcoplumbingsupply.com  www.byaliciafryearson.com
www.e-scooters.frl  www.freedomteaminc.com  www.jmtmjz.com  www.klassociates.info
www.krpano.pro  (NXDOMAIN)          www.centroimprenta.xyz  (SERVFAIL)
```

All 9 match the PDF.

#### 10b. 172.16.0.170 — Emotet

**DLL download (over TLS, so the URL is not visible):**

```bash
zeek-cut ts query answers < dns.log | grep dalgahavuzu
zeek-cut ts id.resp_h id.resp_p duration resp_bytes < conn.log | grep 178.211.56.194
```

```
dalgahavuzu.com -> 178.211.56.194;  443/tcp, 26.3 s, 1,135,569 bytes received
```

Zeek cannot show that this download was an Emotet DLL, because the content is
encrypted. The PDF's attribution relies on URLhaus. What Zeek does show is that a
~1.1 MB download was immediately followed (9 s later) by the C2 pattern below.

**C2 — successful TLS (14 IPs).** This filter keeps TLS sessions from the host
that have **no SNI**. Every legitimate Microsoft connection in this capture sends
an SNI, so they all drop out:

```bash
zeek-cut id.orig_h id.resp_h id.resp_p server_name validation_status < ssl.log |
  awk -F'\t' '$1=="172.16.0.170" && $4=="-" {print $2":"$3, $5}' | sort | uniq -c
```

The server certificates are self-signed (`validation_status`), and `notice.log`
reports 14 `SSL::Invalid_Server_Cert ... self signed certificate` notices for this
host. Sessions that show `-` are TLS resumptions with no certificate exchange.

**C2 — failed attempts (19 IPs).** These are connections to external IPs that
were refused or never answered, with no service identified:

```bash
zeek-cut id.orig_h id.resp_h id.resp_p conn_state service < conn.log |
  awk -F'\t' '$1=="172.16.0.170" && $2!~/^172\.16\./ && $5=="-" &&
              ($4=="REJ"||$4=="S0"||$4=="RSTRH") {print $2":"$3, $4}' | sort | uniq -c
```

Together the two filters return 33 IPs. That set is identical to the PDF's list
for this host: 14 "HTTPS traffic" and 19 "attempted TCP connections". Emotet
carries a hard-coded list of C2 IPs and tries them in turn on 443/8080/80, many of
them offline. That explains the refused connections, mostly in groups of five
retries.

#### 10c. 172.16.0.149 — Emotet with spambot

**DLL download (plain HTTP, so it is fully visible):**

```bash
zeek-cut ts host uri resp_mime_types user_agent < http.log | grep ajaxmatters
zeek-cut mime_type seen_bytes sha256 < files.log | grep dosexec
grep -v '^#' pe.log | cut -f3-7
zeek-cut note msg sub < notice.log | grep Cymru
```

```
www.ajaxmatters.com  /c7g8t/zbBYgukXYxzAF2hZc/  application/x-dosexec
sha256 14b57211308ac8ad2a63c965783d9ba1c2d1930d0cafd884374d143a481f9bf3   <- same as PDF
pe.log: I386, compile_ts 1645628939 (2022-02-23 15:08:59 UTC), WINDOWS_GUI
TeamCymruMalwareHashRegistry::Match  Detection rate: 43% ...
```

The PE compile time is about 3 h 15 min before the download. Compile times can be
forged, so this is a weak indicator.

> **Reproducibility caveat:** the Team Cymru notice comes from a **live DNS
> lookup made when Zeek runs**, not from the pcap. With no network access the
> notice does not appear, and the detection rate and "Last seen" values change
> over time.

**C2 (3 IPs):** use the same no-SNI filter as for .170, leaving out mail ports:

```bash
zeek-cut id.orig_h id.resp_h id.resp_p server_name < ssl.log |
  awk -F'\t' '$1=="172.16.0.149" && $4=="-" && $3!~/^(25|465|587)$/ {print $2":"$3}' | sort | uniq -c
```

```
28 135.148.121.246:8080    5 144.217.88.125:443    2 134.209.156.68:443
```

This matches the PDF.

**Spambot:**

```bash
zeek-cut id.orig_h id.resp_p < conn.log | awk '$2==25||$2==465||$2==587' | sort | uniq -c
zeek-cut ts id.resp_h id.resp_p helo mailfrom rcptto subject tls < smtp.log
zeek-cut source filename mime_type sha256 < files.log | grep SMTP
```

```
.149 -> port 25: 6, 465: 4, 587: 23 connections, 21 distinct servers   (only this host sends SMTP)
helo [173.166.146.112]   (the same HELO for every session)
mailfrom hrd5_hr@idn-ltd.com  rcptto conniebanner28@yahoo.com
subject "Farmers Union Oil Company of Kenmare"
attachment kenmarefarmersunion.com.xlsm
  sha256 4a1ee5d0defbb58b80c7f8e54b710b107200e5a0b7b421e44ed4e61ce23645df
```

A workstation should not send mail directly to outside mail servers on
25/465/587. That alone is a strong spambot indicator. Most sessions upgrade to
TLS (`tls = T`), so their contents are hidden. Zeek parsed only the unencrypted
session, which carries a macro-enabled spreadsheet (`.xlsm`): the usual Emotet
malspam lure. This is the same email the PDF exports with Wireshark's IMF export.
Zeek logs it in `smtp.log` and `files.log` without extra steps.

---

## Mapping to the PDF's tasks

| PDF task | Zeek answer | Section |
|----------|-------------|---------|
| Hosts / usernames (MAC – IP – host – user) | Summary table | Q2, Q4, Q6, Q7 |
| Malware type per host and start time | .131 Formbook 18:29; .170 Emotet 18:25; .149 Emotet + spambot 18:24 | Q9, Q10 |
| Formbook download, C2, failed DNS | Exact match | Q10a |
| Emotet .170 download and C2 (33 IPs) | Exact match | Q10b |
| Emotet .149 DLL, hash, C2, spambot | Exact match | Q10c |
