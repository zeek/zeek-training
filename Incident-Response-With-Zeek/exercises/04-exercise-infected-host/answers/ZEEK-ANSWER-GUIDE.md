# Exercise 4 — Answer Guide Using Only Zeek Logs

This guide shows how to answer each question from the Zeek logs alone, without
Wireshark. Every command runs from the exercise directory against logs made with:

```bash
zeek -C -r Traces/2025-01-22-traffic-analysis-exercise.pcap local policy/protocols/conn/mac-logging
```

See "Enabling MAC address logging" in `../README.md` for how to turn on MAC columns.

Timestamps are Unix epoch values. Convert them with `date -u -r <ts>` (macOS) or
`date -u -d @<ts>` (Linux). The capture is from 2025-01-22 (UTC).

The reference answers come from `2025-01-22-traffic-analysis-exercise-answers.pdf`
(malware-traffic-analysis.net). Questions 1 (OS) and 8 (browser) are **not** in that
PDF. Their answers below are inferred from the logs, and the guide says how strong
that evidence is.

| # | Question | Answer | Main log(s) | Matches PDF? |
|---|----------|--------|-------------|--------------|
| 1 | OS | Windows, NT 10.0 kernel (Windows 10 or 11), 64-bit | `software.log`, `http.log` | Not in PDF |
| 2 | Client IP | 10.1.17.215 | `known_hosts.log`, `conn.log`, `dhcp.log` | Yes |
| 3 | MAC | 00:d0:b7:26:4a:74 | `dhcp.log` (or `conn.log` with mac-logging) | Yes |
| 4 | Hostname | DESKTOP-L8C5GSJ | `dhcp.log`, `kerberos.log` | Yes |
| 5 | User account | shutchenson | `kerberos.log` | Yes |
| 6 | Fake page domain | authenticatoor.org | `dns.log`, `ssl.log`, `conn.log` | Yes |
| 7 | C2 IPs | 5.252.153.241, 45.125.66.32, 45.125.66.252 | `http.log`, `conn.log`, `ssl.log`, `notice.log` | Yes |
| 8 | Browser | Microsoft Edge (inferred, not directly observed) | `ssl.log`, `http.log`, `quic.log` | Not in PDF |

---

## Q2. What is the IP address of the infected client?

Start here, because the other questions depend on it.

```bash
grep -v '^#' known_hosts.log
zeek-cut id.orig_h < conn.log | sort | uniq -c | sort -rn | head
```

Result:

```
10.1.17.2      <- domain controller (WIN-GSH54QLW48D)
10.1.17.215    <- only other internal host
 854 10.1.17.215
```

`10.1.17.215` originates almost every connection (854). It is also the only host
that talks to the C2 addresses in Q7:

```bash
zeek-cut id.orig_h id.resp_h < conn.log | grep -E '5\.252\.153\.241|45\.125\.66\.' | sort | uniq -c
```

**Answer: 10.1.17.215**

---

## Q3. What is the MAC address of the infected client?

**Method A — `dhcp.log` (works with any Zeek run):**

```bash
zeek-cut client_addr mac host_name < dhcp.log
```

```
10.1.17.215   00:d0:b7:26:4a:74   DESKTOP-L8C5GSJ
```

**Method B — `conn.log` (only when `policy/protocols/conn/mac-logging` was loaded):**

```bash
zeek-cut id.orig_h orig_l2_addr < conn.log | sort | uniq -c | sort -rn | head
```

```
 854 10.1.17.215       00:d0:b7:26:4a:74
   3 169.254.168.209   00:d0:b7:26:4a:74   <- same NIC, link-local address before the DHCP lease
   1 10.1.17.2         00:24:e8:7f:09:5d   <- domain controller
   1 0.0.0.0           00:d0:b7:26:4a:74   <- same NIC, DHCP DISCOVER
```

> **Check first:** if `grep '^#fields' conn.log` shows no `orig_l2_addr` column, the
> logs were made without `mac-logging`. Re-run the `zeek` command above (see
> "Enabling MAC address logging" in `../README.md`). Method A works either way.

**Answer: 00:d0:b7:26:4a:74**

---

## Q4. What is the hostname of the infected client?

**Method A — DHCP (option 12 hostname, option 81 FQDN):**

```bash
zeek-cut client_addr host_name client_fqdn domain < dhcp.log
```

```
10.1.17.215  DESKTOP-L8C5GSJ  DESKTOP-L8C5GSJ.bluemoontuesday.com  bluemoontuesday.com
```

**Method B — Kerberos (cross-check).** A Windows computer account is the hostname
followed by `$`:

```bash
zeek-cut id.orig_h client < kerberos.log | grep '\$' | sort -u
```

```
10.1.17.215  DESKTOP-L8C5GSJ$/BLUEMOONTUESDAY.COM   (also lower-case variants)
```

Both sources agree.

**Answer: DESKTOP-L8C5GSJ** (domain `bluemoontuesday.com`)

---

## Q5. What is the user account name from the infected client?

A user account in `kerberos.log` is a `client` value **without** a trailing `$`
(names ending in `$` are machine accounts):

```bash
zeek-cut id.orig_h client request_type < kerberos.log | grep -v '\$' | awk '$2!~/^\//' | sort | uniq -c
```

```
  2 10.1.17.215  shutchenson/BLUEMOONTUESDAY      AS
  2 10.1.17.215  shutchenson/BLUEMOONTUESDAY.COM  AS
  7 10.1.17.215  shutchenson/BLUEMOONTUESDAY.COM  TGS
```

The `AS` request at 1737575110 (19:45:10 UTC) is the user's logon: the client asks
the DC for a ticket-granting ticket. `grep -l -i shutchenson *.log` shows that the
name appears only in `kerberos.log`.

There is no `ntlm.log` for this capture, because the client authenticated with
Kerberos only.

**Answer: shutchenson** (domain BLUEMOONTUESDAY)

---

## Q6. What is the likely domain name for the fake Google Authenticator page?

The user browsed over HTTPS, so `http.log` does not show it. Use DNS and the TLS SNI.

```bash
zeek-cut ts query answers < dns.log | grep -i authent
zeek-cut ts id.resp_h server_name < ssl.log | grep -i -E 'authent|burleson'
```

```
1737575134.72  google-authenticator.burleson-appliance.net  104.21.x.x (Cloudflare)
1737575135.39  authenticatoor.org                           82.221.136.26
1737575136.09  82.221.136.26  authenticatoor.org            (ssl.log SNI)
```

Order of events:

1. 19:45:34 — `google-authenticator.burleson-appliance.net` is looked up. This is
   the **redirect** domain, reached from the malicious ad.
2. 19:45:35 — less than one second later, `authenticatoor.org` (note the
   misspelling, "authentica**too**r") is looked up and contacted over TLS.

Check how much data the client received from that server:

```bash
zeek-cut ts id.resp_h service duration resp_bytes < conn.log | grep 82.221.136.26
```

```
1737575135.92  82.221.136.26  ssl  74.3 s  2231551 bytes
```

The client received about 2.2 MB over 74 seconds. Twenty seconds later, at
19:45:56, the first request to the C2 server appears (Q7). The order is
redirect → `authenticatoor.org` → C2. That timing supports `authenticatoor.org` as
the fake page.

**Answer: authenticatoor.org** (redirector:
`google-authenticator.burleson-appliance.net`)

---

## Q7. What are the IP addresses used for C2 servers?

### 7a. 5.252.153.241 — HTTP payload staging and beaconing

```bash
zeek-cut host < http.log | sort | uniq -c | sort -rn | head
```

```
 594 5.252.153.241        <- 594 of the 627 HTTP requests go to one IP, with no hostname
  21 master16.teamviewer.com
```

```bash
zeek-cut host uri < http.log | awk '$1=="5.252.153.241"{print $2}' | sort | uniq -c | sort -rn
```

```
 588 /1517096937                          <- beacon (all return 404)
   1 /api/file/get-file/264872            <- first stage (19:45:56)
   1 /api/file/get-file/29842.ps1         <- PowerShell script
   1 /api/file/get-file/TeamViewer        <- TeamViewer files fetched for remote access
   1 /api/file/get-file/Teamviewer_Resource_fr
   1 /api/file/get-file/TV
   1 /api/file/get-file/pas.ps1
```

Check the beacon interval:

```bash
zeek-cut ts uri < http.log | awk '$2=="/1517096937"{if(p)print int($1-p+0.5); p=$1}' \
  | sort -n | uniq -c | sort -rn | head -3
```

```
 573 5     <- 573 of 587 gaps are ~5 seconds
   5 6
   2 7
```

A fixed check-in about every 5 seconds from 19:45:58 to 20:38:18 is automated
beaconing, not a person browsing.

### 7b. 45.125.66.32 (TCP 2917) and 45.125.66.252 (TCP 443) — TLS C2

```bash
zeek-cut id.resp_h id.resp_p server_name validation_status < ssl.log | grep 45.125.66 | sort -u
zeek-cut ts id.resp_h id.resp_p duration orig_bytes resp_bytes < conn.log | grep 45.125.66
zeek-cut msg < notice.log | sort | uniq -c
```

What points to C2:

- Both use **self-signed certificates**. `notice.log` raises
  `SSL::Invalid_Server_Cert ... (self signed certificate)` twice.
- `45.125.66.32` listens on **non-standard port 2917**, and its SNI is the bare IP.
- `45.125.66.252:443` sends **no SNI**. One session lasts **1527 s (~25 min)**
  with small byte counts in both directions (8.5 KB / 9.6 KB). That pattern fits an
  interactive C2 channel.
- `45.125.66.32:2917` repeatedly sends ~2.6 MB and ~0.5 MB responses, which fits
  tasking or payload delivery.
- Both first appear at 19:59:46, after the 5.252.153.241 staging.

**Answer: 5.252.153.241, 45.125.66.32, 45.125.66.252**

---

## Q1. What is the OS of the client?

```bash
zeek-cut host unparsed_version < software.log
zeek-cut user_agent < http.log | sort | uniq -c | sort -rn
```

Evidence:

- The user agent contains `Windows NT 10.0; Win64; x64`.
- The client runs Windows-only software: `Microsoft NCSI`, `Microsoft BITS/7.8`,
  `Windows-Update-Agent/1309.2410.30012.0`, `Microsoft-Delivery-Optimization/10.1`
  and `Microsoft-CryptoAPI/10.0`.
- It joins an Active Directory domain (Kerberos, LDAP and SMB to the DC in
  `kerberos.log`, `ldap.log` and `smb_mapping.log`).

Limit: "Windows NT 10.0" is reported by **both Windows 10 and Windows 11**, so these
logs cannot tell them apart.

**Answer: Microsoft Windows, 64-bit, NT 10.0 (Windows 10 or 11)**

---

## Q8. What browser was the user using?

Running the README hint gives this:

```bash
zeek-cut user_agent < http.log | sort | uniq -c | sort -rn
```

```
 593 -
  21 Mozilla/4.0 (compatible; MSIE 6.0; DynGate)                  <- TeamViewer, not a browser
   4 Microsoft BITS/7.8
   3 Windows-Update-Agent/...
   2 Microsoft-CryptoAPI/10.0
   2 Microsoft NCSI
   1 Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 10.0; ... Trident/7.0; ...)
   1 Microsoft-Delivery-Optimization/10.1
```

**Do not take this hint at face value.** None of these user agents belongs to the
browser the user browsed with:

- `DynGate` is the TeamViewer remote-access component that the malware installed
  (Q7a).
- The single `MSIE 7.0 ... Trident/7.0` request is the **first-stage download**
  from the C2 server (`/api/file/get-file/264872`). `software.log` labels it
  "MSIE 11", but it was made by the malicious script process, not by a browser the
  user was driving. All of the user's browsing went over HTTPS, so Zeek never sees
  its user agent.

The browser has to be inferred from the TLS SNI and update traffic:

```bash
zeek-cut server_name < ssl.log | grep -i edge | sort | uniq -c
zeek-cut host < http.log | grep -i msedge | sort -u
zeek-cut server_name client_protocol < quic.log
```

```
edge.microsoft.com, static.edge.microsoftapp.net, config.edge.skype.com   (ssl.log)
msedge.b.tlu.dl.delivery.mp.microsoft.com                                 (http.log, Edge updater)
th.bing.com, assets.msn.com over h3/QUIC                                  (quic.log)
```

These are Microsoft Edge's configuration, update and new-tab endpoints, and they
point to Edge.

Limit: this is **inference, not direct observation**. Edge background services
contact these endpoints even when the user browses with another browser. Proving
which browser rendered `authenticatoor.org` would need the TLS client fingerprint
(JA3/JA4, which needs an extra Zeek package) or host-side evidence.

**Answer: most likely Microsoft Edge (inferred from SNI and update traffic; no
browser user agent is visible in the logs).**

---

## Timeline (UTC, 2025-01-22)

| Time | Event | Log |
|------|-------|-----|
| 19:44:56 | DHCP lease: 10.1.17.215 / DESKTOP-L8C5GSJ / 00:d0:b7:26:4a:74 | dhcp.log |
| 19:45:10 | Kerberos AS request for user `shutchenson` | kerberos.log |
| 19:45:34 | DNS for `google-authenticator.burleson-appliance.net` (redirector) | dns.log |
| 19:45:36 | TLS to `authenticatoor.org` (82.221.136.26), ~2.2 MB received | ssl.log, conn.log |
| 19:45:56 | First stage `GET /api/file/get-file/264872` from 5.252.153.241 | http.log |
| 19:45:58 | ~5 s beaconing to `5.252.153.241/1517096937` begins | http.log |
| 19:47:01–05 | TeamViewer files and `pas.ps1` fetched from 5.252.153.241 | http.log |
| 19:59:46 | TLS C2 to 45.125.66.32:2917 (self-signed) | ssl.log, conn.log |
| 20:00:13 | ~25 min TLS session to 45.125.66.252:443 (self-signed, no SNI) | ssl.log, conn.log |
| 20:38:18 | Last beacon to 5.252.153.241 | http.log |
