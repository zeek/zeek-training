# Exercise 2: Phishing Analysis with Zeek

**Duration**: ~45-60 minutes
**Objective**: Analyze phishing attacks end-to-end using Zeek — from email delivery through credential theft.

## Prerequisites

- Completed Exercises 0 and 1
- Familiarity with `conn.log`, `http.log`, and `files.log`

## Overview

Phishing is a multi-stage attack. This exercise walks through each stage and shows how Zeek can detect it:

```
Phishing Email Arrives
    |
    +-- Attachment? --> Extract files --> Identify IoCs (hashes, types)
    |
    +-- Embedded Link? --> Extract URLs --> Track if clicked
    |
    +-- Credential Form? --> Track HTTP POSTs --> Identify stolen creds
    |
    +-- Lateral Movement --> Track attacker reuse of stolen creds
```

The `smtp-url-analysis` package ([github.com/initconf/smtp-url-analysis](https://github.com/initconf/smtp-url-analysis)) provides production-ready detection for all of these stages.

---

## Part 1: Extract Files from Email Attachments

**Scenario**: An email arrives with attachments. What files were sent?

```bash
zeek -C -r Traces/01-extract-files.pcap scripts/extract-all.zeek
```

### Investigate

1. Check `smtp.log` — who sent the email, to whom, with what subject?
2. Check `files.log` — what files were attached?
   ```bash
   zeek-cut filename mime_type md5 < files.log
   ```
3. Look in the `extract_files/` directory. Identify each file:
   ```bash
   cd extract_files/ && file *
   ```
4. **Check MD5 hashes** against [VirusTotal](https://www.virustotal.com)

### What You Should Find

- A PNG image, a text file, and an HTML document
- The `files.log` shows MIME types, sizes, and hashes for each
- The `smtp.log` connects the files back to the email metadata (sender, recipient, subject)

---

## Part 2: Embedded Links and Click Tracking

**Scenario**: An email contains a link to download software. Did the recipient click it? What happened?

```bash
zeek -C -r Traces/02-embedded-links-file-download.pcap scripts/smtp-url-analysis scripts/extract-all.zeek
```

### Investigate

1. Check `smtpurl_links.log` — what URLs were embedded in the email?
2. Check `smtp_clicked_urls.log` — did anyone click the link?
3. Check `notice.log` — did Zeek raise any alerts?
4. Check `files.log` — was a file downloaded? What type?

### Key Questions

- What was the suspicious file type in the URL?
- Who sent the email? Who received it?
- What file was ultimately downloaded?
- How does Zeek correlate the "email link" with the "HTTP download"?

### Expected Output

- `smtpurl_links.log` shows URLs extracted from the email body
- `smtp_clicked_urls.log` shows the recipient clicked the link and downloaded a `.exe`
- `notice.log` shows `SMTPurl::WatchedFileType` and `SMTPurl::FileDownload` alerts

---

## Part 3: Credential Theft via HTTP POST

**Scenario**: A phishing page captures credentials submitted via an HTTP form.

```bash
zeek -C -r Traces/03-credentials-via-HTTP-post.pcap scripts/smtp-url-analysis scripts/extract-all.zeek
```

### Investigate

1. Check `http.log` — find the POST request to `/login.php`
2. Check `notice.log` — look for `SMTP::SensitivePOST` and `SMTP::SensitivePasswd`
3. **What credentials were stolen?** (visible in the notice message)

### What You Should Find

- A POST to `foo.webdamdb.com/login.php` with cleartext username and password
- Zeek's `smtp-url-analysis` package detects credential submission and generates notices

---

## Part 4: RFC2047 Encoding Bypass

**Scenario**: Attackers use RFC2047 encoding to bypass subject-line filters.

```bash
zeek -C -r Traces/04-smtp-rfc2047-decode.pcap scripts/smtp-url-analysis
```

### Background

RFC 2047 allows encoding non-ASCII text in email headers. Attackers abuse this to bypass regex-based email filters. A subject like:
```
=?UTF-8?B?Q29tcGFjdCBEZXNpZ24gZm9yIEVhc3kgU3RvcmFnZQ==?=
```
...decodes to a readable string that filters would have caught.

### Investigate

1. What is the encoded subject line?
2. What does it decode to?
3. Why would this bypass email security appliances?

---

## Part 5: Pattern Matching in Email Bodies

**Scenario**: Detect sensitive keywords (like "password") in email message bodies.

```bash
zeek -C -r Traces/05-watch-pattern-in-email.pcap scripts/05-watch-pattern-in-email.zeek
```

### Investigate

1. Read the `scripts/05-watch-pattern-in-email.zeek` script
2. What pattern is it looking for?
3. What event does it hook into? (`mime_all_data`)
4. How does it generate a notice when a match is found?

---

## Bonus: Additional Pcaps

The `Traces/misc-pcaps/` directory contains additional scenarios:

| Pcap | Scenario |
|------|----------|
| `06-BogusSiteURL-example.pcap` | Bogus/suspicious site URLs in email |
| `07-HTTPSensitivePOST.pcap` | Sensitive data in HTTP POST |
| `08-extortion.pcap` | Extortion email |
| `09-smtp-SensitiveURLinMail.pcap` | Sensitive URIs embedded in email |
| `10-smtp-all.pcap` | Multiple SMTP scenarios combined |

Run them with:
```bash
zeek -C -r Traces/misc-pcaps/<pcap-file> scripts/smtp-url-analysis scripts/extract-all.zeek
```

---

## Key Takeaways

- Phishing is a **multi-stage attack** — Zeek can detect each stage
- **File extraction** gives you attachments for sandboxing and hash checks
- **URL extraction** from email bodies enables proactive link tracking
- **Click tracking** correlates email URLs with subsequent HTTP requests
- **HTTP POST monitoring** catches credential theft in real-time
- **RFC2047 decoding** defeats encoding-based filter evasion

## Understanding the Scripts

| Script | Purpose |
|--------|---------|
| `extract-all.zeek` | Extract all files from any protocol (SMTP, HTTP, FTP) |
| `smtp-url-analysis/` | Production package: URL extraction, click tracking, credential detection |
| `04-smtp-rfc2047-decode.zeek` | Decode RFC2047-encoded email headers |
| `05-watch-pattern-in-email.zeek` | Regex pattern matching on email body content |
