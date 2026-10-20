---
theme: zeek
---

<!-- _class: lead -->

![bg](https://marp.app/assets/hero-background.svg)

![width:250px](images/zeek-logo.png)
# Introduction to Zeek
### A Zeek training
*Nullcon Berlin, 2026*

---

# About us

<div class="columns">
<div>

## Benjamin Bannier

- ...

</div>
<div>

## Christian Kreibich

Zeek project tech lead

25+ years of Zeek experience

An engineer at Corelight

Recovering academic, Cambridge PhD

</div>
</div>

---

# Agenda

- Zeek's role on your network
- Using Zeek at the command line
- Extending Zeek via its package manager
- Running Zeek clusters
- A deep-dive into Zeek logs

---

# Why Zeek?

Incident response, threat hunting, performance monitoring, traffic analysis,
audits, and policy compliance checks all require one thing:

<center>

## Good network data.

</center>

Zeek gives you "system logs for your network": rich, transactional data that
collect evidence for later analysis. A network flight recorder!

---

![bg w:90%](images/log-vol-vs-fidelity-1.png)

---

![bg w:90%](images/log-vol-vs-fidelity-2.png)

---

![bg w:90%](images/log-vol-vs-fidelity-3.png)

---

![bg w:90%](images/log-vol-vs-fidelity-4.png)

---

![bg w:90%](images/log-vol-vs-fidelity-5.png)

---

![bg w:90%](images/log-vol-vs-fidelity-6.png)

---

# Zeek logs are **network evidence**

Zeek's primary output is **logs**. They capture the activity on your network,
across the protocol stack.

Zeek logs **don't judge**.

Zeek logs are **extremely adaptable** to your site's needs &mdash; the
sweet-spot between full packet capture, Netflow, and alert logs.

---

# Zeek is **three things**

* **A DPI engine:** in-depth parsing of every packet. The parsing creates *events*.

* **A distributed event-based system:** topic-based publish/subscribe *communication* of these events across Zeek.

* **A scripting language:** a domain-specific language that *handles* these events.

---

![bg h:90%](images/zeek-arch-detailed.png)

---

# Examples of Zeek events

<style scoped>pre { font-size: 80%; }</style>

```zeek
event connection_established(c: connection) {
    print fmt("Established connection %s", c$uid);
}

event connection_state_remove(c: connection) {
    print fmt("Connection %s is done", c$uid);
}

event ssl_server_hello(c: connection, version: count,
                       record_version: count, possible_ts: time,
                       server_random: string, session_id: string,
                       cipher: count, comp_method: count) {
    print fmt("Server hello on TLS connection %s", c$uid);
}
```

---

# Zeek ships with a lot of features

- Around 600 types of events
- Some 130 [packet](https://docs.zeek.org/en/current/reference/zeekscript/packet-analyzers.html),
  [protocol](https://docs.zeek.org/en/current/reference/zeekscript/proto-analyzers.html), and
  [file](https://docs.zeek.org/en/current/reference/zeekscript/file-analyzers.html) analyzers
- [75 types of logs](https://docs.zeek.org/en/current/reference/zeekscript/log-files.html)
  for protocols, detections, and behaviors

It's also extremely extensible via scripts, plugins, and packages. More on this
later!

---

# Let's get started

<style scoped>p { font-size: 80%; }</style>

Grab the latest Zeek Docker image and run it:

```shell
$ docker run -it --name zeek-training zeek/zeek
```

In the container, clone our training repository and cd into it.

```console
# git clone --depth 1 https://github.com/zeek/zeek-training.git /opt/zeek-training
# cd /opt/zeek-training/
```

Run the local setup script to pull down additional resources:

```console
# ./setup.sh tutorial
```

---

# Let's get started (continued)

<style scoped>p { font-size: 75%; }</style>

Create a scratch space to do the exercises in:

```console
root@zeek-tutorial:/opt/zeek-training # mkdir -p scratch && cd scratch
```

**NOTE:** In the rest of the slides we'll show `#` for the container prompt for
brevity, assuming you're working in `/opt/zeek-training/scratch`.

To keep a Docker image of this container, run this outside of it:

```shell
$ docker commit zeek-training zeek-training
```

Do a quick check in the container that Zeek works:

```console
# zeek --version
```

---

<!-- _class: chapter -->
# Command-line Zeek

---

# Invoking Zeek

---

# Processing pcaps

---

# Processing live traffic

---

# Loading custom scripts

---

# Providing script values to Zeek

---

<!-- _class: exercise -->
# Exercise: JSON logs

Load a pcap with the addition `tuning/json-logs.zeek`, and take a look at the
logs in your local directory. What do you notice? What do the logs have in
common?

---

<!-- _class: chapter -->
# Zeek packages

---

# Customizing Zeek via packages

Packages can add functionality to Zeek at all levels, including new scripts and
plugins. Almost everything in Zeek is pluggable: users can add packet sources,
protocol parsers, log writers, and more.

---

# Meet zkg, Zeek's package manager

A quick tour of zkg and its available packages.

---

# Working with a package

Install the redis-rce package and run through the steps to show its custom
notices on the included pcap.

---

<!-- _class: exercise -->
# Exercise: the logschema package

This package provides Zeek scripts that generate log schemas for your Zeek
installation. Install the package, then run the following:

```console
$ zeek logschema/export/jsonschema
```

Take a look at your local directory now. What do you find?

---

<!-- _class: chapter -->
# Running Zeek clusters

---

# Basic concepts of a Zeek cluster

In production, Zeek runs as a **cluster of processes**.

Each process (a "node") has a **dedicated responsibility**.

Nodes in the cluster **communicate via pub/sub** on Zeek events.

Running additional nodes, on the same or a different system, allows Zeek
installations to **scale as needed**.

---

# Cluster node types

* **Manager:** one per cluster, central state-keeper and coordination point.

* **Workers:** run the DPI stack, distribute state, and trigger log writes.

* **Proxies:** distributed state-keepers &mdash; a bit like DB shards.

* **Loggers:** one or more per cluster, handle log message output.

---

![bg 20%](images/zeek-cluster-1.png)

---

![bg w:80%](images/zeek-cluster-2.png)

---

![bg w:80%](images/zeek-cluster-3.png)

---

# Managing a cluster via zeekctl

Defining a cluster, deploying its configuration, starting/stopping, and checking
its status.

---

<!-- _class: exercise -->
# Exercise: run your own cluster

Define a few nodes, deploy it, create some network I/O and see logs establish.

---

# Managing a cluster via systemd

Zeek 9 added mature support for systemd generators and a `zeek.conf` config file,
so you get things like:

```console
# systemctl start zeek.target
```

```console
# systemctl restart zeek-worker@1
```

For details, refer to [our docs](https://docs.zeek.org/en/master/advanced/deployment/systemd.html).

---

<!-- _class: chapter -->
# Working with Zeek logs

---

# TSV logs, JSON logs, zeek-cut, and jq

A quick intro to basic textual log wrangling.

---

# Meet conn.log

The "anchor" for many Zeek logs. Introduce notion of an entry for (nearly) every
flow, and UID as an identifier.

---

<div class="columns">
<div>

```console
$ zeek -r ssl.pcap tuning/json-logs
$ cat conn.log | jq
```

</div>
<div>

```json
{
  "ts": 1737691432.129397,
  "uid": "CHSQTt28ehluo38Y8h",
  "id.orig_h": "192.168.0.10",
  "id.orig_p": 55364,
  "id.resp_h": "142.250.189.164",
  "id.resp_p": 443,
  "proto": "tcp",
  "service": "ssl",
  "duration": 0.07700109481811523,
  "orig_bytes": 555,
  "resp_bytes": 25370,
  "conn_state": "SF",
  "local_orig": true,
  "local_resp": false,
  "missed_bytes": 0,
  "history": "ShADadFf",
  "orig_pkts": 27,
  "orig_ip_bytes": 1967,
  "resp_pkts": 28,
  "resp_ip_bytes": 26834,
  "ip_proto": 6
}
...
```

</div>
</div>

---

# Pivoting: dns.log to conn.log

Explore a DNS lookup, and how its DNS transaction leads to the corresponding
conn.log entry.

---

<!-- _class: exercise -->
# Exercise: TBD

TODO: we should check our available pcaps and come up with a good example. Or go
back to the Redis one, since we now have better understanding.

---

<!-- _class: chapter -->
# Wrapping up

---

# Next steps

A few pointers at our docs, Slack, Youtube, etc.
