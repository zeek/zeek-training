---
theme: zeek
_class: lead
---

![bg](https://marp.app/assets/hero-background.svg)

![width:250px](./zeek-logo.png)
# Introduction to Zeek
### A Zeek training
*Nullcon Berlin, 2026*

---

# About us

Benjamin Bannier
- ...

Christian Kreibich
- ...

---

# Agenda

- Zeek's role in your network
- Using Zeek at the command line
- Extending Zeek via its package manager
- Running Zeek clusters
- A deep-dive into Zeek logs

---

# Why Zeek?

Zeek is the equivalent of system logs for your network: transactional data that
collect evidence for later analysis -- a network flight recorder.

---

# Logs as evidence

Zeek logs capture the activity on your network, across the protocol stack. They
are extremely adaptable to your site's needs an policy -- your ideal sweetspot
between full packet capture, Netflow, and alert logs.

---

# Zeek is three things

A DPI engine: in-depth parsing of every packet on the wire.

A distributed event-based system: topic-based pub/sub.

A scripting language: a DSL for network traffic analysis.

---

# Zeek's basic architecture

A walk-through of the DPI -> event queue -> script layer stack.

---

# Let's get started

Details on grabbing the Docker image and how to prep it for the training.

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

In production, Zeek runs as a cluster of processes. Each process (a "node") has
a dedicated responsibility. Nodes in the cluster communicate via pub/sub on Zeek
events. Running additional nodes, on the same or a different system, allows Zeek
installations to scale as needed.

---

# Cluster node types

Introduce the four basic types of nodes.

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

systemd generators and zeek.conf.

Likely no exercise for this, since we're not immediately set up to use systemd
in the container. More as an FYI.

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
