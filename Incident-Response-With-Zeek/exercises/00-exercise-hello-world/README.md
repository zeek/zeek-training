# Exercise 0: Hello World

**Duration**: ~5 minutes
**Objective**: Verify your Zeek installation and understand Zeek's event-driven execution model.

## Prerequisites

- Zeek installed ([install guide](https://docs.zeek.org/en/current/install.html))
- Set up the alias to suppress checksum warnings:
  ```bash
  alias zeek="zeek -C 'FilteredTraceDetection::enable=F'"
  ```

## Setup Check

Confirm Zeek is working:
```bash
zeek -h
```

You should see Zeek's help/usage output.

## The Exercise

Run the Hello World script:
```bash
zeek 00-exercise-hello-world.zeek
```

### What to Observe

1. **Two messages appear** — one from `zeek_init()` and one from `zeek_done()`.
2. These correspond to Zeek's **lifecycle events**:
   - `zeek_init()` fires when Zeek starts up (before processing any traffic)
   - `zeek_done()` fires when Zeek shuts down (after all traffic is processed)

### Why This Matters

Zeek is an **event-driven** system. Everything in Zeek — from parsing packets to generating logs — is built on events. Understanding `zeek_init` and `zeek_done` is the foundation:

- `zeek_init` is where you set up global state, initialize tables, and configure your analysis
- `zeek_done` is where you finalize reports, flush data, and clean up

In later exercises, you'll see events like `connection_established`, `http_request`, `dns_request`, and `smtp_data` — all following this same pattern.

## Quick Reference

| Concept | Description |
|---------|-------------|
| `event` | A named occurrence that Zeek scripts can handle |
| `zeek_init()` | Fires once at startup |
| `zeek_done()` | Fires once at shutdown |
| `print fmt(...)` | Formatted output (like `printf` in C) |

## Next Steps

Once you see the output successfully, you're ready for **Exercise 1: Exploring Logs**.
