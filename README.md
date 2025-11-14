# KAPSULA

**KAPSULA** **message store-and-forward (MSF) node** designed to provide a **truly independent, censorship- and blocking-resistant** way to send messages over the internet — and sometimes even **without an internet connection**.

It operates **completely independently**, requiring **no registration**. This independence imposes certain usage restrictions on public KAPSULA services to prevent abuse. If your usage pattern doesn’t fit within these limits, you can **deploy your own personal message node** and bypass all restrictions.

Running your own node is also ideal if you want to **protect your communications — and even the fact that communication is taking place — from prying eyes**.

**KAPSULA MSF traffic is indistinguishable from regular HTTPS**, blending seamlessly with everyday web browsing. With **ESNI**, you can **hide the MSF endpoint behind another HTTPS website**. Alternatively, you can:

- Place it on a **non-standard port** to evade network scanners,
- Or **embed the endpoint within regular website paths** for added stealth.

## Run it on-premise or use a hosted service

### Self-hosted MSF

```bash
$ docker run -d \
	-v /path/to/data:/data \
	--name msf-node \
	ghcr.io/kapsula-chat/msf-node
```

Check the Docker logs to find the invitation code — it must be provided by every user authorized to communicate through your instance.

```bash
$ docker logs msf-node
```

From now on, all messages addressed to you will be stored and forwarded through your own node.

### Hosted MSF service

https://kapsula.chat/msf-hosted

## Open software

This software is licensed under the AGPL-3.0. Contributions are strongly encouraged and welcome!

### Important Licensing Notice

All code committed to this repository is **automatically released under the AGPL-3.0 license** — the same license that governs the project.

By contributing, you **irrevocably grant** your code under AGPL-3.0. This means:

- Your contribution becomes part of the project and is distributed under AGPL-3.0 **from the moment of submission**.
- **You cannot later change the licensing terms** for your code or restrict its use under AGPL-3.0.
- Anyone receiving the software (including your code) may use, modify, and redistribute it **only under the terms of AGPL-3.0**, including the requirement to share source code.

**Contribute only if you fully agree** to these terms. Thank you for helping build free, open, and independent software!

## Metrics (Netdata / Prometheus)

KAPSULA exposes a lightweight Prometheus-format metrics endpoint at `/health` (same path used by the server). The endpoint returns simple gauge/counter metrics that are safe to scrape frequently and are suitable for Netdata or any Prometheus-compatible collector.

Built-in metrics exposed:

- `kapsula_queued_messages` — number of messages currently queued for write
- `kapsula_goroutines` — number of Go goroutines
- `kapsula_free_space_bytes` — free disk space in the data directory (bytes)
- `kapsula_mem_alloc_bytes` — bytes allocated and still in use
- `kapsula_mem_sys_bytes` — bytes obtained from the OS
- `kapsula_heap_alloc_bytes` — heap bytes allocated
- `kapsula_gc_count` — completed GC cycles

Netdata can scrape Prometheus-format endpoints. Two common ways to collect these metrics:

1) Netdata `python.d.prometheus` collector (recommended when using Netdata installed on a host)

Create or edit `/etc/netdata/python.d/prometheus.conf` and add a `kapsula` job that points at your instance. Example:

```yaml
kapsula:
  name: kapsula
  url: "http://127.0.0.1:8080/health"
  update_every: 10
  timeout: 5
```

After creating the config, restart Netdata:

```bash
sudo systemctl restart netdata
```

Netdata will automatically map Prometheus metrics to charts. If you prefer to control chart names/units, use the `prometheus` collector mappings as described in Netdata docs.

2) Use Netdata Cloud or any Prometheus server (or Prometheus plugin)

If you already run Prometheus, add a scrape job to `prometheus.yml`:

```yaml
scrape_configs:
  - job_name: 'kapsula'
    static_configs:
      - targets: ['127.0.0.1:8080']
    metrics_path: /health
    scrape_interval: 15s
```

Then point Netdata to your Prometheus server (Netdata can read Prometheus as a data source), or connect Netdata Cloud to visualize metrics.

Docker-compose example (exposes `/health` on host):

```yaml
services:
  kapsula:
    image: ghcr.io/kapsula-chat/msf-node:latest
    volumes:
      - ./data:/data
    ports:
      - "8080:8080"
    restart: unless-stopped
```

Notes and recommendations

- The `/health` endpoint is intentionally lightweight and avoids expensive DB scans. It is safe to scrape with a 10s–30s interval.
- If you run Netdata remotely, make sure your firewall allows Netdata to reach the KAPSULA instance's `/health` endpoint.
- Badger-specific metrics (file sizes and counts) are now collected periodically and exposed as:
  - `kapsula_badger_total_size_bytes`
  - `kapsula_badger_sst_files`
  - `kapsula_badger_vlog_files`
  - `kapsula_badger_last_observed_seconds`

These metrics are updated every 30s by a background collector.

Additionally, the server writes a Netdata Prometheus mapping YAML to the data directory at `./data/netdata/kapsula-prometheus-mapping.yaml`. Drop this file into your Netdata `python.d/prometheus` mappings to get a ready-made dashboard mapping for the KAPSULA metrics.

## Environment variables

- KAPSULA_ACCESS_TOKEN
  - Default: ""
  - Example: "secret-token"
  - Description: If set, enables key-based authentication when adding users to the node. The client must provide this token when connecting.