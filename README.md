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
