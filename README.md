# WazabiEDR_Agent

User-mode agent for [WazabiEDR](../WazabiEDR_Doc/README.md): pumps
the kernel driver, spools events to disk, hosts the plugin named pipe.

## Build & run

```powershell
cargo build --release
.\target\release\WazabiEDR_Agent.exe --help
```

The driver must be installed first (see
[`WazabiEDR_Doc/usage/installing-driver.md`](../WazabiEDR_Doc/usage/installing-driver.md)).

## Documentation

Start with **[ARCHITECTURE.md](ARCHITECTURE.md)** — a self-contained overview (FR)
of what the agent does and how it talks to the driver, plugins and the Wazabi server.

The rest of the documentation lives in
**[../WazabiEDR_Doc/](../WazabiEDR_Doc/README.md)**. Highlights for the agent:

- [Driver pump loop](../WazabiEDR_Doc/architecture/agent-pump.md)
- [On-disk spool](../WazabiEDR_Doc/architecture/agent-spool.md)
- [Plugin server](../WazabiEDR_Doc/architecture/plugin-server.md)
- [Plugin manifest store](../WazabiEDR_Doc/architecture/plugin-manifest.md)
- [Plugin identity verification](../WazabiEDR_Doc/architecture/plugin-identity.md)
- [Plugin wire protocol](../WazabiEDR_Doc/architecture/plugin-protocol.md)
- [Running the agent (operator)](../WazabiEDR_Doc/usage/running-agent.md)
- [Config reference (every flag/env)](../WazabiEDR_Doc/reference/config-reference.md)
