# WazabiEDR_Agent

Agent user-mode de l'EDR **WazabiEDR** : pompe le driver kernel, normalise et spoole les events
sur disque (NDJSON + zstd), héberge le serveur de plugins (named pipe), et expédie les lots au
serveur en HTTPS (shipper). Sources de télémétrie : le [driver](../WazabiEDR_Driver/) et des
[plugins](../WazabiEDR_PluginSDK/) ; destination : le [serveur](../WazabiEDR_Server/).

## Build & run

```powershell
cargo build --release
.\target\release\WazabiEDR_Agent.exe
```

Le driver doit être installé d'abord (voir
[`WazabiEDR_Driver/doc/usage/installing-driver.md`](../WazabiEDR_Driver/doc/usage/installing-driver.md)).

## Documentation

Toute la documentation vit désormais **dans les dépôts** (plus de dépôt `WazabiEDR_Doc`).

- 📐 **[ARCHITECTURE.md](ARCHITECTURE.md)** — le document à lire en premier : cycle de vie & threads,
  driver, spool, shipper, serveur de plugins, moteur de détection Waza, configuration.
- 🏃 [doc/usage/running-agent.md](doc/usage/running-agent.md) — lancer l'agent, lire la sortie.
- 🚚 [doc/usage/configuring-shipper.md](doc/usage/configuring-shipper.md) — pointer vers le serveur, token DPAPI.
- 📑 [doc/reference/config-reference.md](doc/reference/config-reference.md) — tout `agent.json`, threads, arrêt.

Voir aussi : la référence des événements kernel
([`WazabiEDR_Driver/doc/reference/event-types.md`](../WazabiEDR_Driver/doc/reference/event-types.md)),
le protocole de fil des plugins
([`WazabiEDR_PluginSDK/doc/reference/plugin-protocol.md`](../WazabiEDR_PluginSDK/doc/reference/plugin-protocol.md)),
et le dépannage transverse
([`WazabiEDR_Server/doc/usage/troubleshooting.md`](../WazabiEDR_Server/doc/usage/troubleshooting.md)).
