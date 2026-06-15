# Référence de configuration de l'agent

Source de vérité unique : `%ProgramData%\WazabiEDR\agent.json`. L'agent **n'a aucune option en
ligne de commande** et **aucune variable d'environnement** — lancer le binaire avec un argument
quelconque imprime un pointeur vers ce fichier et sort. Le fichier est lu **une fois** au
démarrage ; pas de rechargement à chaud.

Source : [`src/config.rs`](../../src/config.rs) (loader + section `agent`),
[`src/shipper/config.rs`](../../src/shipper/config.rs) (section `shipper`),
`src/plugin/{server,manifest}.rs` (côté plugin — chemins codés en dur, non configurables).

## Emplacement & ACL

| Chemin | Rôle |
|---|---|
| `%ProgramData%\WazabiEDR\agent.json` | La configuration de l'agent. ACL Administrateurs uniquement à l'installation. |
| `%ProgramData%\WazabiEDR\plugins\` | Store de manifests de plugins. Codé en dur ; ACL Admin. |
| `\\.\WazabiEDR` | Device du driver que l'agent ouvre. |
| `\\.\pipe\WazabiEDR_plugin` | Named pipe du serveur de plugins. |

`%ProgramData%` est lu dans la variable d'environnement ; à défaut, `C:\ProgramData`.

Le fichier peut être absent au premier démarrage : l'agent écrit alors un **squelette par
défaut** au chemin attendu (en créant le dossier parent au besoin) et continue avec les valeurs
par défaut en mémoire. Le squelette inclut une section `shipper` pré-désactivée avec des valeurs
d'exemple à éditer. Si l'écriture échoue (ACL, disque plein), l'agent log une fois sur stderr et
continue — le démarrage n'est jamais bloqué par un échec d'écriture de config.

## Schéma

```json
{
  "agent": {
    "console_output": true,
    "spool_dir": "C:\\ProgramData\\WazabiEDR\\spool",
    "max_bytes_per_file": 1048576,
    "max_age_secs": 10,
    "max_total_bytes": 268435456,
    "channel_capacity": 1024,
    "zstd_level": 3
  },
  "shipper": {
    "enabled": true,
    "server_url": "https://wazabi.example.com",
    "agent_id": "5f1b3a8e-1c4f-4d2e-9b8a-7e3f6a9c0d11",
    "tenant_id": "acme",
    "tags": { "env": "prod" },
    "token_encrypted_b64": "AQAAANC...",
    "verify_tls": true,
    "timeout_secs": 30,
    "poll_interval_secs": 5,
    "max_backoff_secs": 300
  }
}
```

Les deux sections sont optionnelles. `agent` absente → tous les défauts ci-dessous. `shipper`
absente (ou `enabled: false`) → mode **spool-only**.

### Section `agent`

| Champ | Type | Défaut | Signification |
|---|---|---|---|
| `console_output` | bool | `true` | Imprime les events kernel (lignes lisibles) et plugin (JSON) sur **stdout**. Les lignes de **diagnostic** stderr (`[agent] …`, `[plugin] …`) ne sont pas affectées. `false` pour un déploiement en service. |
| `spool_dir` | string | `%ProgramData%\WazabiEDR\spool` | Dossier de spool racine. Lots kernel à la racine, lots plugin sous `<dir>/plugins/`. |
| `max_bytes_per_file` | u64 | `1048576` (1 Mio) | Fait tourner le fichier actif à cette taille. |
| `max_age_secs` | u64 | `10` | Fait tourner le fichier actif à cet âge, même non plein. |
| `max_total_bytes` | u64 | `268435456` (256 Mio) | Plafond par spool ; les plus vieux lots sont évincés au-delà. Kernel et plugin ont chacun ce budget. |
| `channel_capacity` | usize | `1024` | Taille de la file producteur → writer du spool. Pleine → event jeté. |
| `zstd_level` | i32 | `3` | Niveau de compression des lots scellés. `1` (rapide) … `22` (lent). |

### Section `shipper`

Notes opérationnelles (génération du token DPAPI, ACL, échecs courants) :
[`configuring-shipper.md`](../usage/configuring-shipper.md).

| Champ | Défaut | Requis | Signification |
|---|---|---|---|
| `enabled` | `true` | non | Bascule sans retirer la section. |
| `server_url` | — | **oui** | URL de base du serveur (sans chemin). Le shipper ajoute `/api/v1/agents/{agent_id}/logs`. `/` final retiré. |
| `agent_id` | — | **oui** | UUID attribué par `POST /api/v1/agents/enroll`. Pré-provisionné aujourd'hui. |
| `tenant_id` | — | non | Envoyé en `X-Wazabi-Tenant`. |
| `tags` | `{}` | non | Chaque entrée → `X-Wazabi-Tag-<clé>: <valeur>`. Clés `[A-Za-z0-9_-]`. |
| `token_encrypted_b64` | — | l'un des deux | Cryptogramme DPAPI-LOCAL_MACHINE du `agent_token`, en base64. |
| `token_plain` | — | l'un des deux | `agent_token` en clair. Dev uniquement ; log un avertissement. |
| `verify_tls` | `true` | non | Toujours `true` (rustls) ; champ conservé pour compat future. |
| `timeout_secs` | `30` | non | Timeout HTTP lecture/écriture. |
| `poll_interval_secs` | `5` | non | Sommeil entre deux scans quand rien à envoyer. |
| `max_backoff_secs` | `300` | non | Plafond du backoff exponentiel après échec réessayable. |

Exactement un de `token_encrypted_b64` / `token_plain` est requis quand la section est activée.

## Aide-mémoire de réglage

| Objectif | Ajuster |
|---|---|
| Réduire le taux d'écriture disque | `max_bytes_per_file` et `max_age_secs` plus grands |
| Réduire le CPU au scellage | `zstd_level: 1` |
| Plus de marge sur les pics d'events | `channel_capacity` plus grand |
| Latence de livraison plus courte | `max_age_secs` plus petit (ex. `2`) |
| Moins de disque consommé | `max_total_bytes` plus petit |
| Tourner sans surveillance | `console_output: false` |

## Constantes codées en dur

| Constante | Valeur | Où |
|---|---|---|
| `MAX_CONCURRENT_SESSIONS` | 64 | `src/plugin/server.rs` |
| `MAX_FRAME_BYTES` | 1 Mio | `src/plugin/protocol.rs` |
| `SCHEMA_VERSION` (proto plugin) | 1 | `src/plugin/protocol.rs` |
| `EVENT_VERSION` (events kernel) | **4** côté agent | `src/ipc/events.rs` |
| `MANIFEST_RELOAD_INTERVAL_SEC` | 5 | `src/plugin/server.rs` |
| `STATS_LOG_INTERVAL_SEC` | 30 | `src/plugin/server.rs` |
| `HEARTBEAT_SEC` (annoncé) | 30 | `src/plugin/server.rs` |

> **Mismatch de version à connaître.** L'agent attend `EVENT_VERSION = 4`, mais le **driver**
> (`WazabiEDR_Driver`) émet actuellement la **version 3** (en-tête sans `trunc_count`). Les deux
> côtés doivent être synchronisés : tant que le driver n'est pas monté en v4, l'agent rejettera
> ses événements (version inconnue). À réconcilier.

## Threads créés au démarrage

| Thread | Où | Rôle |
|---|---|---|
| (main) | `main` | Boucle de pompage du driver |
| `wedr-spool-<dir>` | `spool/writer.rs` | Writer du spool (rotation + scellage) — un par spool |
| `wedr-shipper` | `shipper/run.rs` | Draine le spool, POST des lots en HTTPS (si configuré) |
| `wedr-plugin-accept` | `plugin/server.rs` | Boucle d'acceptation du pipe plugin |
| `wedr-plugin-reload` | `plugin/server.rs` | Hot-reload des manifests (5 s) |
| `wedr-plugin-stats` | `plugin/server.rs` | Ligne de stats périodique (30 s) |
| `wedr-plugin-NNNN` | par session acceptée | Worker par session (handshake + ingestion) |

Le writer du spool kernel et `wedr-plugin-accept` sont **critiques** (échec = abandon du
démarrage) ; les autres sont best-effort (un échec de lancement log un avertissement sans
fail-fast).

## Comportement à l'arrêt

Ctrl+C / Ctrl+Break pose `SHUTDOWN: AtomicBool = true`. Le pump sort à son prochain IOCTL ; les
boucles accept/reload/stats à leur prochain tick ; le shipper à son prochain tick. Les workers de
session **ne consultent pas** `SHUTDOWN` — ils sont fauchés par l'OS à la sortie du processus.
`main` joint le superviseur, l'accepteur de plugins, puis les deux writers de spool (qui scellent
leur fichier actif), puis le shipper, puis sort.
