# Lancer l'agent

> Une commande, un fichier de config. L'agent ne prend **aucun flag** ni variable
> d'environnement — tout vit dans `agent.json`.

## Démarrage rapide

```powershell
PS> cd WazabiEDR_Agent
PS> .\target\release\WazabiEDR_Agent.exe
```

L'agent :
- se connecte à `\\.\WazabiEDR` (le device du driver) ;
- spoole les events en NDJSON sous `%ProgramData%\WazabiEDR\spool\` (kernel) et `…\spool\plugins\`
  (plugins) ;
- écoute les plugins sur `\\.\pipe\WazabiEDR_plugin` ;
- lance le shipper HTTPS si `agent.json` a une section `shipper` (voir
  [configuring-shipper.md](configuring-shipper.md)).

Ctrl+C l'arrête proprement (les fichiers actifs sont scellés avant la sortie).

## Configuration

L'agent lit **un seul fichier** au démarrage : `%ProgramData%\WazabiEDR\agent.json`. Absent →
défauts intégrés (pas de shipper). Le schéma complet est dans
[`config-reference.md`](../reference/config-reference.md) ; les éditions les plus fréquentes sont
le flag `agent.console_output` et la section `shipper`.

Exemple minimal — console muette, spool-only, pas d'envoi :

```json
{ "agent": { "console_output": false } }
```

> L'agent **n'a aucun flag CLI**. Lancer `WazabiEDR_Agent.exe foo` (ou `--help`, etc.) imprime un
> court pointeur vers le fichier de config et sort avec le code 0. C'est délibéré : un seul
> endroit à éditer, un seul à auditer.

## Sessions d'exemple

### Run par défaut (sans fichier de config)

```
[plugin] 2 plugin(s) enrolled at startup (C:\ProgramData\WazabiEDR\plugins)
[plugin] server listening on \\.\pipe\WazabiEDR_plugin
[agent] no shipper configured — events stay on disk only
[agent] connected to \\.\WazabiEDR (Ctrl+C to stop) — spool dir: ... — console_output: true
[2026-05-09T20:53:01.400Z] ProcessCreate pid=8884 ppid=4192 creator=4192 path="...\notepad.exe"
[2026-05-09T20:53:01.418Z] ImageLoad    pid=8884 (user) base=0x7ff7a6e90000 size=0x60000 path="..."
^C
[agent] disconnected — kernel spool: 1024 events written, 0 dropped, 12 batches sealed, 0 evicted
```

### Run sans surveillance (console off, shipper on)

```
[shipper] started — endpoint: https://wazabi.example.com/api/v1/agents/5f1b3a8e-…/logs — watching 2 dir(s)
[agent] connected to \\.\WazabiEDR (Ctrl+C to stop) — ... console_output: false
^C
[agent] shipper: 4 batches sent, 0 rejected, 0 retries
```

Pas de lignes d'event sur stdout — seulement le bavardage de diagnostic `[agent]` / `[plugin]` /
`[shipper]` sur stderr. Parfait pour un service.

## Lire la sortie

### Events kernel (stdout, si `console_output: true`)

Lignes lisibles, une par event, formatées par `src/ipc/parser.rs` :

```
[..Z] ProcessCreate pid=8884 ppid=4192 creator=4192 path="..."
[..Z] Registry SetValue pid=4128 key="\REGISTRY\..." value="LastSeen" type=4 data=0x0000ffff
[..Z] ThreadCreate pid=4128 tid=2048 creator=8884 [REMOTE INJECTION from pid=8884]
[..Z] ProcAccess Open src_pid=8884 target_pid=4128 access=VM_READ|VM_WRITE
```

Suffixes possibles :
- `(DROPPED N events since last)` — le ring kernel a évincé N events depuis la dernière livraison
  (agent trop lent OU déconnecté un moment).
- `(TRUNCATED N fields since last)` — N champs chemin/nom/aperçu ont été coupés à la taille du
  buffer fixe par event.

Sémantique des champs : [`event-types.md`](../../../WazabiEDR_Driver/doc/reference/event-types.md)
(dépôt Driver). Le **spool** reçoit toujours l'enveloppe JSON quel que soit le flag console —
`console_output` ne supprime que l'affichage stdout.

### Events plugin (stdout, si `console_output: true`)

Une ligne JSON par event, même enveloppe que le JSON kernel du spool. `plugin_id`,
`plugin_name`, `plugin_pid`, `session_id`, `ts`, `ts_unix_ns` sont **estampillés par l'agent au
niveau de la session** — pas issus du payload du plugin. `plugin_ts_unix_ns` est l'horodatage
*revendiqué* par le plugin, conservé pour inspection mais non fiable pour l'ordre.

### Messages agent / plugin / shipper (stderr — toujours actif)

`console_output: false` ne les fait **pas** taire — il ne tait que les lignes d'event sur stdout.

## Disposition sur disque

```
%ProgramData%\WazabiEDR\agent.json     # le fichier de config (optionnel, ACL Admin)
%ProgramData%\WazabiEDR\spool\         # dossier de spool par défaut
  active.ndjson                        # events kernel en cours d'écriture
  batch-1746799220-0.zst               # lot kernel scellé (NDJSON compressé zstd)
  plugins/
    active.ndjson                      # events plugin en cours d'écriture
    batch-...zst
%ProgramData%\WazabiEDR\plugins\       # store de manifests (géré par l'admin)
  8f3c1d8e-....json
```

## Tourner comme service Windows

Hors périmètre v1 — pas de wrapper de service SCM fourni. Avec `console_output: false`, l'agent
se comporte bien pour `nssm` / `sc.exe` :

```powershell
PS> sc.exe create WazabiEDR_Agent binPath= "C:\Program Files\WazabiEDR\WazabiEDR_Agent.exe" start= auto
PS> sc.exe start  WazabiEDR_Agent
```

Pour le détail de l'architecture interne (pump, spool, shipper, serveur de plugins), voir
[`ARCHITECTURE.md`](../../ARCHITECTURE.md).
