# Architecture de l'agent WazabiEDR

> Document d'onboarding. Objectif : permettre à quelqu'un qui arrive sur le projet de
> comprendre **ce que fait l'agent**, **comment il est structuré**, et **comment il
> dialogue** avec le driver kernel, les plugins, et le serveur Wazabi (console / logs /
> licences). Les chemins entre crochets pointent vers le code (`src/...`) et sont
> cliquables sur GitHub.

## Table des matières

1. [Vue d'ensemble](#1-vue-densemble)
2. [Cycle de vie & threads](#2-cycle-de-vie--threads)
3. [Le driver kernel](#3-interaction-avec-le-driver-kernel)
4. [Le spool sur disque](#4-le-spool-sur-disque)
5. [Le shipper → serveur Wazabi](#5-le-shipper--serveur-wazabi-consolelogs)
6. [Le serveur de plugins](#6-le-serveur-de-plugins-named-pipe)
7. [Le moteur de détection Waza](#7-le-moteur-de-détection-waza)
8. [Configuration](#8-configuration)
9. [Flux de bout en bout & par où commencer](#9-flux-de-bout-en-bout--par-où-commencer)

---

## 1. Vue d'ensemble

`WazabiEDR_Agent` est un **agent EDR en espace utilisateur** (Rust, Windows). Il joue
le rôle de **pont** entre les sources de télémétrie locales et le backend :

- il **pompe** les événements de sécurité émis par le **driver kernel**
  (`\\.\WazabiEDR`) ;
- il **héberge un serveur de plugins** (named pipe) qui acceptent des télémétries
  applicatives, après vérification d'identité du processus connecté ;
- il **normalise** tout en NDJSON, le **persiste sur disque** (spool compressé), puis
  l'**expédie** par lots vers le serveur Wazabi en HTTPS ;
- optionnellement, il **évalue localement** chaque événement contre des règles
  **Waza** (`.waza`) et déclenche des actions (log / alerte / kill-stub).

```text
┌───────────────────────────── AGENT (user-mode, Windows) ─────────────────────────────┐
│                                                                                       │
│  driver  ──IOCTL──►  pump loop (thread main) ─┬─► stdout (parse_and_print)  ◀ console │
│  kernel              src/ipc/device.rs        ├─► NDJSON → spool kernel               │
│                                               └─► detection.process(LogEvent)  ◀ opt  │
│                                                                  │                    │
│  plugins ──pipe──►  workers wedr-plugin-NNNN ─┬─► stdout         │           ◀ console │
│  (named pipe)       src/plugin/server.rs      ├─► NDJSON → spool plugins              │
│                                               └─► detection.process(LogEvent)  ◀ opt  │
│                                                                  │      │             │
│                                                                  ▼      ▼             │
│                                      spool/  active.ndjson → batch-*.zst   actions    │
│                                      src/spool/                  │      (log/alert/   │
│                                                                  ▼       kill-stub)   │
│                                              thread wedr-shipper                       │
│                                              src/shipper/        │                    │
│                                                                  ▼                    │
│                                   HTTPS POST /api/v1/agents/{id}/logs  ─► Wazabi Server │
└───────────────────────────────────────────────────────────────────────────────────────┘
```

Philosophie technique notable :
- **Pas de runtime async** : threads bloquants nommés, plus simples à raisonner pour un
  agent système.
- **Supply-chain minimale** : essentiellement `windows-sys`, `serde`/`serde_json`,
  `zstd`, `ureq`. Pas de `tokio`, pas de crate date/heure (formatage ISO-8601 maison),
  pas de `dashmap`/`tracing`/`anyhow` (on utilise `RwLock`, `eprintln!`,
  `Result<_, String>`).
- **Dégradation gracieuse** : presque tout sous-système est optionnel. Si le spool, le
  shipper, les plugins ou la détection échouent à démarrer, l'agent continue avec ce
  qui marche (souvent : ingestion + stdout).

Le point d'entrée est [`src/main.rs`](src/main.rs).

---

## 2. Cycle de vie & threads

[`src/main.rs`](src/main.rs) orchestre tout le démarrage, puis bloque sur la pump loop,
puis démonte dans l'ordre inverse à l'arrêt.

**Ordre de démarrage :**

1. `shutdown::install()` — installe le handler Ctrl+C / arrêt
   ([`src/shutdown.rs`](src/shutdown.rs)).
2. Chargement de la config `agent.json` ([`src/config.rs`](src/config.rs)).
3. Ouverture du device driver (`open_device`).
4. **Détection Waza** (si `[detection].enabled`) : `DetectionEngine::load` +
   `spawn_reload`.
5. **Spool kernel** puis **spool plugins** (sous-dossier `plugins/`).
6. **Serveur de plugins** + **superviseur** de plugins auto-lancés.
7. **Shipper** (si `[shipper].enabled`).
8. **Pump loop** : boucle bloquante qui pompe le driver jusqu'à `SHUTDOWN`.

**Threads en exécution :**

| Thread | Rôle | Source |
|---|---|---|
| `main` | Pump loop du driver (boucle IOCTL bloquante) | [`ipc/device.rs`](src/ipc/device.rs) |
| `wedr-spool-<dir>` | Écriture/rotation/compression du spool (un par dossier) | [`spool/writer.rs`](src/spool/writer.rs) |
| `wedr-shipper` | Scan des lots + upload HTTPS | [`shipper/run.rs`](src/shipper/run.rs) |
| `wedr-plugin-accept` | Accepte les connexions sur le named pipe | [`plugin/server.rs`](src/plugin/server.rs) |
| `wedr-plugin-NNNN` | Une session plugin (handshake + boucle d'événements) | [`plugin/server.rs`](src/plugin/server.rs) |
| `wedr-plugin-reload` | Recharge le store de manifests (toutes les 5 s) | [`plugin/server.rs`](src/plugin/server.rs) |
| `wedr-plugin-stats` | Log périodique des compteurs (toutes les 30 s) | [`plugin/server.rs`](src/plugin/server.rs) |
| (par plugin) | Superviseur d'un plugin auto-lancé (restart + backoff) | [`plugin/supervisor.rs`](src/plugin/supervisor.rs) |
| `wedr-waza-reload` | Hot-reload des règles `.waza` | [`detection/mod.rs`](src/detection/mod.rs) |

**Arrêt propre :** le handler Ctrl+C positionne un `AtomicBool SHUTDOWN`
([`src/shutdown.rs`](src/shutdown.rs)). Les boucles le consultent et sortent. Le
démontage suit l'ordre inverse du démarrage (superviseur → serveur plugins → spools →
shipper), et chaque sous-système journalise un résumé de ses compteurs sur stderr. Les
workers plugins en I/O bloquante ne sont pas réveillés explicitement : l'OS les réclame
à la sortie du process (compromis v1 assumé, documenté dans `plugin/server.rs`).

---

## 3. Interaction avec le driver kernel

Le driver (`WazabiEDR_Driver/`) observe le système via des callbacks kernel
(création de process/thread, chargement d'image, registre, accès handle) et met les
événements en file. L'agent les **tire** un par un.

### Transport

[`src/ipc/device.rs`](src/ipc/device.rs) ouvre le device de contrôle en **lecture
seule** et boucle sur un IOCTL bloquant :

```rust
// IOCTL code — doit correspondre au driver (WazabiEDR_Driver::ipc).
const IOCTL_WEDR_GET_EVENT: u32 = 0x0022_6000;

let ok = unsafe {
    DeviceIoControl(handle, IOCTL_WEDR_GET_EVENT,
                    ptr::null(), 0,
                    buf.as_mut_ptr() as *mut _, buf.len() as u32,
                    &mut returned, ptr::null_mut())
};
```

Chaque appel rend **un** événement. Si le buffer est trop petit, le driver renvoie
`ERROR_INSUFFICIENT_BUFFER` avec la taille requise ; l'agent agrandit le buffer et
réessaie **sans perdre** l'événement (toujours en file côté kernel). Le device est
ouvert `GENERIC_READ` : **il n'y a pas (encore) de canal de commande** vers le kernel,
d'où le `KillProcess` en stub (voir §7).

### Format de fil

Le format est **binaire et `repr(C, packed)`**, byte-pour-byte identique au driver. Il
est défini côté agent dans [`src/ipc/events.rs`](src/ipc/events.rs) et **doit** rester
synchronisé avec `WazabiEDR_Driver::events` — toute évolution **bump** `EVENT_VERSION`
(actuellement `4`), sinon l'agent rejette l'événement.

```rust
#[repr(C, packed)]
pub struct EventHeader {
    pub version: u16,      // doit == EVENT_VERSION (4)
    pub type_: u16,        // discriminant de type d'événement (1..=7)
    pub timestamp: i64,    // FILETIME Windows : ticks de 100 ns depuis 1601-01-01 UTC
    pub size: u32,
    pub drop_count: u32,   // événements perdus depuis le précédent (ring plein)
    pub trunc_count: u32,  // champs tronqués (chemins trop longs, etc.)
}
```

Lire des champs d'un struct *packed* par référence est de l'UB en Rust : tout passe par
`ptr::read_unaligned` ([`src/ipc/parser.rs`](src/ipc/parser.rs) et
[`src/ipc/json.rs`](src/ipc/json.rs) appliquent la même discipline — « touche l'un,
audite l'autre »).

### Types d'événements & champs

Le décodage produit un `event_type` snake_case (utilisé partout en aval, y compris dans
les règles Waza) et un payload JSON par type :

| Code | `kind` | `event_type` | Champs du payload |
|---|---|---|---|
| 1 | ProcessCreate | `process_create` | `pid`, `parent_pid`, `creating_pid`, `image_path` |
| 2 | ProcessExit | `process_terminate` | `pid` |
| 3 | ImageLoad | `module_load` | `pid`, `scope` (`kernel`/`user`), `image_base`, `image_size`, `image_path` |
| 4 | RegistryModify | `registry_write` | `pid`, `op`, `op_code`, `key_path`, `value_name`?, `value_type`?, `data_size`?, `data_preview_hex`?, `data_truncated`? |
| 5 | ThreadCreate | `thread_create` | `pid`, `tid`, `creating_pid`, `remote_injection` (bool) |
| 6 | ThreadExit | `thread_exit` | `pid`, `tid` |
| 7 | ProcessHandleAccess | `process_handle_access` | `source_pid`, `target_pid`, `desired_access`, `original_desired_access`, `op` (`Open`/`Duplicate`), `op_code` |

Quelques choix utiles à connaître (dans [`src/ipc/json.rs`](src/ipc/json.rs)) :
- `remote_injection` est dérivé (`creating_pid != pid && creating_pid != 0`) pour qu'une
  règle matche un booléen plutôt que de recalculer la comparaison.
- Le preview de valeur de registre est encodé en **hex** (`data_preview_hex`) car JSON
  n'a pas de type binaire.

### Conversion en NDJSON

[`src/ipc/json.rs`](src/ipc/json.rs) décode l'événement **une seule fois** en un
`DecodedKernel`, qui sert à la fois à produire la ligne NDJSON pour le spool **et** le
`LogEvent` pour la détection — pas de double parsing sur le chemin chaud :

```rust
pub fn encode_kernel_event_and_log(buf: &[u8]) -> Result<(Vec<u8>, LogEvent), String> {
    let d = decode_kernel_event(buf)?;   // parse packed → DecodedKernel (1×)
    let line = encode_decoded(&d)?;       // NDJSON pour le spool
    let log = decoded_to_log_event(&d);   // LogEvent pour le moteur Waza
    Ok((line, log))
}
```

L'enveloppe NDJSON est alignée sur le schéma `EventIn` du serveur (`ts`, `module`,
`event_type`, `process{pid,ppid,path}`, `raw`, `source`, `kind`, `event_version`,
`drop_count`, `trunc_count`) pour s'indexer sans erreur dans OpenSearch `wazabi-events`.
Quand la détection est désactivée, on emprunte le chemin moins coûteux
`encode_kernel_event` (ligne seule).

---

## 4. Le spool sur disque

[`src/spool/`](src/spool/) est un **journal d'écriture (WAL)** : on ne pousse jamais un
événement directement sur le réseau. Le pump écrit sur disque, un thread séparé expédie.
Conséquence : un crash perd au pire les derniers événements non flushés ; un endpoint
hors-ligne accumule localement et draine au retour du réseau.

**Disposition** ([`spool/writer.rs`](src/spool/writer.rs),
[`spool/file.rs`](src/spool/file.rs)) :

```text
<spool_dir>/active.ndjson            ← fichier en cours d'écriture
<spool_dir>/batch-<unix>-<seq>.zst   ← lots scellés, compressés zstd, prêts à expédier
<spool_dir>/plugins/…                ← même structure pour les événements plugins
```

Le writer reçoit les lignes via un **canal borné** (`sync_channel`) ; la soumission est
non-bloquante (`try_submit`) — si le canal est plein, l'événement est **droppé et
compté** plutôt que de bloquer le pump. Le fichier actif est **scellé** (renommé en
`batch-*.zst` après compression) quand il dépasse `max_bytes_per_file` **ou** `max_age`.
Un plafond global `max_total_bytes` **évince** les plus vieux lots si le disque se
remplit. Tous ces seuils sont configurables (§8).

Deux spools indépendants tournent : un pour le kernel (`<spool_dir>`) et un pour les
plugins (`<spool_dir>/plugins`), pour qu'un opérateur voie immédiatement la source.

---

## 5. Le shipper → serveur Wazabi (console/logs)

[`src/shipper/`](src/shipper/) est le **seul lien réseau** de l'agent aujourd'hui. Le
thread `wedr-shipper` ([`shipper/run.rs`](src/shipper/run.rs)) :

1. cherche le **plus vieux** `batch-*.zst` parmi les dossiers surveillés (kernel +
   plugins) ;
2. le **décompresse en RAM** (le serveur lit du NDJSON brut, il ne gère pas
   `Content-Encoding: zstd`) ;
3. le **POST** vers `{server_url}/api/v1/agents/{agent_id}/logs` ;
4. réagit au statut :
   - **2xx** → supprime le lot, repart aussitôt (draine au rythme du serveur) ;
   - **4xx** → laisse le lot sur disque (problème de forme à diagnostiquer), log une fois ;
   - **5xx / réseau** → **backoff exponentiel + jitter** (anti-thundering-herd), garde le lot.

```rust
// shipper/config.rs — l'URL est construite une fois au démarrage.
pub fn logs_endpoint(&self) -> String {
    format!("{}/api/v1/agents/{}/logs", self.server_url, self.agent_id)
}
```

**Sécurité** ([`shipper/config.rs`](src/shipper/config.rs),
[`shipper/secret.rs`](src/shipper/secret.rs)) :
- Token **Bearer** stocké chiffré en **DPAPI (LOCAL_MACHINE)**, base64 dans
  `token_encrypted_b64` ; un `token_plain` existe pour le dev mais log un avertissement.
- TLS toujours vérifié (un `verify_tls: false` est refusé avec un warning) ; HTTP simple
  toléré pour le dev mais bruyamment déconseillé.
- En-têtes optionnels `X-Wazabi-Tenant` et `X-Wazabi-Tag-<clé>`.

### Ce que l'agent fait vs. le design serveur

Le serveur (`../WazabiEDR_Server/README.md`) décrit un protocole agent↔serveur bien plus
large. **À ce jour, l'agent n'implémente que l'ingestion de logs.** Le reste est conçu
côté serveur mais **pas encore câblé dans l'agent** :

| Endpoint serveur | Rôle | Implémenté dans l'agent ? |
|---|---|---|
| `POST /api/v1/agents/{id}/logs` | Ingestion télémétrie NDJSON | ✅ **oui** (le shipper) |
| `POST /api/v1/agents/enroll` | Enrôlement (obtenir `agent_id` + token) | ❌ non — `agent_id` est pré-provisionné dans `agent.json` |
| `POST /api/v1/agents/{id}/heartbeat` | Heartbeat + commandes | ❌ non |
| `GET /api/v1/agents/{id}/profile` | Pull profil (modules + règles) | ❌ non — les règles Waza sont chargées **localement** (§7) |
| `POST /api/v1/agents/{id}/alerts` | Ingestion d'alertes | ❌ non — les matchs Waza vont aujourd'hui sur stderr |
| `GET /api/v1/modules/{id}/binary` | Téléchargement de modules | ❌ non |

**Console & serveur de licences.** La « console » est l'interface web du serveur Wazabi
(FastAPI + OpenSearch). L'agent **ne lui parle pas directement** : il alimente
l'ingestion `/logs`, et la console lit ensuite OpenSearch. Le **serveur de licences**
(`/api/v1/licenses/*`) est consommé par les **consoles clientes**, **pas par l'agent** —
l'agent n'a aucune logique de licence. Ces deux briques sont mentionnées ici pour situer
l'agent dans l'écosystème, mais elles sont hors de son périmètre actuel.

---

## 6. Le serveur de plugins (named pipe)

[`src/plugin/`](src/plugin/) permet à des **plugins** (process séparés) d'envoyer de la
télémétrie applicative à l'agent. C'est un serveur **named pipe** :
`\\.\pipe\WazabiEDR_plugin`.

### Protocole de fil

[`plugin/protocol.rs`](src/plugin/protocol.rs) — chaque trame est **un document JSON
préfixé par sa longueur** :

```text
+-------------+----------------------+
| LEN: u32 LE | JSON payload (LEN o) |
+-------------+----------------------+
```

Plafond `MAX_FRAME_BYTES` = 1 MiB (un plugin qui dépasse est déconnecté — un plugin
emballé ne doit pas pouvoir OOM l'agent). Trames **plugin → agent** : `hello`, `event`,
`heartbeat`, `goodbye`. Trames **agent → plugin** : `hello_ack`, `reject`.
`SCHEMA_VERSION` = 1.

### Handshake & vérification d'identité (anti-spoof)

C'est le cœur de la confiance plugin. Avant d'accepter quoi que ce soit, l'agent
**identifie le processus** à l'autre bout du pipe via le kernel
([`plugin/identity.rs`](src/plugin/identity.rs)) — infalsifiable par le plugin
lui-même — puis le confronte au **manifest** déclaré
([`plugin/manifest.rs`](src/plugin/manifest.rs)) :

```rust
// plugin/server.rs (extrait de la validation du handshake)
if hello.schema_version != SCHEMA_VERSION { return Err(SchemaMismatch); }
let manifest = store.get(&hello.plugin_id).ok_or(UnknownPluginId)?;
if manifest.revoked { return Err(Revoked); }
if !paths_match(&identity.image_path, &manifest.expected_path) { return Err(PathMismatch); }
if let Some(expected) = manifest.expected_sha256.as_deref() { /* hash sha256 du binaire */ }
if manifest.expected_signer.is_some() { /* WinVerifyTrust (Authenticode) */ }
```

Trois couches de force croissante : (1) identité OS (PID + chemin image), toujours ;
(2) intégrité SHA-256 du binaire ; (3) signature Authenticode. Le store de manifests est
rechargé à chaud toutes les 5 s (`wedr-plugin-reload`). `MAX_CONCURRENT_SESSIONS` = 64.

### Émission d'un événement plugin

Dans `emit_event` ([`plugin/server.rs`](src/plugin/server.rs)), l'agent **reconstruit**
la ligne JSON depuis l'état de session — les champs d'**attribution** (`plugin_id`,
`session_id`, `plugin_pid`…) viennent de la session vérifiée et **ne peuvent pas être
spoofés** par le payload du plugin. Détail important sur le typage :

- **NDJSON / serveur** : `module="plugin"`, `event_type="plugin_event"` (catch-all), le
  `kind` libre du plugin est conservé dans `kind`/`raw.kind`.
- **Détection Waza** : `module="plugin"`, `event_type = ev.kind` (le `kind` du plugin),
  pour qu'une règle puisse cibler une télémétrie précise, ex. `plugin.app_login.user`.

### Superviseur

[`plugin/supervisor.rs`](src/plugin/supervisor.rs) lance au démarrage les plugins dont le
manifest a `auto_launch: true` (et non `revoked`), passe `WEDR_PLUGIN_ID=<uuid>` en
variable d'environnement, et les **redémarre** en cas de crash avec backoff exponentiel
(1 s → 2 s → … → cap 60 s ; reset si le plugin tient ≥ 5 min).

---

## 7. Le moteur de détection Waza

[`src/detection/`](src/detection/) ajoute une **détection locale** pilotée par des
fichiers de règles `.waza`. **Opt-in** : désactivé par défaut, activé via la section
`[detection]` d'`agent.json` (§8). Désactivé, l'agent se comporte exactement comme avant.

Principe directeur (cf. `CLAUDE.md`) : **zéro hardcoding des champs des modules**. Un
événement est dynamique :

```rust
// detection/event.rs
pub enum FieldValue { Int(i64), Float(f64), Str(String), Bool(bool) } // enum FERMÉ

pub struct LogEvent {
    pub module: String,                       // "kernel_callback" | "plugin"
    pub event_type: String,                   // "process_create", … (ou le `kind` plugin)
    pub fields: HashMap<String, FieldValue>,  // "pid" -> Int(4688)
    pub timestamp: Instant,                   // pour la corrélation temporelle
}
```

`FieldValue` est un enum **fermé** (et non `serde_json::Value`) : la comparaison reste
totale et bon marché, et un type incompatible (champ `Int` vs littéral `Str`) renvoie
`false` au lieu de paniquer.

### Format `.waza`

Deux sections (`Detection`, `Action`), des groupes nommés appariés par nom. Voir
[`rules/main.waza`](rules/main.waza) :

```text
- Detection:
  - RemoteThreadInjection:
      window: 5s
      - kernel_callback.thread_create.remote_injection == true
  - SuspiciousImagePath:
      - kernel_callback.process_create.image_path contains "\\Temp\\"
- Action:
  - RemoteThreadInjection:
    - alert "Possible remote-thread injection"
    - log
```

Le parser ([`detection/waza/parser.rs`](src/detection/waza/parser.rs)) est en deux
couches : un **classifieur de lignes** tolérant à l'indentation (sections / groupes /
directives) et un **parseur d'expressions** (tokenizer + descente récursive,
priorité `or → and → not → atom`). Opérateurs : `== != < > <= >= contains startsWith`,
`&&`, `| / ||`, `!`, parenthèses. Directives : `window: 10s|ms` (fenêtre de corrélation,
défaut 5 s) et `include "./autre.waza"` (résolu relativement au fichier, avec détection
des **inclusions circulaires** et dédup). Le parseur ne connaît **jamais** les noms de
champs concrets : un chemin est un triplet opaque `module.event_type.field`.

### Moteur : index inversé + fenêtre glissante

[`detection/waza/engine.rs`](src/detection/waza/engine.rs) est le composant critique en
perf. À la construction, il bâtit **une fois** un **index inversé**
`(module, event_type) → [indices de règles]`. Sur le chemin chaud, seules les règles qui
référencent ce type d'événement sont évaluées — jamais de balayage O(n_règles) :

```rust
pub fn process_event(&self, event: &LogEvent) -> Vec<(String, Vec<Action>)> {
    let key = (event.module.clone(), event.event_type.clone());
    let Some(rule_indices) = self.index.get(&key) else { return Vec::new(); }; // ① lookup O(1)
    // ② pour chaque règle concernée : pousse l'événement dans SA fenêtre, snapshot, éval
    // ③ une règle matche si AU MOINS une de ses lignes est vraie (OR implicite)
}
```

Chaque règle possède sa propre **fenêtre de corrélation** glissante (`VecDeque`, éviction
O(1) en tête selon `window`). Une feuille `Compare` est vraie s'**il existe** un événement
dans la fenêtre qui la satisfait → c'est ce qui permet la **corrélation multi-événements
et multi-modules** (`And` entre deux événements arrivés dans la même fenêtre). On clone le
snapshot de la fenêtre pour relâcher vite le verrou avant l'évaluation récursive.

### Actions

[`detection/waza/actions.rs`](src/detection/actions.rs) :
`log` et `alert "msg"` sont des `eprintln!` `[waza] …` (légers, sur le thread appelant).
`kill` est un **stub loggé** : le driver est ouvert en lecture seule et n'expose pas
encore de canal de commande, donc il n'y a rien à qui envoyer un ordre de kill.

### Façade & hot-reload

[`detection/mod.rs`](src/detection/mod.rs) expose `DetectionEngine`, la façade que le
reste de l'agent appelle (`process(LogEvent)`). Elle encapsule un
`RwLock<Arc<RuleEngine>>` — le même patron que le store de manifests des plugins. Le
thread `wedr-waza-reload` surveille l'empreinte (mtime + taille) du fichier de règles et
**recharge à chaud** en swappant atomiquement l'`Arc` ; un échec de reparse **garde**
l'ancien moteur (mieux périmé que vide). Un `SchemaRegistry` optionnel
([`detection/schema.rs`](src/detection/schema.rs)) sert uniquement à **valider** les
chemins de champs des règles au chargement (warning sur faute de frappe) — il ne modifie
pas le protocole pipe.

Les deux chemins d'ingestion alimentent le moteur via le même point d'entrée :
`engine.process(log)` dans [`ipc/device.rs`](src/ipc/device.rs) (kernel) et dans
`emit_event` de [`plugin/server.rs`](src/plugin/server.rs) (plugins).

---

## 8. Configuration

Tout vit dans **un seul fichier** : `%ProgramData%\WazabiEDR\agent.json`
([`src/config.rs`](src/config.rs)). **Aucun flag CLI, aucune variable d'environnement** :
un seul endroit à éditer et à auditer. Si le fichier est absent, l'agent **écrit un
squelette** par défaut au premier démarrage et continue avec les valeurs par défaut.

Trois sections, toutes optionnelles :

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
    "enabled": false,
    "server_url": "https://wazabi.example.com",
    "agent_id": "5f1b3a8e-…",
    "token_encrypted_b64": "AQAAANC…"
  },
  "detection": {
    "enabled": false,
    "rules_path": "C:\\ProgramData\\WazabiEDR\\rules\\main.waza",
    "schema_path": "",
    "default_window_secs": 5,
    "reload_interval_secs": 5
  }
}
```

- `agent` absent ⇒ tous les défauts. `console_output` ne pilote que **stdout** ; les
  messages de diagnostic (`[agent]`, `[plugin]`, `[waza]`, erreurs) restent sur stderr.
- `shipper` absent / `enabled:false` ⇒ **mode spool-only** (les lots restent sur disque).
- `detection` absent / `enabled:false` ⇒ **pas de détection** (comportement historique).

---

## 9. Flux de bout en bout & par où commencer

```text
                    ┌──────────────┐         ┌───────────────┐
   driver kernel ──►│ ipc/device   │         │ plugin/server │◄── plugins (named pipe)
   (IOCTL)          │  pump loop   │         │  workers      │   (après vérif identité)
                    └──────┬───────┘         └──────┬────────┘
                           │ encode_kernel_event_and_log     │ emit_event (anti-spoof)
                           ▼                                  ▼
                    ┌─────────────────────  LogEvent + ligne NDJSON  ──────────────────┐
                    │                                                                  │
            (NDJSON)│                                                  (LogEvent) opt   │
                    ▼                                                          ▼        │
            ┌───────────────┐   batch-*.zst   ┌──────────────┐        ┌──────────────┐ │
            │ spool/writer  │ ──────────────► │ shipper/run  │ HTTPS  │ detection/   │ │
            │ (kernel+plug.)│                 │ POST /logs   │ ─────► │ Waza engine  │ │
            └───────────────┘                 └──────────────┘  Wazabi└──────┬───────┘ │
                                                                Server       │ actions │
                                                                             ▼         │
                                                                   [waza] log / alert  │
                                                                    / kill (stub)      │
                                                                                       │
                                                          OpenSearch ◄─ console web ────┘
```

**Checklist de lecture du code, dans l'ordre :**

1. [`src/main.rs`](src/main.rs) — l'orchestration : ce qui démarre, dans quel ordre, et
   comment ça s'arrête.
2. [`src/ipc/device.rs`](src/ipc/device.rs) → [`src/ipc/json.rs`](src/ipc/json.rs) —
   comment un événement driver devient une ligne NDJSON + un `LogEvent`.
3. [`src/spool/mod.rs`](src/spool/mod.rs) puis [`src/shipper/run.rs`](src/shipper/run.rs)
   — comment les événements sont persistés puis expédiés.
4. [`src/plugin/protocol.rs`](src/plugin/protocol.rs) →
   [`src/plugin/identity.rs`](src/plugin/identity.rs) →
   [`src/plugin/server.rs`](src/plugin/server.rs) — le canal plugins et sa sécurité.
5. [`src/detection/mod.rs`](src/detection/mod.rs) →
   [`src/detection/waza/engine.rs`](src/detection/waza/engine.rs) — la détection locale.
6. [`src/config.rs`](src/config.rs) — les leviers de réglage.

Pour le détail du contrat agent↔serveur (au-delà de l'ingestion `/logs`), voir
[`../WazabiEDR_Server/README.md`](../WazabiEDR_Server/README.md).
