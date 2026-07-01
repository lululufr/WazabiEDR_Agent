# Architecture de l'agent WazabiEDR

> Document d'onboarding. Il s'adresse à un développeur qui sait coder et connaît
> l'architecture Windows, **mais ne connaît rien à ce projet**. On part donc de zéro :
> chaque terme propre au projet ou au domaine est expliqué (entre parenthèses) à sa
> première apparition, et on déroule les mécanismes au lieu de seulement les nommer.
> Les chemins entre crochets renvoient au code (`src/...`) et sont cliquables sur GitHub.

## Table des matières

1. [Vue d'ensemble](#1-vue-densemble)
2. [Cycle de vie & threads](#2-cycle-de-vie--threads)
3. [Le driver kernel](#3-le-driver-kernel)
4. [Le spool sur disque](#4-le-spool-sur-disque)
5. [Le shipper → serveur Wazabi](#5-le-shipper--serveur-wazabi)
6. [Le serveur de plugins](#6-le-serveur-de-plugins)
7. [Le moteur de détection Waza](#7-le-moteur-de-détection-waza)
8. [Configuration](#8-configuration)
9. [Flux de bout en bout & par où commencer](#9-flux-de-bout-en-bout--par-où-commencer)

---

## 1. Vue d'ensemble

WazabiEDR est un **EDR** (*Endpoint Detection and Response* : un système de sécurité qui
surveille en continu ce qui se passe sur une machine — créations de processus, écritures
dans le registre, etc. — pour détecter et tracer les comportements malveillants). Le
projet a trois briques : un **driver kernel** (pilote qui s'exécute dans le noyau Windows
et observe les événements système au plus bas niveau), cet **agent** (programme en espace
utilisateur, *user-mode*, c'est-à-dire un processus ordinaire sans privilèges noyau), et
un **serveur** Wazabi (backend web qui reçoit et stocke la télémétrie).

Le mot **télémétrie** désigne ici le flux d'événements observés sur la machine (qui a
lancé quel programme, qui a touché quelle clé de registre, etc.). Le rôle de l'agent est
d'être le **pont** entre les sources de télémétrie locales (le driver et des plugins) et
le serveur distant. Concrètement, l'agent fait quatre choses :

1. Il **pompe** les événements émis par le driver kernel. « Pomper » signifie qu'il
   réclame activement les événements un par un au driver (voir le *pump loop* en §2 et §3).
2. Il **héberge un serveur de plugins**. Un *plugin* est un programme tiers, séparé, qui
   envoie sa propre télémétrie applicative à l'agent ; l'agent vérifie d'abord l'identité
   du programme connecté avant de lui faire confiance (§6).
3. Il **normalise** tout. « Normaliser » veut dire : convertir des formats hétérogènes
   (la structure binaire du driver, le JSON libre d'un plugin) vers un format texte
   unique et stable, le **NDJSON** (*Newline-Delimited JSON* : un document JSON par
   ligne, les lignes séparées par des retours à la ligne). Il **persiste** ce NDJSON sur
   disque (le *spool*, §4), puis l'**expédie** par lots au serveur en HTTPS (le *shipper*,
   §5).
4. Optionnellement, il **évalue localement** chaque événement contre des règles de
   détection écrites dans des fichiers `.waza`, et déclenche des actions quand une règle
   correspond (§7).

```text
┌───────────────────────────── AGENT (user-mode, Windows) ─────────────────────────────┐
│                                                                                       │
│  driver  ──IOCTL──►  pump loop (thread main) ─┬─► stdout (affichage lisible)  ◀ option│
│  kernel              src/ipc/device.rs        ├─► NDJSON → spool kernel               │
│                                               └─► detection.process(LogEvent)  ◀ option│
│                                                                  │                    │
│  plugins ──pipe──►  workers wedr-plugin-NNNN ─┬─► stdout         │           ◀ option │
│  (named pipe)       src/plugin/server.rs      ├─► NDJSON → spool plugins              │
│                                               └─► detection.process(LogEvent)  ◀ option│
│                                                                  │      │             │
│                                                                  ▼      ▼             │
│                                      spool/  active.ndjson → batch-*.zst   actions    │
│                                      src/spool/                  │      (log/alerte/  │
│                                                                  ▼       kill-stub)   │
│                                              thread wedr-shipper                       │
│                                              src/shipper/        │                    │
│                                                                  ▼                    │
│                                   HTTPS POST /api/v1/agents/{id}/logs  ─► serveur Wazabi│
└───────────────────────────────────────────────────────────────────────────────────────┘
```

Trois partis pris structurants, expliqués parce qu'ils reviennent partout :

- **Threads bloquants plutôt qu'`async`.** Beaucoup de programmes réseau modernes
  utilisent la programmation *asynchrone* (un seul thread qui jongle entre des milliers
  de tâches via un *runtime* comme Tokio). Ici, on a choisi des **threads système
  classiques** (un fil d'exécution OS par tâche, qui se met simplement en attente quand il
  n'a rien à faire). C'est plus simple à raisonner pour un agent système, au prix de
  quelques threads en plus.
- **Dépendances minimales.** L'agent n'embarque presque aucune bibliothèque tierce :
  `windows-sys` (les API Windows brutes), `serde`/`serde_json` (sérialisation JSON),
  `zstd` (compression), `ureq` (client HTTP simple). Pas de runtime async, pas de
  bibliothèque de date/heure (le formatage ISO-8601 est fait à la main). Cela réduit la
  surface d'attaque et la maintenance.
- **Dégradation gracieuse.** Presque chaque sous-système est facultatif. Si le spool, le
  shipper, les plugins ou la détection n'arrivent pas à démarrer, l'agent ne s'arrête
  pas : il continue avec ce qui fonctionne (au minimum : pomper le driver et afficher les
  événements). Un échec localisé n'abat jamais l'ensemble.

Le point d'entrée du programme est [`src/main.rs`](src/main.rs).

---

## 2. Cycle de vie & threads

[`src/main.rs`](src/main.rs) est le chef d'orchestre : il démarre chaque sous-système dans
un ordre précis, puis se bloque sur la boucle qui pompe le driver, et enfin démonte tout
proprement à l'arrêt.

Plusieurs sous-systèmes tournent en parallèle, chacun dans son propre **thread nommé** (un
thread auquel on a donné une étiquette, ce qui le rend identifiable dans un débogueur ou
un outil système — pratique pour savoir lequel consomme du CPU). Voici la cartographie :

| Thread | Rôle | Source |
|---|---|---|
| `main` | Le *pump loop* : boucle qui réclame les événements au driver | [`ipc/device.rs`](src/ipc/device.rs) |
| `wedr-spool-<dir>` | Écrit, fait tourner et compresse le spool (un thread par dossier de spool) | [`spool/writer.rs`](src/spool/writer.rs) |
| `wedr-shipper` | Lit les lots sur disque et les envoie au serveur | [`shipper/run.rs`](src/shipper/run.rs) |
| `wedr-plugin-accept` | Attend et accepte les connexions des plugins | [`plugin/server.rs`](src/plugin/server.rs) |
| `wedr-plugin-NNNN` | Gère une session plugin de bout en bout (un par plugin connecté) | [`plugin/server.rs`](src/plugin/server.rs) |
| `wedr-plugin-reload` | Recharge la liste des plugins autorisés (toutes les 5 s) | [`plugin/server.rs`](src/plugin/server.rs) |
| `wedr-plugin-stats` | Journalise un résumé de compteurs (toutes les 30 s) | [`plugin/server.rs`](src/plugin/server.rs) |
| (un par plugin) | Surveille et relance un plugin auto-lancé qui aurait planté | [`plugin/supervisor.rs`](src/plugin/supervisor.rs) |
| `wedr-waza-reload` | Recharge à chaud les règles de détection quand le fichier change | [`detection/mod.rs`](src/detection/mod.rs) |

**L'ordre de démarrage n'est pas arbitraire :**

1. Installer le gestionnaire d'arrêt (`shutdown::install()`, [`src/shutdown.rs`](src/shutdown.rs)).
   On le fait en tout premier pour qu'un Ctrl+C reçu pendant l'initialisation soit déjà
   pris en compte.
2. Charger la configuration depuis `agent.json` ([`src/config.rs`](src/config.rs)). Tout
   le reste dépend de ses valeurs.
3. Ouvrir le device du driver. Si le driver n'est pas là, inutile d'aller plus loin.
4. Démarrer la **détection Waza** si elle est activée (§7).
5. Démarrer les **spools** (kernel puis plugins) — *avant* les producteurs d'événements,
   pour qu'aucun événement n'arrive avant que le tampon d'écriture soit prêt à le recevoir.
6. Démarrer le **serveur de plugins** et le **superviseur** des plugins à lancer
   automatiquement.
7. Démarrer le **shipper** si l'envoi vers le serveur est configuré.
8. Entrer dans le **pump loop**, qui bloque le thread `main` jusqu'à l'arrêt.

**L'arrêt** repose sur un mécanisme unique et simple. Le gestionnaire d'arrêt (déclenché
par Ctrl+C ou par un gestionnaire de service Windows) positionne un **drapeau atomique
partagé** nommé `SHUTDOWN` — un booléen (`AtomicBool`) que tous les threads peuvent lire
sans verrou. Chaque boucle vérifie périodiquement ce drapeau et sort dès qu'il passe à
`true`. Le démontage se fait ensuite dans l'**ordre inverse** du démarrage (superviseur,
puis serveur de plugins, puis spools, puis shipper), pour que les derniers événements en
vol aient une chance d'être écrits puis expédiés avant la fermeture. Chaque sous-système
affiche un résumé de ses compteurs sur **stderr** (la sortie d'erreur standard) en
partant.

> Détail honnête : les threads `wedr-plugin-NNNN` qui lisent un plugin font de l'I/O
> *bloquante* et ne consultent pas `SHUTDOWN`. À l'arrêt, c'est le système qui les
> termine quand le processus se ferme. C'est un compromis assumé pour la v1 (un arrêt
> gracieux par session demanderait de l'I/O annulable sur chaque worker, pour peu de gain).

---

## 3. Le driver kernel

Le driver (`WazabiEDR_Driver/`, un autre dépôt du projet) s'exécute dans le noyau et pose
des **callbacks kernel** (fonctions que Windows appelle automatiquement à chaque événement
système d'un type donné : création de processus, création de thread, chargement d'une
image — c'est-à-dire d'un exécutable ou d'une DLL —, modification du registre, ouverture
d'un handle sur un autre processus). À chaque déclenchement, le driver fabrique un
enregistrement d'événement et le met dans une file. L'agent vient ensuite **tirer** ces
événements de la file.

### Le transport : un IOCTL en boucle

La communication passe par un **IOCTL** (*I/O Control* : le mécanisme standard Windows
pour qu'un programme user-mode envoie une commande à un driver et reçoive une réponse, via
un *device* — un point d'accès nommé exposé par le driver, ici `\\.\WazabiEDR`).

[`src/ipc/device.rs`](src/ipc/device.rs) ouvre ce device **en lecture seule**, puis
exécute le **pump loop** (la boucle de pompage) : à chaque tour, il envoie l'IOCTL
« donne-moi le prochain événement » et bloque jusqu'à recevoir une réponse.

```rust
// Le code de l'IOCTL doit correspondre exactement à celui du driver.
const IOCTL_WEDR_GET_EVENT: u32 = 0x0022_6000;

let ok = unsafe {
    DeviceIoControl(handle, IOCTL_WEDR_GET_EVENT,
                    ptr::null(), 0,                          // pas de données en entrée
                    buf.as_mut_ptr() as *mut _, buf.len() as u32, // buffer de sortie
                    &mut returned, ptr::null_mut())
};
```

`DeviceIoControl` est l'appel Windows qui envoie l'IOCTL ; il remplit notre buffer avec un
événement et indique combien d'octets ont été écrits (`returned`).

Deux conséquences importantes de ce design :

- **Le device est ouvert en lecture seule** (`GENERIC_READ`). L'agent peut donc *recevoir*
  des événements mais **pas envoyer d'ordre** au kernel. C'est pour cela que l'action
  « tuer un processus » de la détection est un *stub* (une implémentation factice qui se
  contente de journaliser l'intention) : il n'existe pas encore de canal pour transmettre
  un ordre de kill au driver (§7).
- **Le buffer peut être trop petit.** Si l'événement à livrer est plus gros que le buffer
  fourni, le driver renvoie l'erreur `ERROR_INSUFFICIENT_BUFFER` et indique la taille
  nécessaire. L'agent agrandit alors son buffer et **réessaie** — l'événement, lui, reste
  dans la file côté kernel et n'est pas perdu.

### Le format de fil : du binaire compact

Les événements voyagent en **binaire** (pas en texte), dans des structures déclarées
`repr(C, packed)`. `repr(C)` aligne la structure comme le ferait le langage C (disposition
mémoire prévisible et identique des deux côtés) ; `packed` supprime tout octet de
remplissage (*padding*) pour que la structure soit aussi compacte que possible et
**identique octet pour octet** entre le driver et l'agent. La contrepartie : on ne peut
pas lire un champ d'une telle structure par référence (ce serait un accès mémoire
potentiellement non aligné, comportement indéfini en Rust) ; on doit copier chaque champ
via `ptr::read_unaligned` (lecture qui ne suppose aucun alignement).

Le format est défini côté agent dans [`src/ipc/events.rs`](src/ipc/events.rs) et **doit**
rester synchronisé avec le driver. Tout changement incrémente une version (`EVENT_VERSION`,
actuellement `4`) ; si l'agent reçoit une version qu'il ne connaît pas, il rejette
l'événement au lieu de le mal interpréter. Chaque événement commence par un en-tête commun :

```rust
#[repr(C, packed)]
pub struct EventHeader {
    pub version: u16,      // doit valoir EVENT_VERSION (4)
    pub type_: u16,        // type d'événement (1 à 7, voir tableau ci-dessous)
    pub timestamp: i64,    // FILETIME : nombre de tranches de 100 ns depuis le 1er jan. 1601 UTC
    pub size: u32,         // taille totale de cet événement
    pub drop_count: u32,   // nb d'événements perdus depuis le précédent livré
    pub trunc_count: u32,  // nb de champs tronqués depuis le précédent livré
}
```

Deux champs méritent une explication :

- **FILETIME** est la représentation du temps native de Windows : un entier 64 bits
  comptant les intervalles de 100 nanosecondes écoulés depuis le 1er janvier 1601 à minuit
  UTC. L'agent le convertit en horodatage ISO-8601 lisible pour le NDJSON.
- **`drop_count`** : le driver stocke les événements dans un **ring** (*ring buffer*, file
  circulaire de taille fixe). Si l'agent ne pompe pas assez vite et que le ring se remplit,
  les plus anciens événements sont écrasés ; le driver compte combien ont été perdus depuis
  la dernière livraison réussie et le rapporte ici. De même, `trunc_count` compte les
  champs **tronqués** (par ex. un chemin de fichier plus long que le buffer fixe prévu). Ces
  compteurs remontent dans le NDJSON quand ils sont non nuls, pour que l'opérateur sache
  qu'il a manqué quelque chose.

### Les sept types d'événements

Le décodage produit un `event_type` en *snake_case* (minuscules avec underscores), utilisé
de façon cohérente dans tout le reste de l'agent — y compris dans les règles Waza — et un
payload JSON (les données utiles propres au type) :

| Code | Libellé | `event_type` | Champs du payload |
|---|---|---|---|
| 1 | ProcessCreate | `process_create` | `pid`, `parent_pid`, `creating_pid`, `image_path` |
| 2 | ProcessExit | `process_terminate` | `pid` |
| 3 | ImageLoad | `module_load` | `pid`, `scope` (`kernel`/`user`), `image_base`, `image_size`, `image_path` |
| 4 | RegistryModify | `registry_write` | `pid`, `op`, `op_code`, `key_path`, et pour un SetValue : `value_name`, `value_type`, `data_size`, `data_preview_hex`, `data_truncated` |
| 5 | ThreadCreate | `thread_create` | `pid`, `tid`, `creating_pid`, `remote_injection` (booléen) |
| 6 | ThreadExit | `thread_exit` | `pid`, `tid` |
| 7 | ProcessHandleAccess | `process_handle_access` | `source_pid`, `target_pid`, `desired_access`, `original_desired_access`, `op` (`Open`/`Duplicate`), `op_code` |

Deux raffinements utiles, faits dans [`src/ipc/json.rs`](src/ipc/json.rs) :

- `remote_injection` est **calculé** par l'agent (vrai si le thread est créé par un autre
  processus que celui qui l'héberge : `creating_pid != pid && creating_pid != 0`). C'est le
  schéma classique d'une *injection de thread distant* (technique d'attaque). On le
  pré-calcule pour qu'une règle puisse tester un simple booléen.
- L'aperçu de donnée d'une écriture de registre est encodé en **hexadécimal**
  (`data_preview_hex`), car le JSON n'a pas de type binaire natif et une valeur de registre
  n'est pas forcément du texte.

### La conversion en NDJSON (et en LogEvent)

[`src/ipc/json.rs`](src/ipc/json.rs) est le **point de conversion unique** du binaire vers
le texte. Subtilité de performance : la fonction décode l'événement **une seule fois** dans
une structure intermédiaire (`DecodedKernel`), qui sert à produire *à la fois* la ligne
NDJSON destinée au spool *et* l'objet `LogEvent` destiné au moteur de détection (le
`LogEvent` est expliqué en §7). On évite ainsi de parser deux fois sur le chemin chaud
(*hot path* : le code exécuté pour chaque événement, là où la performance compte le plus).

```rust
pub fn encode_kernel_event_and_log(buf: &[u8]) -> Result<(Vec<u8>, LogEvent), String> {
    let d = decode_kernel_event(buf)?;   // décodage binaire → DecodedKernel (une seule fois)
    let line = encode_decoded(&d)?;       // → ligne NDJSON pour le spool
    let log = decoded_to_log_event(&d);   // → LogEvent pour le moteur Waza
    Ok((line, log))
}
```

La ligne NDJSON est mise en forme exactement comme le serveur l'attend (champs `ts`,
`module`, `event_type`, un bloc `process`, le payload brut sous `raw`, plus les métadonnées
`source`/`kind`/`event_version`/`drop_count`/`trunc_count`), de sorte qu'elle soit indexée
sans erreur côté serveur. Quand la détection est désactivée, l'agent emprunte une variante
plus légère (`encode_kernel_event`) qui ne produit que la ligne, sans construire le
`LogEvent` inutile.

---

## 4. Le spool sur disque

Le **spool** désigne ici un **tampon de fichiers sur disque où l'agent accumule les
événements avant de les envoyer** — une file d'attente persistante entre la production
(rapide, locale) et l'envoi réseau (lent, faillible). C'est un schéma classique des EDR de
production, et le code de [`src/spool/`](src/spool/) en explique le pourquoi : on n'envoie
jamais les événements un par un sur le réseau (chaque envoi paierait une poignée de main
TLS et des en-têtes, et la moindre coupure réseau perdrait des données). À la place :

1. le pump loop produit les événements aussi vite que l'OS les fournit ;
2. l'agent les écrit sur disque dans un **journal d'écriture** (*WAL*, *Write-Ahead Log* :
   on écrit d'abord sur disque, on traite ensuite — c'est ce module) ;
3. un thread séparé (le shipper, §5) lit les lots scellés et les envoie au serveur.

L'intérêt de séparer (2) et (3) : un crash de l'agent ne perd au pire que les tout derniers
événements non encore écrits, et une machine hors-ligne accumule ses lots localement puis
les draine quand le réseau revient.

**Disposition des fichiers** ([`spool/writer.rs`](src/spool/writer.rs),
[`spool/file.rs`](src/spool/file.rs)) :

```text
<spool_dir>/active.ndjson            ← le fichier en cours d'écriture
<spool_dir>/batch-<unix>-<seq>.zst   ← lots « scellés », compressés, prêts à être envoyés
<spool_dir>/plugins/…                ← même structure, pour les événements des plugins
```

Le mécanisme, étape par étape :

- Le thread d'écriture (`wedr-spool-…`) reçoit les lignes via un **canal borné**
  (`sync_channel` : une file inter-threads de capacité fixe). « Borné » est important : si
  le consommateur (le thread d'écriture) prend du retard et que la file est pleine, la
  soumission ne bloque pas le producteur. À la place, l'événement est **droppé et compté**
  (`try_submit`). Le choix est délibéré : mieux vaut perdre quelques événements et le
  signaler que de figer le pump loop et risquer de faire déborder le ring kernel.
- Le fichier `active.ndjson` est **scellé** quand il dépasse une taille
  (`max_bytes_per_file`) **ou** un âge (`max_age`). « Sceller » signifie : le fermer, le
  compresser avec **zstd** (*Zstandard*, un algorithme de compression rapide), et le
  renommer en `batch-<timestamp>-<numéro>.zst`. À partir de là, le shipper peut le prendre.
- Un plafond global (`max_total_bytes`) limite la taille totale du dossier de spool : si on
  le dépasse (réseau coupé depuis longtemps, par ex.), les **plus vieux lots sont
  supprimés** (*évincés*) pour faire de la place. Tous ces seuils sont configurables (§8).

Deux spools indépendants tournent en parallèle : un pour les événements du driver
(`<spool_dir>`) et un pour les événements des plugins (`<spool_dir>/plugins`). Les séparer
permet à un opérateur qui inspecte le disque de voir immédiatement quelle source a produit
quoi.

---

## 5. Le shipper → serveur Wazabi

Le **shipper** (« expéditeur ») est le composant qui **envoie les lots du spool au serveur
distant**. C'est le **seul lien réseau** de l'agent aujourd'hui. Il vit dans son thread
`wedr-shipper` ([`shipper/run.rs`](src/shipper/run.rs)) et tourne en boucle :

1. il cherche le **plus ancien** lot `batch-*.zst` parmi les dossiers surveillés (spool
   kernel + spool plugins) ;
2. il le **décompresse en mémoire**. Pourquoi décompresser, puisque le spool est compressé ?
   Parce que le serveur lit le corps de la requête comme du NDJSON brut et ne gère pas la
   décompression à la volée — on lui envoie donc le texte décompressé ;
3. il l'envoie via une requête **HTTP POST** vers
   `{server_url}/api/v1/agents/{agent_id}/logs` ;
4. il réagit au **code de statut HTTP** renvoyé :
   - **2xx** (succès) → le lot est supprimé du disque, et la boucle repart aussitôt pour
     vider le spool au rythme où le serveur l'accepte ;
   - **4xx** (erreur côté client, ex. format invalide) → le lot est **laissé sur disque**
     pour diagnostic, avec un message journalisé une fois. Le réessayer en boucle ne ferait
     que gaspiller du CPU ;
   - **5xx** (erreur serveur) ou échec réseau → on attend selon un **backoff exponentiel
     avec jitter**, puis on réessaie le même lot.

```rust
// shipper/config.rs — l'URL complète est construite une fois au démarrage.
pub fn logs_endpoint(&self) -> String {
    format!("{}/api/v1/agents/{}/logs", self.server_url, self.agent_id)
}
```

Le **backoff exponentiel** est une attente qui double à chaque échec (1 s, 2 s, 4 s, …
plafonnée à une valeur max) : on évite de marteler un serveur déjà en difficulté. Le
**jitter** est un aléa ajouté à ce délai (±25 %) : si une flotte de cent agents tombe en
panne réseau en même temps, sans jitter ils réessaieraient tous *au même instant* et
écraseraient le serveur au moment où il redémarre (*thundering herd*, « ruée du troupeau »).
Le jitter étale ces réessais.

**Sécurité de l'envoi** ([`shipper/config.rs`](src/shipper/config.rs),
[`shipper/secret.rs`](src/shipper/secret.rs)) :

- L'authentification se fait par un **token Bearer** (un jeton secret placé dans l'en-tête
  HTTP `Authorization: Bearer <token>`). Ce token est stocké **chiffré avec DPAPI**
  (*Data Protection API* : le service de Windows qui chiffre/déchiffre des secrets liés à la
  machine ou à l'utilisateur, sans que le programme ait à gérer lui-même une clé), puis
  encodé en base64 dans le champ `token_encrypted_b64`. Un champ `token_plain` (en clair)
  existe pour le développement, mais l'agent affiche alors un avertissement.
- TLS (le chiffrement HTTPS) est **toujours** vérifié ; une demande de le désactiver est
  refusée avec un avertissement. Le HTTP en clair est toléré pour le dev mais bruyamment
  déconseillé.

### Ce que l'agent fait vraiment, vs. le design du serveur

Le serveur Wazabi (`../WazabiEDR_Server/README.md`) décrit un protocole agent↔serveur bien
plus riche. **À ce jour, l'agent n'implémente que l'envoi de logs.** Le reste est conçu
côté serveur mais **pas encore câblé dans l'agent** ; il est listé ici pour situer ce qui
existe :

| Endpoint serveur | Rôle | Implémenté dans l'agent ? |
|---|---|---|
| `POST /api/v1/agents/{id}/logs` | Ingestion de la télémétrie NDJSON | ✅ **oui** — c'est le shipper |
| `POST /api/v1/agents/enroll` | *Enrôlement* (obtenir un `agent_id` et un token) | ❌ non — `agent_id` est saisi à la main dans `agent.json` |
| `POST /api/v1/agents/{id}/heartbeat` | *Heartbeat* (signal périodique « je suis vivant ») + récup. de commandes | ❌ non |
| `GET /api/v1/agents/{id}/profile` | Récupérer la config (modules + règles) depuis le serveur | ❌ non — les règles Waza sont chargées **localement** (§7) |
| `POST /api/v1/agents/{id}/alerts` | Envoyer les alertes au serveur | ❌ non — les correspondances de règles vont aujourd'hui sur stderr |
| `GET /api/v1/modules/{id}/binary` | Télécharger des modules | ❌ non |

**À propos de la « console » et du « serveur de licences ».** Ces deux termes
apparaissent dans la doc serveur, voici comment ils se situent par rapport à l'agent :

- La **console** est l'interface web d'administration de Wazabi (un backend FastAPI qui
  stocke les événements dans OpenSearch — un moteur de recherche/indexation). **L'agent ne
  lui parle pas directement.** Il se contente d'alimenter l'endpoint `/logs` ; la console
  lit ensuite ces données depuis le stockage. Le lien est donc indirect.
- Le **serveur de licences** (`/api/v1/licenses/*`) gère l'activation et le suivi des
  licences clientes. Il est consommé par les **consoles des clients**, **pas par l'agent**.
  L'agent n'a aucune logique de licence. On le mentionne uniquement pour cartographier
  l'écosystème ; c'est hors de son périmètre.

---

## 6. Le serveur de plugins

Un **plugin** est un programme tiers, distinct de l'agent, qui produit sa propre télémétrie
applicative (par exemple : « tel utilisateur s'est connecté à telle appli »). L'agent
expose un serveur auquel ces plugins se connectent pour lui transmettre leurs événements.
Le code est dans [`src/plugin/`](src/plugin/).

### Le canal : un named pipe

La communication passe par un **named pipe** (*tube nommé* : un canal de communication
inter-processus de Windows, identifié par un nom — ici `\\.\pipe\WazabiEDR_plugin` — par
lequel deux processus échangent un flux d'octets, un peu comme une socket locale).

Le serveur a un thread **accepteur** (`wedr-plugin-accept`) qui attend les connexions en
**overlapped I/O** (le mode d'I/O *asynchrone* de Windows, où une opération peut être lancée
puis attendue de façon interruptible — cela permet à l'accepteur de se réveiller à l'arrêt
plutôt que de rester bloqué pour toujours). Dès qu'un plugin se connecte, l'accepteur lui
dédie un **thread worker** (`wedr-plugin-NNNN`) qui gère toute sa session, et retourne
attendre la connexion suivante. Une limite (`MAX_CONCURRENT_SESSIONS`, 64) plafonne le
nombre de plugins simultanés : au-delà, les nouvelles connexions sont refusées, pour qu'un
plugin défaillant qui se reconnecterait en boucle ne sature pas l'agent.

### Le format des messages

[`plugin/protocol.rs`](src/plugin/protocol.rs) — chaque message (*frame*, trame) est **un
document JSON précédé de sa longueur** :

```text
+-------------+----------------------+
| LEN: u32 LE | charge utile JSON    |
| (4 octets)  | (LEN octets)         |
+-------------+----------------------+
```

`LEN` est un entier 32 bits *little-endian* (LE : octet de poids faible en premier, la
convention x86) qui dit combien d'octets de JSON suivent. Ce *préfixe de longueur* (*length
framing*) permet au lecteur de savoir exactement où s'arrête un message, sans deviner. Une
limite dure (`MAX_FRAME_BYTES`, 1 Mio) borne la taille d'une trame : un plugin qui dépasse
est déconnecté, pour qu'il ne puisse pas épuiser la mémoire de l'agent.

Le dialogue suit un **handshake** (poignée de main : un échange initial obligatoire qui
établit et valide la session avant tout échange de données). Trames **plugin → agent** :
`hello` (première trame, identifie le plugin), `event` (un enregistrement de télémétrie),
`heartbeat` (signal de vie, optionnel), `goodbye` (déconnexion propre, optionnelle). Trames
**agent → plugin** : `hello_ack` (handshake accepté) ou `reject` (refusé, avec un motif).

### La vérification d'identité (le cœur de la confiance)

Avant d'accepter le moindre événement, l'agent doit s'assurer que le processus à l'autre
bout du pipe est bien le plugin légitime, et pas un imposteur. Il croise pour cela
l'identité réelle du processus avec un **manifest** (fiche signalétique déclarée à l'avance
pour chaque plugin autorisé : son identifiant, le chemin attendu de son exécutable, et
éventuellement son empreinte et son signataire — voir [`plugin/manifest.rs`](src/plugin/manifest.rs)).
La vérification ([`plugin/identity.rs`](src/plugin/identity.rs)) a **trois couches**, de la
plus forte à la plus optionnelle :

```rust
// plugin/server.rs — extrait de la validation du handshake
if hello.schema_version != SCHEMA_VERSION { return Err(SchemaMismatch); }
let manifest = store.get(&hello.plugin_id).ok_or(UnknownPluginId)?;
if manifest.revoked { return Err(Revoked); }
if !paths_match(&identity.image_path, &manifest.expected_path) { return Err(PathMismatch); }
if let Some(expected) = manifest.expected_sha256.as_deref() { /* compare le hash SHA-256 du binaire */ }
if manifest.expected_signer.is_some() { /* WinVerifyTrust : vérifie la signature Authenticode */ }
```

1. **Identité OS** (toujours) : l'agent demande au *kernel* qui est connecté au pipe
   (`GetNamedPipeClientProcessId` donne le PID du client) et résout le chemin de son
   exécutable sur disque. C'est **infalsifiable par le plugin lui-même** : pour mentir
   là-dessus, il faudrait déjà être SYSTEM, auquel cas le modèle de menace est de toute
   façon caduc. L'agent vérifie ensuite que ce chemin correspond à celui du manifest.
2. **Intégrité du binaire** (si le manifest le précise) : l'agent calcule le **hash
   SHA-256** (empreinte cryptographique) du fichier exécutable et le compare à la valeur
   attendue. Cela ferme la faille « le chemin est bon, mais le binaire a été remplacé ».
3. **Signature Authenticode** (si le manifest le précise) : l'agent appelle
   **WinVerifyTrust** (l'API Windows qui valide une signature *Authenticode* — la signature
   numérique d'un binaire par un éditeur, avec sa chaîne de certificats) pour confirmer que
   le binaire est signé et que la chaîne est valide.

La liste des plugins autorisés est rechargée à chaud toutes les 5 secondes par le thread
`wedr-plugin-reload`, pour qu'un ajout/retrait soit pris en compte sans redémarrer l'agent.

### L'émission d'un événement plugin (attribution anti-spoof)

Quand un plugin valide envoie un `event`, la fonction `emit_event`
([`plugin/server.rs`](src/plugin/server.rs)) **reconstruit elle-même** la ligne JSON à
partir de l'état de la session vérifiée. C'est une protection **anti-spoof** (anti-usurpation) :
les champs d'**attribution** (qui identifie la source — `plugin_id`, `session_id`,
`plugin_pid`) proviennent de la session vérifiée par l'agent, et **non** du contenu envoyé
par le plugin. Un plugin ne peut donc pas se faire passer pour un autre en bricolant son
payload.

Un détail à connaître : un événement plugin reçoit **deux** étiquetages selon la
destination :

- vers le **NDJSON / serveur** : `module="plugin"` et `event_type="plugin_event"` (un type
  générique fourre-tout) ; le `kind` libre choisi par le plugin (ex. `"app.login"`) est
  conservé à côté ;
- vers le **moteur de détection** : `module="plugin"` et `event_type = kind` du plugin,
  pour qu'une règle Waza puisse cibler finement un type de télémétrie précis (par ex.
  `plugin.app_login.user`).

### Le superviseur

Certains plugins doivent tourner en permanence. Le **superviseur**
([`plugin/supervisor.rs`](src/plugin/supervisor.rs)) lance au démarrage de l'agent les
plugins dont le manifest porte `auto_launch: true`, leur passe leur identifiant via la
variable d'environnement `WEDR_PLUGIN_ID`, et les **relance** s'ils plantent, avec un
backoff exponentiel (1 s → 2 s → 4 s … plafonné à 60 s, et remis à 1 s si le plugin tient
au moins 5 minutes — pour ne pas relancer en boucle un plugin durablement cassé).

---

## 7. Le moteur de détection Waza

Cette couche permet à l'agent de **détecter localement** des comportements suspects, sans
attendre le serveur. La détection est pilotée par des fichiers de **règles** écrites dans un
petit langage maison, **Waza** (extension `.waza`). Le code est dans
[`src/detection/`](src/detection/).

> **Référence de grammaire** : [`doc/reference/waza-rules.md`](doc/reference/waza-rules.md)
> (sections, opérateurs, throttle, mode déconnecté, exemples).

> **Note d'organisation** : depuis la mise en place de l'éditeur web côté console,
> le parser / AST / engine vivent dans un crate frère `wedr-waza-core`
> (`../WazabiEDR_WazaCore/`). Le moteur est ainsi partagé entre l'agent (qui
> hot-reload des fichiers `.waza`) et le binaire `wedr-waza-check`
> (`WazabiEDR_Utils`) que le serveur invoque pour valider / simuler / lister
> le schéma. Une seule implémentation de la grammaire, pas de risque de
> dérive parser-serveur ↔ moteur-agent. Le module `src/detection/` ne
> contient plus que la *façade* (`DetectionEngine`), l'exécuteur d'actions
> et le pont d'alerte vers le control plane.

C'est une fonctionnalité **opt-in** (« par adhésion » : désactivée par défaut, il faut
l'activer explicitement dans la config, §8). Désactivée, l'agent se comporte exactement
comme avant son ajout, sans aucun surcoût.

### Principe directeur : zéro champ codé en dur

L'exigence centrale (issue de `CLAUDE.md`) est qu'**aucun nom de champ de module ne soit
codé en dur** dans l'agent : ajouter un nouveau module, ou un nouveau champ à un module
existant, ne doit demander aucune modification du code de détection. Pour cela, un événement
est représenté de façon **dynamique** :

```rust
// detection/event.rs
pub enum FieldValue { Int(i64), Float(f64), Str(String), Bool(bool) } // enum FERMÉ

pub struct LogEvent {
    pub module: String,                       // "kernel_callback" ou "plugin"
    pub event_type: String,                   // "process_create", … (ou le `kind` d'un plugin)
    pub fields: HashMap<String, FieldValue>,  // table dynamique : "pid" -> Int(4688)
    pub timestamp: Instant,                   // instant d'arrivée, pour la corrélation temporelle
}
```

Un **`LogEvent`** est donc un événement normalisé que n'importe quelle source produit : un
couple `module` / `event_type`, plus une **table de champs dynamique** (`fields`) dont les
clés ne sont pas connues à la compilation. Une règle compare ses critères à cette table par
simple recherche de clé. **`FieldValue`** est un *enum fermé* (un type somme dont la liste
des variantes est fixée : entier, flottant, chaîne, booléen). On l'a préféré à un type JSON
générique pour deux raisons : la comparaison reste **totale** (deux types incompatibles,
comme un champ entier comparé à une chaîne littérale, renvoient `false` au lieu de planter)
et **bon marché** (pas d'allocation sur le chemin chaud).

### Le format `.waza`

Un fichier `.waza` a deux sections, `Detection` et `Action`, faites de groupes nommés
appariés par leur nom. Exemple tiré de [`rules/main.waza`](rules/main.waza) :

```text
- Detection:
  - RemoteThreadInjection:
      window: 5s
      - kernel_callback.thread_create.remote_injection == true
  - SuspiciousImagePath:
      - kernel_callback.process_create.image_path contains "\\Temp\\"
- Action:
  - RemoteThreadInjection:
    - alert "Injection de thread distant possible"
    - log
```

Chaque ligne de condition désigne un champ par un chemin pointé
`module.event_type.field`. Le **parser** ([`detection/waza/parser.rs`](src/detection/waza/parser.rs))
travaille en deux temps : un classifieur de lignes (qui distingue sections, groupes,
directives et conditions, en tolérant l'indentation) et un parseur d'expressions
(*tokenizer* qui découpe en symboles, puis *analyse à descente récursive* qui construit
l'arbre logique en respectant les priorités `ou → et → non → atome`). Les opérateurs
disponibles : `==`, `!=`, `<`, `>`, `<=`, `>=`, `contains` (contient), `startsWith`
(commence par), combinés avec `&&` (et), `|`/`||` (ou), `!` (non) et des parenthèses. Deux
directives : `window: 10s|ms` (la fenêtre de corrélation du groupe, voir plus bas) et
`include "./autre.waza"` (inclut un autre fichier, résolu relativement au fichier courant,
avec **détection des inclusions circulaires** pour éviter les boucles infinies). Point
important : le parser **ne connaît jamais les noms de champs concrets** — un chemin est pour
lui un triplet opaque.

### Le moteur : index inversé + fenêtre de corrélation

[`detection/waza/engine.rs`](src/detection/waza/engine.rs) est le composant le plus
sensible en performance, puisqu'il s'exécute pour *chaque* événement. Deux idées le rendent
rapide et expressif.

D'abord, un **index inversé** (*inverted index* : une table qui, à partir d'une clé, donne
directement la liste des éléments qui la référencent — comme l'index d'un livre qui mène
d'un mot aux pages). Ici, on construit **une seule fois** au démarrage une table
`(module, event_type) → [indices des règles qui parlent de ce type]`. Sur le chemin chaud,
au lieu de tester *toutes* les règles à chaque événement (coût proportionnel au nombre de
règles), on fait une recherche directe et on n'évalue **que** les règles concernées :

```rust
pub fn process_event(&self, event: &LogEvent) -> Vec<(String, Vec<Action>)> {
    let key = (event.module.clone(), event.event_type.clone());
    // ① Recherche directe : si aucune règle ne parle de ce type, on s'arrête immédiatement.
    let Some(rule_indices) = self.index.get(&key) else { return Vec::new(); };
    // ② Pour chaque règle concernée : on insère l'événement dans SA fenêtre, on prend un
    //    instantané, on évalue. Une règle « matche » si AU MOINS une de ses lignes est vraie.
}
```

Ensuite, une **fenêtre de corrélation** (*correlation window* : une mémoire glissante des
événements récents, propre à chaque règle). Concrètement, chaque règle possède une file
(`VecDeque`) qui ne garde que les événements survenus dans les `window` dernières secondes
(les plus anciens sont retirés en tête, opération en temps constant). Une condition feuille
(`Compare`) est considérée vraie s'**il existe** dans la fenêtre un événement qui la
satisfait. C'est ce qui permet la **corrélation entre plusieurs événements et plusieurs
modules** : une règle peut exiger qu'un événement du driver *et* un événement d'un plugin
soient présents ensemble dans la même fenêtre temporelle (un `&&` entre deux types
d'événements différents). Si l'un des deux est arrivé trop tôt et a quitté la fenêtre, la
règle ne se déclenche pas.

### Les actions

Quand une règle correspond, ses actions s'exécutent ([`detection/waza/actions.rs`](src/detection/actions.rs)).
`log` et `alert "message"` écrivent une ligne `[waza] …` sur stderr (opérations légères,
exécutées sur le thread appelant pour ne pas ralentir l'ingestion). `kill` (tuer le
processus) est pour l'instant un **stub** (implémentation factice qui journalise seulement
l'intention) : comme vu en §3, le driver est ouvert en lecture seule et n'expose pas encore
de canal de commande, donc il n'y a personne à qui envoyer l'ordre de kill.

### La façade et le rechargement à chaud

Le reste de l'agent ne manipule pas le moteur directement : il passe par une **façade**
(une interface unique qui cache la complexité interne), `DetectionEngine`
([`detection/mod.rs`](src/detection/mod.rs)), dont le seul point d'entrée utile est
`process(LogEvent)`. En interne, cette façade détient le moteur dans un
`RwLock<Arc<RuleEngine>>` — un *pointeur partagé* (`Arc`, comptage de références) protégé
par un *verrou lecteurs/écrivain* (`RwLock`, qui autorise plusieurs lectures simultanées
mais une seule écriture exclusive). Cette combinaison permet le **rechargement à chaud**
(*hot-reload* : remplacer les règles pendant que l'agent tourne, sans le redémarrer).

Le rechargement est assuré par `spawn_reload` (la fonction qui *lance le thread de
rechargement* `wedr-waza-reload`). Ce thread surveille le fichier de règles via une
**empreinte** (sa date de modification et sa taille) ; quand l'empreinte change, il
re-parse le fichier et **échange atomiquement** le pointeur du moteur (les évaluations en
cours continuent sereinement avec l'ancien jusqu'à ce qu'elles relâchent leur référence).
Si le nouveau fichier est invalide, l'ancien moteur est **conservé** (mieux vaut des règles
périmées que pas de règles du tout) et une erreur est journalisée. Un registre de schémas
optionnel ([`detection/schema.rs`](src/detection/schema.rs)) sert uniquement, au
chargement, à **valider** que les champs cités par les règles existent (et à avertir d'une
éventuelle faute de frappe) ; il ne modifie en rien le protocole pipe.

Enfin, les deux sources alimentent le moteur par le même point d'entrée : un appel à
`engine.process(log)` dans le pump loop ([`ipc/device.rs`](src/ipc/device.rs)) pour le
kernel, et dans `emit_event` ([`plugin/server.rs`](src/plugin/server.rs)) pour les plugins.

---

## 8. Configuration

Tout le paramétrage tient dans **un seul fichier** : `%ProgramData%\WazabiEDR\agent.json`
([`src/config.rs`](src/config.rs)). L'agent **n'a aucune option en ligne de commande ni
variable d'environnement** : un seul endroit à éditer et à auditer, pas de dérive entre
outils de déploiement. Si le fichier est absent au démarrage, l'agent **écrit
automatiquement un squelette** par défaut (avec les sections désactivées et des valeurs
d'exemple à compléter), puis démarre avec les valeurs par défaut.

Le fichier a trois sections, **toutes facultatives** :

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

La règle de lecture est uniforme : **une section absente ou désactivée fait basculer le
sous-système correspondant dans son mode dégradé**, sans empêcher l'agent de tourner :

- `agent` absent ⇒ toutes les valeurs par défaut. `console_output` ne pilote que
  l'affichage sur **stdout** (la sortie standard) ; les messages de diagnostic
  (`[agent]`, `[plugin]`, `[waza]`, erreurs) restent toujours sur **stderr**. Couper
  `console_output` est utile pour un déploiement en service Windows non surveillé.
- `shipper` absent ou `enabled: false` ⇒ **mode spool-only** : les événements sont écrits
  sur disque mais jamais envoyés (un opérateur peut les récupérer à la main).
- `detection` absent ou `enabled: false` ⇒ **pas de détection** (comportement historique
  de l'agent).

---

## 9. Flux de bout en bout & par où commencer

Le schéma suivant relie tous les composants vus précédemment. Un événement entre par la
gauche (driver ou plugin), est normalisé en `LogEvent` + ligne NDJSON, puis suit deux
chemins indépendants : la **persistance/envoi** (spool → shipper → serveur) et la
**détection locale** (moteur Waza → actions).

```text
                    ┌──────────────┐         ┌───────────────┐
   driver kernel ──►│ ipc/device   │         │ plugin/server │◄── plugins (named pipe)
   (IOCTL)          │  pump loop   │         │  workers      │   (après vérif. d'identité)
                    └──────┬───────┘         └──────┬────────┘
                           │ encode_kernel_event_and_log     │ emit_event (attribution anti-spoof)
                           ▼                                  ▼
                    ┌─────────────────────  LogEvent + ligne NDJSON  ──────────────────┐
                    │                                                                  │
            (NDJSON)│                                                  (LogEvent) option│
                    ▼                                                          ▼        │
            ┌───────────────┐   batch-*.zst   ┌──────────────┐        ┌──────────────┐ │
            │ spool/writer  │ ──────────────► │ shipper/run  │ HTTPS  │ moteur Waza  │ │
            │ (kernel+plug.)│                 │ POST /logs   │ ─────► │ detection/   │ │
            └───────────────┘                 └──────────────┘ serveur└──────┬───────┘ │
                                                                 Wazabi      │ actions │
                                                                             ▼         │
                                                                   [waza] log / alerte │
                                                                    / kill (stub)      │
                                                                                       │
                                            console web ◄─ stockage (OpenSearch) ◄──────┘
```

**Pour lire le code dans le bon ordre :**

1. [`src/main.rs`](src/main.rs) — l'orchestration : ce qui démarre, dans quel ordre, et
   comment l'agent s'arrête.
2. [`src/ipc/device.rs`](src/ipc/device.rs) puis [`src/ipc/json.rs`](src/ipc/json.rs) —
   comment un événement binaire du driver devient une ligne NDJSON et un `LogEvent`.
3. [`src/spool/mod.rs`](src/spool/mod.rs) puis [`src/shipper/run.rs`](src/shipper/run.rs) —
   comment les événements sont mis en file sur disque, puis envoyés au serveur.
4. [`src/plugin/protocol.rs`](src/plugin/protocol.rs) →
   [`src/plugin/identity.rs`](src/plugin/identity.rs) →
   [`src/plugin/server.rs`](src/plugin/server.rs) — le canal des plugins et sa sécurité.
5. [`src/detection/mod.rs`](src/detection/mod.rs) →
   [`src/detection/waza/engine.rs`](src/detection/waza/engine.rs) — la détection locale.
6. [`src/config.rs`](src/config.rs) — tous les leviers de réglage.

Pour le détail du contrat agent↔serveur au-delà de l'ingestion `/logs`, voir
[`../WazabiEDR_Server/README.md`](../WazabiEDR_Server/README.md).
