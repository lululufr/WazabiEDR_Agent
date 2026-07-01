# Règles `.waza` — référence

Les règles de détection WazabiEDR sont écrites dans un DSL textuel maison
(le format `.waza`). Le **même** parser et le **même** moteur sont utilisés
côté agent (Rust, hot-reload) et côté serveur (via le binaire
`wedr-waza-check` invoqué en subprocess par l'API) — il n'y a qu'une
implémentation de la grammaire (`wedr-waza-core`).

Ce document est la référence normative. Si le code Rust diverge, c'est le
code qui est faux.

---

## Vue d'ensemble

Un fichier `.waza` contient deux sections de premier niveau, `Detection`
et `Action`. Chacune contient des **groupes nommés**. Le nom relie une
règle (groupe de conditions) à ses actions :

```text
- Detection:
  - LsassHandleSnoop:
      window: 10s
      throttle: 1/min
      - kernel_callback.process_handle_access.op == "Open" && kernel_callback.process_create.image_path contains "lsass"

- Action:
  - LsassHandleSnoop:
    - alert "Process opened a handle to lsass.exe"
    - log
```

> ⚠️ **Une condition tient sur UNE ligne.** Le parser découpe par
> lignes ; il n'y a pas de continuation `\` ni d'auto-jointure
> d'indent. Pour un AND-OR complexe, garde tout sur la même ligne ou
> éclate en plusieurs lignes OR-ées (rappel : les lignes dans un même
> groupe sont en **OU implicite**, pour un ET utiliser `&&`).

---

## Sections

### `Detection`

Contient les groupes-règles. Chaque groupe est introduit par son nom
suivi de `:`. À l'intérieur du groupe :

| Directive | Rôle | Défaut |
|---|---|---|
| `window: <durée>` | Fenêtre de corrélation entre évènements | 5 s |
| `throttle: <N>/<durée>` | Anti-storm : `N` déclenchements max par fenêtre roulante | aucun |
| `include "<path>"` | Inclut un autre fichier `.waza` (résolu relatif au fichier courant) | — |
| `- <expression>` | Condition (une par ligne, OR implicite entre lignes) | — |

### `Action`

Contient les actions exécutées quand le groupe `Detection` du même nom
déclenche. Actions disponibles :

| Action | Effet | Disponible |
|---|---|---|
| `log` | Trace `[waza] MATCH` côté agent | ✅ |
| `alert "message"` | Trace + forward à `/agents/{id}/alerts` côté serveur | ✅ |
| `kill` (alias : `killProcess`, `kill_process`) | Tuer le processus incriminé | ⚠️ stub (le driver est read-only) |

---

## Grammaire des expressions

```
expression := or
or         := and ('||' and)*   |   and ('|' and)*
and        := not ('&&' not)*
not        := '!' not   |   atom
atom       := '(' or ')'   |   comparison
comparison := PATH op value
PATH       := <module>.<event_type>.<field>
op         := '==' | '!=' | '<' | '>' | '<=' | '>='
            | 'contains' | 'startsWith'
value      := <int> | <float> | <string> | <bool>
```

### Opérateurs par type

| Type field | Opérateurs supportés |
|---|---|
| `int` / `float` | `== != < > <= >=` |
| `string` | `== != contains startsWith` |
| `bool` | `== !=` |

Les comparaisons type-incompatibles (ex. `int.field == "4688"`) retournent
**false** sans crash.

### Littéraux

- **String** : `"texte"`, avec échappes `\"`, `\\`, `\n`, `\t`
- **Int** : `4688`, `-3`
- **Float** : `0.5`, `-1.25`
- **Bool** : `true`, `false`

### Commentaires

`# commentaire jusqu'à fin de ligne` — accepté **en début OU en milieu**
de ligne. À l'intérieur d'une string littérale, `#` reste littéral.

```text
- kernel_callback.process_create.pid == 4688  # OK ici, jusqu'au EOL
- kernel_callback.process_create.image_path contains "foo#bar.exe"  # "#" dans la string n'est PAS un commentaire
```

### Durées

`window:` et `throttle:` acceptent les suffixes :

| Suffixe | Sens |
|---|---|
| `<n>ms` | millisecondes |
| `<n>s` | secondes |
| `<n>m` ou `<n>/min` | minutes |
| `<n>h` ou `<n>/hour` | heures |
| `<n>` (nu) | secondes |

Pour `throttle:` uniquement, les raccourcis `<N>/sec`, `<N>/min`,
`<N>/hour` sont équivalents à `<N>/1s`, `<N>/60s`, `<N>/3600s`.

---

## Chemins de champs

Un chemin est `module.event_type.field`. **Aucune** valeur n'est codée en
dur dans le parser — un champ inconnu ne déclenche rien (pas d'erreur).
Si une `schema.json` est chargée, le parser warn sur les chemins qui n'y
sont pas listés (typos probables).

### Module `kernel_callback`

Évènements émis par le driver (cf. `WazabiEDR_Driver/doc/reference/event-types.md`) :

| Event type | Fields |
|---|---|
| `process_create` | `pid`, `parent_pid`, `creating_pid`, `image_path` |
| `process_terminate` | `pid` |
| `module_load` | `pid`, `scope` (`"kernel"`/`"user"`), `image_base`, `image_size`, `image_path` |
| `registry_write` | `pid`, `op`, `op_code`, `key_path`, `value_name`, `value_type`, `data_size`, `data_preview_hex`, `data_truncated` |
| `thread_create` | `pid`, `tid`, `creating_pid`, `remote_injection` |
| `thread_exit` | `pid`, `tid` |
| `process_handle_access` | `source_pid`, `target_pid`, `desired_access`, `original_desired_access`, `op` (`"Open"`/`"Duplicate"`) |

### Module `plugin`

Le champ `event_type` reflète le `kind` choisi par le plugin (ex.
`"defender.alert"`). Les champs sont le payload aplati que le plugin
envoie. Pas de schéma figé.

---

## Corrélation : sémantique

Le `window:` définit une **fenêtre glissante par règle**. Quand un
évènement arrive et que sa règle pourrait le concerner (index inversé),
il est poussé dans la fenêtre de cette règle. Ensuite **chaque ligne** de
la règle (chaque condition au top level, OR implicite entre lignes) est
évaluée contre le contenu actuel de la fenêtre.

Une condition `A && B` est satisfaite ssi il existe **dans la fenêtre**
un évènement satisfaisant A ET un évènement satisfaisant B — **pas
forcément le même**. C'est ce qui permet la corrélation multi-évènement.

> **Limite connue** : le moteur ne lie pas les pid entre évènements
> d'une corrélation. `process_handle_access.target_pid == thread_create.pid`
> n'est pas exprimable aujourd'hui — il faut un opérateur de jointure
> dédié à venir.

---

## Throttle (anti-storm)

```text
- NoisyRule:
    throttle: 1/min
    - kernel_callback.process_create.image_path contains "scanner"
```

Le moteur garde un anneau des derniers déclenchements de la règle. Si
ajouter un nouveau déclenchement dépasse `max` dans la fenêtre `per`, la
détection est **étouffée** (pas d'actions). Indépendant du `window:` de
corrélation : la corrélation décide si la règle match, le throttle
décide si on agit.

---

## Mode déconnecté

L'agent fonctionne **sans serveur**. Si tu fournis un fichier
`<rules_path>` à la main, le moteur le charge au démarrage et le
re-charge à chaque changement (hot-reload). Les alertes sont tracées
localement (`eprintln!`).

Quand le serveur est là, l'agent télécharge automatiquement le template
de profil et écrit les sources des règles activées dans
`<server_rules_path>` (chemin configurable, default
`<ProgramData>/WazabiEDR/rules/server.waza`). Pour que ces règles soient
appliquées, ton `<rules_path>` doit contenir :

```text
- Detection:
  # ... tes règles locales ...
  - include "./server.waza"

- Action:
  # ... tes actions locales ...
```

À chaque sync de profil, l'agent réécrit `server.waza` puis appelle
`DetectionEngine::force_reload()` — la nouvelle version est appliquée en
quelques millisecondes.

Désactiver le push serveur : `detection.server_rules_path = ""` dans
`agent.json`.

---

## Validation côté opérateur

Le moteur Waza tourne **uniquement côté agent** : c'est lui qui parse
le `.waza` quand il pull son profil. Le serveur ne valide rien, il
stocke et distribue. Une règle syntaxiquement cassée est rejetée par
l'agent au load — l'erreur remontera via heartbeat dans une itération
future (TODO côté agent : champ `rule_errors[]` dans la heartbeat).

L'API expose un seul endpoint Waza :

| Endpoint | Rôle |
|---|---|
| `GET /api/v1/admin/rules/_schema` | Liste statique des `(module, event_type, field, type)` kernel pour alimenter l'autocomplétion de l'éditeur web. Définie dans `app/services/waza_schema.py` côté serveur, **miroir** de `wedr_waza_core::schema::builtin_kernel_schema` côté Rust. |

Pour valider / simuler une règle **avant** de la pousser à la flotte,
utiliser le binaire CLI `wedr-waza-check` (vit dans `WazabiEDR_Utils`) :

```text
wedr-waza-check validate my_rule.waza
wedr-waza-check simulate my_rule.waza my_event.json
wedr-waza-check schema
```

Le binaire est l'outil opérateur — pas une dépendance serveur.

---

## Exemples

### Process lancé depuis %TEMP%

```text
- Detection:
  - SuspiciousImagePath:
      - kernel_callback.process_create.image_path contains "\\Temp\\"
      - kernel_callback.process_create.image_path contains "\\AppData\\Local\\Temp"

- Action:
  - SuspiciousImagePath:
    - alert "Process launched from a temp directory"
```

### Heuristique injection (`OpenProcess` + `CreateRemoteThread` dans la même fenêtre)

```text
- Detection:
  - ProcessHollowingInjection:
      window: 10s
      throttle: 1/min
      - kernel_callback.process_handle_access.op == "Open" && kernel_callback.thread_create.remote_injection == true

- Action:
  - ProcessHollowingInjection:
    - alert "Possible process hollowing / remote injection"
    - log
```

### Plugin (Defender bridge — exemple)

```text
- Detection:
  - DefenderMalwareDetected:
      - plugin.defender.severity_id >= 4

- Action:
  - DefenderMalwareDetected:
    - alert "Defender detected malware (severity ≥ 4)"
```

(Le `module` reste `plugin`, l'`event_type` est le `kind` que le plugin
émet, ici `defender`.)

---

## Erreurs courantes

| Symptôme | Cause |
|---|---|
| `line N: invalid field path 'foo'` | Le chemin n'a pas 3 segments séparés par `.` |
| `line N: bad window '10x'` | Suffixe de durée inconnu — utiliser `ms`/`s`/`m`/`h` |
| `line N: bad throttle '1/foo'` | Format attendu : `N/sec`, `N/min`, `N/hour` ou `N/<durée>` |
| `line N: unknown action 'block'` | Seules `log`, `alert`, `kill` sont implémentées |
| `line N: duplicate Detection group 'X'` | Le même nom de règle apparaît deux fois en Detection. Renommer ou fusionner. |
| `line N: duplicate Action group 'X'` | Idem côté Action. |
| `rule 'X' has a Detection group but no matching Action group` | Une Detection sans Action ne produit rien — ajouter la section Action ou supprimer la rule. |
| Règle compile mais ne déclenche jamais | Le champ référencé n'existe pas réellement dans le module (typo). Charger une `schema.json` pour avoir un warn loud. |
| Règle déclenche mais aucune alerte côté serveur | `Action` ne contient pas `alert` (ou le control plane n'est pas câblé, ou le `detection.send_alerts` est `false`). |
