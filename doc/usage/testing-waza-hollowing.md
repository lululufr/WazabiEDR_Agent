# Tester la détection Waza « process hollowing »

> Procédure de **test manuel** de la règle `ProcessHollowingInjection`
> (`rules/main.waza`). On déclenche volontairement un motif d'injection bénin sur une
> machine de test, puis on vérifie que l'agent émet l'alerte Waza.

> ⚠️ **À faire uniquement sur une VM / machine de test que vous maîtrisez.** On déclenche
> une vraie injection de thread distant. Jamais sur un poste de production.

---

## 1. Ce que la règle détecte (et ses limites)

La règle corrèle, **dans une fenêtre de 10 s**, deux événements kernel :

```
kernel_callback.process_handle_access.op == "Open"
&& kernel_callback.thread_create.remote_injection == true
```

- `process_handle_access.op == "Open"` : un processus a **ouvert un handle** vers un autre
  processus (`OpenProcess`).
- `thread_create.remote_injection == true` : un **thread distant** a été créé (l'agent met ce
  booléen à `true` quand le processus créateur n'est pas le processus cible — motif
  `CreateRemoteThread`).

C'est le motif de base d'une injection / d'un *process hollowing* (un processus en ouvre un
autre puis y détourne l'exécution).

> **Limites assumées (heuristique).** Le moteur actuel :
> - ne **lie pas** les PID des deux événements entre eux : la règle se déclenche dès qu'un
>   handle-open **et** un thread distant coexistent dans la fenêtre, même s'ils concernent des
>   processus différents → faux positifs possibles sur une machine chargée ;
> - ne peut pas tester les **bits** de `desired_access` (pas d'opérateur bit-à-bit), donc on
>   ne distingue pas un `OpenProcess` en lecture seule d'un `OpenProcess` avec droits
>   d'écriture mémoire.
>
> Pour un test manuel propre, gardez la VM au repos pendant la manip : l'injection sera alors
> le seul couple d'événements dans la fenêtre.

---

## 2. Prérequis

- Une **VM Windows de test**, shell **PowerShell en administrateur**.
- Le **driver WazabiEDR installé et chargé** (voir
  [`WazabiEDR_Driver/doc/usage/installing-driver.md`](../../../WazabiEDR_Driver/doc/usage/installing-driver.md)).
- L'agent **buildé en release** : `cargo build --release` →
  `target\release\WazabiEDR_Agent.exe`.
- `mavinject.exe` (présent par défaut dans `C:\Windows\System32\` sur Windows 10/11).

---

## 3. Activer la détection

La détection est **opt-in** : tant que la section `detection` n'est pas activée, l'agent se
comporte comme avant.

1. Copier le fichier de règles à l'emplacement par défaut :

   ```powershell
   PS> $rules = "$env:ProgramData\WazabiEDR\rules"
   PS> New-Item -ItemType Directory -Force $rules | Out-Null
   PS> Copy-Item .\rules\main.waza "$rules\main.waza" -Force
   ```

2. Éditer `%ProgramData%\WazabiEDR\agent.json` pour activer `detection` :

   ```json
   {
     "agent": { "console_output": true },
     "detection": {
       "enabled": true,
       "rules_path": "C:\\ProgramData\\WazabiEDR\\rules\\main.waza"
     }
   }
   ```

> La détection voit **tous** les événements du driver. L'éventuelle section `filter`
> (allow-list) ne coupe que ce qui est spoolé/envoyé au serveur — elle **n'affecte pas** la
> détection locale. Inutile d'y toucher pour ce test.

---

## 4. Lancer l'agent et confirmer le chargement des règles

Les messages de l'agent (`[agent]`, `[waza]`, erreurs) sortent sur **stderr** ; les events
bruts (si `console_output: true`) sortent sur **stdout**. Pour tout voir et garder une trace :

```powershell
PS> .\target\release\WazabiEDR_Agent.exe 2>&1 | Tee-Object -FilePath waza-test.log
```

Au démarrage, vérifier la ligne de chargement :

```
[waza] loaded 4 rule(s) from C:\ProgramData\WazabiEDR\rules\main.waza
```

> Si cette ligne n'apparaît pas, la détection n'est pas active : voir le
> [dépannage](#8-dépannage).

Laisser cette fenêtre ouverte ; elle affichera l'alerte.

---

## 5. Préparer une cible bénigne

Dans une **deuxième** fenêtre PowerShell (admin) :

```powershell
PS> Start-Process notepad
PS> (Get-Process notepad).Id      # ← noter ce PID, c'est la cible
```

Il faut aussi une **DLL valide** à injecter. N'importe quelle DLL correcte suffit ; voici une
DLL bénigne minimale (son `DllMain` ne fait rien et renvoie `TRUE`) :

```c
// benign.c
#include <windows.h>
BOOL APIENTRY DllMain(HMODULE h, DWORD reason, LPVOID reserved) {
    return TRUE;
}
```

Compilation (au choix) :

```powershell
# Avec les Build Tools MSVC (depuis un "x64 Native Tools Command Prompt") :
PS> cl /LD benign.c

# …ou avec MinGW :
PS> gcc -shared -o benign.dll benign.c
```

---

## 6. Déclencher l'injection

`mavinject.exe` est un utilitaire **signé et intégré à Windows** qui injecte une DLL via
`OpenProcess` + `CreateRemoteThread` → il produit **les deux** événements dont la règle a
besoin :

```powershell
PS> mavinject.exe <PID_notepad> /INJECTRUNNING C:\chemin\vers\benign.dll
```

> Ne visez **que** votre `notepad` de test, jamais un processus système.

---

## 7. Résultat attendu

### Succès

Dans la fenêtre de l'agent, **dans les 10 s** suivant l'injection, sur stderr :

```
[waza] ALERT rule='ProcessHollowingInjection' msg='Possible process hollowing / remote injection' (kernel_callback.thread_create)
[waza] MATCH rule='ProcessHollowingInjection' -> LOG (kernel_callback.thread_create)
```

C'est le signal direct que la détection fonctionne.

Pour **corroborer** (si `console_output: true`), on voit aussi passer sur stdout les events
bruts qui ont déclenché la règle, par exemple :

```json
{"event_type":"process_handle_access", ... ,"raw":{"op":"Open", ...}}
{"event_type":"thread_create",         ... ,"raw":{"remote_injection":true, ...}}
```

### Test négatif (important)

Fermez `notepad`, rouvrez-en un **sans** l'injecter :

```powershell
PS> Start-Process notepad
```

➡️ **Aucune** ligne `ProcessHollowingInjection` ne doit apparaître. La règle n'est évaluée que
lorsqu'arrive un `process_handle_access` ou un `thread_create` (index inversé), et le simple
lancement d'un notepad ne crée pas de thread distant.

---

## 8. Dépannage

Rien ne s'affiche après l'injection ? Vérifier dans l'ordre :

| Vérification | Comment |
|---|---|
| Détection active | La ligne `[waza] loaded N rule(s)` est-elle apparue au démarrage ? Sinon `detection.enabled` n'est pas à `true` ou `agent.json` est mal formé. |
| Bon fichier de règles | `rules_path` pointe-t-il bien vers le `main.waza` que vous avez copié ? La règle `ProcessHollowingInjection` y est-elle ? |
| On regarde stderr | Les `[waza] ...` sont sur **stderr** ; assurez-vous de ne pas avoir filtré que stdout (utiliser `2>&1`). |
| Le driver livre des events | Voit-on d'autres events passer (lancer/fermer des process) ? Sinon le driver n'est pas chargé / pas connecté. |
| Délai | L'`ALERT` arrive dans la fenêtre de 10 s **après** que les deux events sont survenus ; relancez l'injection si vous avez trop attendu. |
| `mavinject` a réussi | `echo $LASTEXITCODE` après la commande doit être `0`. Une DLL invalide ou un PID protégé fait échouer l'injection (donc pas de thread distant créé). |

---

## 9. Alternative sans `mavinject`

Si `mavinject.exe` est indisponible, n'importe quel injecteur classique faisant
`OpenProcess` → `VirtualAllocEx` → `WriteProcessMemory` → `CreateRemoteThread` vers le PID de
`notepad` produit le même couple d'événements (handle-open + thread distant) et déclenche la
règle. `mavinject` reste la voie recommandée car il est déjà présent et signé.
