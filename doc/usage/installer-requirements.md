# Installeur agent — pré-requis système

Document de référence pour le futur installeur (MSI / `setup.exe`).
Liste **exhaustivement** ce qu'il faut mettre en place sur la machine
cible pour que l'agent et ses sous-systèmes (driver, ETW, polling)
fonctionnent à 100 %.

> Tout ce qui figure ici doit être idempotent : l'installeur doit pouvoir
> tourner deux fois sans casser l'état précédent.

## 1. Fichiers et arborescence

| Chemin | Contenu | Permissions |
|---|---|---|
| `C:\Program Files\WazabiEDR\WazabiEDR_Agent.exe` | Binaire agent (release) | `BUILTIN\Administrators:F`, `NT AUTHORITY\SYSTEM:F`, `BUILTIN\Users:RX` |
| `C:\Program Files\WazabiEDR\WazabiEDR_Driver.sys` | Driver kernel signé | Idem |
| `C:\Program Files\WazabiEDR\WazabiEDR_Driver.inf` | Manifest driver | Idem |
| `C:\Program Files\WazabiEDR\WazabiEDR_Driver.cat` | Catalogue signé | Idem |
| `C:\ProgramData\WazabiEDR\agent.json` | Config résolue (server URL + token) | `BUILTIN\Administrators:F`, `NT AUTHORITY\SYSTEM:F` **uniquement** (le token y est en clair) |
| `C:\ProgramData\WazabiEDR\spool\` | Spool d'events local | Idem `agent.json` |
| `C:\ProgramData\WazabiEDR\spool\plugins\` | Spool d'events plugins | Idem |
| `C:\ProgramData\WazabiEDR\quarantine\` | Fichiers quarantinés par le bouton "Quarantaine fichier" | Idem |
| `C:\ProgramData\WazabiEDR\rules\` | Règles Waza (si activé) | Idem |
| `C:\ProgramData\WazabiEDR\plugins\` | Manifestes plugins enregistrés via `wedr-plugin enroll` | Idem |

Toutes les ACLs ci-dessus doivent être posées **avant** d'écrire le fichier,
sinon `agent.json` peut se retrouver avec les permissions héritées du
parent (parfois `Users:R`, ce qui expose le token).

## 2. Driver kernel — installation

```powershell
# 1. Copier le driver dans Program Files (déjà fait au step 1)
# 2. L'installer comme service kernel
sc.exe create WazabiEDR `
    type= kernel `
    start= demand `
    binPath= "C:\Program Files\WazabiEDR\WazabiEDR_Driver.sys" `
    DisplayName= "WazabiEDR Kernel Driver"

# 3. Le démarrer
sc.exe start WazabiEDR
```

Le `start= demand` est volontaire : l'agent démarre le driver au boot
via son propre service (étape suivante). En cas de crash agent, le driver
reste utilisable pour les outils CLI (`wedr-plugin`).

**Si test signing requis** (driver dev non signé EV) :
```powershell
bcdedit /set testsigning on
# Reboot obligatoire après.
```

## 3. Agent — service Windows

L'agent doit tourner en **SYSTEM** (pour ETW privilégié + accès driver) :

```powershell
sc.exe create WazabiEDRAgent `
    binPath= "C:\Program Files\WazabiEDR\WazabiEDR_Agent.exe" `
    DisplayName= "WazabiEDR User-mode Agent" `
    start= auto `
    obj= LocalSystem `
    depend= WazabiEDR

# Description visible dans services.msc
sc.exe description WazabiEDRAgent "Pump driver events, ETW providers, persistence polling and ship telemetry."

# Restart auto en cas de crash : trois tentatives à 60s d'intervalle
sc.exe failure WazabiEDRAgent reset= 86400 actions= restart/60000/restart/60000/restart/60000

sc.exe start WazabiEDRAgent
```

L'option `obj= LocalSystem` est cruciale : sans elle l'agent perd
`SeSystemProfilePrivilege` et la majorité des providers ETW refusent
de s'enable.

## 4. ETW — providers à activer en GPO / registre

L'agent **consomme** ETW ; il ne crée pas de provider. Mais certains
providers ne **génèrent** des events que si une option système est on :

### 4.1 PowerShell ScriptBlock Logging (EventID 4104)

```powershell
$key = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
New-Item -Path $key -Force | Out-Null
Set-ItemProperty -Path $key -Name "EnableScriptBlockLogging" -Value 1 -Type DWord
Set-ItemProperty -Path $key -Name "EnableScriptBlockInvocationLogging" -Value 1 -Type DWord
```

Sans cette clé, le provider `Microsoft-Windows-PowerShell` n'émet pas
les script-blocks décodés — l'agent verra `ps=0` dans ses stats.

### 4.2 WMI Activity (EventID 5857 + 5861)

Activé par défaut sur Windows 10+. Aucune action requise.

### 4.3 DNS-Client (EventID 3008 / 3009)

Activé par défaut. Aucune action.

### 4.4 Kernel-Network (TCP/UDP)

Activé par défaut. Aucune action.

### 4.5 Schannel-Events (TLS handshake)

Activé par défaut. **Note** : EventID 36880 ne fournit le SNI que pour
TLS ≥ 1.2 (TLS 1.3 chiffre le ClientHello → SNI vide).

### 4.6 AMSI

Nécessite **Microsoft Defender** actif (le provider n'est émis que par
le service `WinDefend`). Si Defender est désactivé / remplacé par un
AV tiers, le provider AMSI est silencieux. L'installeur doit vérifier :

```powershell
$defender = Get-Service WinDefend -ErrorAction SilentlyContinue
if (-not $defender -or $defender.Status -ne 'Running') {
    Write-Warning "Microsoft Defender inactif - le provider ETW AMSI sera silencieux."
}
```

## 5. Firewall — autoriser l'agent à sortir

```powershell
New-NetFirewallRule -DisplayName "WazabiEDR Agent - outbound HTTPS" `
    -Direction Outbound `
    -Program "C:\Program Files\WazabiEDR\WazabiEDR_Agent.exe" `
    -Action Allow `
    -Protocol TCP `
    -RemotePort 443,8080 `
    -Profile Any

# Optionnel pour les utils CLI (rien à autoriser, ils ne sortent pas)
```

## 6. Privilèges supplémentaires

L'agent en `LocalSystem` a déjà tout ce qu'il faut, sauf :

- **SeDebugPrivilege** : utile pour `kill_process` sur des process
  protégés. Activé par défaut pour SYSTEM.
- **SeSecurityPrivilege** : nécessaire pour lire les SACL (pas utilisé
  actuellement, mais requis si on ajoute un auditeur de SACL).
- **SeSystemProfilePrivilege** : implicite pour SYSTEM. Indispensable
  pour `StartTraceW`.

Aucune élévation manuelle nécessaire si l'agent tourne en
`obj= LocalSystem`.

## 7. Exclusions Defender (pour éviter l'auto-quarantaine)

Defender peut quarantiner les fichiers du spool (zstd compressé +
contenu suspect parfois). À exclure :

```powershell
Add-MpPreference -ExclusionPath "C:\ProgramData\WazabiEDR"
Add-MpPreference -ExclusionPath "C:\Program Files\WazabiEDR"
Add-MpPreference -ExclusionProcess "WazabiEDR_Agent.exe"
```

## 8. Enrôlement initial

L'installeur peut soit demander interactivement, soit prendre le token
en argument :

```powershell
# Variante 1 : laisser l'opérateur compléter agent.json à la main
# (skeleton auto-généré au premier boot agent, voir config.rs)

# Variante 2 : poser le token + URL via /silent /serverurl=... /token=...
$cfg = @{
    shipper = @{
        enabled = $true
        server_url = "https://wazabi.your-org.example.com"
        enrollment_token = "$EnrollmentToken"  # passé en arg installer
    }
    control = @{ enabled = $true; heartbeat_interval_secs = 30 }
    etw = @{ enabled = $true; dns = $true; tcp = $true; powershell = $true;
             wmi = $true; schannel = $true; amsi = $true }
    polling = @{ enabled = $true; services = $true; scheduled_tasks = $true;
                 interval_secs = 30 }
}
$cfg | ConvertTo-Json -Depth 5 | Set-Content -Path "C:\ProgramData\WazabiEDR\agent.json" -Encoding UTF8
Restart-Service WazabiEDRAgent
```

Le premier `WazabiEDRAgent.exe` après écriture du fichier déclenche
l'auto-enroll : POST `/api/v1/agents/enroll`, réécriture du fichier
avec `agent_id` + `token_plain`, suppression de `enrollment_token`.

## 9. Désinstallation

```powershell
sc.exe stop WazabiEDRAgent
sc.exe delete WazabiEDRAgent
sc.exe stop WazabiEDR
sc.exe delete WazabiEDR

# Nettoyer firewall, exclusions, registry, fichiers
Remove-NetFirewallRule -DisplayName "WazabiEDR Agent - outbound HTTPS" -ErrorAction SilentlyContinue
Remove-MpPreference -ExclusionPath "C:\ProgramData\WazabiEDR" -ErrorAction SilentlyContinue
Remove-MpPreference -ExclusionPath "C:\Program Files\WazabiEDR" -ErrorAction SilentlyContinue
Remove-MpPreference -ExclusionProcess "WazabiEDR_Agent.exe" -ErrorAction SilentlyContinue
Remove-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Recurse -ErrorAction SilentlyContinue
Remove-Item "C:\ProgramData\WazabiEDR" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item "C:\Program Files\WazabiEDR" -Recurse -Force
```

Order matters : agent **avant** driver (l'agent maintient une handle
sur `\\.\WazabiEDR`).

## 9.5 Côté serveur — appliquer le nouveau mapping OpenSearch

Le serveur déclare maintenant un mapping explicite sur ~25 sous-champs
de `raw.*` (DNS, network, integrity, persistence, AMSI…). OpenSearch
**applique le nouveau mapping uniquement aux indices créés après**.
Pour qu'un déploiement existant en profite, deux options :

```powershell
# Option A — drop + recreate (PERD la télémétrie déjà ingérée) :
docker compose exec opensearch curl -X DELETE http://localhost:9200/wazabi-events
docker compose restart api    # recrée l'index via le template au boot

# Option B — rollover (production) :
docker compose exec opensearch curl -X POST http://localhost:9200/wazabi-events/_rollover \
  -H "Content-Type: application/json" -d '{"conditions":{"max_age":"0d"}}'
```

Sans cette étape, les agrégations `terms` sur `raw.query_name` /
`raw.is_malicious` etc. fonctionnent quand même (auto-mapping
dynamique) mais peuvent rater les valeurs > 256 chars ou retourner
silencieusement vide sur les boolean stockés comme string.

## 10. Checklist installeur

- [ ] Copier les binaires dans `C:\Program Files\WazabiEDR\`
- [ ] Créer l'arbo `C:\ProgramData\WazabiEDR\{spool,quarantine,rules,plugins}`
- [ ] ACLer ces dossiers SYSTEM+Administrators
- [ ] Installer le driver kernel via `sc.exe create … type= kernel`
- [ ] Démarrer le driver
- [ ] Activer la GPO `EnableScriptBlockLogging` (registre)
- [ ] Vérifier que Microsoft Defender tourne (sinon warning sur AMSI)
- [ ] Créer le service agent `WazabiEDRAgent` en `obj= LocalSystem`
- [ ] Configurer le restart automatique (`sc.exe failure`)
- [ ] Ajouter la règle pare-feu sortante TCP 443/8080
- [ ] Ajouter les exclusions Defender pour `WazabiEDR\` (sinon
      auto-quarantaine du spool)
- [ ] Écrire `agent.json` avec server_url + enrollment_token (si mode
      silencieux) ; sinon laisser le squelette auto-généré
- [ ] Démarrer le service agent
- [ ] Vérifier les logs (`Get-WinEvent -ProviderName "Service Control Manager"`)
- [ ] Au bout de ~60s : vérifier dans la console serveur que l'endpoint
      apparaît avec un `last_checkin_at` récent et des events qui
      arrivent.
