# Configurer le shipper réseau

> Comment pointer l'agent vers **Wazabi Server**, générer un token Bearer protégé par DPAPI, et
> vérifier la chaîne de bout en bout. Détail d'architecture : [`ARCHITECTURE.md`](../../ARCHITECTURE.md)
> (§ shipper). Contrat de l'API serveur :
> [`server-api.md`](../../../WazabiEDR_Server/doc/reference/server-api.md).

`agent.json` porte toute la configuration de l'agent — voir
[`config-reference.md`](../reference/config-reference.md) pour le schéma complet (sections `agent`
+ `shipper`). Cette page ne couvre que la partie shipper.

## La version 30 secondes

1. Avoir un Wazabi Server joignable (dev : `make up` dans `WazabiEDR_Server/`, puis
   `http://localhost:8080`).
2. Enrôler l'agent (manuel aujourd'hui) : obtenir un `agent_id` (UUID) et un `agent_token`
   (Bearer) via `POST /api/v1/agents/enroll`. Tant que l'agent n'a pas son propre auto-enrôlement,
   lancer l'appel soi-même (curl ou `scripts/simulate_agent.py`) et copier les valeurs.
3. Générer un token protégé par DPAPI depuis l'`agent_token` en clair (PowerShell, ci-dessous).
4. Déposer `agent.json` dans `%ProgramData%\WazabiEDR\agent.json`.
5. Relancer l'agent. La ligne de démarrage affiche
   `[shipper] started — endpoint: https://…/api/v1/agents/<uuid>/logs` quand tout est résolu.

## `agent.json` — section shipper

Même parent que le store de manifests, **même politique d'ACL** (Administrateurs uniquement). Lu
**une fois** au démarrage ; pas de hot-reload — un changement nécessite un redémarrage. Le
shipper construit `{server_url}/api/v1/agents/{agent_id}/logs` lui-même ; ne fournissez pas ce
chemin (le `/` final de `server_url` est retiré automatiquement).

```json
{
  "shipper": {
    "enabled": true,
    "server_url": "https://wazabi.example.com",
    "agent_id": "5f1b3a8e-1c4f-4d2e-9b8a-7e3f6a9c0d11",
    "tenant_id": "acme",
    "tags": { "env": "prod", "region": "eu-w1" },
    "token_encrypted_b64": "AQAAANCMnd8BFdERjHoAwE/Cl+sB...",
    "verify_tls": true,
    "timeout_secs": 30,
    "poll_interval_secs": 5,
    "max_backoff_secs": 300
  }
}
```

Le tableau complet des champs est dans [`config-reference.md`](../reference/config-reference.md).
Point clé : **exactement un** de `token_encrypted_b64` / `token_plain` doit être présent ; les
deux à la fois sont rejetés (intention ambiguë).

## Poser l'ACL du fichier

L'ACL `%ProgramData%` par défaut est permissive. Pour un fichier de token EDR, on veut
Administrateurs uniquement. PowerShell admin :

```powershell
$path = "$env:ProgramData\WazabiEDR\agent.json"
$acl = New-Object System.Security.AccessControl.FileSecurity
$acl.SetAccessRuleProtection($true, $false)   # coupe l'héritage
$acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
    "BUILTIN\Administrators", "FullControl", "Allow")))
$acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
    "NT AUTHORITY\SYSTEM", "FullControl", "Allow")))
Set-Acl -Path $path -AclObject $acl
```

## Générer `token_encrypted_b64`

L'agent déchiffre le token via `CryptUnprotectData` sous le scope DPAPI **LOCAL_MACHINE**. L'étape
de chiffrement correspondante (à lancer sur **la même machine** que l'agent — le cryptogramme est
lié à la machine) :

```powershell
Add-Type -AssemblyName System.Security
$plaintext = Read-Host "Token" -AsSecureString
$plainBytes = [Runtime.InteropServices.Marshal]::PtrToStringUni(
    [Runtime.InteropServices.Marshal]::SecureStringToBSTR($plaintext))
$bytes = [Text.Encoding]::UTF8.GetBytes($plainBytes)
$ciphertext = [Security.Cryptography.ProtectedData]::Protect(
    $bytes, $null, [Security.Cryptography.DataProtectionScope]::LocalMachine)
[Convert]::ToBase64String($ciphertext)
```

Copier la base64 imprimée dans `agent.json` comme `token_encrypted_b64`, puis jeter le clair.

> **Pourquoi LOCAL_MACHINE et pas CURRENT_USER ?** La cible de déploiement est un service Windows
> (sous `LocalSystem` ou un compte de service) : un blob DPAPI *user-scoped* produit par votre
> session interactive ne se déchiffrerait pas sous ce compte. Le scope LOCAL_MACHINE est
> déchiffrable par **tout** processus de l'hôte — acceptable puisque l'ACL du fichier restreint
> déjà la lecture aux Administrateurs.

## Vérifier la chaîne

Après redémarrage, l'agent imprime (stderr) :

```
[shipper] started — endpoint: https://wazabi.example.com/api/v1/agents/5f1b3a8e-…/logs — watching 2 dir(s)
```

Les envois réussis sont **silencieux** par design (le shipper ne log que les erreurs et les
retries). Le résumé de fin imprime les totaux : `[agent] shipper: 142 batches sent, 0 rejected,
3 retries`.

## Test local contre un listener stub

Le shipper POST toujours du NDJSON décompressé (décompression en mémoire), donc un listener HTTP
trivial suffit à valider la chaîne sans monter Wazabi Server.

```json
{
  "shipper": {
    "enabled": true,
    "server_url": "http://127.0.0.1:8080",
    "agent_id": "00000000-0000-0000-0000-000000000001",
    "token_plain": "debug-token",
    "poll_interval_secs": 1
  }
}
```

```python
# wedr_listener.py  (python -m http.server ne convient PAS : il répond 501 au POST)
from http.server import BaseHTTPRequestHandler, HTTPServer
import sys
class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get('Content-Length', 0)); body = self.rfile.read(n)
        print(f'\n=== POST {self.path}  {n} bytes ===', flush=True)
        sys.stdout.buffer.write(body); sys.stdout.write('\n'); sys.stdout.flush()
        self.send_response(200); self.send_header('Content-Length', '0'); self.end_headers()
    def log_message(self, *a): pass
HTTPServer(('127.0.0.1', 8080), Handler).serve_forever()
```

`token_plain` évite DPAPI pour le test (l'agent log un avertissement, à ignorer).

## Échecs courants

| Symptôme | Cause | Correctif |
|---|---|---|
| `[shipper] config error: ... not utf-8` | Cryptogramme déchiffré mais pas du texte | Mauvais clair, régénérer |
| `CryptUnprotectData failed: error 13` | Cryptogramme chiffré sur une autre machine | Régénérer sur l'hôte de l'agent |
| `[shipper] server returned 401` | Token faux/expiré | Réémettre le token, régénérer le cryptogramme |
| `[shipper] server returned 413` | Lot trop gros | Baisser `max_bytes_per_file` (rotation plus tôt) |
| `[shipper] transient failure (transport: ...)` | Réseau down, DNS, TLS | Réseau de l'hôte ; le backoff réessaie indéfiniment |
| Les lots s'accumulent, shipper non lancé | Pas de section shipper | Cette page :) |

## Ce qui n'est pas encore couvert

- **Auto-enrôlement** : l'agent n'appelle pas encore `POST /api/v1/agents/enroll` lui-même ;
  l'opérateur pré-provisionne `agent_id` + token.
- **Déploiement en service** : pas encore livré comme service Windows (mais le combo
  `agent.json` + DPAPI LOCAL_MACHINE est déjà la bonne réponse).
- **Hot-reload** : éditer `agent.json` nécessite un redémarrage.
