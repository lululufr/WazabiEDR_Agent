<#
.SYNOPSIS
    Bootstrap initial d'un agent WazabiEDR contre un serveur Wazabi.

.DESCRIPTION
    En une commande :
      1. Vérifie la connectivité au serveur (/health/ready).
      2. Appelle POST /api/v1/agents/enroll avec le token d'enrôlement.
      3. Écrit %ProgramData%\WazabiEDR\agent.json (backup auto si existe).
      4. (option) Encrypt le bearer avec DPAPI-LOCAL_MACHINE.
      5. (option) Build le binaire en release.

    Idempotent en mode -Force : ré-enrôle l'agent et réécrit la config.
    Sans -Force, refuse d'écraser un agent.json existant.

    À lancer en PowerShell **Administrateur** : l'écriture sous %ProgramData%
    et la lecture DPAPI-LOCAL_MACHINE le réclament.

.PARAMETER ServerUrl
    Base URL du serveur Wazabi. Ex : http://192.168.1.179:8080.
    Le script ajoute /api/v1/agents/{id}/logs lui-même.

.PARAMETER EnrollmentToken
    Token d'enrôlement partagé. Côté serveur : `make enrollment-token`
    ou la variable ENROLLMENT_TOKEN du .env.

.PARAMETER Hostname
    Hostname à reporter au serveur. Par défaut : $env:COMPUTERNAME.

.PARAMETER UseDpapi
    Encrypt le bearer avec DPAPI-LOCAL_MACHINE (production-leaning). Sans ça,
    le token est stocké en clair dans agent.json (token_plain, avec warning
    runtime). Utile uniquement en dev.

.PARAMETER BuildRelease
    Build `cargo build --release` après la config. À défaut, le script suppose
    que le binaire est déjà construit.

.PARAMETER Force
    Écrase un agent.json existant (un backup `.bak.<timestamp>` est créé).

.EXAMPLE
    .\bootstrap.ps1 -ServerUrl http://192.168.1.179:8080 `
                    -EnrollmentToken cd489eab... `
                    -BuildRelease

.EXAMPLE
    .\bootstrap.ps1 -ServerUrl http://localhost:8080 `
                    -EnrollmentToken dev-enrollment-token-change-me `
                    -UseDpapi -Force
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ServerUrl,

    [Parameter(Mandatory = $true)]
    [string]$EnrollmentToken,

    [string]$Hostname = $env:COMPUTERNAME,

    [switch]$UseDpapi,

    [switch]$BuildRelease,

    [switch]$Force
)

$ErrorActionPreference = 'Stop'

# Le path canonique de l'agent.json — duplique la const Rust
# `WazabiEDR_Agent/src/config.rs::AGENT_CONFIG_FILE` pour éviter
# qu'un opérateur l'oublie. Si la const Rust bouge, mettre à jour ici.
$ProgramData = if ($env:ProgramData) { $env:ProgramData } else { 'C:\ProgramData' }
$AgentDir    = Join-Path $ProgramData 'WazabiEDR'
$AgentJson   = Join-Path $AgentDir 'agent.json'
$SpoolDir    = Join-Path $AgentDir 'spool'

# --- Sanity check : admin (pour écrire sous %ProgramData% et DPAPI machine) ---
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal(
    [Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "Pas en Administrateur. L'écriture sous $AgentDir ou DPAPI-LOCAL_MACHINE peut échouer."
}

# Normalise le ServerUrl (pas de slash final, le shipper l'ajoute lui-même)
$ServerUrl = $ServerUrl.TrimEnd('/')

# --- 1. Sonde santé serveur ----------------------------------------------------
Write-Host ">>> Vérification du serveur $ServerUrl/health/ready…" -ForegroundColor Cyan
try {
    $health = Invoke-RestMethod -Uri "$ServerUrl/health/ready" -Method Get -TimeoutSec 5
    Write-Host "    ✅ Serveur ready ($($health | ConvertTo-Json -Compress))"
} catch {
    Write-Host "    ❌ Serveur injoignable : $($_.Exception.Message)" -ForegroundColor Red
    throw "Vérifie ServerUrl, le pare-feu, et que 'make setup' a bien fini côté serveur."
}

# --- 2. Enrôlement -------------------------------------------------------------
Write-Host ">>> Enrôlement de l'agent (hostname=$Hostname)…" -ForegroundColor Cyan

# IP locale — sert juste à informer le serveur (champ host.ip), pas critique
# si erreur on envoie null
$localIp = $null
try {
    $localIp = (Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop `
        | Where-Object { $_.IPAddress -notlike '169.254.*' -and $_.IPAddress -ne '127.0.0.1' } `
        | Select-Object -First 1).IPAddress
} catch {}

$osVersion = try { (Get-CimInstance Win32_OperatingSystem).Caption } catch { 'Windows' }

$enrollBody = @{
    enrollment_token = $EnrollmentToken
    host = @{
        hostname   = $Hostname
        ip         = $localIp
        os         = 'Windows'
        os_version = $osVersion
    }
    agent_version = '0.1.0'
} | ConvertTo-Json -Depth 5 -Compress

try {
    $enrollResp = Invoke-RestMethod `
        -Uri "$ServerUrl/api/v1/agents/enroll" `
        -Method Post `
        -ContentType 'application/json' `
        -Body $enrollBody `
        -TimeoutSec 15
} catch {
    $code = $_.Exception.Response.StatusCode.value__
    $body = try { $_.ErrorDetails.Message } catch { $_.Exception.Message }
    if ($code -eq 401) {
        Write-Host "    ❌ 401 : EnrollmentToken refusé. Récupère le bon via 'make enrollment-token' côté serveur." -ForegroundColor Red
    } else {
        Write-Host "    ❌ Enrôlement échoué (HTTP $code) : $body" -ForegroundColor Red
    }
    throw
}

$agentId    = $enrollResp.agent_id
$agentToken = $enrollResp.agent_token
$interval   = $enrollResp.checkin_interval_seconds
Write-Host "    ✅ agent_id=$agentId  (checkin interval ${interval}s)"

# --- 3. Préparer agent.json ----------------------------------------------------
if (-not (Test-Path $AgentDir)) {
    Write-Host ">>> Création de $AgentDir" -ForegroundColor Cyan
    New-Item -ItemType Directory -Path $AgentDir -Force | Out-Null
}

if ((Test-Path $AgentJson) -and -not $Force) {
    throw "$AgentJson existe déjà. Relance avec -Force pour le remplacer (un backup sera fait)."
}
if (Test-Path $AgentJson) {
    $backup = "$AgentJson.bak.$(Get-Date -Format 'yyyyMMddHHmmss')"
    Copy-Item -Path $AgentJson -Destination $backup
    Write-Host ">>> Backup de l'ancien agent.json → $backup" -ForegroundColor Yellow
}

# --- 3a. Token : DPAPI ou plain ------------------------------------------------
$shipperSection = [ordered]@{
    enabled    = $true
    server_url = $ServerUrl
    agent_id   = $agentId
}
if ($UseDpapi) {
    Write-Host ">>> DPAPI-LOCAL_MACHINE encryption du bearer…" -ForegroundColor Cyan
    Add-Type -AssemblyName System.Security
    $tokenBytes  = [Text.Encoding]::UTF8.GetBytes($agentToken)
    $cipherBytes = [Security.Cryptography.ProtectedData]::Protect(
        $tokenBytes,
        $null,
        [Security.Cryptography.DataProtectionScope]::LocalMachine)
    $shipperSection['token_encrypted_b64'] = [Convert]::ToBase64String($cipherBytes)
    Write-Host "    ✅ Token DPAPI-protected ($($cipherBytes.Length) bytes ciphertext)"
} else {
    $shipperSection['token_plain'] = $agentToken
    Write-Warning "Token stocké en clair (token_plain). Pour la prod, relance avec -UseDpapi."
}

$shipperSection['poll_interval_secs'] = 1   # drain rapide en dev
$shipperSection['timeout_secs']       = 30
$shipperSection['max_backoff_secs']   = 60

$config = [ordered]@{
    '_comment' = "Bootstrappé par scripts/bootstrap.ps1 le $(Get-Date -Format 's'). " +
                 "Régénérer avec '.\bootstrap.ps1 -ServerUrl … -Force'."
    'agent' = [ordered]@{
        console_output = $true
        spool_dir      = $SpoolDir
    }
    'shipper' = $shipperSection
}

$json = $config | ConvertTo-Json -Depth 10
# ConvertTo-Json utilise UTF-16 par défaut sur PS5.1 ; force UTF-8 sans BOM.
[IO.File]::WriteAllText($AgentJson, $json + "`n", (New-Object Text.UTF8Encoding($false)))
Write-Host ">>> agent.json écrit à $AgentJson" -ForegroundColor Green

# --- 3b. ACL Administrators-only (best-effort) ---------------------------------
try {
    $acl = New-Object Security.AccessControl.FileSecurity
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($principal in @('BUILTIN\Administrators', 'NT AUTHORITY\SYSTEM')) {
        $rule = New-Object Security.AccessControl.FileSystemAccessRule(
            $principal, 'FullControl', 'Allow')
        $acl.AddAccessRule($rule)
    }
    Set-Acl -Path $AgentJson -AclObject $acl
    Write-Host ">>> ACL : Administrators + SYSTEM only" -ForegroundColor Green
} catch {
    Write-Warning "Pose d'ACL impossible : $($_.Exception.Message). Le fichier reste avec l'ACL héritée."
}

# --- 4. Build optionnel --------------------------------------------------------
if ($BuildRelease) {
    Write-Host ">>> cargo build --release…" -ForegroundColor Cyan
    Push-Location (Split-Path $PSScriptRoot -Parent)
    try {
        cargo build --release
        if ($LASTEXITCODE -ne 0) { throw "cargo build a échoué (exit $LASTEXITCODE)" }
        $binary = Join-Path (Get-Location) 'target\release\WazabiEDR_Agent.exe'
        Write-Host "    ✅ Binaire : $binary"
    } finally {
        Pop-Location
    }
}

# --- 5. Récap final ------------------------------------------------------------
Write-Host ""
Write-Host "═══════════════════════════════════════════════════════════════════" -ForegroundColor Green
Write-Host "  Agent bootstrappé." -ForegroundColor Green
Write-Host "═══════════════════════════════════════════════════════════════════" -ForegroundColor Green
Write-Host "  agent_id     : $agentId"
Write-Host "  server_url   : $ServerUrl"
Write-Host "  agent.json   : $AgentJson"
Write-Host "  spool dir    : $SpoolDir"
Write-Host ""
Write-Host "  Prérequis runtime :"
Write-Host "    - Driver WazabiEDR chargé et bound (testsigning ON)"
Write-Host "    - Voir WazabiEDR_Doc/usage/installing-driver.md"
Write-Host ""
Write-Host "  Lancer l'agent :"
Write-Host "    .\target\release\WazabiEDR_Agent.exe"
Write-Host ""
Write-Host "  Vérifier l'arrivée des events côté serveur :"
Write-Host "    curl $ServerUrl/openapi.json | Out-Null   # serveur joignable"
Write-Host "    Invoke-RestMethod ($ServerUrl -replace ':8080',':9200')/wazabi-events/_count"
Write-Host "═══════════════════════════════════════════════════════════════════" -ForegroundColor Green
