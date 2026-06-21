<#
.SYNOPSIS
    Bootstrap one-shot d'un agent WazabiEDR contre un serveur Wazabi.

.DESCRIPTION
    En une commande :
      1. Vérifie le serveur (/healthz).
      2. Télécharge un agent.json pré-rempli depuis /api/v1/bootstrap/agent.json
         (le serveur est source de vérité sur le shape du fichier).
      3. (option) Convertit token_plain → token_encrypted_b64 (DPAPI-LOCAL_MACHINE).
      4. (option) cargo build --release.

    Idempotent en mode -Force : ré-écrit la config.
    Sans -Force, refuse d'écraser un agent.json existant (backup auto).

    À lancer en PowerShell **Administrateur** : %ProgramData% + DPAPI le réclament.

.PARAMETER ServerUrl
    Base URL du serveur Wazabi. Ex : http://192.168.1.179:8080.

.PARAMETER Token
    INGEST_TOKEN partagé. Côté serveur : `make token` ou la variable du .env
    (ou le token auto-généré lu dans /data/ingest_token au 1er boot).

.PARAMETER AgentId
    Identifiant agent à indexer côté serveur. Défaut : $env:COMPUTERNAME (côté
    agent Rust si non transmis). Ce paramètre permet de l'overrider.

.PARAMETER UseDpapi
    Convertit le token_plain reçu en token_encrypted_b64 DPAPI-LOCAL_MACHINE.
    Recommandé en prod.

.PARAMETER BuildRelease
    `cargo build --release` après la config.

.PARAMETER Force
    Écrase l'agent.json existant (backup `.bak.<timestamp>` créé).

.EXAMPLE
    .\bootstrap.ps1 -ServerUrl http://192.168.1.179:8080 -Token cd489eab... -BuildRelease

.EXAMPLE
    .\bootstrap.ps1 -ServerUrl http://localhost:8080 -Token <token> -UseDpapi -Force
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] [string]$ServerUrl,
    [Parameter(Mandatory = $true)] [string]$Token,
    [string]$AgentId,
    [switch]$UseDpapi,
    [switch]$BuildRelease,
    [switch]$Force
)

$ErrorActionPreference = 'Stop'

$ProgramData = if ($env:ProgramData) { $env:ProgramData } else { 'C:\ProgramData' }
$AgentDir    = Join-Path $ProgramData 'WazabiEDR'
$AgentJson   = Join-Path $AgentDir 'agent.json'

$ServerUrl = $ServerUrl.TrimEnd('/')

$currentPrincipal = New-Object Security.Principal.WindowsPrincipal(
    [Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "Pas en Administrateur. L'écriture sous $AgentDir ou DPAPI peut échouer."
}

# --- 1. Sonde santé serveur ---------------------------------------------------
Write-Host ">>> $ServerUrl/healthz…" -ForegroundColor Cyan
try {
    $health = Invoke-RestMethod -Uri "$ServerUrl/healthz" -Method Get -TimeoutSec 5
    Write-Host "    OK (opensearch: $($health.opensearch.ok))"
} catch {
    throw "Serveur injoignable : $($_.Exception.Message). Vérifie ServerUrl + firewall."
}

# --- 2. Télécharge l'agent.json complet ---------------------------------------
$url = "$ServerUrl/api/v1/bootstrap/agent.json"
if ($AgentId) { $url += "?agent_id=$([Uri]::EscapeDataString($AgentId))" }

Write-Host ">>> GET $url" -ForegroundColor Cyan
try {
    $resp = Invoke-RestMethod -Uri $url -Method Get -TimeoutSec 10 `
        -Headers @{ Authorization = "Bearer $Token" }
} catch {
    $code = $_.Exception.Response.StatusCode.value__
    if ($code -eq 401) {
        throw "401 : Token refusé. Récupère le bon via 'make token' côté serveur."
    }
    throw "Échec : $($_.Exception.Message)"
}

# Convertit en PSCustomObject avec PowerShell-style keys pour manipulation
$config = $resp

# --- 3. DPAPI optionnel : remplace token_plain par token_encrypted_b64 --------
if ($UseDpapi) {
    Write-Host ">>> DPAPI-LOCAL_MACHINE encryption du token…" -ForegroundColor Cyan
    Add-Type -AssemblyName System.Security
    $tokenBytes  = [Text.Encoding]::UTF8.GetBytes($config.shipper.token_plain)
    $cipherBytes = [Security.Cryptography.ProtectedData]::Protect(
        $tokenBytes, $null, [Security.Cryptography.DataProtectionScope]::LocalMachine)
    $b64 = [Convert]::ToBase64String($cipherBytes)

    # Reconstruit shipper sans token_plain, avec token_encrypted_b64
    $newShipper = [ordered]@{}
    foreach ($p in $config.shipper.PSObject.Properties) {
        if ($p.Name -eq 'token_plain') { continue }
        $newShipper[$p.Name] = $p.Value
    }
    $newShipper['token_encrypted_b64'] = $b64
    $config.shipper = $newShipper
    Write-Host "    Token DPAPI-protected ($($cipherBytes.Length) bytes)"
}

# --- 4. Écriture du fichier ---------------------------------------------------
if (-not (Test-Path $AgentDir)) {
    New-Item -ItemType Directory -Path $AgentDir -Force | Out-Null
}

if ((Test-Path $AgentJson) -and -not $Force) {
    throw "$AgentJson existe déjà. Relance avec -Force (backup auto)."
}
if (Test-Path $AgentJson) {
    $backup = "$AgentJson.bak.$(Get-Date -Format 'yyyyMMddHHmmss')"
    Copy-Item -Path $AgentJson -Destination $backup
    Write-Host ">>> Backup → $backup" -ForegroundColor Yellow
}

$json = $config | ConvertTo-Json -Depth 10
[IO.File]::WriteAllText($AgentJson, $json + "`n", (New-Object Text.UTF8Encoding($false)))
Write-Host ">>> agent.json écrit à $AgentJson" -ForegroundColor Green

# ACL Administrators + SYSTEM
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
    Write-Warning "ACL impossible : $($_.Exception.Message)"
}

# --- 5. Build optionnel -------------------------------------------------------
if ($BuildRelease) {
    Write-Host ">>> cargo build --release…" -ForegroundColor Cyan
    Push-Location (Split-Path $PSScriptRoot -Parent)
    try {
        cargo build --release
        if ($LASTEXITCODE -ne 0) { throw "cargo build a échoué (exit $LASTEXITCODE)" }
        Write-Host "    Binaire : $(Join-Path (Get-Location) 'target\release\WazabiEDR_Agent.exe')"
    } finally {
        Pop-Location
    }
}

Write-Host ""
Write-Host "  Agent bootstrappé." -ForegroundColor Green
Write-Host "    agent.json : $AgentJson"
Write-Host "    agent_id   : $(if ($config.shipper.agent_id) { $config.shipper.agent_id } else { '<COMPUTERNAME> (défauté côté agent)' })"
Write-Host "    server_url : $($config.shipper.server_url)"
Write-Host ""
Write-Host "  Prérequis : driver WazabiEDR chargé (cf. WazabiEDR_Doc/usage/installing-driver.md)"
Write-Host "  Lancer : .\target\release\WazabiEDR_Agent.exe"
