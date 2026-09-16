<#
.SYNOPSIS
    Launches the full LUNATIC-IT SIEM stack on Windows via Docker Desktop.

.DESCRIPTION
    Windows equivalent of `docs/DEVELOPMENT.md`'s
    `cp .env.example .env && docker compose up -d --build`. Meant to be
    double-clicked via start.bat, or run directly from PowerShell.

    Never overwrites an existing .env — only creates one on first run, and
    only touches MFA_ENCRYPTION_KEY in it (the one value in .env.example
    that is a placeholder string, not a usable default: it is not valid
    base64, so cryptography.fernet.Fernet() rejects it the first time MFA
    setup or an existing TOTP secret is touched). Every other .env.example
    default is already internally consistent for a throwaway local run
    (see that file's own comments) and is left untouched, exactly as the
    Linux quickstart in docs/DEVELOPMENT.md leaves it.
#>

param(
    [switch]$NoBrowser
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
Set-Location $repoRoot

function Write-Step($message) { Write-Host "==> $message" -ForegroundColor Cyan }
function Write-Warn($message) { Write-Host $message -ForegroundColor Yellow }
function Write-Fail($message) { Write-Host $message -ForegroundColor Red }
function Write-Ok($message) { Write-Host $message -ForegroundColor Green }

Write-Host "== LUNATIC-IT SIEM - Windows launcher ==" -ForegroundColor Cyan

# --- 1. Docker Desktop present and running ------------------------------
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Write-Fail "Docker introuvable dans le PATH."
    Write-Host "Installez Docker Desktop (avec le backend WSL2) : https://www.docker.com/products/docker-desktop/"
    exit 1
}

docker info *>$null
if ($LASTEXITCODE -ne 0) {
    Write-Fail "Docker Desktop ne repond pas."
    Write-Host "Demarrez Docker Desktop, attendez qu'il affiche 'Engine running', puis relancez ce script."
    exit 1
}

# --- 2. Prepare .env (never overwrite an existing one) -------------------
$envPath = Join-Path $repoRoot ".env"
$envExamplePath = Join-Path $repoRoot ".env.example"

if (-not (Test-Path $envPath)) {
    Write-Step "Aucun .env trouve - creation a partir de .env.example"
    Copy-Item $envExamplePath $envPath

    # Generates a real Fernet key (url-safe base64 of exactly 32 random
    # bytes) - the one .env.example value that is a placeholder string
    # rather than a directly usable default. See the header comment above.
    # Uses the RandomNumberGenerator.Create()/GetBytes() instance pattern
    # rather than the static Fill() helper, since Fill() is not available
    # on the .NET Framework runtime that Windows PowerShell 5.1 (the
    # default on a stock Windows 10/11 install) ships with.
    $keyBytes = New-Object byte[] 32
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $rng.GetBytes($keyBytes)
    $fernetKey = [Convert]::ToBase64String($keyBytes).Replace('+', '-').Replace('/', '_')

    (Get-Content $envPath) |
        ForEach-Object {
            if ($_ -match '^MFA_ENCRYPTION_KEY=') {
                "MFA_ENCRYPTION_KEY=$fernetKey"
            } else {
                $_
            }
        } | Set-Content $envPath -Encoding UTF8

    Write-Ok "Fichier .env cree avec une cle MFA_ENCRYPTION_KEY generee."
    Write-Warn "Les mots de passe par defaut de .env.example restent en place - usage local jetable uniquement."
    Write-Warn "Pour tout ce qui depasse un essai jetable, editez .env et changez chaque mot de passe/secret."
} else {
    Write-Step ".env existant detecte - conserve tel quel"
}

# --- 3. Bring the stack up -------------------------------------------------
Write-Step "Demarrage de la stack (le premier build peut prendre plusieurs minutes)"
docker compose up -d --build
if ($LASTEXITCODE -ne 0) {
    Write-Fail "echec de 'docker compose up'. Voir les logs ci-dessus."
    exit $LASTEXITCODE
}

# --- 4. Wait for the backend to answer /health -----------------------------
Write-Step "Attente de la disponibilite du backend (http://localhost:8000/health)"
$backendReady = $false
for ($i = 0; $i -lt 60; $i++) {
    try {
        $resp = Invoke-WebRequest -Uri "http://localhost:8000/health" -UseBasicParsing -TimeoutSec 2
        if ($resp.StatusCode -eq 200) { $backendReady = $true; break }
    } catch {
        Start-Sleep -Seconds 2
    }
}

if (-not $backendReady) {
    Write-Warn "Le backend ne repond pas encore apres 2 minutes."
    Write-Warn "Verifiez l'etat des conteneurs : docker compose ps"
    Write-Warn "Et les logs : docker compose logs backend"
} else {
    Write-Ok "Backend disponible."
}

# --- 5. Summary -------------------------------------------------------------
Write-Host ""
Write-Host "== Stack demarree ==" -ForegroundColor Green
Write-Host "Frontend              : http://localhost:5173"
Write-Host "API (docs Swagger)    : http://localhost:8000/docs"
Write-Host "Health / readiness    : http://localhost:8000/health, /ready"
Write-Host "Grafana               : http://localhost:3000"
Write-Host "OpenSearch Dashboards : http://localhost:5601"
Write-Host "Prometheus            : http://localhost:9090"
Write-Host ""
Write-Host "Etat des conteneurs   : docker compose ps"
Write-Host "Arreter la stack      : scripts\windows\stop.bat"
Write-Host ""

if (-not $NoBrowser -and $backendReady) {
    Start-Process "http://localhost:5173"
}
