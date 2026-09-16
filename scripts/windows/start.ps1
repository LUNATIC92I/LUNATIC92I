<#
.SYNOPSIS
    Launches the full LUNATIC-IT SIEM stack on Windows via Docker Desktop.

.DESCRIPTION
    Windows equivalent of `docs/DEVELOPMENT.md`'s
    `cp .env.example .env && docker compose up -d --build`. Meant to be
    double-clicked via start.bat, or run directly from PowerShell.

    Never overwrites an existing .env - only creates one on first run, and
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

# Deliberately NOT $ErrorActionPreference = "Stop" at script scope: with
# that set, PowerShell promotes ANY stderr line from an external command
# (docker included) into a terminating error, even when that stream is
# redirected to $null - so a plain "Docker Desktop isn't running" message
# on stderr would abort the whole script before the $LASTEXITCODE checks
# below ever ran, instead of hitting the friendly messages they print.
# Native command failures are handled explicitly via $LASTEXITCODE
# instead; the one block with real cmdlet calls (.env creation) opts into
# -ErrorAction Stop itself, scoped to just that try/catch.
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
    try {
        Copy-Item $envExamplePath $envPath -ErrorAction Stop

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

        (Get-Content $envPath -ErrorAction Stop) |
            ForEach-Object {
                if ($_ -match '^MFA_ENCRYPTION_KEY=') {
                    "MFA_ENCRYPTION_KEY=$fernetKey"
                } else {
                    $_
                }
            } | Set-Content $envPath -Encoding UTF8 -ErrorAction Stop

        Write-Ok "Fichier .env cree avec une cle MFA_ENCRYPTION_KEY generee."
        Write-Warn "Les mots de passe par defaut de .env.example restent en place - usage local jetable uniquement."
        Write-Warn "Pour tout ce qui depasse un essai jetable, editez .env et changez chaque mot de passe/secret."
    } catch {
        Write-Fail "echec de la creation de .env : $($_.Exception.Message)"
        exit 1
    }
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

# --- 5. Create a Desktop shortcut on first run -----------------------------
# So every run after this one is a plain double-click on a Desktop icon,
# with no folder to navigate into at all. Idempotent (checks for the
# shortcut first) and non-destructive (only ever creates, never touches an
# existing one - if the user deleted it, it is simply recreated next run).
try {
    $desktop = [Environment]::GetFolderPath("Desktop")
    $shortcutPath = Join-Path $desktop "LUNATIC-IT SIEM.lnk"
    $rootLauncher = Join-Path $repoRoot "Demarrer-LUNATIC-SIEM.bat"

    if (-not (Test-Path $shortcutPath) -and (Test-Path $rootLauncher)) {
        $wshell = New-Object -ComObject WScript.Shell
        $shortcut = $wshell.CreateShortcut($shortcutPath)
        $shortcut.TargetPath = $rootLauncher
        $shortcut.WorkingDirectory = $repoRoot
        $shortcut.IconLocation = "shell32.dll,166"
        $shortcut.Description = "Demarrer LUNATIC-IT SIEM"
        $shortcut.Save()
        Write-Ok "Raccourci Bureau cree : $shortcutPath"
        Write-Host "La prochaine fois, double-cliquez simplement sur son icone."
    }
} catch {
    # Non-fatal - the root .bat file still works directly either way.
    Write-Warn "Impossible de creer le raccourci Bureau automatiquement (pas bloquant)."
}

# --- 6. Summary -------------------------------------------------------------
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
