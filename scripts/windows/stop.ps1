<#
.SYNOPSIS
    Stops the LUNATIC-IT SIEM stack started by start.ps1.

.PARAMETER RemoveData
    Also drops the named volumes (Postgres/Redis/OpenSearch/Grafana data) -
    the Windows equivalent of `docker compose down -v`. Off by default so a
    double-click of stop.bat never destroys data by accident.
#>

param(
    [switch]$RemoveData
)

# Deliberately not $ErrorActionPreference = "Stop" - see start.ps1's own
# comment on this: it would promote any stderr line from `docker` itself
# into a script-aborting exception, bypassing the $LASTEXITCODE check below.
$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
Set-Location $repoRoot

Write-Host "== LUNATIC-IT SIEM - arret de la stack ==" -ForegroundColor Cyan

if ($RemoveData) {
    Write-Host "Arret des conteneurs ET suppression des volumes de donnees..." -ForegroundColor Yellow
    docker compose down -v
} else {
    Write-Host "Arret des conteneurs (les donnees sont conservees)..." -ForegroundColor Cyan
    docker compose down
}

if ($LASTEXITCODE -ne 0) {
    Write-Host "echec de 'docker compose down'. Voir les logs ci-dessus." -ForegroundColor Red
    exit $LASTEXITCODE
}

Write-Host "Stack arretee." -ForegroundColor Green
