<#
.SYNOPSIS
    Haalt HardenKit op uit de GitHub-repository en vervangt de lokaal geïnstalleerde module.

.DESCRIPTION
    Bedoeld voor lab- en testomgevingen. Voor productie (klant-DC's) blijft de RMM het
    distributiekanaal met gepinde, gesignde releases zonder internetafhankelijkheid op de DC
    (zie docs/PRD.md); dit script hoort daarom bewust niet bij de module zelf.

    Werkwijze, zonder code rechtstreeks uit te voeren (geen irm | iex):
      1. -Ref (branch, tag of commit) via de GitHub-API omzetten naar een vaste commit-SHA.
      2. Is die SHA al geïnstalleerd, dan stoppen (tenzij -Force).
      3. De zip van precies die SHA downloaden en uitpakken naar een tijdelijke map.
      4. In een apart Windows PowerShell 5.1-proces controleren dat de nieuwe module laadt.
      5. Pas dan de huidige module naar 'HardenKit.previous' verplaatsen en de nieuwe neerzetten.
      6. Dit script zelf bijwerken naar de versie uit dezelfde commit.

    Verwachte indeling (dit script staat naast de modulemap):
      <InstallPath>\Update-HardenKit.ps1
      <InstallPath>\HardenKit\HardenKit.psd1
      <InstallPath>\HardenKit.installed.json   (bron, ref en SHA van de geïnstalleerde versie)
    Andere mappen in <InstallPath> (zoals Data\) worden niet aangeraakt.

.PARAMETER Ref
    Branch, tag of commit om te installeren. Standaard 'main'. Gebruik een tag of SHA om een
    versie vast te pinnen.

.PARAMETER InstallPath
    Map waarin de modulemap 'HardenKit' staat. Standaard de map van dit script.

.PARAMETER Repository
    GitHub-repository als 'eigenaar/naam'.

.PARAMETER Force
    Ook installeren als dezelfde commit al geïnstalleerd is.

.EXAMPLE
    C:\ProgramData\HardenKit\Update-HardenKit.ps1

.EXAMPLE
    C:\ProgramData\HardenKit\Update-HardenKit.ps1 -Ref 93ab452

.NOTES
    Vereist uitgaand HTTPS-verkeer naar api.github.com en codeload.github.com.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$Ref = 'main',

    # Geen $PSScriptRoot als default: die is in Windows PowerShell 5.1 leeg in het param-blok.
    [string]$InstallPath,

    [string]$Repository = 'WilfredGen3e/hardenkit',

    [switch]$Force
)

$ErrorActionPreference = 'Stop'
if (-not $InstallPath) { $InstallPath = $PSScriptRoot }
# Windows PowerShell 5.1 onderhandelt op oudere builds niet altijd TLS 1.2.
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

$moduleDir    = Join-Path $InstallPath 'HardenKit'
$previousDir  = Join-Path $InstallPath 'HardenKit.previous'
$installedLog = Join-Path $InstallPath 'HardenKit.installed.json'
$headers      = @{ 'User-Agent' = 'HardenKit-Updater' }

# 1. Ref -> vaste SHA, zodat download en logregel over exact dezelfde commit gaan.
$commit = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repository/commits/$Ref" -Headers $headers -UseBasicParsing
$sha = $commit.sha
$shortSha = $sha.Substring(0, 7)
Write-Host "Ref '$Ref' = commit $shortSha ($($commit.commit.message.Split("`n")[0]))"

# 2. Al actueel?
if ((Test-Path $installedLog) -and -not $Force) {
    $installed = Get-Content $installedLog -Raw | ConvertFrom-Json
    if ($installed.Sha -eq $sha) {
        Write-Host "Commit $shortSha is al geïnstalleerd. Gebruik -Force om opnieuw te installeren."
        return
    }
    Write-Host "Geïnstalleerd: $($installed.Sha.Substring(0, 7)) (ref '$($installed.Ref)', $($installed.InstalledAtUtc))"
}

$work = Join-Path ([IO.Path]::GetTempPath()) "HardenKit-update-$shortSha"
try {
    # 3. Downloaden en uitpakken.
    if (Test-Path $work) { Remove-Item $work -Recurse -Force }
    New-Item -ItemType Directory -Path $work | Out-Null
    $zip = Join-Path $work 'hardenkit.zip'
    Invoke-WebRequest -Uri "https://codeload.github.com/$Repository/zip/$sha" -OutFile $zip -Headers $headers -UseBasicParsing
    Expand-Archive -Path $zip -DestinationPath $work
    Get-ChildItem $work -Recurse -File | Unblock-File

    $extracted = Get-ChildItem $work -Directory | Select-Object -First 1
    $newModuleDir = Join-Path $extracted.FullName 'HardenKit'
    $newManifest = Join-Path $newModuleDir 'HardenKit.psd1'
    if (-not (Test-Path $newManifest)) {
        throw "Geen HardenKit\HardenKit.psd1 gevonden in de download van $shortSha."
    }

    # 4. Laadt de nieuwe versie in Windows PowerShell 5.1 (de DC-doelgroep)? Apart proces,
    #    zodat een kapotte versie de huidige sessie niet vervuilt.
    $check = & powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Import-Module '$newManifest' -Force -ErrorAction Stop; (Get-Command -Module HardenKit).Count" 2>&1
    if ($LASTEXITCODE -ne 0 -or -not ("$($check | Select-Object -Last 1)" -match '^\d+$') -or [int]"$($check | Select-Object -Last 1)" -lt 1) {
        throw "Nieuwe versie $shortSha laadt niet in Windows PowerShell 5.1; huidige installatie ongewijzigd. Uitvoer: $check"
    }

    if (-not $PSCmdlet.ShouldProcess($moduleDir, "Vervangen door commit $shortSha")) { return }

    # 5. Wisselen via kopiëren, niet via Move-Item op de map zelf: een map hernoemen faalt met
    #    "Access denied" zodra een Verkenner-venster of andere shell erin staat (gezien op de
    #    lab-DC). De inhoud vervangen lukt dan wel.
    Remove-Module HardenKit -ErrorAction SilentlyContinue
    if (Test-Path $previousDir) { Remove-Item $previousDir -Recurse -Force }
    if (Test-Path $moduleDir) {
        Copy-Item $moduleDir $previousDir -Recurse
    }
    else {
        New-Item -ItemType Directory -Path $moduleDir | Out-Null
    }
    try {
        Get-ChildItem $moduleDir -Force | Remove-Item -Recurse -Force
        Copy-Item (Join-Path $newModuleDir '*') $moduleDir -Recurse
    }
    catch {
        $fout = $_
        if (Test-Path $previousDir) {
            Get-ChildItem $moduleDir -Force | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
            Copy-Item (Join-Path $previousDir '*') $moduleDir -Recurse
        }
        throw "Plaatsen van de nieuwe versie mislukt, vorige versie teruggezet: $fout"
    }

    [pscustomobject]@{
        Repository     = $Repository
        Ref            = $Ref
        Sha            = $sha
        InstalledAtUtc = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    } | ConvertTo-Json | Set-Content -Path $installedLog -Encoding UTF8

    # 6. Dit script zelf bijwerken (PowerShell heeft het al volledig ingelezen, overschrijven mag).
    $newUpdater = Join-Path $extracted.FullName 'tools\Update-HardenKit.ps1'
    if ((Test-Path $newUpdater) -and $PSCommandPath) {
        Copy-Item $newUpdater $PSCommandPath -Force
    }

    Write-Host "HardenKit bijgewerkt naar $shortSha."
    if (Test-Path $previousDir) { Write-Host "Vorige versie staat in $previousDir." }
    Write-Host "Laden met: Import-Module '$(Join-Path $moduleDir 'HardenKit.psd1')' -Force"
}
finally {
    if (Test-Path $work) { Remove-Item $work -Recurse -Force -ErrorAction SilentlyContinue }
}
