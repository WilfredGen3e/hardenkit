function New-HKReport {
    <#
    .SYNOPSIS
        Leest een map met JSON-dagbestanden van Export-HKData en schrijft één HTML-rapport.

    .DESCRIPTION
        Leest alle dagbestanden (van alle DC's, over de volledige meetperiode) in -InputPath,
        slaat statusbestanden (*.state.json) en bestanden met een onbekende schemaversie over,
        merget de findings (zie Merge-HKFindings), berekent per maatregel de status en de
        correlaties (zie Resolve-HKReportModel) en rendert dat naar één zelfstandig HTML-bestand
        (zie ConvertTo-HKReportHtml): data als JSON in de pagina, geen externe scripts/fonts,
        werkt offline.

    .PARAMETER InputPath
        Map met JSON-dagbestanden van één klant (van Export-HKData).

    .PARAMETER OutputPath
        Pad van het te schrijven HTML-rapport.

    .PARAMETER ClientCode
        Klantcode voor de titel van het rapport. Weggelaten: wordt overgenomen uit het eerste
        gelezen dagbestand.

    .PARAMETER MinimumDays
        Minimaal aantal gemeten dagen voor een niet-Onbekend status (zie PRD: standaard 28).

    .PARAMETER MissingSpnThreshold
        Drempel voor losse missing_spn-bevindingen. Voorlopige default — PRD noemt de exacte
        waarde nog als open vraag (zie docs/CLAUDE.md).

    .PARAMETER LockoutThreshold
        Zelfde, voor lockouts. Voorlopige default.

    .OUTPUTS
        PSCustomObject met OutputPath, FilesRead, FilesSkipped, Model (het berekende
        rapportmodel, voor wie het programmatisch verder wil gebruiken).

    .NOTES
        Fase 0. Alleen-lezen (behalve het eigen HTML-bestand). Zie Resolve-HKReportModel voor
        de volledige status-/correlatielogica en de bewuste vereenvoudigingen daarin.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$InputPath,

        [Parameter(Mandatory)]
        [string]$OutputPath,

        [string]$ClientCode,

        [int]$MinimumDays = 28,
        [int]$MissingSpnThreshold = 5,
        [int]$LockoutThreshold = 5
    )

    if (-not (Test-Path -Path $InputPath)) {
        throw "New-HKReport: InputPath '$InputPath' bestaat niet."
    }

    $files = @(Get-ChildItem -Path $InputPath -Filter '*.json' -File -ErrorAction Stop | Where-Object { $_.Name -notlike '*.state.json' })

    if ($files.Count -eq 0) {
        throw "New-HKReport: geen dagbestanden gevonden in '$InputPath'."
    }

    $allFindings = [System.Collections.Generic.List[psobject]]::new()
    $fileSummaries = [System.Collections.Generic.List[psobject]]::new()
    $skippedFiles = [System.Collections.Generic.List[string]]::new()
    $resolvedClientCode = $ClientCode

    foreach ($file in $files) {
        try {
            $content = Get-Content -Path $file.FullName -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
        }
        catch {
            Write-Warning "New-HKReport: $($file.FullName) kon niet gelezen worden als JSON: $_"
            $skippedFiles.Add($file.Name)
            continue
        }

        if ($content.schema -ne '1.0') {
            Write-Warning "New-HKReport: $($file.FullName) heeft een onbekende schemaversie ('$($content.schema)'), overgeslagen."
            $skippedFiles.Add($file.Name)
            continue
        }

        if (-not $resolvedClientCode) { $resolvedClientCode = $content.client }

        foreach ($finding in @($content.findings)) { $allFindings.Add($finding) }

        $collectors = @{}
        if ($content.collectors) {
            foreach ($prop in $content.collectors.PSObject.Properties) { $collectors[$prop.Name] = $prop.Value }
        }

        $auditMeasures = @{}
        if ($content.auditConfig -and $content.auditConfig.Measures) {
            foreach ($measure in @($content.auditConfig.Measures)) { $auditMeasures[$measure.Measure] = $measure.Status }
        }

        $fileSummaries.Add([pscustomobject]@{
                Host          = $content.host
                Role          = $content.role
                WindowFrom    = $content.window.from
                WindowTo      = $content.window.to
                Collectors    = $collectors
                AuditMeasures = $auditMeasures
            })
    }

    if ($fileSummaries.Count -eq 0) {
        throw "New-HKReport: geen bruikbare dagbestanden gevonden in '$InputPath' (schemaversie klopt niet of onleesbaar)."
    }

    $mergedFindings = @(@($allFindings.ToArray()) | Merge-HKFindings)

    $model = Resolve-HKReportModel -Findings $mergedFindings -FileSummaries $fileSummaries.ToArray() -MinimumDays $MinimumDays -MissingSpnThreshold $MissingSpnThreshold -LockoutThreshold $LockoutThreshold

    $generatedAtUtc = (Get-Date).ToUniversalTime()
    $titleClientCode = if ($resolvedClientCode) { $resolvedClientCode } else { 'onbekend' }
    $html = ConvertTo-HKReportHtml -Model $model -ClientCode $titleClientCode -GeneratedAtUtc $generatedAtUtc

    $outputDir = Split-Path -Parent $OutputPath
    if ($outputDir -and -not (Test-Path -Path $outputDir)) {
        New-Item -Path $outputDir -ItemType Directory -Force | Out-Null
    }

    Set-Content -Path $OutputPath -Value $html -Encoding UTF8

    [pscustomobject]@{
        OutputPath   = $OutputPath
        FilesRead    = $fileSummaries.Count
        FilesSkipped = $skippedFiles.ToArray()
        Model        = $model
    }
}
