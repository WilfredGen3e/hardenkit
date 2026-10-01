function Export-HKData {
    <#
    .SYNOPSIS
        Roept alle fase 0-collectors aan en schrijft het resultaat als JSON weg.

    .DESCRIPTION
        Dit is de enige functie die een engineer of de RMM daadwerkelijk aanroept (dagelijks,
        als SYSTEM) — de losse Get-HK*-functies zijn interne bouwstenen. Bepaalt de hostrol
        (Get-HKHostRole); op een DC worden Test-HKAuditConfig, Get-HKBaseline, Get-HKNtlmUsage
        en Get-HKLdapBinding aangeroepen. Eventlog-collectors lezen incrementeel vanaf de
        RecordId's in het statusbestand van de vorige run. Schrijft twee bestanden in
        -OutputPath:
          - <klant>_<host>_<yyyyMMdd>.json — het dagbestand volgens het PRD-schema (schema,
            client, host, role, moduleVersion, window, collectors, auditConfig, baseline,
            findings).
          - <klant>_<host>.state.json — laatst gelezen RecordId per log, voor de volgende
            incrementele run.
        Gedeeltelijke uitval van één collector resulteert in status 'onbekend' voor die
        collector in het dagbestand, niet in een afgebroken run. Fase 0 ondersteunt alleen
        DC's; op een andere hostrol wordt een leeg dagbestand geschreven met alle collectors op
        'onbekend'.

        Fase 0 schrijft alleen naar schijf (-OutputPath, bv. een share). Dit is bewust: de DC
        praat alleen met de RMM-agent en post zelf nooit naar een webhook of externe dienst
        (zie PRD, uitgangspunt 5 en de Rewst-sectie). Ophalen/doorsturen is een apart
        RMM/Rewst-vraagstuk (fase 2), niet iets wat deze functie zelf doet.

    .PARAMETER ClientCode
        Klantcode die in het dagbestand wordt opgenomen.

    .PARAMETER OutputPath
        Map waarin het dagbestand en het statusbestand worden weggeschreven. Wordt aangemaakt
        als die nog niet bestaat.

    .PARAMETER ComputerName
        Host om te meten. Alleen de lokale machine wordt ondersteund.

    .OUTPUTS
        PSCustomObject met DataFilePath, StateFilePath, Collectors (status per collector) en
        FindingsCount.

    .NOTES
        Fase 0. Alleen-lezen (behalve de eigen output-/statusbestanden van de module zelf).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ClientCode,

        [Parameter(Mandatory)]
        [string]$OutputPath,

        [string]$ComputerName = $env:COMPUTERNAME
    )

    if ($ComputerName -ne [string]$env:COMPUTERNAME) {
        throw "Export-HKData ondersteunt alleen de lokale machine."
    }

    $moduleVersion = $MyInvocation.MyCommand.Module.Version.ToString()
    $hostFqdn = Get-HKLocalFqdn
    $runCompletedUtc = (Get-Date).ToUniversalTime()

    if (-not (Test-Path -Path $OutputPath)) {
        New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
    }

    $stateFilePath = Join-Path $OutputPath "$ClientCode`_$ComputerName.state.json"
    $dataFilePath = Join-Path $OutputPath ('{0}_{1}_{2}.json' -f $ClientCode, $ComputerName, $runCompletedUtc.ToString('yyyyMMdd'))

    $previousState = $null
    if (Test-Path -Path $stateFilePath) {
        try {
            $previousState = Get-Content -Path $stateFilePath -Raw | ConvertFrom-Json
        }
        catch {
            Write-Warning "Export-HKData: statusbestand $stateFilePath kon niet gelezen worden, start zonder vorige state: $_"
            $previousState = $null
        }
    }

    $role = Get-HKHostRole -ComputerName $ComputerName

    $collectorStatus = [ordered]@{
        auditConfig = 'ok'
        baseline    = 'ok'
        ntlmUsage   = 'ok'
        ldapBinding = 'ok'
    }

    $auditConfig = $null
    $baseline = $null
    $ntlmUsage = $null
    $ldapBinding = $null

    if ($role -eq 'DC') {
        try {
            $auditConfig = Test-HKAuditConfig -ComputerName $ComputerName
            if (@($auditConfig.Collectors.PSObject.Properties | Where-Object Value -eq 'onbekend').Count -gt 0) {
                $collectorStatus.auditConfig = 'onbekend'
            }
        }
        catch {
            Write-Warning "Export-HKData: Test-HKAuditConfig faalde: $_"
            $collectorStatus.auditConfig = 'onbekend'
        }

        try {
            $baseline = Get-HKBaseline -ComputerName $ComputerName
            if (@($baseline.Collectors.PSObject.Properties | Where-Object Value -eq 'onbekend').Count -gt 0) {
                $collectorStatus.baseline = 'onbekend'
            }
        }
        catch {
            Write-Warning "Export-HKData: Get-HKBaseline faalde: $_"
            $collectorStatus.baseline = 'onbekend'
        }

        try {
            $ntlmUsage = Get-HKNtlmUsage -ComputerName $ComputerName -SecurityStartRecordId $previousState.lastSecurityRecordId -NtlmOperationalStartRecordId $previousState.lastNtlmOperationalRecordId
            if (@($ntlmUsage.Collectors.PSObject.Properties | Where-Object Value -eq 'onbekend').Count -gt 0) {
                $collectorStatus.ntlmUsage = 'onbekend'
            }
        }
        catch {
            Write-Warning "Export-HKData: Get-HKNtlmUsage faalde: $_"
            $collectorStatus.ntlmUsage = 'onbekend'
        }

        try {
            $ldapBinding = Get-HKLdapBinding -ComputerName $ComputerName -DirectoryServiceStartRecordId $previousState.lastDirectoryServiceRecordId
            if (@($ldapBinding.Collectors.PSObject.Properties | Where-Object Value -eq 'onbekend').Count -gt 0) {
                $collectorStatus.ldapBinding = 'onbekend'
            }
        }
        catch {
            Write-Warning "Export-HKData: Get-HKLdapBinding faalde: $_"
            $collectorStatus.ldapBinding = 'onbekend'
        }
    }
    else {
        Write-Warning "Export-HKData: host-rol is '$role', fase 0 ondersteunt alleen DC's. Geen collectors uitgevoerd."
        foreach ($key in @($collectorStatus.Keys)) { $collectorStatus[$key] = 'onbekend' }
    }

    # $ntlmUsage/$ldapBinding zijn $null als de collector faalde of de hostrol geen DC is.
    # @($null.Findings) is @($null) — een array mét één $null-element, niet leeg (zie
    # docs/LESSONS.md) — dus eerst expliciet op $null checken, niet alleen op @(...) vertrouwen.
    $findings = [System.Collections.Generic.List[psobject]]::new()
    if ($ntlmUsage) {
        foreach ($row in @($ntlmUsage.Findings)) { $findings.Add((ConvertTo-HKFindingRecord -InputObject $row)) }
    }
    if ($ldapBinding) {
        foreach ($row in @($ldapBinding.Findings)) { $findings.Add((ConvertTo-HKFindingRecord -InputObject $row)) }
    }

    $windowFromUtc = if ($previousState.runCompletedUtc) { [datetime]$previousState.runCompletedUtc } else { $null }

    $newState = [ordered]@{
        lastSecurityRecordId         = if ($ntlmUsage) { $ntlmUsage.LastSecurityRecordId } else { $previousState.lastSecurityRecordId }
        lastNtlmOperationalRecordId  = if ($ntlmUsage) { $ntlmUsage.LastNtlmOperationalRecordId } else { $previousState.lastNtlmOperationalRecordId }
        lastDirectoryServiceRecordId = if ($ldapBinding) { $ldapBinding.LastDirectoryServiceRecordId } else { $previousState.lastDirectoryServiceRecordId }
        runCompletedUtc              = $runCompletedUtc.ToString('yyyy-MM-ddTHH:mm:ssZ')
    }

    $data = [ordered]@{
        schema        = '1.0'
        client        = $ClientCode
        host          = $hostFqdn
        role          = $role
        moduleVersion = $moduleVersion
        window        = [ordered]@{
            from = if ($windowFromUtc) { $windowFromUtc.ToString('yyyy-MM-ddTHH:mm:ssZ') } else { $null }
            to   = $runCompletedUtc.ToString('yyyy-MM-ddTHH:mm:ssZ')
        }
        collectors    = [pscustomobject]$collectorStatus
        auditConfig   = $auditConfig
        baseline      = $baseline
        findings      = $findings.ToArray()
    }

    ([pscustomobject]$data | ConvertTo-Json -Depth 10) | Set-Content -Path $dataFilePath -Encoding UTF8
    ([pscustomobject]$newState | ConvertTo-Json) | Set-Content -Path $stateFilePath -Encoding UTF8

    [pscustomobject]@{
        DataFilePath  = $dataFilePath
        StateFilePath = $stateFilePath
        Collectors    = [pscustomobject]$collectorStatus
        FindingsCount = $findings.Count
    }
}
