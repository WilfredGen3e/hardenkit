function Get-HKSysvolReplicationInfo {
    <#
    .SYNOPSIS
        Bepaalt welke technologie SYSVOL repliceert (DFSR of het verouderde FRS) en of SYSVOL
        gereed is.

    .DESCRIPTION
        Leest status van de DFSR- en NTFRS-services en de registrywaarde SysvolReady onder
        HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters. Dit is een momentopname van
        de configuratie; replicatiefouten zelf worden gemeten door Get-HKDomainHealth
        (Directory Service/DFSR-eventlog, zie PRD).

    .PARAMETER ComputerName
        Host om te bevragen. Alleen de lokale machine wordt ondersteund.

    .OUTPUTS
        PSCustomObject met Technology ('DFSR'/'FRS'/'Onbekend') en Ready ([bool]).

    .NOTES
        Fase 0. Alleen-lezen.
    #>
    [CmdletBinding()]
    param(
        [string]$ComputerName = $env:COMPUTERNAME
    )

    if ($ComputerName -ne [string]$env:COMPUTERNAME) {
        throw "Get-HKSysvolReplicationInfo ondersteunt alleen de lokale machine."
    }

    $dfsr = Get-Service -Name 'DFSR' -ErrorAction SilentlyContinue
    $ntfrs = Get-Service -Name 'NTFRS' -ErrorAction SilentlyContinue

    $technology =
        if ($dfsr -and $dfsr.Status -eq 'Running') { 'DFSR' }
        elseif ($ntfrs -and $ntfrs.Status -eq 'Running') { 'FRS' }
        else { 'Onbekend' }

    $sysvolReady = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' -Name 'SysvolReady' -ErrorAction SilentlyContinue).SysvolReady

    [pscustomobject]@{
        Technology = $technology
        Ready      = [bool]($sysvolReady -eq 1)
    }
}
