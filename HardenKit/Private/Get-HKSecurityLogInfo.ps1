function Get-HKSecurityLogInfo {
    <#
    .SYNOPSIS
        Leest grootte, recordaantal en de oudste gebeurtenis van het Security-eventlog.

    .DESCRIPTION
        Gebruikt Get-WinEvent -ListLog voor de maximale grootte en het huidige recordaantal, en
        leest één keer het oudste event om te bepalen hoeveel geschiedenis beschikbaar is. Dit
        is de basis om te zien of de Security-log te snel overrolt voor een complete
        meetperiode van 28 dagen.

    .PARAMETER ComputerName
        Host om te bevragen. Standaard de lokale machine.

    .OUTPUTS
        PSCustomObject met MaximumSizeInBytes, RecordCount, OldestRecordUtc, NewestRecordUtc.

    .NOTES
        Fase 0. Alleen-lezen.
    #>
    [CmdletBinding()]
    param(
        [string]$ComputerName = $env:COMPUTERNAME
    )

    $listLogParams = @{ ListLog = 'Security'; ErrorAction = 'Stop' }
    $oldestParams = @{ LogName = 'Security'; Oldest = $true; MaxEvents = 1; ErrorAction = 'SilentlyContinue' }
    if ($ComputerName -ne [string]$env:COMPUTERNAME) {
        $listLogParams['ComputerName'] = $ComputerName
        $oldestParams['ComputerName'] = $ComputerName
    }

    $log = Get-WinEvent @listLogParams
    $oldest = Get-WinEvent @oldestParams

    [pscustomobject]@{
        MaximumSizeInBytes = $log.MaximumSizeInBytes
        RecordCount        = $log.RecordCount
        OldestRecordUtc    = if ($oldest) { $oldest.TimeCreated.ToUniversalTime() } else { $null }
        NewestRecordUtc    = if ($log.LastWriteTime) { $log.LastWriteTime.ToUniversalTime() } else { $null }
    }
}
