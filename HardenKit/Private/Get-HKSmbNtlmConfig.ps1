function Get-HKSmbNtlmConfig {
    <#
    .SYNOPSIS
        Leest LmCompatibilityLevel, NTLM-verzendrestricties, SMB1-status en Print Spooler-status.

    .DESCRIPTION
        Combineert een aantal kleine, gerelateerde registry-/service-uitlezingen uit de
        nulmeting: LmCompatibilityLevel (HKLM:\...\Control\Lsa), RestrictSendingNTLMTraffic en
        RestrictReceivingNTLMTraffic (HKLM:\...\Control\Lsa\MSV1_0), SMB1-status
        (HKLM:\...\Services\LanmanServer\Parameters) en de Print Spooler-service.

    .PARAMETER ComputerName
        Host om te bevragen. Alleen de lokale machine wordt ondersteund.

    .OUTPUTS
        PSCustomObject met LmCompatibilityLevel, RestrictSendingNTLMTraffic,
        RestrictReceivingNTLMTraffic, Smb1Enabled, PrintSpoolerStatus, PrintSpoolerStartType.

    .NOTES
        Fase 0. Alleen-lezen. Ontbrekende registrywaarden komen terug als $null (= niet via GPO
        geconfigureerd), niet als een aangenomen default.
    #>
    [CmdletBinding()]
    param(
        [string]$ComputerName = $env:COMPUTERNAME
    )

    if ($ComputerName -ne [string]$env:COMPUTERNAME) {
        throw "Get-HKSmbNtlmConfig ondersteunt alleen de lokale machine."
    }

    $lsaPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    $msv10Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'
    $smbPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'

    $lmCompatibilityLevel = (Get-ItemProperty -Path $lsaPath -Name 'LmCompatibilityLevel' -ErrorAction SilentlyContinue).LmCompatibilityLevel
    $restrictSending = (Get-ItemProperty -Path $msv10Path -Name 'RestrictSendingNTLMTraffic' -ErrorAction SilentlyContinue).RestrictSendingNTLMTraffic
    $restrictReceiving = (Get-ItemProperty -Path $msv10Path -Name 'RestrictReceivingNTLMTraffic' -ErrorAction SilentlyContinue).RestrictReceivingNTLMTraffic
    $smb1 = (Get-ItemProperty -Path $smbPath -Name 'SMB1' -ErrorAction SilentlyContinue).SMB1

    $spooler = Get-Service -Name 'Spooler' -ErrorAction SilentlyContinue

    [pscustomobject]@{
        LmCompatibilityLevel         = $lmCompatibilityLevel
        RestrictSendingNTLMTraffic   = $restrictSending
        RestrictReceivingNTLMTraffic = $restrictReceiving
        Smb1Enabled                  = if ($null -ne $smb1) { [bool]$smb1 } else { $null }
        PrintSpoolerStatus           = if ($spooler) { $spooler.Status.ToString() } else { $null }
        PrintSpoolerStartType        = if ($spooler) { $spooler.StartType.ToString() } else { $null }
    }
}
