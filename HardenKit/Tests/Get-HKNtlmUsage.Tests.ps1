#Requires -Modules Pester

# Module importeren op scriptniveau (niet in BeforeAll): InModuleScope hieronder heeft de
# module nodig tijdens Pester's Discovery-fase, die vóór BeforeAll/Run-blokken draait.
$script:ModuleRoot = Split-Path -Parent $PSScriptRoot
$script:ManifestPath = Join-Path $script:ModuleRoot 'HardenKit.psd1'
Import-Module $script:ManifestPath -Force

AfterAll {
    Remove-Module HardenKit -ErrorAction SilentlyContinue
}

InModuleScope HardenKit {

    Describe 'ConvertFrom-HKEventXml' {
        # Pure parsing-logica, los van Get-WinEvent zelf, dus platformonafhankelijk testbaar met
        # vaste XML-fixtures.

        It 'parsed een 4624-event (NTLMv1) correct' {
            $xml = @'
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}" />
    <EventID>4624</EventID>
    <TimeCreated SystemTime="2026-10-01T06:02:11.1234567Z" />
    <EventRecordID>123456</EventRecordID>
    <Channel>Security</Channel>
    <Computer>dc01.contoso.com</Computer>
  </System>
  <EventData>
    <Data Name="TargetUserName">svc_scan</Data>
    <Data Name="TargetUserSid">S-1-5-21-1-2-3-1001</Data>
    <Data Name="AuthenticationPackageName">NTLM</Data>
    <Data Name="LmPackageName">NTLM V1</Data>
    <Data Name="WorkstationName">SCANNER01</Data>
    <Data Name="IpAddress">10.0.0.50</Data>
    <Data Name="IpPort"></Data>
  </EventData>
</Event>
'@
            $result = ConvertFrom-HKEventXml -Xml $xml
            $result.EventId | Should -Be 4624
            $result.EventRecordId | Should -Be 123456
            $result.Computer | Should -Be 'dc01.contoso.com'
            $result.TimeCreatedUtc | Should -Be ([datetime]'2026-10-01T06:02:11.1234567Z').ToUniversalTime()
            $result.EventData['TargetUserName'] | Should -Be 'svc_scan'
            $result.EventData['LmPackageName'] | Should -Be 'NTLM V1'
            $result.EventData['IpAddress'] | Should -Be '10.0.0.50'
            $result.EventData['IpPort'] | Should -BeNullOrEmpty
        }

        It 'slaat Data-elementen zonder Name-attribuut over' {
            $xml = @'
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <EventID>4776</EventID>
    <TimeCreated SystemTime="2026-10-01T06:00:00.0000000Z" />
    <EventRecordID>1</EventRecordID>
    <Computer>dc01.contoso.com</Computer>
  </System>
  <EventData>
    <Data Name="TargetUserName">jdoe</Data>
    <Data>GeenNaamAttribuut</Data>
  </EventData>
</Event>
'@
            $result = ConvertFrom-HKEventXml -Xml $xml
            $result.EventData.Keys | Should -Not -Contain ''
            $result.EventData['TargetUserName'] | Should -Be 'jdoe'
        }
    }

    Describe 'Test-HKIsIpOrAlias' {
        # Pure logica.

        It 'herkent IPv4-adressen' {
            Test-HKIsIpOrAlias -Target '10.0.0.50' | Should -BeTrue
        }

        It 'herkent IPv6-adressen' {
            Test-HKIsIpOrAlias -Target '2001:db8::1' | Should -BeTrue
        }

        It 'herkent een naam zonder punt als alias' {
            Test-HKIsIpOrAlias -Target 'legacyprinter' | Should -BeTrue
        }

        It 'herkent een FQDN niet als IP/alias' {
            Test-HKIsIpOrAlias -Target 'webserver.contoso.com' | Should -BeFalse
        }

        It 'geeft False voor leeg of ontbrekend doel' {
            Test-HKIsIpOrAlias -Target '' | Should -BeFalse
            Test-HKIsIpOrAlias -Target $null | Should -BeFalse
        }
    }

    Describe 'ConvertTo-HKAggregate' {
        # Pure logica.

        It 'groepeert en telt correct, met first/last seen' {
            $rows = @(
                [pscustomobject]@{ Measure = 'ntlmv1'; AccountName = 'svc_scan'; TimeCreatedUtc = [datetime]'2026-10-01T06:00:00Z' }
                [pscustomobject]@{ Measure = 'ntlmv1'; AccountName = 'svc_scan'; TimeCreatedUtc = [datetime]'2026-10-01T08:00:00Z' }
                [pscustomobject]@{ Measure = 'ntlmv1'; AccountName = 'other'; TimeCreatedUtc = [datetime]'2026-10-01T09:00:00Z' }
            )
            $result = @($rows | ConvertTo-HKAggregate -GroupBy @('Measure', 'AccountName'))
            $result.Count | Should -Be 2

            $scan = $result | Where-Object AccountName -eq 'svc_scan'
            $scan.Count | Should -Be 2
            $scan.FirstSeenUtc | Should -Be ([datetime]'2026-10-01T06:00:00Z')
            $scan.LastSeenUtc | Should -Be ([datetime]'2026-10-01T08:00:00Z')
        }

        It 'geeft een lege lijst terug bij lege invoer' {
            $result = @(@() | ConvertTo-HKAggregate -GroupBy @('Measure'))
            $result.Count | Should -Be 0
        }
    }

    Describe 'Remote guard en NoMatchingEventsFound op Get-HKWinEvent' {
        # Get-WinEvent bestaat alleen op Windows; Mock heeft het echte commando nodig om te
        # kunnen vervangen, dus deze twee slaan over op andere platformen (zelfde beperking als
        # Get-HKHostRole/Get-CimInstance, zie HardenKit.Tests.ps1).

        It 'weigert een andere computer dan de lokale' {
            { Get-HKWinEvent -LogName 'Security' -Id 4624 -ComputerName 'ANDERE-HOST' } | Should -Throw -ExpectedMessage '*alleen de lokale machine*'
        }

        It 'geeft een lege lijst terug als Get-WinEvent "geen events gevonden" meldt' -Skip:(-not $IsWindows) {
            Mock -ModuleName HardenKit Get-WinEvent {
                $err = [System.Management.Automation.ErrorRecord]::new(
                    [System.Exception]::new('No events were found that match the specified selection criteria.'),
                    'NoMatchingEventsFound',
                    [System.Management.Automation.ErrorCategory]::ObjectNotFound,
                    $null
                )
                throw $err
            }
            $result = @(Get-HKWinEvent -LogName 'Security' -Id 4624)
            $result.Count | Should -Be 0
        }

        It 'geeft andere Get-WinEvent-fouten door' -Skip:(-not $IsWindows) {
            Mock -ModuleName HardenKit Get-WinEvent { throw 'toegang geweigerd' }
            { Get-HKWinEvent -LogName 'Security' -Id 4624 } | Should -Throw
        }
    }
}

Describe 'Get-HKNtlmUsage' {

    Context 'alle bronnen leesbaar' {

        BeforeAll {
            Mock -ModuleName HardenKit Get-HKWinEvent {
                if ($LogName -eq 'Security') {
                    @(
                        [pscustomobject]@{
                            TimeCreatedUtc = [datetime]'2026-10-01T06:00:00Z'
                            EventRecordId  = 100
                            EventId        = 4624
                            Computer       = 'dc01.contoso.com'
                            EventData      = @{
                                TargetUserName             = 'svc_scan'
                                TargetUserSid              = 'S-1-5-21-1-2-3-1001'
                                AuthenticationPackageName  = 'NTLM'
                                LmPackageName              = 'NTLM V1'
                                WorkstationName            = 'SCANNER01'
                                IpAddress                  = '10.0.0.50'
                            }
                        }
                        [pscustomobject]@{
                            TimeCreatedUtc = [datetime]'2026-10-01T07:00:00Z'
                            EventRecordId  = 101
                            EventId        = 4624
                            Computer       = 'dc01.contoso.com'
                            EventData      = @{
                                TargetUserName             = 'svc_scan'
                                TargetUserSid              = 'S-1-5-21-1-2-3-1001'
                                AuthenticationPackageName  = 'NTLM'
                                LmPackageName              = 'NTLM V2'
                                WorkstationName            = 'SCANNER01'
                                IpAddress                  = '10.0.0.50'
                            }
                        }
                        [pscustomobject]@{
                            TimeCreatedUtc = [datetime]'2026-10-01T06:30:00Z'
                            EventRecordId  = 102
                            EventId        = 4776
                            Computer       = 'dc01.contoso.com'
                            EventData      = @{
                                TargetUserName = 'jdoe'
                                Workstation    = 'WKS01'
                                PackageName    = 'MICROSOFT_AUTHENTICATION_PACKAGE_V1_0'
                            }
                        }
                    )
                }
                else {
                    @(
                        [pscustomobject]@{
                            TimeCreatedUtc = [datetime]'2026-10-01T06:15:00Z'
                            EventRecordId  = 200
                            EventId        = 8004
                            Computer       = 'dc01.contoso.com'
                            EventData      = @{
                                UserName    = 'svc_app'
                                Workstation = 'APP01'
                                ServerName  = '10.0.0.99'
                            }
                        }
                        [pscustomobject]@{
                            TimeCreatedUtc = [datetime]'2026-10-01T06:45:00Z'
                            EventRecordId  = 201
                            EventId        = 8004
                            Computer       = 'dc01.contoso.com'
                            EventData      = @{
                                UserName    = 'svc_app'
                                Workstation = 'APP01'
                                ServerName  = 'fileserver.contoso.com'
                            }
                        }
                    )
                }
            }
        }

        It 'markeert beide collectors als ok' {
            $result = Get-HKNtlmUsage
            $result.Collectors.SecurityLog | Should -Be 'ok'
            $result.Collectors.NtlmOperationalLog | Should -Be 'ok'
        }

        It 'neemt alleen echte NTLM V1-logons mee in de ntlmv1-maatregel' {
            $result = Get-HKNtlmUsage
            $ntlmv1 = @($result.Findings | Where-Object Measure -eq 'ntlmv1')
            $ntlmv1.Count | Should -Be 1
            $ntlmv1[0].AccountName | Should -Be 'svc_scan'
            $ntlmv1[0].Count | Should -Be 1
        }

        It 'neemt 4776 mee als ntlm_4776' {
            $result = Get-HKNtlmUsage
            $row = $result.Findings | Where-Object Measure -eq 'ntlm_4776'
            $row.AccountName | Should -Be 'jdoe'
            $row.ClientFqdn | Should -Be 'WKS01'
        }

        It 'classificeert het doel van 8004-events als IP/alias of FQDN' {
            $result = Get-HKNtlmUsage
            $rows = @($result.Findings | Where-Object Measure -eq 'ntlm_8004')
            $rows.Count | Should -Be 2
            ($rows | Where-Object Target -eq '10.0.0.99').IsIpOrAlias | Should -BeTrue
            ($rows | Where-Object Target -eq 'fileserver.contoso.com').IsIpOrAlias | Should -BeFalse
        }

        It 'geeft de hoogste geziene RecordId per log terug' {
            $result = Get-HKNtlmUsage
            $result.LastSecurityRecordId | Should -Be 102
            $result.LastNtlmOperationalRecordId | Should -Be 201
        }
    }

    Context 'NTLM/Operational-log niet leesbaar, Security-log wel' {

        BeforeAll {
            Mock -ModuleName HardenKit Get-HKWinEvent {
                if ($LogName -eq 'Security') {
                    @()
                }
                else {
                    throw 'toegang geweigerd'
                }
            }
        }

        It 'breekt de run niet af en markeert alleen NtlmOperationalLog als onbekend' {
            { Get-HKNtlmUsage -WarningAction SilentlyContinue } | Should -Not -Throw
            $result = Get-HKNtlmUsage -WarningAction SilentlyContinue
            $result.Collectors.SecurityLog | Should -Be 'ok'
            $result.Collectors.NtlmOperationalLog | Should -Be 'onbekend'
            $result.Findings.Count | Should -Be 0
        }
    }

    Context 'geen events in beide logs' {

        BeforeAll {
            Mock -ModuleName HardenKit Get-HKWinEvent { @() }
        }

        It 'geeft lege Findings terug zonder fouten' {
            $result = Get-HKNtlmUsage
            $result.Collectors.SecurityLog | Should -Be 'ok'
            $result.Collectors.NtlmOperationalLog | Should -Be 'ok'
            $result.Findings.Count | Should -Be 0
        }
    }
}
