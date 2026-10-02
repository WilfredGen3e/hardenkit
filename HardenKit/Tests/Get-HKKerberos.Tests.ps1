#Requires -Modules Pester

$script:ModuleRoot = Split-Path -Parent $PSScriptRoot
$script:ManifestPath = Join-Path $script:ModuleRoot 'HardenKit.psd1'
Import-Module $script:ManifestPath -Force

AfterAll {
    Remove-Module HardenKit -ErrorAction SilentlyContinue
}

Describe 'Get-HKKerberos' {

    Context 'alle bronnen leesbaar' {

        BeforeAll {
            Mock -ModuleName HardenKit Get-HKWinEvent {
                if ($LogName -eq 'Security') {
                    @(
                        # 4769, succesvol, RC4 -> kerberos_rc4_des
                        [pscustomobject]@{
                            TimeCreatedUtc = [datetime]'2026-10-01T06:00:00Z'; EventRecordId = 100; EventId = 4769; Computer = 'dc01.contoso.com'
                            EventData      = @{ TargetUserName = 'svc_old'; TargetSid = 'S-1-5-21-1-2-3-2001'; ServiceName = 'fileserver'; Status = '0x0'; TicketEncryptionType = '0x17'; IpAddress = '10.0.0.20' }
                        }
                        # 4769, succesvol, AES -> geen finding (sterke encryptie)
                        [pscustomobject]@{
                            TimeCreatedUtc = [datetime]'2026-10-01T06:05:00Z'; EventRecordId = 101; EventId = 4769; Computer = 'dc01.contoso.com'
                            EventData      = @{ TargetUserName = 'jdoe'; TargetSid = 'S-1-5-21-1-2-3-1001'; ServiceName = 'fileserver'; Status = '0x0'; TicketEncryptionType = '0x12'; IpAddress = '10.0.0.21' }
                        }
                        # 4769, fout 0x7 -> missing_spn
                        [pscustomobject]@{
                            TimeCreatedUtc = [datetime]'2026-10-01T06:10:00Z'; EventRecordId = 102; EventId = 4769; Computer = 'dc01.contoso.com'
                            EventData      = @{ TargetUserName = 'appsvc'; TargetSid = 'S-1-5-21-1-2-3-3001'; ServiceName = 'HTTP/missingspn.contoso.com'; Status = '0x7'; TicketEncryptionType = '0x12'; IpAddress = '10.0.0.30' }
                        }
                        # 4768, succesvol, DES -> kerberos_rc4_des
                        [pscustomobject]@{
                            TimeCreatedUtc = [datetime]'2026-10-01T06:15:00Z'; EventRecordId = 103; EventId = 4768; Computer = 'dc01.contoso.com'
                            EventData      = @{ TargetUserName = 'legacyuser'; TargetSid = 'S-1-5-21-1-2-3-4001'; ResultCode = '0x0'; TicketEncryptionType = '0x1'; IpAddress = '10.0.0.40' }
                        }
                        # 4769, zwak encryptietype maar mislukt -> geen finding (niet succesvol)
                        [pscustomobject]@{
                            TimeCreatedUtc = [datetime]'2026-10-01T06:20:00Z'; EventRecordId = 104; EventId = 4769; Computer = 'dc01.contoso.com'
                            EventData      = @{ TargetUserName = 'faaltuser'; TargetSid = 'S-1-5-21-1-2-3-5001'; ServiceName = 'fileserver'; Status = '0x6'; TicketEncryptionType = '0x17'; IpAddress = '10.0.0.50' }
                        }
                    )
                }
                else {
                    @(
                        # System-event 11: dubbele SPN
                        [pscustomobject]@{
                            TimeCreatedUtc = [datetime]'2026-10-01T06:25:00Z'; EventRecordId = 200; EventId = 11; Computer = 'dc01.contoso.com'
                            EventData      = @{ ServicePrincipalName = 'HTTP/webserver.contoso.com' }
                        }
                        # System-event 41: zwakke certificaatmapping
                        [pscustomobject]@{
                            TimeCreatedUtc = [datetime]'2026-10-01T06:30:00Z'; EventRecordId = 201; EventId = 41; Computer = 'dc01.contoso.com'
                            EventData      = @{ TargetUserName = 'certuser'; TargetSid = 'S-1-5-21-1-2-3-6001'; CertificateSubject = 'CN=certuser' }
                        }
                    )
                }
            }
        }

        It 'markeert beide collectors als ok' {
            $result = Get-HKKerberos
            $result.Collectors.SecurityLog | Should -Be 'ok'
            $result.Collectors.SystemLog | Should -Be 'ok'
        }

        It 'neemt alleen succesvolle tickets met zwakke encryptie mee als kerberos_rc4_des' {
            $result = Get-HKKerberos
            $rows = @($result.Findings | Where-Object Measure -eq 'kerberos_rc4_des')
            $rows.Count | Should -Be 2
            ($rows | Where-Object AccountName -eq 'svc_old') | Should -Not -BeNullOrEmpty
            ($rows | Where-Object AccountName -eq 'legacyuser') | Should -Not -BeNullOrEmpty
            # AES-event en het mislukte 0x17-event horen hier niet in terecht te komen.
            ($rows | Where-Object AccountName -eq 'jdoe') | Should -BeNullOrEmpty
            ($rows | Where-Object AccountName -eq 'faaltuser') | Should -BeNullOrEmpty
        }

        It 'neemt 4769 met Status 0x7 mee als missing_spn' {
            $result = Get-HKKerberos
            $row = $result.Findings | Where-Object Measure -eq 'missing_spn'
            $row.AccountName | Should -Be 'appsvc'
            $row.Target | Should -Be 'HTTP/missingspn.contoso.com'
        }

        It 'neemt System-event 11 mee als duplicate_spn met de SPN als Target' {
            $result = Get-HKKerberos
            $row = $result.Findings | Where-Object Measure -eq 'duplicate_spn'
            $row.Target | Should -Be 'HTTP/webserver.contoso.com'
            $row.AccountName | Should -BeNullOrEmpty
        }

        It 'neemt System-event 41 mee als cert_mapping' {
            $result = Get-HKKerberos
            $row = $result.Findings | Where-Object Measure -eq 'cert_mapping'
            $row.AccountName | Should -Be 'certuser'
            $row.Target | Should -Be 'CN=certuser'
        }

        It 'geeft de hoogste geziene RecordId per log terug' {
            $result = Get-HKKerberos
            $result.LastSecurityRecordId | Should -Be 104
            $result.LastSystemRecordId | Should -Be 201
        }
    }

    Context 'System-log niet leesbaar, Security-log wel' {

        BeforeAll {
            Mock -ModuleName HardenKit Get-HKWinEvent {
                if ($LogName -eq 'Security') { @() }
                else { throw 'toegang geweigerd' }
            }
        }

        It 'breekt de run niet af en markeert alleen SystemLog als onbekend' {
            { Get-HKKerberos -WarningAction SilentlyContinue } | Should -Not -Throw
            $result = Get-HKKerberos -WarningAction SilentlyContinue
            $result.Collectors.SecurityLog | Should -Be 'ok'
            $result.Collectors.SystemLog | Should -Be 'onbekend'
            $result.Findings.Count | Should -Be 0
        }
    }

    Context 'geen events' {

        BeforeAll {
            Mock -ModuleName HardenKit Get-HKWinEvent { @() }
        }

        It 'geeft lege Findings terug zonder fouten' {
            $result = Get-HKKerberos
            $result.Findings.Count | Should -Be 0
        }
    }
}
