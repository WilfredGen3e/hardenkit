#Requires -Modules Pester

$script:ModuleRoot = Split-Path -Parent $PSScriptRoot
$script:ManifestPath = Join-Path $script:ModuleRoot 'HardenKit.psd1'
Import-Module $script:ManifestPath -Force

AfterAll {
    Remove-Module HardenKit -ErrorAction SilentlyContinue
}

Describe 'Get-HKDomainHealth' {

    Context 'alle bronnen leesbaar' {

        BeforeAll {
            Mock -ModuleName HardenKit Get-HKWinEvent {
                switch ($LogName) {
                    'Security' {
                        @(
                            [pscustomobject]@{ TimeCreatedUtc = [datetime]'2026-10-01T06:00:00Z'; EventRecordId = 100; EventId = 4740; Computer = 'dc01.contoso.com'
                                EventData = @{ TargetUserName = 'jdoe'; TargetSid = 'S-1-5-21-1-2-3-1001'; CallerComputerName = 'WKS01' } }
                            [pscustomobject]@{ TimeCreatedUtc = [datetime]'2026-10-01T06:05:00Z'; EventRecordId = 101; EventId = 4625; Computer = 'dc01.contoso.com'
                                EventData = @{ TargetUserName = 'jdoe'; TargetUserSid = 'S-1-5-21-1-2-3-1001'; WorkstationName = 'WKS01'; IpAddress = '10.0.0.11' } }
                        )
                    }
                    'System' {
                        @(
                            [pscustomobject]@{ TimeCreatedUtc = [datetime]'2026-10-01T06:10:00Z'; EventRecordId = 200; EventId = 5827; Computer = 'dc01.contoso.com'
                                EventData = @{ MachineAccount = 'OLDPC$' } }
                            [pscustomobject]@{ TimeCreatedUtc = [datetime]'2026-10-01T06:15:00Z'; EventRecordId = 201; EventId = 5816; Computer = 'dc01.contoso.com'
                                EventData = @{} }
                            [pscustomobject]@{ TimeCreatedUtc = [datetime]'2026-10-01T06:20:00Z'; EventRecordId = 202; EventId = 50; Computer = 'dc01.contoso.com'
                                EventData = @{} }
                            [pscustomobject]@{ TimeCreatedUtc = [datetime]'2026-10-01T23:59:00Z'; EventRecordId = 203; EventId = 5807; Computer = 'dc01.contoso.com'
                                EventData = @{ Count = '15' } }
                        )
                    }
                    'Directory Service' {
                        @(
                            [pscustomobject]@{ TimeCreatedUtc = [datetime]'2026-10-01T06:25:00Z'; EventRecordId = 300; EventId = 1865; Computer = 'dc01.contoso.com'
                                EventData = @{} }
                        )
                    }
                }
            }
        }

        It 'markeert alle drie de collectors als ok' {
            $result = Get-HKDomainHealth
            $result.Collectors.SecurityLog | Should -Be 'ok'
            $result.Collectors.SystemLog | Should -Be 'ok'
            $result.Collectors.DirectoryServiceLog | Should -Be 'ok'
        }

        It 'neemt 5827 mee als netlogon_secure_channel met het machine-account' {
            $result = Get-HKDomainHealth
            $row = $result.Findings | Where-Object Measure -eq 'netlogon_secure_channel'
            $row.AccountName | Should -Be 'OLDPC$'
        }

        It 'telt 5816 als netlogon_saturation-voorval' {
            $result = Get-HKDomainHealth
            $row = $result.Findings | Where-Object Measure -eq 'netlogon_saturation'
            $row.Count | Should -Be 1
        }

        It 'telt W32Time 50 als time_sync-voorval' {
            $result = Get-HKDomainHealth
            $row = $result.Findings | Where-Object Measure -eq 'time_sync'
            $row.Count | Should -Be 1
        }

        It 'combineert 4740 en 4625 onder lockouts, met de juiste bron per event' {
            $result = Get-HKDomainHealth
            $rows = @($result.Findings | Where-Object Measure -eq 'lockouts')
            $rows.Count | Should -Be 2
            ($rows | Where-Object ClientFqdn -eq 'WKS01').Count | Should -Not -BeNullOrEmpty
        }

        It 'telt 1865 als replication-voorval' {
            $result = Get-HKDomainHealth
            $row = $result.Findings | Where-Object Measure -eq 'replication'
            $row.Count | Should -Be 1
        }

        It 'zet 5807 apart als UnknownSubnetsDailySummary, niet in Findings' {
            $result = Get-HKDomainHealth
            $result.UnknownSubnetsDailySummary.Count | Should -Be 1
            $result.UnknownSubnetsDailySummary[0].Count | Should -Be 15
            $result.Findings | Where-Object Measure -eq 'unknown_subnets' | Should -BeNullOrEmpty
        }

        It 'geeft de hoogste geziene RecordId per log terug' {
            $result = Get-HKDomainHealth
            $result.LastSecurityRecordId | Should -Be 101
            $result.LastSystemRecordId | Should -Be 203
            $result.LastDirectoryServiceRecordId | Should -Be 300
        }
    }

    Context 'System-log niet leesbaar, de andere twee wel' {

        BeforeAll {
            Mock -ModuleName HardenKit Get-HKWinEvent {
                if ($LogName -eq 'System') { throw 'toegang geweigerd' }
                else { @() }
            }
        }

        It 'breekt de run niet af en markeert alleen SystemLog als onbekend' {
            { Get-HKDomainHealth -WarningAction SilentlyContinue } | Should -Not -Throw
            $result = Get-HKDomainHealth -WarningAction SilentlyContinue
            $result.Collectors.SecurityLog | Should -Be 'ok'
            $result.Collectors.SystemLog | Should -Be 'onbekend'
            $result.Collectors.DirectoryServiceLog | Should -Be 'ok'
            $result.Findings.Count | Should -Be 0
        }
    }

    Context 'geen events' {

        BeforeAll {
            Mock -ModuleName HardenKit Get-HKWinEvent { @() }
        }

        It 'geeft lege resultaten terug zonder fouten' {
            $result = Get-HKDomainHealth
            $result.Findings.Count | Should -Be 0
            $result.UnknownSubnetsDailySummary.Count | Should -Be 0
        }
    }
}
