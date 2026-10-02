#Requires -Modules Pester

$script:ModuleRoot = Split-Path -Parent $PSScriptRoot
$script:ManifestPath = Join-Path $script:ModuleRoot 'HardenKit.psd1'
Import-Module $script:ManifestPath -Force

AfterAll {
    Remove-Module HardenKit -ErrorAction SilentlyContinue
}

InModuleScope HardenKit {

    Describe 'ConvertTo-HKFindingRecord' {
        # Pure mapping-logica.

        It 'zet een interne findingregel om naar de PRD-JSON-vorm' {
            $row = [pscustomobject]@{
                Measure      = 'ntlmv1'
                AccountName  = 'svc_scan'
                AccountSid   = 'S-1-5-21-1-2-3-1001'
                ClientFqdn   = 'scanner01.contoso.com'
                ClientIp     = '10.0.0.50'
                Target       = $null
                Count        = 412
                FirstSeenUtc = [datetime]'2026-10-01T06:02:11Z'
                LastSeenUtc  = [datetime]'2026-10-01T22:47:03Z'
            }
            $result = ConvertTo-HKFindingRecord -InputObject $row

            $result.measure | Should -Be 'ntlmv1'
            $result.client.fqdn | Should -Be 'scanner01.contoso.com'
            $result.client.ip | Should -Be '10.0.0.50'
            $result.account.name | Should -Be 'svc_scan'
            $result.account.sid | Should -Be 'S-1-5-21-1-2-3-1001'
            $result.count | Should -Be 412
            $result.firstSeen | Should -Be '2026-10-01T06:02:11Z'
            $result.lastSeen | Should -Be '2026-10-01T22:47:03Z'
            $result.PSObject.Properties.Match('target').Count | Should -Be 0
            $result.PSObject.Properties.Match('isIpOrAlias').Count | Should -Be 0
        }

        It 'neemt target en isIpOrAlias mee als ze aanwezig zijn' {
            $row = [pscustomobject]@{
                Measure      = 'ntlm_8004'
                AccountName  = 'svc_app'
                AccountSid   = $null
                ClientFqdn   = 'app01.contoso.com'
                ClientIp     = $null
                Target       = '10.0.0.99'
                IsIpOrAlias  = $true
                Count        = 3
                FirstSeenUtc = [datetime]'2026-10-01T06:00:00Z'
                LastSeenUtc  = [datetime]'2026-10-01T06:30:00Z'
            }
            $result = ConvertTo-HKFindingRecord -InputObject $row

            $result.target | Should -Be '10.0.0.99'
            $result.isIpOrAlias | Should -BeTrue
        }
    }
}

Describe 'Export-HKData' {

    Context 'op een DC, alle collectors leesbaar' {

        BeforeAll {
            $script:outputPath = Join-Path $TestDrive 'out1'

            Mock -ModuleName HardenKit Get-HKHostRole { 'DC' }
            Mock -ModuleName HardenKit Get-HKLocalFqdn { 'dc01.contoso.com' }
            Mock -ModuleName HardenKit Test-HKAuditConfig {
                [pscustomobject]@{
                    Collectors = [pscustomobject]@{ AuditPolicy = 'ok'; SecurityLog = 'ok'; NtlmAudit = 'ok'; LdapAudit = 'ok' }
                    Measures   = @()
                }
            }
            Mock -ModuleName HardenKit Get-HKBaseline {
                [pscustomobject]@{
                    Collectors = [pscustomobject]@{ OperatingSystem = 'ok' }
                    OperatingSystem = [pscustomobject]@{ Caption = 'Windows Server 2022' }
                }
            }
            Mock -ModuleName HardenKit Get-HKNtlmUsage {
                [pscustomobject]@{
                    Collectors                  = [pscustomobject]@{ SecurityLog = 'ok'; NtlmOperationalLog = 'ok' }
                    Findings                     = @(
                        [pscustomobject]@{ Measure = 'ntlmv1'; AccountName = 'svc_scan'; AccountSid = $null; ClientFqdn = 'scanner01'; ClientIp = '10.0.0.50'; Target = $null; Count = 5; FirstSeenUtc = [datetime]'2026-10-01T06:00:00Z'; LastSeenUtc = [datetime]'2026-10-01T06:10:00Z' }
                    )
                    LastSecurityRecordId        = 500
                    LastNtlmOperationalRecordId = 600
                }
            }
            Mock -ModuleName HardenKit Get-HKLdapBinding {
                [pscustomobject]@{
                    Collectors                   = [pscustomobject]@{ DirectoryServiceLog = 'ok' }
                    Findings                      = @(
                        [pscustomobject]@{ Measure = 'ldap_signing'; AccountName = 'jdoe'; AccountSid = $null; ClientFqdn = $null; ClientIp = '10.0.0.5'; Target = $null; Count = 2; FirstSeenUtc = [datetime]'2026-10-01T06:00:00Z'; LastSeenUtc = [datetime]'2026-10-01T07:00:00Z' }
                    )
                    SigningDailySummary          = @([pscustomobject]@{ TimeCreatedUtc = [datetime]'2026-10-01T23:59:00Z'; Count = 42 })
                    ChannelBindingDailySummary   = @()
                    LastDirectoryServiceRecordId = 700
                }
            }
            Mock -ModuleName HardenKit Get-HKKerberos {
                [pscustomobject]@{
                    Collectors            = [pscustomobject]@{ SecurityLog = 'ok'; SystemLog = 'ok' }
                    Findings              = @(
                        [pscustomobject]@{ Measure = 'missing_spn'; AccountName = 'appsvc'; AccountSid = $null; ClientFqdn = $null; ClientIp = '10.0.0.30'; Target = 'HTTP/missingspn.contoso.com'; Count = 1; FirstSeenUtc = [datetime]'2026-10-01T06:00:00Z'; LastSeenUtc = [datetime]'2026-10-01T06:00:00Z' }
                    )
                    LastSecurityRecordId  = 800
                    LastSystemRecordId    = 900
                }
            }
            Mock -ModuleName HardenKit Get-HKDomainHealth {
                [pscustomobject]@{
                    Collectors                    = [pscustomobject]@{ SecurityLog = 'ok'; SystemLog = 'ok'; DirectoryServiceLog = 'ok' }
                    Findings                       = @(
                        [pscustomobject]@{ Measure = 'lockouts'; AccountName = 'jdoe'; AccountSid = $null; ClientFqdn = 'WKS01'; ClientIp = $null; Target = $null; Count = 1; FirstSeenUtc = [datetime]'2026-10-01T06:00:00Z'; LastSeenUtc = [datetime]'2026-10-01T06:00:00Z' }
                    )
                    UnknownSubnetsDailySummary    = @([pscustomobject]@{ TimeCreatedUtc = [datetime]'2026-10-01T23:59:00Z'; Count = 15 })
                    LastSecurityRecordId          = 1000
                    LastSystemRecordId            = 1100
                    LastDirectoryServiceRecordId  = 1200
                }
            }
            Mock -ModuleName HardenKit Get-HKOutbound {
                [pscustomobject]@{
                    Collectors = [pscustomobject]@{ Connections = 'ok' }
                    Findings   = @(
                        [pscustomobject]@{ Measure = 'outbound'; AccountName = $null; AccountSid = $null; ClientFqdn = 'update.microsoft.com'; ClientIp = '20.0.0.1'; Target = 'svchost'; Count = 3; FirstSeenUtc = [datetime]'2026-10-01T06:00:00Z'; LastSeenUtc = [datetime]'2026-10-01T06:00:00Z' }
                    )
                }
            }
        }

        It 'schrijft het dagbestand en het statusbestand' {
            $result = Export-HKData -ClientCode 'KLANT01' -OutputPath $script:outputPath
            Test-Path $result.DataFilePath | Should -BeTrue
            Test-Path $result.StateFilePath | Should -BeTrue
        }

        It 'markeert alle collectors als ok en telt de findings op' {
            $result = Export-HKData -ClientCode 'KLANT01' -OutputPath $script:outputPath
            $result.Collectors.auditConfig | Should -Be 'ok'
            $result.Collectors.baseline | Should -Be 'ok'
            $result.Collectors.ntlmUsage | Should -Be 'ok'
            $result.Collectors.ldapBinding | Should -Be 'ok'
            $result.Collectors.kerberos | Should -Be 'ok'
            $result.Collectors.domainHealth | Should -Be 'ok'
            $result.Collectors.outbound | Should -Be 'ok'
            $result.FindingsCount | Should -Be 5
        }

        It 'schrijft een dagbestand volgens het PRD-schema' {
            $result = Export-HKData -ClientCode 'KLANT01' -OutputPath $script:outputPath
            $data = Get-Content -Path $result.DataFilePath -Raw | ConvertFrom-Json

            $data.schema | Should -Be '1.0'
            $data.client | Should -Be 'KLANT01'
            $data.host | Should -Be 'dc01.contoso.com'
            $data.role | Should -Be 'DC'
            $data.findings.Count | Should -Be 5
            ($data.findings | Where-Object measure -eq 'ntlmv1').account.name | Should -Be 'svc_scan'
            ($data.findings | Where-Object measure -eq 'missing_spn').target | Should -Be 'HTTP/missingspn.contoso.com'
            ($data.findings | Where-Object measure -eq 'lockouts').client.fqdn | Should -Be 'WKS01'
            ($data.findings | Where-Object measure -eq 'outbound').target | Should -Be 'svchost'
            $data.baseline.OperatingSystem.Caption | Should -Be 'Windows Server 2022'
        }

        It 'neemt de dagsamenvattingen (2887/3041/5807) mee in dailySummaries, niet in findings' {
            $result = Export-HKData -ClientCode 'KLANT01' -OutputPath $script:outputPath
            $data = Get-Content -Path $result.DataFilePath -Raw | ConvertFrom-Json

            $data.dailySummaries.ldapSigning.Count | Should -Be 1
            $data.dailySummaries.ldapSigning[0].Count | Should -Be 42
            $data.dailySummaries.unknownSubnets.Count | Should -Be 1
            $data.dailySummaries.unknownSubnets[0].Count | Should -Be 15
            $data.findings | Where-Object measure -eq 'unknown_subnets' | Should -BeNullOrEmpty
        }

        It 'persisteert de hoogste RecordId per log in het statusbestand' {
            $result = Export-HKData -ClientCode 'KLANT01' -OutputPath $script:outputPath
            $state = Get-Content -Path $result.StateFilePath -Raw | ConvertFrom-Json
            $state.lastSecurityRecordId | Should -Be 500
            $state.lastNtlmOperationalRecordId | Should -Be 600
            $state.lastDirectoryServiceRecordId | Should -Be 700
            $state.lastKerberosSecurityRecordId | Should -Be 800
            $state.lastSystemRecordId | Should -Be 900
            $state.lastDomainHealthSecurityRecordId | Should -Be 1000
            $state.lastDomainHealthSystemRecordId | Should -Be 1100
            $state.lastDomainHealthDirectoryServiceRecordId | Should -Be 1200
        }

        It 'geeft StartRecordIds uit een eerdere state-run door aan de volgende run' {
            $null = Export-HKData -ClientCode 'KLANT01' -OutputPath $script:outputPath
            $null = Export-HKData -ClientCode 'KLANT01' -OutputPath $script:outputPath

            Should -Invoke -ModuleName HardenKit Get-HKNtlmUsage -ParameterFilter {
                $SecurityStartRecordId -eq 500 -and $NtlmOperationalStartRecordId -eq 600
            }
            Should -Invoke -ModuleName HardenKit Get-HKLdapBinding -ParameterFilter {
                $DirectoryServiceStartRecordId -eq 700
            }
            Should -Invoke -ModuleName HardenKit Get-HKKerberos -ParameterFilter {
                $SecurityStartRecordId -eq 800 -and $SystemStartRecordId -eq 900
            }
            Should -Invoke -ModuleName HardenKit Get-HKDomainHealth -ParameterFilter {
                $SecurityStartRecordId -eq 1000 -and $SystemStartRecordId -eq 1100 -and $DirectoryServiceStartRecordId -eq 1200
            }
        }

        It 'laat window.from leeg bij de eerste run en gevuld bij de tweede' {
            $outputPath = Join-Path $TestDrive 'out-window'
            $first = Export-HKData -ClientCode 'KLANT01' -OutputPath $outputPath
            $firstData = Get-Content -Path $first.DataFilePath -Raw | ConvertFrom-Json
            $firstData.window.from | Should -BeNullOrEmpty

            Start-Sleep -Milliseconds 1100
            $second = Export-HKData -ClientCode 'KLANT01' -OutputPath $outputPath
            $secondData = Get-Content -Path $second.DataFilePath -Raw | ConvertFrom-Json
            $secondData.window.from | Should -Not -BeNullOrEmpty
        }
    }

    Context 'één collector faalt' {

        BeforeAll {
            $script:outputPath2 = Join-Path $TestDrive 'out2'

            Mock -ModuleName HardenKit Get-HKHostRole { 'DC' }
            Mock -ModuleName HardenKit Get-HKLocalFqdn { 'dc01.contoso.com' }
            Mock -ModuleName HardenKit Test-HKAuditConfig {
                [pscustomobject]@{ Collectors = [pscustomobject]@{ AuditPolicy = 'ok' }; Measures = @() }
            }
            Mock -ModuleName HardenKit Get-HKBaseline {
                [pscustomobject]@{ Collectors = [pscustomobject]@{ OperatingSystem = 'ok' } }
            }
            Mock -ModuleName HardenKit Get-HKNtlmUsage { throw 'toegang geweigerd' }
            Mock -ModuleName HardenKit Get-HKLdapBinding {
                [pscustomobject]@{ Collectors = [pscustomobject]@{ DirectoryServiceLog = 'ok' }; Findings = @(); LastDirectoryServiceRecordId = 1 }
            }
            Mock -ModuleName HardenKit Get-HKKerberos {
                [pscustomobject]@{ Collectors = [pscustomobject]@{ SecurityLog = 'ok'; SystemLog = 'ok' }; Findings = @(); LastSecurityRecordId = 1; LastSystemRecordId = 1 }
            }
            Mock -ModuleName HardenKit Get-HKDomainHealth {
                [pscustomobject]@{ Collectors = [pscustomobject]@{ SecurityLog = 'ok'; SystemLog = 'ok'; DirectoryServiceLog = 'ok' }; Findings = @(); UnknownSubnetsDailySummary = @(); LastSecurityRecordId = 1; LastSystemRecordId = 1; LastDirectoryServiceRecordId = 1 }
            }
            Mock -ModuleName HardenKit Get-HKOutbound {
                [pscustomobject]@{ Collectors = [pscustomobject]@{ Connections = 'ok' }; Findings = @() }
            }
        }

        It 'breekt de run niet af en markeert alleen ntlmUsage als onbekend' {
            { Export-HKData -ClientCode 'KLANT01' -OutputPath $script:outputPath2 -WarningAction SilentlyContinue } | Should -Not -Throw
            $result = Export-HKData -ClientCode 'KLANT01' -OutputPath $script:outputPath2 -WarningAction SilentlyContinue
            $result.Collectors.ntlmUsage | Should -Be 'onbekend'
            $result.Collectors.baseline | Should -Be 'ok'
            $result.Collectors.ldapBinding | Should -Be 'ok'
            $result.Collectors.kerberos | Should -Be 'ok'
            $result.Collectors.domainHealth | Should -Be 'ok'
            $result.Collectors.outbound | Should -Be 'ok'
        }
    }

    Context 'niet-DC-rol' {

        BeforeAll {
            $script:outputPath3 = Join-Path $TestDrive 'out3'
            Mock -ModuleName HardenKit Get-HKHostRole { 'MemberServer' }
            Mock -ModuleName HardenKit Get-HKLocalFqdn { 'srv01.contoso.com' }
            # Should -Invoke -Times 0 hieronder heeft een gedefinieerde Mock nodig om tegen te
            # controleren, ook al wordt die nooit aangeroepen.
            Mock -ModuleName HardenKit Test-HKAuditConfig { }
            Mock -ModuleName HardenKit Get-HKBaseline { }
            Mock -ModuleName HardenKit Get-HKNtlmUsage { }
            Mock -ModuleName HardenKit Get-HKLdapBinding { }
            Mock -ModuleName HardenKit Get-HKKerberos { }
            Mock -ModuleName HardenKit Get-HKDomainHealth { }
            Mock -ModuleName HardenKit Get-HKOutbound { }
        }

        It 'markeert alle collectors als onbekend zonder ze aan te roepen' {
            $result = Export-HKData -ClientCode 'KLANT01' -OutputPath $script:outputPath3 -WarningAction SilentlyContinue
            $result.Collectors.auditConfig | Should -Be 'onbekend'
            $result.Collectors.baseline | Should -Be 'onbekend'
            $result.Collectors.ntlmUsage | Should -Be 'onbekend'
            $result.Collectors.ldapBinding | Should -Be 'onbekend'
            $result.Collectors.kerberos | Should -Be 'onbekend'
            $result.Collectors.domainHealth | Should -Be 'onbekend'
            $result.Collectors.outbound | Should -Be 'onbekend'
            $result.FindingsCount | Should -Be 0

            Should -Invoke -ModuleName HardenKit Test-HKAuditConfig -Times 0
            Should -Invoke -ModuleName HardenKit Get-HKBaseline -Times 0
        }
    }
}
