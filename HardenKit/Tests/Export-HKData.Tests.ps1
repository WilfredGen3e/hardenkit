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
            $result.FindingsCount | Should -Be 3
        }

        It 'schrijft een dagbestand volgens het PRD-schema' {
            $result = Export-HKData -ClientCode 'KLANT01' -OutputPath $script:outputPath
            $data = Get-Content -Path $result.DataFilePath -Raw | ConvertFrom-Json

            $data.schema | Should -Be '1.0'
            $data.client | Should -Be 'KLANT01'
            $data.host | Should -Be 'dc01.contoso.com'
            $data.role | Should -Be 'DC'
            $data.findings.Count | Should -Be 3
            ($data.findings | Where-Object measure -eq 'ntlmv1').account.name | Should -Be 'svc_scan'
            ($data.findings | Where-Object measure -eq 'missing_spn').target | Should -Be 'HTTP/missingspn.contoso.com'
            $data.baseline.OperatingSystem.Caption | Should -Be 'Windows Server 2022'
        }

        It 'persisteert de hoogste RecordId per log in het statusbestand' {
            $result = Export-HKData -ClientCode 'KLANT01' -OutputPath $script:outputPath
            $state = Get-Content -Path $result.StateFilePath -Raw | ConvertFrom-Json
            $state.lastSecurityRecordId | Should -Be 500
            $state.lastNtlmOperationalRecordId | Should -Be 600
            $state.lastDirectoryServiceRecordId | Should -Be 700
            $state.lastKerberosSecurityRecordId | Should -Be 800
            $state.lastSystemRecordId | Should -Be 900
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
        }

        It 'breekt de run niet af en markeert alleen ntlmUsage als onbekend' {
            { Export-HKData -ClientCode 'KLANT01' -OutputPath $script:outputPath2 -WarningAction SilentlyContinue } | Should -Not -Throw
            $result = Export-HKData -ClientCode 'KLANT01' -OutputPath $script:outputPath2 -WarningAction SilentlyContinue
            $result.Collectors.ntlmUsage | Should -Be 'onbekend'
            $result.Collectors.baseline | Should -Be 'ok'
            $result.Collectors.ldapBinding | Should -Be 'ok'
            $result.Collectors.kerberos | Should -Be 'ok'
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
        }

        It 'markeert alle collectors als onbekend zonder ze aan te roepen' {
            $result = Export-HKData -ClientCode 'KLANT01' -OutputPath $script:outputPath3 -WarningAction SilentlyContinue
            $result.Collectors.auditConfig | Should -Be 'onbekend'
            $result.Collectors.baseline | Should -Be 'onbekend'
            $result.Collectors.ntlmUsage | Should -Be 'onbekend'
            $result.Collectors.ldapBinding | Should -Be 'onbekend'
            $result.Collectors.kerberos | Should -Be 'onbekend'
            $result.FindingsCount | Should -Be 0

            Should -Invoke -ModuleName HardenKit Test-HKAuditConfig -Times 0
            Should -Invoke -ModuleName HardenKit Get-HKBaseline -Times 0
        }
    }
}
