#Requires -Modules Pester

$script:ModuleRoot = Split-Path -Parent $PSScriptRoot
$script:ManifestPath = Join-Path $script:ModuleRoot 'HardenKit.psd1'
Import-Module $script:ManifestPath -Force

AfterAll {
    Remove-Module HardenKit -ErrorAction SilentlyContinue
}

InModuleScope HardenKit {

    Describe 'ConvertTo-HKNormalizedSpnTarget' {
        It 'haalt de klasse voor de slash weg en zet lowercase' {
            ConvertTo-HKNormalizedSpnTarget -Value 'HTTP/FileServer.Contoso.com' | Should -Be 'fileserver.contoso.com'
        }
        It 'laat een kale servernaam ongewijzigd behalve lowercase' {
            ConvertTo-HKNormalizedSpnTarget -Value 'FileServer' | Should -Be 'fileserver'
        }
        It 'haalt een poortnummer na een dubbele punt weg' {
            ConvertTo-HKNormalizedSpnTarget -Value 'HTTP/fileserver.contoso.com:8080' | Should -Be 'fileserver.contoso.com'
        }
        It 'geeft $null terug bij lege invoer' {
            ConvertTo-HKNormalizedSpnTarget -Value '' | Should -BeNullOrEmpty
            ConvertTo-HKNormalizedSpnTarget -Value $null | Should -BeNullOrEmpty
        }
    }

    Describe 'ConvertTo-HKHtmlEncoded' {
        It 'encodeert HTML-gevoelige tekens' {
            ConvertTo-HKHtmlEncoded -Value '<script>alert(1)</script> & "quotes"' | Should -Be '&lt;script&gt;alert(1)&lt;/script&gt; &amp; &quot;quotes&quot;'
        }
        It 'geeft een lege string terug voor $null' {
            ConvertTo-HKHtmlEncoded -Value $null | Should -Be ''
        }
    }

    Describe 'Merge-HKFindings' {
        It 'telt counts op en pakt vroegste/laatste tijd over meerdere regels met dezelfde sleutel' {
            $rows = @(
                [pscustomobject]@{ measure = 'ntlmv1'; client = [pscustomobject]@{ fqdn = 'scanner01'; ip = '10.0.0.50' }; account = [pscustomobject]@{ name = 'svc_scan'; sid = 'S-1-5-21-1' }; count = 5; firstSeen = '2026-10-01T06:00:00Z'; lastSeen = '2026-10-01T06:10:00Z' }
                [pscustomobject]@{ measure = 'ntlmv1'; client = [pscustomobject]@{ fqdn = 'scanner01'; ip = '10.0.0.50' }; account = [pscustomobject]@{ name = 'svc_scan'; sid = 'S-1-5-21-1' }; count = 3; firstSeen = '2026-10-02T06:00:00Z'; lastSeen = '2026-10-02T06:10:00Z' }
            )
            $result = @($rows | Merge-HKFindings)
            $result.Count | Should -Be 1
            $result[0].count | Should -Be 8
            $result[0].firstSeen | Should -Be ([datetime]'2026-10-01T06:00:00Z')
            $result[0].lastSeen | Should -Be ([datetime]'2026-10-02T06:10:00Z')
        }

        It 'houdt verschillende sleutels apart' {
            $rows = @(
                [pscustomobject]@{ measure = 'ntlmv1'; client = [pscustomobject]@{ fqdn = 'a'; ip = $null }; account = [pscustomobject]@{ name = 'x'; sid = $null }; count = 1; firstSeen = '2026-10-01T06:00:00Z'; lastSeen = '2026-10-01T06:00:00Z' }
                [pscustomobject]@{ measure = 'ntlmv1'; client = [pscustomobject]@{ fqdn = 'b'; ip = $null }; account = [pscustomobject]@{ name = 'y'; sid = $null }; count = 1; firstSeen = '2026-10-01T06:00:00Z'; lastSeen = '2026-10-01T06:00:00Z' }
            )
            $result = @($rows | Merge-HKFindings)
            $result.Count | Should -Be 2
        }

        It 'behoudt target en isIpOrAlias' {
            $rows = @(
                [pscustomobject]@{ measure = 'ntlm_8004'; client = [pscustomobject]@{ fqdn = 'app01'; ip = $null }; account = [pscustomobject]@{ name = 'svc_app'; sid = $null }; target = '10.0.0.99'; isIpOrAlias = $true; count = 2; firstSeen = '2026-10-01T06:00:00Z'; lastSeen = '2026-10-01T06:00:00Z' }
            )
            $result = @($rows | Merge-HKFindings)
            $result[0].target | Should -Be '10.0.0.99'
            $result[0].isIpOrAlias | Should -BeTrue
        }

        It 'geeft een lege lijst terug bij lege invoer' {
            $result = @(@() | Merge-HKFindings)
            $result.Count | Should -Be 0
        }
    }
}

InModuleScope HardenKit {

    Describe 'Resolve-HKReportModel' {

        Context 'Groen: geen findings, alles ok, genoeg dagen' {
            BeforeAll {
                $script:fileSummaries = @(
                    [pscustomobject]@{
                        Host = 'dc01.contoso.com'; Role = 'DC'
                        WindowFrom = '2026-09-01T00:00:00Z'; WindowTo = '2026-09-29T00:00:00Z'
                        Collectors = @{ ntlmUsage = 'ok'; ldapBinding = 'ok'; kerberos = 'ok'; domainHealth = 'ok'; outbound = 'ok' }
                        AuditMeasures = @{ ntlmv1 = 'Ok'; ntlm_8004 = 'Ok'; ntlm_4776 = 'Ok'; ldap_signing = 'Ok'; ldap_channel_binding = 'Ok'; kerberos_rc4_des = 'Ok'; missing_spn = 'Ok'; lockouts = 'Ok' }
                    }
                )
            }

            It 'geeft Groen voor een maatregel zonder findings' {
                $model = Resolve-HKReportModel -Findings @() -FileSummaries $script:fileSummaries -MinimumDays 28
                $model.MeasuredDays | Should -BeGreaterOrEqual 28
                ($model.Measures | Where-Object Measure -eq 'ntlmv1').Status | Should -Be 'Groen'
            }
        }

        Context 'Onbekend: te kort gemeten' {
            BeforeAll {
                $script:fileSummaries = @(
                    [pscustomobject]@{
                        Host = 'dc01.contoso.com'; Role = 'DC'
                        WindowFrom = '2026-09-25T00:00:00Z'; WindowTo = '2026-09-29T00:00:00Z'
                        Collectors = @{ ntlmUsage = 'ok' }
                        AuditMeasures = @{ ntlmv1 = 'Ok' }
                    }
                )
            }

            It 'geeft Onbekend als de meetperiode korter is dan MinimumDays' {
                $model = Resolve-HKReportModel -Findings @() -FileSummaries $script:fileSummaries -MinimumDays 28
                $model.MeasuredDays | Should -BeLessThan 28
                ($model.Measures | Where-Object Measure -eq 'ntlmv1').Status | Should -Be 'Onbekend'
            }
        }

        Context 'Onbekend: collector niet overal ok' {
            BeforeAll {
                $script:fileSummaries = @(
                    [pscustomobject]@{
                        Host = 'dc01.contoso.com'; Role = 'DC'
                        WindowFrom = '2026-09-01T00:00:00Z'; WindowTo = '2026-09-29T00:00:00Z'
                        Collectors = @{ ntlmUsage = 'ok' }
                        AuditMeasures = @{ ntlmv1 = 'Ok' }
                    }
                    [pscustomobject]@{
                        Host = 'dc02.contoso.com'; Role = 'DC'
                        WindowFrom = '2026-09-01T00:00:00Z'; WindowTo = '2026-09-29T00:00:00Z'
                        Collectors = @{ ntlmUsage = 'onbekend' }
                        AuditMeasures = @{ ntlmv1 = 'Ok' }
                    }
                )
            }

            It 'geeft Onbekend als één DC de collector niet kon lezen' {
                $model = Resolve-HKReportModel -Findings @() -FileSummaries $script:fileSummaries -MinimumDays 28
                ($model.Measures | Where-Object Measure -eq 'ntlmv1').Status | Should -Be 'Onbekend'
            }
        }

        Context 'Onbekend: auditvoorwaarde niet overal voldaan' {
            BeforeAll {
                $script:fileSummaries = @(
                    [pscustomobject]@{
                        Host = 'dc01.contoso.com'; Role = 'DC'
                        WindowFrom = '2026-09-01T00:00:00Z'; WindowTo = '2026-09-29T00:00:00Z'
                        Collectors = @{ ntlmUsage = 'ok' }
                        AuditMeasures = @{ ntlmv1 = 'NietVoldaan' }
                    }
                )
            }

            It 'geeft Onbekend als de auditvoorwaarde ergens niet voldaan is' {
                $model = Resolve-HKReportModel -Findings @() -FileSummaries $script:fileSummaries -MinimumDays 28
                ($model.Measures | Where-Object Measure -eq 'ntlmv1').Status | Should -Be 'Onbekend'
            }
        }

        Context 'Oranje: findings met een bekende, oplosbare oorzaak' {
            BeforeAll {
                $script:fileSummaries = @(
                    [pscustomobject]@{
                        Host = 'dc01.contoso.com'; Role = 'DC'
                        WindowFrom = '2026-09-01T00:00:00Z'; WindowTo = '2026-09-29T00:00:00Z'
                        Collectors = @{ kerberos = 'ok' }
                        AuditMeasures = @{ missing_spn = 'Ok' }
                    }
                )
                $script:findings = @(
                    [pscustomobject]@{ measure = 'missing_spn'; client = [pscustomobject]@{ fqdn = $null; ip = '10.0.0.30' }; account = [pscustomobject]@{ name = 'appsvc'; sid = $null }; target = 'HTTP/missingspn.contoso.com'; count = 3; firstSeen = '2026-09-10T06:00:00Z'; lastSeen = '2026-09-11T06:00:00Z' }
                )
            }

            It 'geeft Oranje met een oplosbare toelichting voor missing_spn' {
                $model = Resolve-HKReportModel -Findings $script:findings -FileSummaries $script:fileSummaries -MinimumDays 28
                $m = $model.Measures | Where-Object Measure -eq 'missing_spn'
                $m.Status | Should -Be 'Oranje'
                $m.Count | Should -Be 3
                $m.Reason | Should -Match 'SPN'
            }
        }

        Context 'Al stuk: netlogon_secure_channel met findings wint van Onbekend' {
            BeforeAll {
                # Opzettelijk te kort gemeten EN geen auditvoorwaarde (is er ook niet voor deze
                # maatregel) — Al stuk moet alsnog winnen, want het is nu al zichtbaar kapot.
                $script:fileSummaries = @(
                    [pscustomobject]@{
                        Host = 'dc01.contoso.com'; Role = 'DC'
                        WindowFrom = '2026-09-25T00:00:00Z'; WindowTo = '2026-09-26T00:00:00Z'
                        Collectors = @{ domainHealth = 'ok' }
                        AuditMeasures = @{}
                    }
                )
                $script:findings = @(
                    [pscustomobject]@{ measure = 'netlogon_secure_channel'; client = [pscustomobject]@{ fqdn = $null; ip = $null }; account = [pscustomobject]@{ name = 'OLDPC$'; sid = $null }; count = 10; firstSeen = '2026-09-25T06:00:00Z'; lastSeen = '2026-09-25T07:00:00Z' }
                )
            }

            It 'geeft AlStuk, ook al is de meetperiode te kort' {
                $model = Resolve-HKReportModel -Findings $script:findings -FileSummaries $script:fileSummaries -MinimumDays 28
                $m = $model.Measures | Where-Object Measure -eq 'netlogon_secure_channel'
                $m.Status | Should -Be 'AlStuk'
                $model.AlStuk.Measure | Should -Contain 'netlogon_secure_channel'
            }
        }

        Context 'Correlatie: missing_spn en ntlm_8004 op dezelfde genormaliseerde servicenaam' {
            BeforeAll {
                $script:fileSummaries = @(
                    [pscustomobject]@{
                        Host = 'dc01.contoso.com'; Role = 'DC'
                        WindowFrom = '2026-09-01T00:00:00Z'; WindowTo = '2026-09-29T00:00:00Z'
                        Collectors = @{ kerberos = 'ok'; ntlmUsage = 'ok' }
                        AuditMeasures = @{ missing_spn = 'Ok'; ntlm_8004 = 'Ok' }
                    }
                )
                $script:findings = @(
                    [pscustomobject]@{ measure = 'missing_spn'; client = [pscustomobject]@{ fqdn = $null; ip = '10.0.0.30' }; account = [pscustomobject]@{ name = 'appsvc'; sid = $null }; target = 'HTTP/fileserver.contoso.com'; count = 2; firstSeen = '2026-09-10T06:00:00Z'; lastSeen = '2026-09-10T06:05:00Z' }
                    [pscustomobject]@{ measure = 'ntlm_8004'; client = [pscustomobject]@{ fqdn = 'app01'; ip = $null }; account = [pscustomobject]@{ name = 'appsvc'; sid = $null }; target = 'fileserver.contoso.com'; isIpOrAlias = $false; count = 2; firstSeen = '2026-09-10T06:05:00Z'; lastSeen = '2026-09-10T06:10:00Z' }
                )
            }

            It 'herkent de correlatie tussen missing_spn en ntlm_8004' {
                $model = Resolve-HKReportModel -Findings $script:findings -FileSummaries $script:fileSummaries -MinimumDays 28
                $model.CorrelatedMissingSpn | Should -Contain 'HTTP/fileserver.contoso.com'
            }
        }

        Context 'Outbound-allowlist, gegroepeerd per proces' {
            BeforeAll {
                $script:fileSummaries = @(
                    [pscustomobject]@{
                        Host = 'dc01.contoso.com'; Role = 'DC'
                        WindowFrom = '2026-09-01T00:00:00Z'; WindowTo = '2026-09-29T00:00:00Z'
                        Collectors = @{ outbound = 'ok' }
                        AuditMeasures = @{}
                    }
                )
                $script:findings = @(
                    [pscustomobject]@{ measure = 'outbound'; client = [pscustomobject]@{ fqdn = 'update.microsoft.com'; ip = '20.0.0.1' }; account = [pscustomobject]@{ name = $null; sid = $null }; target = 'svchost'; count = 3; firstSeen = '2026-09-10T06:00:00Z'; lastSeen = '2026-09-10T06:00:00Z' }
                    [pscustomobject]@{ measure = 'outbound'; client = [pscustomobject]@{ fqdn = $null; ip = '10.0.0.5' }; account = [pscustomobject]@{ name = $null; sid = $null }; target = 'svchost'; count = 1; firstSeen = '2026-09-10T06:00:00Z'; lastSeen = '2026-09-10T06:00:00Z' }
                )
            }

            It 'groepeert outbound-bevindingen per proces, niet in de stoplight-lijst' {
                $model = Resolve-HKReportModel -Findings $script:findings -FileSummaries $script:fileSummaries -MinimumDays 28
                $model.Measures | Where-Object Measure -eq 'outbound' | Should -BeNullOrEmpty
                $model.Outbound.Count | Should -Be 1
                $model.Outbound[0].Process | Should -Be 'svchost'
                $model.Outbound[0].Destinations.Count | Should -Be 2
            }
        }

        Context 'DC-compleetheid' {
            It 'markeert een DC met genoeg dagbestanden als compleet' {
                $files = 1..28 | ForEach-Object {
                    [pscustomobject]@{ Host = 'dc01.contoso.com'; Role = 'DC'; WindowFrom = '2026-09-01T00:00:00Z'; WindowTo = '2026-09-29T00:00:00Z'; Collectors = @{}; AuditMeasures = @{} }
                }
                $model = Resolve-HKReportModel -Findings @() -FileSummaries $files -MinimumDays 28
                ($model.DcCompleteness | Where-Object Host -eq 'dc01.contoso.com').Complete | Should -BeTrue
            }

            It 'markeert een DC met te weinig dagbestanden als niet compleet' {
                $files = 1..5 | ForEach-Object {
                    [pscustomobject]@{ Host = 'dc02.contoso.com'; Role = 'DC'; WindowFrom = '2026-09-01T00:00:00Z'; WindowTo = '2026-09-06T00:00:00Z'; Collectors = @{}; AuditMeasures = @{} }
                }
                $model = Resolve-HKReportModel -Findings @() -FileSummaries $files -MinimumDays 28
                ($model.DcCompleteness | Where-Object Host -eq 'dc02.contoso.com').Complete | Should -BeFalse
            }
        }
    }

    Describe 'ConvertTo-HKReportHtml' {
        BeforeAll {
            # De accountnaam bevat een complete </script><script>-payload: dit test niet alleen
            # HTML-encoding van de zichtbare tabel, maar ook dat de JSON-data-island (die de
            # ruwe waarde legitiem als JSON-string bevat) niet voortijdig kan sluiten — zie
            # ConvertTo-HKReportHtml en docs/LESSONS.md.
            $script:maliciousName = 'appsvc</script><script>alert(1)</script>'
            $script:model = Resolve-HKReportModel -Findings @(
                [pscustomobject]@{ measure = 'missing_spn'; client = [pscustomobject]@{ fqdn = $null; ip = '10.0.0.30' }; account = [pscustomobject]@{ name = $script:maliciousName; sid = $null }; target = 'HTTP/x'; count = 1; firstSeen = '2026-09-10T06:00:00Z'; lastSeen = '2026-09-10T06:00:00Z' }
            ) -FileSummaries @(
                [pscustomobject]@{ Host = 'dc01.contoso.com'; Role = 'DC'; WindowFrom = '2026-09-01T00:00:00Z'; WindowTo = '2026-09-29T00:00:00Z'; Collectors = @{ kerberos = 'ok' }; AuditMeasures = @{ missing_spn = 'Ok' } }
            ) -MinimumDays 28
        }

        It 'produceert geldige, zelfstandige HTML zonder externe resources' {
            $html = ConvertTo-HKReportHtml -Model $script:model -ClientCode 'KLANT01' -GeneratedAtUtc (Get-Date).ToUniversalTime()
            $html | Should -Match '<!DOCTYPE html>'
            $html | Should -Match 'KLANT01'
            $html | Should -Not -Match '<script src='
            $html | Should -Not -Match 'https?://'
        }

        It 'HTML-encodeert waarden uit findingdata in de zichtbare tabellen' {
            $html = ConvertTo-HKReportHtml -Model $script:model -ClientCode 'KLANT01' -GeneratedAtUtc (Get-Date).ToUniversalTime()
            $html | Should -Match '<td>appsvc&lt;/script&gt;&lt;script&gt;alert\(1\)&lt;/script&gt;</td>'
        }

        It 'laat de payload in de JSON-data-island de scripttag niet voortijdig sluiten' {
            $html = ConvertTo-HKReportHtml -Model $script:model -ClientCode 'KLANT01' -GeneratedAtUtc (Get-Date).ToUniversalTime()
            # Elke letterlijke "</script" (zonder backslash-escape) moet onze eigen, bedoelde
            # sluit-tag zijn — niet een uit de findingdata afkomstige die de JSON-island vroegtijdig
            # zou kunnen afbreken.
            $unescapedCloses = [regex]::Matches($html, '(?<!\\)</script').Count
            $unescapedCloses | Should -Be 1
        }

        It 'bevat de ruwe data als JSON in de pagina' {
            $html = ConvertTo-HKReportHtml -Model $script:model -ClientCode 'KLANT01' -GeneratedAtUtc (Get-Date).ToUniversalTime()
            $html | Should -Match '<script type="application/json" id="hk-data">'
        }

        It 'serialiseert Findings als een array in de JSON-data, ook bij precies 1 finding (regressietest)' {
            # Eerder gaf een ongewrapte if/else in Resolve-HKReportModel hier een kaal object
            # i.p.v. een 1-element array — zie docs/LESSONS.md.
            $html = ConvertTo-HKReportHtml -Model $script:model -ClientCode 'KLANT01' -GeneratedAtUtc (Get-Date).ToUniversalTime()
            $jsonMatch = [regex]::Match($html, '(?s)<script type="application/json" id="hk-data">\r?\n(.*)\r?\n</script>')
            $jsonMatch.Success | Should -BeTrue
            $parsed = $jsonMatch.Groups[1].Value | ConvertFrom-Json

            $missingSpn = $parsed.Measures | Where-Object Measure -eq 'missing_spn'
            $missingSpn.Findings.GetType().IsArray | Should -BeTrue
            @($missingSpn.Findings).Count | Should -Be 1
        }
    }
}

Describe 'New-HKReport' {

    Context 'echte dagbestanden op schijf' {

        BeforeAll {
            $script:inputPath = Join-Path $TestDrive 'input1'
            New-Item -Path $script:inputPath -ItemType Directory -Force | Out-Null
            $script:outputFile = Join-Path $TestDrive 'report1.html'

            $baseDay = [datetime]'2026-09-01T00:00:00Z'

            for ($i = 0; $i -lt 30; $i++) {
                $day = $baseDay.AddDays($i)
                $windowFrom = $day.ToString('yyyy-MM-ddTHH:mm:ssZ')
                $windowTo = $day.AddDays(1).ToString('yyyy-MM-ddTHH:mm:ssZ')

                $findings = @()
                if ($i -eq 10) {
                    $findings = @(
                        @{ measure = 'missing_spn'; client = @{ fqdn = $null; ip = '10.0.0.30' }; account = @{ name = 'appsvc'; sid = $null }; target = 'HTTP/fileserver.contoso.com'; count = 2; firstSeen = $windowFrom; lastSeen = $windowTo }
                    )
                }

                $data = [ordered]@{
                    schema        = '1.0'
                    client        = 'KLANT01'
                    host          = 'dc01.contoso.com'
                    role          = 'DC'
                    moduleVersion = '0.1.0'
                    window        = @{ from = $windowFrom; to = $windowTo }
                    collectors    = @{ auditConfig = 'ok'; baseline = 'ok'; ntlmUsage = 'ok'; ldapBinding = 'ok'; kerberos = 'ok'; domainHealth = 'ok'; outbound = 'ok' }
                    auditConfig   = @{ Measures = @(@{ Measure = 'missing_spn'; Status = 'Ok' }) }
                    baseline      = @{}
                    findings      = $findings
                    dailySummaries = @{ ldapSigning = @(); ldapChannelBinding = @(); unknownSubnets = @() }
                }

                $fileName = "KLANT01_dc01.contoso.com_$($day.ToString('yyyyMMdd')).json"
                $data | ConvertTo-Json -Depth 10 | Set-Content -Path (Join-Path $script:inputPath $fileName) -Encoding UTF8
            }

            # Statusbestand: moet overgeslagen worden, niet als dagbestand gelezen.
            '{"lastSecurityRecordId": 1}' | Set-Content -Path (Join-Path $script:inputPath 'KLANT01_dc01.contoso.com.state.json') -Encoding UTF8
        }

        It 'schrijft een HTML-rapport' {
            $result = New-HKReport -InputPath $script:inputPath -OutputPath $script:outputFile
            Test-Path $script:outputFile | Should -BeTrue
            $result.FilesRead | Should -Be 30
        }

        It 'negeert het statusbestand' {
            $result = New-HKReport -InputPath $script:inputPath -OutputPath $script:outputFile
            $result.FilesRead | Should -Be 30
        }

        It 'berekent Oranje voor missing_spn met het juiste aantal' {
            $result = New-HKReport -InputPath $script:inputPath -OutputPath $script:outputFile
            $m = $result.Model.Measures | Where-Object Measure -eq 'missing_spn'
            $m.Status | Should -Be 'Oranje'
            $m.Count | Should -Be 2
        }

        It 'bevat KLANT01 en de bevinding in de HTML' {
            New-HKReport -InputPath $script:inputPath -OutputPath $script:outputFile | Out-Null
            $html = Get-Content -Path $script:outputFile -Raw
            $html | Should -Match 'KLANT01'
            $html | Should -Match 'appsvc'
        }
    }

    Context 'onbekende schemaversie wordt overgeslagen' {

        BeforeAll {
            $script:inputPath2 = Join-Path $TestDrive 'input2'
            New-Item -Path $script:inputPath2 -ItemType Directory -Force | Out-Null
            $script:outputFile2 = Join-Path $TestDrive 'report2.html'

            $good = [ordered]@{
                schema = '1.0'; client = 'KLANT01'; host = 'dc01.contoso.com'; role = 'DC'; moduleVersion = '0.1.0'
                window = @{ from = '2026-09-01T00:00:00Z'; to = '2026-09-02T00:00:00Z' }
                collectors = @{}; auditConfig = @{ Measures = @() }; baseline = @{}; findings = @()
                dailySummaries = @{ ldapSigning = @(); ldapChannelBinding = @(); unknownSubnets = @() }
            }
            $bad = [ordered]@{ schema = '9.9'; client = 'KLANT01'; host = 'dc01.contoso.com'; role = 'DC' }

            $good | ConvertTo-Json -Depth 10 | Set-Content -Path (Join-Path $script:inputPath2 'KLANT01_dc01.contoso.com_20260901.json') -Encoding UTF8
            $bad | ConvertTo-Json -Depth 10 | Set-Content -Path (Join-Path $script:inputPath2 'KLANT01_dc01.contoso.com_20260902.json') -Encoding UTF8
        }

        It 'leest alleen het bestand met de bekende schemaversie' {
            $result = New-HKReport -InputPath $script:inputPath2 -OutputPath $script:outputFile2 -WarningAction SilentlyContinue
            $result.FilesRead | Should -Be 1
            $result.FilesSkipped | Should -Contain 'KLANT01_dc01.contoso.com_20260902.json'
        }
    }

    Context 'geen dagbestanden' {
        It 'gooit een duidelijke fout als InputPath geen JSON-bestanden bevat' {
            $emptyPath = Join-Path $TestDrive 'empty'
            New-Item -Path $emptyPath -ItemType Directory -Force | Out-Null
            { New-HKReport -InputPath $emptyPath -OutputPath (Join-Path $TestDrive 'report3.html') } | Should -Throw
        }

        It 'gooit een duidelijke fout als InputPath niet bestaat' {
            { New-HKReport -InputPath (Join-Path $TestDrive 'bestaat-niet') -OutputPath (Join-Path $TestDrive 'report4.html') } | Should -Throw
        }
    }
}
