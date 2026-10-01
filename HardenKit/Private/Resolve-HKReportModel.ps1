function Resolve-HKReportModel {
    <#
    .SYNOPSIS
        Berekent het volledige rapportmodel (status per maatregel, "al stuk", correlaties,
        outbound-allowlist) uit samengevoegde data van meerdere dagbestanden/DC's.

    .DESCRIPTION
        De "brein"-functie van New-HKReport, bewust gescheiden van het lezen van bestanden en
        het wegschrijven van HTML (zie docs/LESSONS.md: I/O-laag los van pure logica). Bepaalt
        per maatregel de status (Ok/NietVoldaan/Onbekend/AlStuk) volgens de PRD-regels:
          - Onbekend als de onderliggende collector niet overal 'ok' was, de benodigde
            auditinstelling niet overal aanstond, of de gemeten periode korter is dan
            -MinimumDays.
          - AlStuk voor netlogon_secure_channel/cert_mapping/replication zodra er bevindingen
            zijn — dit wint van Onbekend, want een gezien probleem is harder bewijs dan een
            onvolledige meting.
          - Groen als er geen bevindingen zijn (en aan de voorwaarden hierboven voldaan is).
          - Oranje als er bevindingen zijn. Fase 0 bepaalt NIET automatisch Rood (dat vereist
            mensenkennis van welke bron "oude apparatuur/leverancier" is, zie PRD) — elke
            maatregel met bevindingen krijgt Oranje met een duidelijke actie, en voor
            missing_spn/IsIpOrAlias-gevallen een specifiek oplosbare fix; voor de rest een
            notitie dat een engineer beoordeelt of de bron vervangbaar is (en zo niet, handmatig
            naar Rood zet).

        Correlatieregels (fase 0, zie PRD):
          - NTLM-fallback door ontbrekende SPN: een missing_spn-finding voor service S en een
            ntlm_8004-finding met Target gelijk aan (het servicedeel van) S worden gekoppeld.
            Vereenvoudiging: matcht alleen op de genormaliseerde servicenaam, niet ook op
            dezelfde client — 4769 geeft een client-IP, 8004 een workstation-naam, en die twee
            velden zijn niet betrouwbaar met elkaar te vergelijken zonder DNS-resolutie (zie
            docs/LESSONS.md).
          - NTLM naar IP of alias: ntlm_8004-findings met IsIpOrAlias=true worden apart
            gemarkeerd (de vlag komt al uit Get-HKNtlmUsage).
          - "Eén oorzaak, meerdere effecten" (NTLM-volume + Netlogon-verzadiging; tijdsafwijking
            + Kerberos-fouten): in fase 0 alleen als tekstuele notitie bij de betrokken
            maatregelen, geen echte samenvoeging tot one finding — dat vereist fijnmazige
            tijdreeks-correlatie die nu niet is gebouwd. Expliciet gedocumenteerd gat.

    .PARAMETER Findings
        Gemergede findingregels (output van Merge-HKFindings) over alle maatregelen.

    .PARAMETER FileSummaries
        Eén item per gelezen dagbestand: Host, Role, WindowFrom, WindowTo, Collectors
        (hashtable collectorsleutel -> 'ok'/'onbekend'), AuditMeasures (hashtable
        maatregelnaam -> Status uit Test-HKAuditConfig).

    .PARAMETER MinimumDays
        Minimaal aantal gemeten dagen voor een niet-Onbekend stoplight-status.

    .PARAMETER MissingSpnThreshold
        Drempel (aantal) voor losse missing_spn-bevindingen zonder gekoppeld NTLM-verkeer,
        voordat ze als vermeldenswaardig gemarkeerd worden. Voorlopige default; PRD noemt de
        exacte drempelwaarde nog als open vraag.

    .PARAMETER LockoutThreshold
        Zelfde, voor lockouts. Voorlopige default.

    .OUTPUTS
        PSCustomObject met MeasuredFrom, MeasuredTo, MeasuredDays, DcCompleteness,
        Measures (per-maatregel resultaten), AlStuk (subset met status AlStuk), Outbound
        (allowlist-voorstel per proces).

    .NOTES
        Fase 0. Pure functie, geen I/O.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [psobject[]]$Findings,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [psobject[]]$FileSummaries,

        [int]$MinimumDays = 28,
        [int]$MissingSpnThreshold = 5,
        [int]$LockoutThreshold = 5
    )

    $measureDefs = @(
        [pscustomobject]@{ Measure = 'ntlmv1'; Label = 'NTLMv1 / LM'; Category = 'Stoplight'; CollectorKey = 'ntlmUsage'; Action = 'NTLMv1 uitfaseren op de genoemde apparaten/accounts (LmCompatibilityLevel verhogen).' }
        [pscustomobject]@{ Measure = 'ntlm_8004'; Label = 'NTLM-gebruik (algemeen)'; Category = 'Stoplight'; CollectorKey = 'ntlmUsage'; Action = 'Voor bindingen naar IP/alias: verbinden op servernaam of SPN voor de alias registreren. Overige bindingen per geval beoordelen.' }
        [pscustomobject]@{ Measure = 'ntlm_4776'; Label = 'NTLM credential validation'; Category = 'Stoplight'; CollectorKey = 'ntlmUsage'; Action = 'Bron van de NTLM-credentialvalidatie identificeren en waar mogelijk naar Kerberos migreren.' }
        [pscustomobject]@{ Measure = 'ldap_signing'; Label = 'LDAP signing (unsigned/simple bind)'; Category = 'Stoplight'; CollectorKey = 'ldapBinding'; Action = 'Genoemde clients/accounts overzetten op gesigned LDAP.' }
        [pscustomobject]@{ Measure = 'ldap_channel_binding'; Label = 'LDAP channel binding'; Category = 'Stoplight'; CollectorKey = 'ldapBinding'; Action = 'Genoemde clients updaten/configureren voor channel binding-ondersteuning.' }
        [pscustomobject]@{ Measure = 'kerberos_rc4_des'; Label = 'Kerberos RC4/DES'; Category = 'Stoplight'; CollectorKey = 'kerberos'; Action = 'RC4/DES uitfaseren op de genoemde accounts/services (msDS-SupportedEncryptionTypes).' }
        [pscustomobject]@{ Measure = 'missing_spn'; Label = 'Ontbrekende SPN (NTLM-fallback)'; Category = 'Stoplight'; CollectorKey = 'kerberos'; Action = 'De ontbrekende SPN registreren op het juiste account (setspn -S).' }
        [pscustomobject]@{ Measure = 'duplicate_spn'; Label = 'Dubbele SPN'; Category = 'Stoplight'; CollectorKey = 'kerberos'; Action = 'De dubbele SPN-registratie opschonen (controleren met setspn -X, dan verwijderen van het onjuiste account).' }
        [pscustomobject]@{ Measure = 'netlogon_saturation'; Label = 'Netlogon-verzadiging'; Category = 'Stoplight'; CollectorKey = 'domainHealth'; Action = 'Oorzaak van de NTLM-belasting identificeren en verminderen.' }
        [pscustomobject]@{ Measure = 'lockouts'; Label = 'Lockouts / mislukte logons'; Category = 'Stoplight'; CollectorKey = 'domainHealth'; Action = 'Bron van de lockouts/foute wachtwoorden (genoemde client/account) onderzoeken.' }
        [pscustomobject]@{ Measure = 'time_sync'; Label = 'Tijdsynchronisatie'; Category = 'Stoplight'; CollectorKey = 'domainHealth'; Action = 'Tijdbron van de PDC-emulator controleren (zie Get-HKBaseline) en W32Time-configuratie herstellen.' }
        [pscustomobject]@{ Measure = 'netlogon_secure_channel'; Label = 'Netlogon secure channel geweigerd'; Category = 'AlStuk'; CollectorKey = 'domainHealth'; Action = 'Machineaccount van de genoemde apparaten resetten, of apparaat vervangen als het geweigerd blijft.' }
        [pscustomobject]@{ Measure = 'cert_mapping'; Label = 'Zwakke certificaatmapping'; Category = 'AlStuk'; CollectorKey = 'kerberos'; Action = 'Certificaatmapping van de genoemde accounts herzien (altSecurityIdentities, sterke mapping).' }
        [pscustomobject]@{ Measure = 'replication'; Label = 'AD-replicatiefouten'; Category = 'AlStuk'; CollectorKey = 'domainHealth'; Action = "Replicatiefouten onderzoeken met 'repadmin /showrepl' op de betrokken DC's." }
    )

    # --- Gemeten periode: vroegste window.from tot laatste window.to over alle DC-bestanden. ---
    $dcFiles = @($FileSummaries | Where-Object Role -eq 'DC')
    $windowFroms = @($dcFiles | Where-Object { $_.WindowFrom } | ForEach-Object { [datetime]$_.WindowFrom })
    $windowTos = @($dcFiles | Where-Object { $_.WindowTo } | ForEach-Object { [datetime]$_.WindowTo })

    $measuredFrom = if ($windowFroms.Count -gt 0) { ($windowFroms | Measure-Object -Minimum).Minimum } elseif ($windowTos.Count -gt 0) { ($windowTos | Measure-Object -Minimum).Minimum } else { $null }
    $measuredTo = if ($windowTos.Count -gt 0) { ($windowTos | Measure-Object -Maximum).Maximum } else { $null }
    $measuredDays = if ($measuredFrom -and $measuredTo) { [math]::Round(($measuredTo - $measuredFrom).TotalDays) } else { 0 }

    # --- Per-DC compleetheid: proxy = aantal dagbestanden >= MinimumDays (zie docs/LESSONS.md). ---
    $dcCompleteness = @(
        $dcFiles | Group-Object -Property Host | ForEach-Object {
            $filesForHost = $_.Group
            [pscustomobject]@{
                Host          = $_.Name
                DaysObserved  = $filesForHost.Count
                Complete      = $filesForHost.Count -ge $MinimumDays
            }
        }
    )

    # --- Per-collector en per-maatregel-audit compleetheid over alle DC-bestanden. ---
    $collectorOk = @{}
    foreach ($file in $dcFiles) {
        foreach ($key in $file.Collectors.Keys) {
            if (-not $collectorOk.ContainsKey($key)) { $collectorOk[$key] = $true }
            if ($file.Collectors[$key] -ne 'ok') { $collectorOk[$key] = $false }
        }
    }

    $auditOk = @{}
    $auditSeen = @{}
    foreach ($file in $dcFiles) {
        foreach ($key in $file.AuditMeasures.Keys) {
            $auditSeen[$key] = $true
            if (-not $auditOk.ContainsKey($key)) { $auditOk[$key] = $true }
            if ($file.AuditMeasures[$key] -ne 'Ok') { $auditOk[$key] = $false }
        }
    }

    # --- Findings per maatregel groeperen. ---
    $findingsByMeasure = @{}
    foreach ($f in $Findings) {
        if (-not $findingsByMeasure.ContainsKey($f.measure)) { $findingsByMeasure[$f.measure] = [System.Collections.Generic.List[psobject]]::new() }
        $findingsByMeasure[$f.measure].Add($f)
    }

    # --- Correlatie: missing_spn <-> ntlm_8004 (genormaliseerde servicenaam, via
    # ConvertTo-HKNormalizedSpnTarget). Zie .DESCRIPTION voor de vereenvoudiging t.o.v. de
    # letterlijke PRD-regel (geen client-matching). ---
    $ntlm8004Targets = @{}
    $ntlm8004FindingsForCorrelation = @(if ($findingsByMeasure.ContainsKey('ntlm_8004')) { @($findingsByMeasure['ntlm_8004']) } else { @() })
    foreach ($f in $ntlm8004FindingsForCorrelation) {
        $norm = ConvertTo-HKNormalizedSpnTarget -Value $f.target
        if ($norm) { $ntlm8004Targets[$norm] = $true }
    }

    $correlatedMissingSpn = [System.Collections.Generic.List[string]]::new()
    $missingSpnFindingsForCorrelation = @(if ($findingsByMeasure.ContainsKey('missing_spn')) { @($findingsByMeasure['missing_spn']) } else { @() })
    foreach ($f in $missingSpnFindingsForCorrelation) {
        $norm = ConvertTo-HKNormalizedSpnTarget -Value $f.target
        if ($norm -and $ntlm8004Targets.ContainsKey($norm)) {
            $correlatedMissingSpn.Add($f.target)
        }
    }

    # --- Status per maatregel bepalen. ---
    $measures = foreach ($def in $measureDefs) {
        # Niet @($findingsByMeasure[$def.Measure]) direct: een ontbrekende hashtable-key geeft
        # $null terug, en @($null) is een array mét één $null-element, niet leeg (zie
        # docs/LESSONS.md). Eerst expliciet op het bestaan van de key checken, én het hele
        # if/else-blok met @(...) omwikkelen — anders unwrapt de if/else-expressie zelf een
        # 0- of 1-element array weer (dezelfde les, zie ook Export-HKData).
        $findingsForMeasure = @(if ($findingsByMeasure.ContainsKey($def.Measure)) { @($findingsByMeasure[$def.Measure]) } else { @() })
        $count = if ($findingsForMeasure.Count -gt 0) { ($findingsForMeasure | Measure-Object -Property count -Sum).Sum } else { 0 }

        $thisCollectorOk = if ($collectorOk.ContainsKey($def.CollectorKey)) { $collectorOk[$def.CollectorKey] } else { $false }
        $thisAuditOk = if ($auditSeen.ContainsKey($def.Measure)) { $auditOk[$def.Measure] } else { $true }

        $status = $null
        $reason = $null

        if (-not $thisCollectorOk) {
            $status = 'Onbekend'
            $reason = 'De onderliggende bron kon niet overal betrouwbaar gelezen worden.'
        }
        elseif (-not $thisAuditOk) {
            $status = 'Onbekend'
            $reason = 'De benodigde auditinstelling stond niet overal aan.'
        }
        elseif ($def.Category -eq 'Stoplight' -and $measuredDays -lt $MinimumDays) {
            $status = 'Onbekend'
            $reason = "Minder dan $MinimumDays dagen gemeten ($measuredDays dagen)."
        }
        elseif ($def.Category -eq 'AlStuk' -and $findingsForMeasure.Count -gt 0) {
            $status = 'AlStuk'
            $reason = 'Er zijn al weigeringen/fouten gezien — dit speelt nu al, los van de meetperiode.'
        }
        elseif ($findingsForMeasure.Count -eq 0) {
            $status = 'Groen'
            $reason = 'Geen gebruik gezien in de meetperiode.'
        }
        else {
            $status = 'Oranje'
            if ($def.Measure -eq 'missing_spn') {
                $reason = 'Ontbrekende SPN gezien — oplosbaar door de SPN te registreren.'
            }
            elseif ($def.Measure -eq 'ntlm_8004') {
                $ipOrAliasCount = @($findingsForMeasure | Where-Object { $_.PSObject.Properties.Match('isIpOrAlias').Count -gt 0 -and $_.isIpOrAlias }).Count
                $reason = if ($ipOrAliasCount -gt 0) { "$ipOrAliasCount van de $($findingsForMeasure.Count) bindingen gaan naar een IP-adres of alias — oplosbaar." } else { 'Gebruik gezien; per bron beoordelen.' }
            }
            else {
                $reason = 'Gebruik gezien. Beoordeel of de genoemde bronnen vervangbaar zijn; zo niet, markeer deze maatregel handmatig als Rood.'
            }
        }

        [pscustomobject]@{
            Measure   = $def.Measure
            Label     = $def.Label
            Category  = $def.Category
            Status    = $status
            Reason    = $reason
            Action    = $def.Action
            Count     = $count
            Findings  = $findingsForMeasure
        }
    }

    $measures = @($measures)

    # "Eén oorzaak, meerdere effecten": lichte tekstuele notitie, geen echte samenvoeging (zie
    # .DESCRIPTION — fijnmazige tijdreeks-correlatie is een gedocumenteerd gat in fase 0).
    $ntlmVolumeMeasures = @('ntlmv1', 'ntlm_8004', 'ntlm_4776')
    $hasNtlmVolume = @($measures | Where-Object { $_.Measure -in $ntlmVolumeMeasures -and $_.Count -gt 0 }).Count -gt 0
    $saturationMeasure = $measures | Where-Object Measure -eq 'netlogon_saturation'
    if ($saturationMeasure -and $saturationMeasure.Count -gt 0 -and $hasNtlmVolume) {
        $saturationMeasure.Reason += ' Let op: valt samen met NTLM-volume (ntlmv1/ntlm_8004/ntlm_4776) in dezelfde periode — mogelijk dezelfde oorzaak, niet geverifieerd op tijdstip-niveau.'
    }

    $alStuk = @($measures | Where-Object Status -eq 'AlStuk')

    # --- Outbound-allowlist: aparte sectie, niet in de stoplight-tabel (zie PRD-rapportsectie). ---
    $outboundFindings = @(if ($findingsByMeasure.ContainsKey('outbound')) { @($findingsByMeasure['outbound']) } else { @() })
    $outbound = @(
        $outboundFindings | Group-Object -Property target | ForEach-Object {
            [pscustomobject]@{
                Process      = $_.Name
                Destinations = @($_.Group | ForEach-Object {
                        [pscustomobject]@{ Fqdn = $_.client.fqdn; Ip = $_.client.ip; Count = $_.count }
                    })
            }
        }
    )

    [pscustomobject]@{
        MeasuredFrom         = $measuredFrom
        MeasuredTo           = $measuredTo
        MeasuredDays         = $measuredDays
        MinimumDays          = $MinimumDays
        DcCompleteness       = $dcCompleteness
        Measures             = @($measures | Where-Object Measure -ne 'outbound')
        AlStuk               = $alStuk
        Outbound             = $outbound
        CorrelatedMissingSpn = @($correlatedMissingSpn)
    }
}
