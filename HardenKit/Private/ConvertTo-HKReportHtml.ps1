function ConvertTo-HKReportHtml {
    <#
    .SYNOPSIS
        Rendert het rapportmodel (Resolve-HKReportModel) naar een zelfstandige HTML-pagina.

    .DESCRIPTION
        Bouwt één offline-werkend HTML-bestand: inline CSS, geen externe scripts/fonts, geen
        JavaScript nodig voor de werking (in/uitklappen van technische details gebeurt met
        native <details>/<summary>-elementen). De ruwe data staat ook als JSON in de pagina
        (<script type="application/json">), zodat technische lezers die kunnen inspecteren.
        Elke waarde die uit AD/eventdata komt, gaat door ConvertTo-HKHtmlEncoded — zie die
        functie voor waarom.

    .PARAMETER Model
        Het rapportmodel van Resolve-HKReportModel.

    .PARAMETER ClientCode
        Klantcode voor de titel/kop van het rapport.

    .PARAMETER GeneratedAtUtc
        Tijdstip van genereren (UTC), getoond in de kop.

    .OUTPUTS
        String (de volledige HTML-pagina).

    .NOTES
        Fase 0. Pure functie, geen I/O (schrijven naar schijf gebeurt in New-HKReport zelf).
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [psobject]$Model,

        [Parameter(Mandatory)]
        [string]$ClientCode,

        [Parameter(Mandatory)]
        [datetime]$GeneratedAtUtc
    )

    $enc = { param($v) ConvertTo-HKHtmlEncoded -Value $v }

    $statusLabels = @{
        Groen    = 'Groen — kan dicht'
        Oranje   = 'Oranje — kan dicht na fixes'
        Rood     = 'Rood — breekt nu'
        Onbekend = 'Onbekend'
        AlStuk   = 'Al stuk'
    }

    function Format-HKUtc {
        param($Value)
        if (-not $Value) { return '—' }
        ([datetime]$Value).ToString('yyyy-MM-dd HH:mm') + ' UTC'
    }

    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.AppendLine('<!DOCTYPE html>')
    [void]$sb.AppendLine('<html lang="nl">')
    [void]$sb.AppendLine('<head>')
    [void]$sb.AppendLine('<meta charset="utf-8">')
    [void]$sb.AppendLine('<meta name="viewport" content="width=device-width, initial-scale=1">')
    [void]$sb.AppendLine("<title>HardenKit-rapport — $(& $enc $ClientCode)</title>")
    [void]$sb.AppendLine(@'
<style>
  :root {
    --hk-groen: #2e7d32; --hk-groen-bg: #e8f5e9;
    --hk-oranje: #e65100; --hk-oranje-bg: #fff3e0;
    --hk-rood: #b71c1c; --hk-rood-bg: #ffebee;
    --hk-onbekend: #616161; --hk-onbekend-bg: #f5f5f5;
    --hk-alstuk: #880e4f; --hk-alstuk-bg: #fce4ec;
    --hk-fg: #1b1b1b; --hk-bg: #ffffff; --hk-border: #dddddd;
  }
  body { font-family: -apple-system, Segoe UI, Arial, sans-serif; color: var(--hk-fg); background: var(--hk-bg); margin: 0; padding: 0 1.5rem 3rem; max-width: 60rem; }
  header { padding: 1.5rem 0 1rem; border-bottom: 2px solid var(--hk-border); margin-bottom: 1.5rem; }
  h1 { margin: 0 0 0.25rem; font-size: 1.6rem; }
  h2 { margin-top: 2.5rem; border-bottom: 1px solid var(--hk-border); padding-bottom: 0.25rem; }
  table { border-collapse: collapse; width: 100%; margin: 0.75rem 0 1.5rem; }
  th, td { text-align: left; padding: 0.4rem 0.6rem; border-bottom: 1px solid var(--hk-border); font-size: 0.92rem; }
  th { background: #fafafa; }
  .hk-badge { display: inline-block; padding: 0.15rem 0.6rem; border-radius: 1rem; font-weight: 600; font-size: 0.85rem; }
  .hk-badge-groen { color: var(--hk-groen); background: var(--hk-groen-bg); }
  .hk-badge-oranje { color: var(--hk-oranje); background: var(--hk-oranje-bg); }
  .hk-badge-rood { color: var(--hk-rood); background: var(--hk-rood-bg); }
  .hk-badge-onbekend { color: var(--hk-onbekend); background: var(--hk-onbekend-bg); }
  .hk-badge-alstuk { color: var(--hk-alstuk); background: var(--hk-alstuk-bg); }
  details { margin: 0.5rem 0; border: 1px solid var(--hk-border); border-radius: 0.3rem; padding: 0.5rem 0.75rem; }
  summary { cursor: pointer; font-weight: 600; }
  .hk-alstuk-section { border: 2px solid var(--hk-alstuk); background: var(--hk-alstuk-bg); border-radius: 0.4rem; padding: 0.75rem 1rem; margin-bottom: 1rem; }
  .hk-muted { color: #666; font-size: 0.9rem; }
  code { background: #f2f2f2; padding: 0.1rem 0.3rem; border-radius: 0.2rem; }
</style>
'@)
    [void]$sb.AppendLine('</head>')
    [void]$sb.AppendLine('<body>')

    # --- Kop ---
    [void]$sb.AppendLine('<header>')
    [void]$sb.AppendLine("<h1>HardenKit-rapport — $(& $enc $ClientCode)</h1>")
    [void]$sb.AppendLine("<p class=`"hk-muted`">Gegenereerd: $(Format-HKUtc $GeneratedAtUtc)</p>")
    $periodText = if ($Model.MeasuredFrom -and $Model.MeasuredTo) {
        "$(Format-HKUtc $Model.MeasuredFrom) – $(Format-HKUtc $Model.MeasuredTo) ($($Model.MeasuredDays) dagen)"
    }
    else {
        'onbekend (geen volledige meetvensters gevonden)'
    }
    $periodWarning = if ($Model.MeasuredDays -lt $Model.MinimumDays) { " <strong>Let op: minder dan $($Model.MinimumDays) dagen gemeten.</strong>" } else { '' }
    [void]$sb.AppendLine("<p>Gemeten periode: $periodText.$periodWarning</p>")
    [void]$sb.AppendLine('</header>')

    # --- DC-compleetheid ---
    [void]$sb.AppendLine('<section id="dc-completeness">')
    [void]$sb.AppendLine('<h2>DC&#39;s met complete data</h2>')
    if ($Model.DcCompleteness.Count -eq 0) {
        [void]$sb.AppendLine('<p class="hk-muted">Geen DC-data gevonden in de aangeleverde bestanden.</p>')
    }
    else {
        [void]$sb.AppendLine('<table><tr><th>DC</th><th>Dagen met data</th><th>Compleet (&gt;= minimum)</th></tr>')
        foreach ($dc in $Model.DcCompleteness) {
            $completeLabel = if ($dc.Complete) { 'Ja' } else { 'Nee' }
            [void]$sb.AppendLine("<tr><td>$(& $enc $dc.Host)</td><td>$($dc.DaysObserved)</td><td>$completeLabel</td></tr>")
        }
        [void]$sb.AppendLine('</table>')
    }
    [void]$sb.AppendLine('</section>')

    # --- Al stuk ---
    [void]$sb.AppendLine('<section id="al-stuk">')
    [void]$sb.AppendLine('<h2>Al stuk — dit speelt nu al</h2>')
    if ($Model.AlStuk.Count -eq 0) {
        [void]$sb.AppendLine('<p class="hk-muted">Geen actieve weigeringen/fouten gezien.</p>')
    }
    else {
        foreach ($m in $Model.AlStuk) {
            [void]$sb.AppendLine('<div class="hk-alstuk-section">')
            [void]$sb.AppendLine("<strong>$(& $enc $m.Label)</strong> — $(& $enc $m.Reason)<br>")
            [void]$sb.AppendLine("<span class=`"hk-muted`">Actie: $(& $enc $m.Action)</span>")
            [void]$sb.AppendLine('<table><tr><th>Account</th><th>Client (FQDN/IP)</th><th>Doel</th><th>Aantal</th><th>Eerst</th><th>Laatst</th></tr>')
            foreach ($row in $m.Findings) {
                $clientText = @($row.client.fqdn, $row.client.ip) | Where-Object { $_ } | Select-Object -First 1
                [void]$sb.AppendLine("<tr><td>$(& $enc $row.account.name)</td><td>$(& $enc $clientText)</td><td>$(& $enc $row.target)</td><td>$($row.count)</td><td>$(Format-HKUtc $row.firstSeen)</td><td>$(Format-HKUtc $row.lastSeen)</td></tr>")
            }
            [void]$sb.AppendLine('</table>')
            [void]$sb.AppendLine('</div>')
        }
    }
    [void]$sb.AppendLine('</section>')

    # --- Stoplicht-overzicht ---
    [void]$sb.AppendLine('<section id="stoplight">')
    [void]$sb.AppendLine('<h2>Overzicht per maatregel</h2>')
    [void]$sb.AppendLine('<table><tr><th>Maatregel</th><th>Status</th><th>Aantal</th><th>Toelichting</th></tr>')
    foreach ($m in $Model.Measures) {
        $badgeClass = 'hk-badge-' + $m.Status.ToLowerInvariant()
        $badgeLabel = if ($statusLabels.ContainsKey($m.Status)) { $statusLabels[$m.Status] } else { $m.Status }
        [void]$sb.AppendLine("<tr><td>$(& $enc $m.Label)</td><td><span class=`"hk-badge $badgeClass`">$(& $enc $badgeLabel)</span></td><td>$($m.Count)</td><td>$(& $enc $m.Reason)</td></tr>")
    }
    [void]$sb.AppendLine('</table>')
    [void]$sb.AppendLine('</section>')

    # --- Details per maatregel ---
    [void]$sb.AppendLine('<section id="details">')
    [void]$sb.AppendLine('<h2>Details per maatregel</h2>')
    foreach ($m in $Model.Measures) {
        $badgeLabel = if ($statusLabels.ContainsKey($m.Status)) { $statusLabels[$m.Status] } else { $m.Status }
        [void]$sb.AppendLine('<details>')
        [void]$sb.AppendLine("<summary>$(& $enc $m.Label) — $(& $enc $badgeLabel) ($($m.Count))</summary>")
        [void]$sb.AppendLine("<p>$(& $enc $m.Reason)</p>")
        [void]$sb.AppendLine("<p><strong>Voorgestelde actie:</strong> $(& $enc $m.Action)</p>")
        if ($m.Findings.Count -gt 0) {
            [void]$sb.AppendLine('<table><tr><th>Account</th><th>Client (FQDN/IP)</th><th>Doel</th><th>Aantal</th><th>Eerst</th><th>Laatst</th></tr>')
            foreach ($row in $m.Findings) {
                $clientText = @($row.client.fqdn, $row.client.ip) | Where-Object { $_ } | Select-Object -First 1
                [void]$sb.AppendLine("<tr><td>$(& $enc $row.account.name)</td><td>$(& $enc $clientText)</td><td>$(& $enc $row.target)</td><td>$($row.count)</td><td>$(Format-HKUtc $row.firstSeen)</td><td>$(Format-HKUtc $row.lastSeen)</td></tr>")
            }
            [void]$sb.AppendLine('</table>')
        }
        else {
            [void]$sb.AppendLine('<p class="hk-muted">Geen bevindingen.</p>')
        }
        [void]$sb.AppendLine('</details>')
    }
    [void]$sb.AppendLine('</section>')

    # --- Outbound allowlist ---
    [void]$sb.AppendLine('<section id="outbound">')
    [void]$sb.AppendLine('<h2>Allowlist-voorstel uitgaand verkeer</h2>')
    if ($Model.Outbound.Count -eq 0) {
        [void]$sb.AppendLine('<p class="hk-muted">Geen uitgaande verbindingen geregistreerd.</p>')
    }
    else {
        foreach ($proc in $Model.Outbound) {
            [void]$sb.AppendLine('<details>')
            [void]$sb.AppendLine("<summary>$(& $enc $proc.Process) ($($proc.Destinations.Count) bestemming(en))</summary>")
            [void]$sb.AppendLine('<table><tr><th>DNS-naam</th><th>IP</th><th>Aantal</th></tr>')
            foreach ($d in $proc.Destinations) {
                [void]$sb.AppendLine("<tr><td>$(& $enc $d.Fqdn)</td><td>$(& $enc $d.Ip)</td><td>$($d.Count)</td></tr>")
            }
            [void]$sb.AppendLine('</table>')
            [void]$sb.AppendLine('</details>')
        }
    }
    [void]$sb.AppendLine('</section>')

    # --- Ruwe data als JSON, voor technische inspectie. </script in de data zelf escapen om de
    # tag niet voortijdig te sluiten (zie docs/LESSONS.md-stijl voorzichtigheid). ---
    $jsonData = $Model | ConvertTo-Json -Depth 12
    $jsonData = $jsonData -replace '(?i)</script', '<\/script'
    [void]$sb.AppendLine('<script type="application/json" id="hk-data">')
    [void]$sb.AppendLine($jsonData)
    [void]$sb.AppendLine('</script>')

    [void]$sb.AppendLine('</body>')
    [void]$sb.AppendLine('</html>')

    $sb.ToString()
}
