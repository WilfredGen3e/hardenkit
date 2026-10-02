# Lessons learned — HardenKit

Doel: valkuilen die we al eens tegenkwamen, zodat we ze niet opnieuw ontdekken. **Check dit
bestand voor je aan een nieuwe collector begint.** Voeg een item toe zodra je een niet-triviale
bug fixt (niet voor typo's of iets dat de linter al vangt) — kort: wat ging er mis, waarom, en
de fix.

## PowerShell-taalvalkuilen

### `[string]$Param = $env:X` vergelijken met het ongetypeerde `$env:X`
**Wat:** op een host zonder de env-var (bv. `$env:COMPUTERNAME` op macOS) wordt een getypeerd
`[string]$ComputerName = $env:COMPUTERNAME`-default `''`, maar `$env:COMPUTERNAME` zelf blijft
`$null`. `'' -eq $null` is `False` in PowerShell, dus `if ($ComputerName -ne $env:COMPUTERNAME)`
gooit ten onrechte.
**Fix:** cast beide kanten expliciet: `if ($ComputerName -ne [string]$env:COMPUTERNAME)`.
**Waar gezien:** alle "alleen lokale machine"-guards (Get-HKAuditPolicy,
Get-HKNtlmAuditSetting, Get-HKLdapAuditSettings, Get-HKSecurityLogInfo, Test-HKAuditConfig, en
alle Get-HKBaseline-helpers).

### De "comma-trick" (`, $array`) om array-uitpakken te voorkomen, faalt binnen Pester's `InModuleScope`
**Wat:** `, $results.ToArray()` als laatste statement, bedoeld om te voorkomen dat PowerShell
een 0- of 1-element array uitrolt op de pipeline, gaf binnen Pester's `InModuleScope` een
dubbel-geneste array terug (empirisch vastgesteld met een losse repro buiten de module, niet
uit documentatie af te leiden).
**Fix:** geen comma-trick gebruiken; functies laten gewoon losse objecten streamen
(`$results.ToArray()` zónder comma), en de aanroeper wrapt zelf met `@(...)` voor een
betrouwbare array.
**Algemenere regel (geverifieerd, geldt los van de comma-trick):** een functie waarvan de
uitvoer naar 0 objecten enumereert, geeft bij *directe* toekenning (`$x = Get-Foo`, geen pipe)
altijd `$null` terug — ook als de functie zelf intern al netjes `@(...)` gebruikt
(bv. `@($events | ForEach-Object {...})` als laatste statement). De `@(...)` binnen de
functie-body beschermt de aanroeper dus niet. Enige betrouwbare fix: wrap de *aanroep*, nooit
(alleen) de functie-body: `$x = @(Get-Foo)`. Pas dit overal toe waar een functie 0..N objecten
kan teruggeven en de aanroeper `.Count` of een foreach op het resultaat doet.

**Keerzijde, net zo belangrijk:** `@($null)` (of `@($iets.Dat.Null.Is)`) is géén lege array —
het is een array mét één element, en dat element is `$null`. Dus `@(...)` rond een mogelijk
`$null`-waarde "repareert" niets; een `foreach` daarover loopt gewoon één keer met `$row = $null`.
Check expliciet op `$null`/`if ($x) { ... }` vóórdat je `@($x.Property)` doet, in plaats van te
vertrouwen op `@(...)` alleen. **Samengevat: `@(...)` lost het "0 objecten → $null"-probleem bij
een aanroep op, maar maakt een losse `$null`-waarde niet tot een lege array — twee verschillende
problemen, twee verschillende fixes.**
**Waar gezien:** `Export-HKData` crashte op een falende collector of een niet-DC-rol, omdat
`@($ntlmUsage.Findings)` bij `$ntlmUsage -eq $null` een array met één `$null`-element gaf in
plaats van leeg — opgelost met een expliciete `if ($ntlmUsage) { ... }` vóór de `foreach`.

**Nog een generalisatie, empirisch bevestigd:** het "0-of-1-element-array wordt uitgepakt"-gedrag
geldt niet alleen voor functiereturns en een kale `foreach`-als-expressie (zie hierboven), maar
voor élke PowerShell-constructie die impliciet naar de pipeline schrijft, waaronder een
**`if/else`-blok dat als expressie gebruikt wordt** (`$x = if (...) { @(...) } else { @() }`).
Zelfs als beide takken al expliciet `@(...)` gebruiken, wordt het resultaat bij toekenning alsnog
uitgepakt als er 0 of 1 elementen in zitten. Fix: wrap het hele if/else-blok, niet de losse
takken: `$x = @(if (...) { @(...) } else { @() })`.
**Waar gezien:** `Export-HKData`'s `dailySummaries`-object: `ldapSigning = if ($ldapBinding)
{ @(...) } else { @() }` gaf bij precies 1 item een kaal object terug in plaats van een
1-element array, en `ConvertTo-Json` schreef het dus ook niet als JSON-array weg. Vond dit pas
op bij het testen van de JSON-uitvoer, niet bij het schrijven van de code zelf — **reden te meer
om dit soort constructies altijd te testen met 0, 1 én meerdere elementen, nooit alleen met 0 of
meerdere.**
**Waar gezien:** `ConvertFrom-HKSetspnOutput` en het gebruik van `Get-HKDuplicateSpn` in
`Get-HKBaseline`.

### Lege string in een pipeline naar een `[string[]]`-parameter
**Wat:** `[AllowEmptyCollection()]` staat een lege *array* toe, maar niet een los element dat
een lege string is binnen een niet-lege array die via de pipeline binnenkomt. Testinvoer met
blanco regels (zoals echte `auditpol`/`setspn`-uitvoer die blanco regels bevat) brak hierop met
"Cannot bind argument ... because it is an empty string."
**Fix:** `[AllowEmptyString()]` toevoegen naast `[AllowEmptyCollection()]`.
**Waar gezien:** `ConvertFrom-HKAuditPolicyCsv`, `ConvertFrom-HKSetspnOutput`.

## Testconventies (ter voorkoming van vals-positieve tests)

### Private functies buiten `InModuleScope` aanroepen geeft vals-positieve `-Throw`-asserts
**Wat:** een eerste testopzet riep private (niet-geëxporteerde) functies rechtstreeks aan in een
testscript buiten de module. PowerShell gooit dan "command not found" — en dat laat
`Should -Throw` zonder `-ExpectedMessage` slagen, ook al is de eigenlijke guard-logica nooit
uitgevoerd.
**Fix:** test private functies altijd binnen `InModuleScope <ModuleName> { ... }`, én gebruik
`-ExpectedMessage` bij `Should -Throw` zodat een verkeerde foutoorzaak niet per ongeluk als
geslaagde test telt.
**Waar gezien:** `Test-HKAuditConfig.Tests.ps1` (herschreven), toegepast in
`Get-HKBaseline.Tests.ps1`.

### Een losse testhulpfunctie op scriptniveau is niet betrouwbaar zichtbaar in `BeforeAll`/`Mock`
**Wat:** een `function New-HKTestEvent { ... }` bovenaan het testbestand (buiten
`InModuleScope`, gewoon op scriptniveau) gaf "command not found" zodra die werd aangeroepen
vanuit een `BeforeAll`-blok of een `Mock`-scriptblock — ook toen die niet eens over de
module-grens ging. Oorzaak niet volledig doorgrond; empirisch vastgesteld, niet aangenomen.
**Fix:** geen losse testhulpfunctie voor fixtures; bouw fixture-objecten inline als
`[pscustomobject]@{...}` (zoals in `Get-HKNtlmUsage.Tests.ps1`), of bouw de data op in een
variabele vlak vóór de `Mock`-aanroep en laat de mock-scriptblock alleen die variabele
teruggeven (closures over variabelen werken wél betrouwbaar).
**Waar gezien:** eerste opzet van `Get-HKLdapBinding.Tests.ps1`.

### Een `It`-blok met `</script>` letterlijk in de testnaam breekt Pester 6 zelf
**Wat:** `It 'doet iets met </script> erin' { 1 | Should -Be 1 }` faalt met
`CommandNotFoundException: The term '$/script' is not recognized...` — een bug in Pester 6 zelf
(losse repro met een triviale testbody bevestigt dit, niets met de eigen code te maken), niet
iets om tijd in te steken om te doorgronden.
**Fix:** geen letterlijke `</script>`/vergelijkbare HTML-tag-syntax in een testnaam; parafraseer
("...de scripttag niet voortijdig sluiten" i.p.v. "...de `</script>`-tag niet voortijdig
sluiten"). De test zelf (de body) kan zulke strings gewoon verwerken; alleen de titel breekt.
**Waar gezien:** `New-HKReport.Tests.ps1`, test van `ConvertTo-HKReportHtml`'s
JSON-escaping.

### `@($hashtable[$ontbrekendeKey])` is weer de `@($null)`-valkuil, nu via een hashtable-lookup
**Wat:** dezelfde "`@($null)` is een array mét één `$null`-element, niet leeg"-regel (zie
hierboven) sloeg hier toe via een andere route: `$findingsByMeasure[$measure]` op een
niet-bestaande key geeft `$null`, en `@(...)` daaromheen "repareert" dat niet. Gaf een
`foreach`-loop die één keer met een `$null`-element draaide, en crashte zodra er een
member/property op aangeroepen werd (`$_.PSObject.Properties...` op `$null`).
**Fix:** eerst `.ContainsKey($measure)` checken, pas dan `@($hashtable[$measure])`; anders `@()`.
**Waar gezien:** `Resolve-HKReportModel` — drie plekken (per-maatregel findings, de
missing_spn/ntlm_8004-correlatie, de outbound-groepering) hadden deze bug, gevonden door de
"Groen zonder findings"-test (niet door de tests die toevallig wél findings hadden).

### `-Skip:(-not $IsWindows)` verbergt kapotte tests op de macOS-ontwikkelmachine
**Wat:** de drie `Get-HKHostRole`-tests in `HardenKit.Tests.ps1` riepen de private functie
buiten `InModuleScope` aan (dezelfde valkuil als hierboven). Omdat ze op macOS werden
overgeslagen, bleef dat onopgemerkt; bij de eerste run op Windows faalden ze alle drie met
"command not found".
**Fix:** aanroep in `InModuleScope HardenKit { ... }` gezet. Les: tests die alleen op Windows
draaien zijn pas gevalideerd na een run op Windows. Draai de volledige suite op een
Windows-machine vóór een release/pilot, niet alleen op macOS.
**Waar gezien:** `HardenKit.Tests.ps1`, eerste Pester-run op Windows (02-10-2026).

### Scriptbestanden zonder UTF-8 BOM laden niet in Windows PowerShell 5.1
**Wat:** alle `.ps1`/`.psm1`/`.psd1` waren UTF-8 zonder BOM. pwsh 7 leest dat goed, maar
Windows PowerShell 5.1 (wat een DC draait) leest het als Windows-1252. Een `—` (bytes
`E2 80 94`) wordt dan `â€"`, en dat laatste teken telt in PowerShell als aanhalingsteken: de
string sluit voortijdig en `ConvertTo-HKReportHtml.ps1` gaf parse-fouten, waardoor de hele
module niet laadde. Alle tests draaiden op pwsh 7 en zagen het dus niet.
**Fix:** UTF-8 met BOM voor alle scriptbestanden, plus een regressietest in
`HardenKit.Tests.ps1` die elk bestand op de BOM controleert. Na elke wijziging ook
`powershell.exe -Command "Import-Module ...\HardenKit.psd1"` (5.1) draaien, niet alleen pwsh.
**Waar gezien:** eerste import in Windows PowerShell 5.1 (02-10-2026).

### auditpol-subcategorienamen zijn gelokaliseerd
**Wat:** `auditpol /get /subcategory:"Logon"` geeft op een Nederlandstalige Windows fout
`0x57` (ongeldige parameter): daar heet het "Aanmelden". `Test-HKAuditConfig` zette daardoor
alle auditpol-afhankelijke maatregelen op Onbekend. Bevestigd met `auditpol /list
/subcategory:* /v` op een NL-machine.
**Fix:** `Get-HKAuditPolicy` vraagt op met de taalonafhankelijke GUID (de Engelse naam blijft
de sleutel in het resultaat). `ConvertFrom-HKAuditPolicyCsv` herkent Engelse en Nederlandse
tekst (kolom op naam, anders op positie, voor het geval de kopregel vertaald is) en gooit een
fout bij onbekende tekst zodat het Onbekend wordt in plaats van onterecht NietVoldaan. Een
numerieke kolom bestaat niet in de /r-uitvoer (bevestigd op een DC).
**Waar gezien:** smoke-test van `Test-HKAuditConfig` op een NL-Windows 11 (02-10-2026).

### `setspn -X`: exitcode 1 bij succes, en de verzonnen fixtures klopten niet
**Wat:** op een echte Server 2022-DC gaf `setspn -X` exitcode 1 terwijl de run gewoon slaagde
("found 0 group of duplicate SPNs."), dus `DuplicateSpn` werd altijd `onbekend`. Daarnaast
week de echte uitvoer af van de testfixtures: `found` met kleine letter, `Processing entry N`-
regels, en SPN-regels met het achtervoegsel "is registered on these accounts:". De oude parser
zou van de lab-uitvoer 9 nep-SPN's gemaakt hebben.
**Fix:** succes bepalen op de slotregel `found N group`, niet op de exitcode; boilerplate
hoofdletterongevoelig herkennen; achtervoegsel strippen. Echte lab-uitvoer als fixture.
**Les:** fixtures op basis van documentatie zijn een gok. Zodra er echte uitvoer is, die
letterlijk als fixture opnemen.
**Waar gezien:** `Get-HKBaseline` op lab-DC DEMO-DC-001, Server 2022 EN (02-10-2026).

## Werkwijze voor Windows-only logica op een macOS-ontwikkelmachine

Pester-tests draaien lokaal op macOS (pwsh); de module zelf draait alleen op Windows Server
DC's. Daarom splitsen we Windows-only logica (CIM, registry, `auditpol.exe`, `setspn.exe`,
`w32tm.exe`, ADSI/AD) consequent in twee lagen:

1. Een dunne I/O-laag die de externe tool/cmdlet aanroept (bv. `Get-HKAuditPolicy`,
   `Get-HKDuplicateSpn`). Hiervoor volstaat een cross-platform remote-guard-test plus latere
   handmatige validatie op een echte DC.
2. Een pure parsing-/logicalaag zonder Windows-afhankelijkheid (bv.
   `ConvertFrom-HKAuditPolicyCsv`, `ConvertFrom-HKSetspnOutput`). Deze laag krijgt de
   uitgebreide tests, want die kunnen écht overal draaien.

## Nog niet op een echte DC geverifieerd — pilot-testlijst

Onderstaande zijn aannames op basis van Microsoft-documentatie, niet getest tegen een live DC.
**Dit is de lijst om af te werken zodra de eerste pilot draait** (zie ook de open vragen in
`CLAUDE.md`): per item een event dumpen (`(Get-WinEvent ...)[0].ToXml()`) of de instelling
opzoeken, en de code + test-fixtures bijstellen waar nodig.

- Registrynamen: `AuditNTLMInDomain`, `16 LDAP Interface Events`, `LdapEnforceChannelBinding`,
  `LDAPServerIntegrity`, `RestrictSendingNTLMTraffic`, `RestrictReceivingNTLMTraffic`,
  `SysvolReady`.
- `auditpol.exe /get /subcategory:{GUID} /r` — **EN bevestigd** op Server 2022 (02-10-2026):
  geen numerieke kolom, alleen tekst in `Inclusion Setting` (`Success and Failure` e.d.),
  CSV zonder aanhalingstekens. **NL nog open:** kloppen de terugvalteksten (`Geslaagd`/
  `Mislukt`/`Geslaagd en mislukt`/`Geen controle`) en is de kopregel vertaald (parser valt dan
  terug op de 5e kolom)? Elevated op een NL-machine draaien.
- `setspn.exe -X`-uitvoer: Engelstalig geparsed; op een Nederlandstalige installatie kan deze
  tekst afwijken.
- EventData-veldnamen event 8004 (NTLM/Operational): `UserName`, `Workstation`, `ServerName` —
  matig zeker (8004 is minder uitgebreid publiek gedocumenteerd dan 4624/4776).
- EventData-veldnamen events 2887/2889/3039/3041 (Directory Service, LDAP signing/channel
  binding): `Client`, `IdentityUser`, `Count` — **minst zekere aanname in dit project tot nu
  toe**, eerst valideren. Ook te bevestigen: of 2887/3041 echt periodieke 24-uurs tellingen zijn
  zonder per-client detail (huidige aanname) of toch per-client data bevatten.
- EventData-veldnamen Security-events 4768/4769 (`TargetUserName`, `TargetSid`, `ServiceName`,
  `Status`/`ResultCode`, `TicketEncryptionType`, `IpAddress`) — redelijk zeker, net zo goed
  gedocumenteerd als 4624. De encryptietype-waarden (`0x17`/`0x18` RC4, `0x1`/`0x3` DES) zelf
  ook te bevestigen.
- EventData-veldnamen System-events 11 (KDC, `ServicePrincipalName`) en 39/40/41 (Kdcsvc,
  `TargetUserName`, `TargetSid`, `CertificateSubject`) — zelfde onzekerheidscategorie als de
  LDAP-events hierboven; minder gedocumenteerd dan de Security-log events.
- EventData-veldnamen System-events 5827/5828 (`MachineAccount`) — net zo onzeker als de
  LDAP-events. Ook te bevestigen: of 5816-5819 (netlogon_saturation) écht geen bruikbaar
  per-client veld hebben (huidige aanname: puur als los voorval geteld) of toch iets als een
  workstation-naam bevatten; en of 5807 inderdaad een periodieke telling is zonder per-client
  IP (zoals 2887/3041) — per-client IP-detail voor onbekende subnetten zit mogelijk alleen in
  `netlogon.log` (tekstbestand, niet het eventlog), wat fase 0 nu niet parset.
- DFSR-replicatiefouten (los van de Directory Service-events 1311/1865/2042 die wél gelezen
  worden) worden in fase 0 niet gelezen — PRD noemt dit als "o.a.", dus mogelijk gat.

## Bekende vereenvoudigingen in New-HKReport (fase 0)

Dit zijn bewuste, gedocumenteerde scope-keuzes in `Resolve-HKReportModel` — geen bugs, maar wel
dingen om tegen echte pilotdata te toetsen en eventueel te verfijnen:

- **Geen automatische Rood-status.** De PRD-voorwaarde voor Rood ("bronnen die niet zonder meer
  op te lossen zijn, oude apparatuur, leverancier") is met alleen eventdata niet vast te stellen
  zonder CMDB-kennis. Fase 0 geeft bevindingen altijd Oranje met een toelichting dat een
  engineer beoordeelt of de bron vervangbaar is; Rood is een bewust handmatige vervolgstap.
- **Drempelwaarden (`-MissingSpnThreshold`, `-LockoutThreshold`, default 5) zijn nog niet
  toegepast in de statuslogica** — de parameters bestaan, maar `Resolve-HKReportModel` filtert
  er nog niet mee (alle bevindingen tellen nu even zwaar, ongeacht aantal). PRD noemt de
  drempelwaarde zelf ook nog als open vraag; dit verder uitwerken zodra die beantwoord is.
- **Correlatie "NTLM-fallback door ontbrekende SPN"** matcht alleen op de genormaliseerde
  servicenaam, niet ook op dezelfde client (zie `ConvertTo-HKNormalizedSpnTarget`) — 4769 geeft
  een client-IP, 8004 een workstation-naam, niet betrouwbaar te vergelijken zonder DNS.
- **Correlatie "één oorzaak, meerdere effecten"** (NTLM-volume + Netlogon-verzadiging;
  tijdsafwijking + Kerberos-fouten) is alleen een tekstuele notitie, geen echte samenvoeging tot
  één bevinding — fijnmazige tijdreeks-correlatie is niet gebouwd in fase 0.
- **DC-compleetheid is een proxy** (aantal dagbestanden >= `-MinimumDays`), geen controle op
  aaneengesloten dagen zonder gaten.
- **Gemeten periode per maatregel is in fase 0 het globale kalenderbereik** (vroegste
  window.from tot laatste window.to over alle bestanden), niet per maatregel geslicet op de
  dagen waarop de onderliggende collector specifiek 'ok' was. PRD zegt letterlijk "het rapport
  toont per maatregel de werkelijke gemeten periode" — dit is dus een vereenvoudiging t.o.v. de
  letterlijke tekst, bewust gekozen om scope behapbaar te houden.
