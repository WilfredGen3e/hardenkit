# HardenKit

## Doel

Alleen-lezen PowerShell-module die meet wat er breekt als on-premises Active Directory gehardend wordt. In plaats van alleen te melden wát er mis is (zoals PingCastle/Purple Knight), meet HardenKit per hardeningmaatregel wie of wat er nog gebruik van maakt, zodat engineers een onderbouwde go/no-go kunnen nemen.

Volledige requirements: [`docs/PRD.md`](docs/PRD.md).

## Technische keuzes

- **Taal/platform:** Windows PowerShell 5.1, doelgroep Windows Server 2016+ domain controllers.
- **Alleen lezen:** de module wijzigt niets aan het domein, behalve bewust en apart gemeld het aanzetten van auditinstellingen.
- **Databron:** `Get-WinEvent` met XPath-filters, incrementeel per laatste RecordId, plus configuratie-nulmeting (auditpol, LDAP-instellingen, SPN's, tijdbron, replicatie).
- **Dataformaat:** één JSON-bestand per host per dag (schema geversioneerd, zie PRD), geaggregeerd — geen ruwe events, geen secrets.
- **Rapport:** `New-HKReport` genereert één zelfstandig offline HTML-bestand per klant (geen externe scripts/fonts), stoplicht per maatregel.
- **Distributie:** GitHub als bron, RMM als standaard installatiekanaal (geen internetafhankelijkheid op de DC), gesigned releases, gepinde versies. Geen `irm | iex`.
- **Geen** eigen webapp of centrale opslag in fase 0.

## Structuur

- `docs/PRD.md` — volledige productvereisten (bron van waarheid voor scope/fasering).
- Module-structuur (collectors, `Export-HKData`, `New-HKReport`, tests) nog op te zetten.

## Fasering

- **Fase 0** (huidige focus): meten op DC's alleen — nulmeting, NTLM/LDAP/Kerberos/domain health collectors, JSON-export, HTML-rapport. Geen member servers, Rewst of centrale opslag nodig.
- **Fase 1:** member servers, service-inventaris (scheduled tasks, services, IIS-pools, SQL Agent-jobs) gekoppeld aan serviceaccounts; SMBv1 op alle servers.
- **Fase 2:** gericht meten op werkplekken (NTLM-herkomst per proces, Kerberos-fouten client), Rewst-koppeling (RMM-orkestratie, IT Glue, PSA-tickets).

Elke fase start pas als de gate van de vorige fase gehaald is (zie PRD).

## Status

- **01-10-2026:** PRD vastgelegd (`docs/PRD.md`).
- **01-10-2026:** Moduleskelet opgezet in `HardenKit/`: manifest (`HardenKit.psd1`), root module (`HardenKit.psm1`), negen public-functies als skeletons (comment-based help + `throw "...nog niet geïmplementeerd."`), private helper `Get-HKHostRole` (DC/member server-detectie, enige echte logica tot nu toe), Pester-tests (manifest geldig, juiste exports, `Get-HKHostRole`-gedrag; CIM-tests geskipt buiten Windows). Lokaal gevalideerd met pwsh/Pester, gepusht naar `main`.
- **01-10-2026:** `Test-HKAuditConfig` geïmplementeerd. Leunt op vier nieuwe private helpers: `Get-HKAuditPolicy` (auditpol-subcategorieën via `ConvertFrom-HKAuditPolicyCsv`, apart gehouden zodat de CSV-parsing platformonafhankelijk testbaar is), `Get-HKSecurityLogInfo` (grootte/recordaantal/oudste event), `Get-HKNtlmAuditSetting` (registry `AuditNTLMInDomain`) en `Get-HKLdapAuditSettings` (registry LDAP-diagnostiekniveau + channel binding-modus). `Test-HKAuditConfig` combineert deze tot per-maatregel status `Ok` / `NietVoldaan` / `Onbekend`, met per-bron try/catch zodat een falende bron niet de hele run breekt ("onbekend is niet groen"). Alle vier helpers ondersteunen bewust alleen de lokale machine (geen remote auditpol/registry). 19 Pester-tests toegevoegd en groen (incl. een geïntroduceerde en gefixte bug: `[string]$ComputerName`-default vs. ongetypeerd `$env:COMPUTERNAME` gaf valse ongelijkheid op een host zonder die env var). Gecommit en gepusht naar `main`.
  - **Bekende aanname, nog te verifiëren op een echte DC:** de exacte registrynamen (`AuditNTLMInDomain`, `16 LDAP Interface Events`, `LdapEnforceChannelBinding`) en de Engelstalige `auditpol`-uitvoer (`Success`/`Failure`/`Success and Failure`/`No Auditing`) zijn gebaseerd op Microsoft-documentatie, niet op een live DC getest. Op een Nederlandstalige Windows-installatie kan de auditpol-tekst afwijken.
- **01-10-2026:** `Get-HKBaseline` geïmplementeerd: OS-versie/rol, DC-lijst + PDC-emulator (`Get-HKDomainControllerInfo`, via .NET `System.DirectoryServices.ActiveDirectory`, geen ActiveDirectory-module nodig), dubbele SPN's (`Get-HKDuplicateSpn`, parsing apart in `ConvertFrom-HKSetspnOutput` net als bij auditpol), krbtgt-wachtwoordleeftijd (`Get-HKKrbtgtAge`, via ADSI), tijdbron (`Get-HKTimeSource`, `w32tm /query /source`), SYSVOL-technologie+gereedheid (`Get-HKSysvolReplicationInfo`), LmCompatibilityLevel/NTLM-verzendrestricties/SMB1/Print Spooler (`Get-HKSmbNtlmConfig`). Hergebruikt `Get-HKLdapAuditSettings` en `Get-HKSecurityLogInfo` uit `Test-HKAuditConfig` i.p.v. te dupliceren; `Get-HKLdapAuditSettings` uitgebreid met `LdapServerIntegrity` (LDAP-signing-vereiste, stond nog niet in de eerdere versie). Zelfde try/catch-per-bron-patroon als `Test-HKAuditConfig` ("onbekend is niet groen", geen afgebroken run). Alle nieuwe helpers bewust alleen lokaal (consistente remoting-houding over de hele module). 32 Pester-tests groen in totaal, 3 geskipt buiten Windows.
  - **Twee PowerShell-bugs gevonden en gefixt tijdens het testen:** (1) dezelfde `[string]$ComputerName`-default-valkuil als eerder, nu ook in de nieuwe helpers. (2) De "comma-trick" (`, $array`) om een lege/1-element array niet te laten uitpakken bleek binnen Pester's `InModuleScope` een dubbel-geneste array te geven (empirisch vastgesteld, niet uit documentatie) — opgelost door functies gewoon losse objecten te laten streamen en de aanroeper `@(...)` te laten gebruiken; `Get-HKBaseline` wrapt `Get-HKDuplicateSpn` zelf ook met `@(...)` omdat een functie die als laatste statement een lege array heeft, bij direct aanroepen (niet via pipe) `$null` teruggeeft in plaats van een lege array — ook dat empirisch bevestigd, niet aangenomen.
  - **Zelfde bekende aanname-caveat als bij `Test-HKAuditConfig`:** registrynamen (`LDAPServerIntegrity`, `RestrictSendingNTLMTraffic`, `RestrictReceivingNTLMTraffic`, `SysvolReady`) en de Engelstalige `setspn -X`/`w32tm`-uitvoer nog niet op een echte DC geverifieerd.
- Eerstvolgende stap: volgende collector implementeren — voorstel `Get-HKNtlmUsage` (NTLMv1/LM via 4624, NTLM-gebruik via 8004, credential validation via 4776) als eerste eventlog-collector, omdat die de incrementele `Get-WinEvent`-leespatroon introduceert die `Get-HKLdapBinding`/`Get-HKKerberos`/`Get-HKDomainHealth` ook nodig hebben. Plan bespreken en akkoord afwachten voor het bouwen begint.

## Open vragen (uit PRD, nog niet beantwoord)

- Welke extra RC4-auditevents heeft Microsoft toegevoegd aan 4768/4769?
- Rewst: kan het via onze RMM scripts starten en output ophalen? Ondersteunt het webhook-auth?
- Publieke of privérepository?
- Drempelwaarden voor 0x7-fouten en lockouts?
- Waar JSON/rapporten bewaren: klant-share of centraal?
- Welk codesigning-certificaat, wie beheert het?
