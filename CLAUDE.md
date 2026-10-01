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

- **01-10-2026:** PRD vastgelegd (`docs/PRD.md`). Nog geen code. Eerstvolgende stap: scaffold van de module opzetten (moduleskelet, manifest, mapstructuur voor collectors) — plan bespreken en akkoord afwachten voor het bouwen begint.

## Open vragen (uit PRD, nog niet beantwoord)

- Welke extra RC4-auditevents heeft Microsoft toegevoegd aan 4768/4769?
- Rewst: kan het via onze RMM scripts starten en output ophalen? Ondersteunt het webhook-auth?
- Publieke of privérepository?
- Drempelwaarden voor 0x7-fouten en lockouts?
- Waar JSON/rapporten bewaren: klant-share of centraal?
- Welk codesigning-certificaat, wie beheert het?
