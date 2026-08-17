# Monatsabrechnung Smoobu

Kommandozeilen-Programm, das aus der [Smoobu-API](https://docs.smoobu.com/#introduction)
eine Monatsabrechnung für **alle Unterkünfte** erstellt. Es ruft alle Buchungen ab,
deren **Abreisedatum im angegebenen Monat liegt**, und schreibt die Ergebnisse in
einen CSV-Report.

## Abgerechnete Felder

Pro Buchung werden ermittelt:

| Spalte              | Bedeutung |
|---------------------|-----------|
| Buchungs-ID         | Smoobu-Reservierungs-ID |
| Unterkunft / -ID    | Apartment-Name und ID |
| Gast                | Gastname |
| Anreise / Abreise   | Datum (yyyy-mm-dd) |
| Nächte              | Abreise − Anreise |
| Personen            | adults + children (Fallback: guests) |
| **Personennächte**  | Personen × Nächte |
| Gesamtpreis         | `price` der Buchung |
| Steuer              | Summe aller Preiselemente vom Typ `tax`/`vat` |
| Payment-Charge      | Summe aller Preiselemente vom Typ `paymentCharge`/`commission` |
| Bezahlter Betrag    | `prepayment` (sofern `prepaymentStatus = 1`) |
| Überwiesener Betrag | Gesamtpreis − Steuer − Payment-Charge (nur bei bezahlten Buchungen) |
| Währung / Preisstatus | Währung + Zahlungsstatus |

> Hinweis: Smoobu liefert Steuern und Gebühren nicht immer als separates Feld auf
> der Buchung. Das Programm ruft daher zusätzlich die **Preiselemente** je Buchung
> ab (`/api/booking/{id}/price-elements`) und summiert die Typen `tax` und
> `paymentCharge`. Sind in der Reservierung bereits `priceElements` enthalten,
> werden diese direkt verwendet (weniger API-Aufrufe).

## Authentifizierung

Verwendet wird die von Smoobu **empfohlene HMAC-Authentifizierung**. Jeder Request
wird signiert mit `X-API-Key`, `X-Timestamp`, `X-Nonce` (UUID v4) und
`X-Signature` (Base64 HMAC-SHA256). Der veraltete `Api-Key`-Header wird am
25.09.2026 abgeschaltet.

API-Key und API-Secret werden in Smoobu unter
**Einstellungen → Advanced → API Keys** erzeugt.

Die Zugangsdaten werden über die Umgebungsvariablen bereitgestellt:

- `SMOOBU_LABEL` – der API-Key (Label)
- `SMOOBU_KEY` – das API-Secret

## Einrichtung

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
# .env mit SMOOBU_LABEL (API-Key) und SMOOBU_KEY (API-Secret) befüllen
```

## Nutzung

```bash
python abrechnung.py 2026-04
```

Alternative Formate für den Monat:

```bash
python abrechnung.py 04.2026
python abrechnung.py 202604
python abrechnung.py 2026-04 -o export/april.csv
python abrechnung.py 2026-04 --api-key usr_live_xxx --api-secret geheim
```

Ausgabe ist eine CSV-Datei (Standard: `abrechnung_2026-04.csv`) sowie eine
Zusammenfassung auf der Konsole.

## Tests

```bash
python -m pytest -q
```

Die Tests benötigen keine echten Smoobu-Zugänge; sie arbeiten mit einem
Mock-Client gegen fixture-artige Buchungsdaten.
