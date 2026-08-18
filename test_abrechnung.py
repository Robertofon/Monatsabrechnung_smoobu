"""Tests für das Monatsabrechnungsmodul.

Die Tests benötigen keine echten Smoobu-Zugänge. Stattdessen wird ein
Mock-Client verwendet, der die Buchungsdaten aus den Fixtures zurückgibt.
"""

from __future__ import annotations

import csv
import hashlib
import hmac
import base64
from datetime import date

import abrechnung


class FakeClient(abrechnung.SmoobuClient):
    """Client, der keine echten HTTP-Aufrufe macht."""

    def __init__(self, apartments, reservations, price_elements=None):
        # Konstruktor von SmoobuClient umgehen, damit keine Credentials nötig sind.
        self.config = abrechnung.SmoobuConfig()
        self._apartments = apartments
        self._reservations = reservations
        self._price_elements = price_elements or {}
        self.get_apartments_calls = 0
        self.get_reservations_calls = 0
        self.get_price_elements_calls = 0

    def get_apartments(self):
        self.get_apartments_calls += 1
        return self._apartments

    def get_reservations(self, from_date, to_date):
        self.get_reservations_calls += 1
        return self._reservations

    def get_price_elements(self, booking_id):
        self.get_price_elements_calls += 1
        return self._price_elements.get(booking_id, [])


# ---------------------------------------------------------------------- #
# Fixtures
# ---------------------------------------------------------------------- #
APARTMENTS = [
    {"id": 1, "name": "Ferienwohnung Nord"},
    {"id": 2, "name": "Ferienhaus Süd"},
]


def _reservation(
    rid,
    apartment_id,
    arrival,
    departure,
    *,
    adults=2,
    children=0,
    price=100.0,
    prepayment=100.0,
    prepayment_status=1,
    price_status=1,
    price_elements=None,
    channel_id=63,
    channel_name="Airbnb",
    first_name="Max",
    last_name="Mustermann",
):
    return {
        "id": rid,
        "apartmentId": apartment_id,
        "arrivalDate": arrival,
        "departureDate": departure,
        "adults": adults,
        "children": children,
        "price": price,
        "prepayment": prepayment,
        "prepaymentStatus": prepayment_status,
        "priceStatus": price_status,
        "priceCurrency": "EUR",
        "firstName": first_name,
        "lastName": last_name,
        "channelId": channel_id,
        "channelName": channel_name,
        "priceElements": price_elements or [],
    }


# Buchungen für April 2026. Abfragezeitraum wird vom Modul großzügig gewählt,
# relevante Auswahl entscheidet am departureDate.
RESERVATIONS = [
    # Endet am 30.04.2026 -> IM Zielmonat
    _reservation(
        101, 1, "2026-04-25", "2026-04-30",
        adults=2, children=1, price=500.00, prepayment=500.00,
        price_elements=[
            {"type": "basePrice", "amount": 450.0},
            {"type": "cleaningFee", "amount": 30.0},
            {"type": "tax", "amount": 20.0},
            {"type": "paymentCharge", "amount": 10.0},
            {"type": "commission", "amount": 50.0},
        ],
    ),
    # Endet am 01.05.2026 -> NICHT im Zielmonat April
    _reservation(102, 2, "2026-04-28", "2026-05-01", price=300.00),
    # Endet am 10.04.2026 -> IM Zielmonat
    _reservation(
        103, 2, "2026-04-05", "2026-04-10", adults=2, price=200.00,
        prepayment=200.00,
        price_elements=[{"type": "basePrice", "amount": 200.0}],
    ),
    # Endet am 31.03.2026 -> NICHT im Zielmonat
    _reservation(104, 1, "2026-03-20", "2026-03-31", price=400.00),
]


# ---------------------------------------------------------------------- #
# Signatur
# ---------------------------------------------------------------------- #
def test_signatur_entspricht_smoobu_canonical_string():
    config = abrechnung.SmoobuConfig(api_key="usr_live_abc123", api_secret="geheim")
    client = abrechnung.SmoobuClient(config)

    body = b'{"apartmentId":123,"from":"2026-04-01","to":"2026-04-10"}'
    headers = client._sign("GET", "/api/reservations", "from=2026-04-01&to=2026-04-10", body)

    # Kanonischen String nachbauen und Signatur verifizieren.
    body_hash = hashlib.sha256(body).hexdigest()
    canonical_query = "from=2026-04-01&to=2026-04-10"  # bereits sortiert
    canonical = "\n".join(
        ["GET", "/api/reservations", canonical_query,
         headers["X-Timestamp"], headers["X-Nonce"], body_hash, config.api_key]
    )
    expected = base64.b64encode(
        hmac.new(b"geheim", canonical.encode("utf-8"), hashlib.sha256).digest()
    ).decode("ascii")
    assert headers["X-Signature"] == expected
    assert headers["X-API-Key"] == "usr_live_abc123"
    assert headers["X-Nonce"]  # UUID vorhanden


def test_canonical_query_sortiert_alphabetisch():
    out = abrechnung.SmoobuClient._canonical_query("to=2026-04-10&from=2026-04-01&page=1")
    assert out == "from=2026-04-01&page=1&to=2026-04-10"


def test_canonical_query_leer():
    assert abrechnung.SmoobuClient._canonical_query("") == ""


# ---------------------------------------------------------------------- #
# Monatsfilter
# ---------------------------------------------------------------------- #
def make_billing():
    client = FakeClient(APARTMENTS, RESERVATIONS)
    return abrechnung.MonthlyBilling(client)


def test_nur_im_zielmonat_endende_buchungen():
    rows = make_billing().build(2026, 4)
    ids = sorted(r.booking_id for r in rows)
    assert ids == [101, 103]  # 102 endet im Mai, 104 im März -> draußen


def test_naechte_personen_personennaechte():
    rows = {r.booking_id: r for r in make_billing().build(2026, 4)}

    # Buchung 101: 25.04 -> 30.04 = 5 Nächte, 2+1 = 3 Personen
    r = rows[101]
    assert r.nights == 5
    assert r.persons == 3
    assert r.person_nights == 15  # 3 * 5

    # Buchung 103: 05.04 -> 10.04 = 5 Nächte, 2 Personen
    r = rows[103]
    assert r.nights == 5
    assert r.persons == 2
    assert r.person_nights == 10


def test_steuer_und_payment_charge_aus_preiselementen():
    rows = {r.booking_id: r for r in make_billing().build(2026, 4)}
    r = rows[101]
    assert r.tax == 20.0
    assert r.payment_charge == 10.0


def test_ueberwiesener_betrag_und_bezahlt():
    rows = {r.booking_id: r for r in make_billing().build(2026, 4)}

    # Buchung 101: price 500, tax 20, paymentCharge 10 -> ueberwiesen 470
    r = rows[101]
    assert r.total_price == 500.0
    assert r.paid_amount == 500.0
    assert r.transferred_amount == 470.0

    # Buchung 103: keine tax/charge, priceStatus=1 -> ueberwiesen = price
    r = rows[103]
    assert r.transferred_amount == 200.0
    assert r.paid_amount == 200.0


def test_unbezahlte_buchung_liefert_keinen_ueberweisungsbetrag():
    reservations = [
        _reservation(
            200, 1, "2026-04-01", "2026-04-05",
            price=300.0, prepayment=0.0, prepayment_status=0, price_status=0,
        ),
    ]
    client = FakeClient(APARTMENTS, reservations)
    rows = {r.booking_id: r for r in abrechnung.MonthlyBilling(client).build(2026, 4)}
    r = rows[200]
    assert r.paid_amount == 0.0
    assert r.transferred_amount == 0.0


# ---------------------------------------------------------------------- #
# Preis-Elemente via Endpoint
# ---------------------------------------------------------------------- #
def test_preiselemente_werden_nachgeladen_wenn_in_reservierung_fehlen():
    reservations = [
        _reservation(
            300, 1, "2026-04-01", "2026-04-05",
            price=200.0, prepayment=200.0, price_elements=None,
        ),
    ]
    price_elements = {300: [{"type": "tax", "amount": 15.0}, {"type": "paymentCharge", "amount": 5.0}]}
    client = FakeClient(APARTMENTS, reservations, price_elements=price_elements)
    rows = {r.booking_id: r for r in abrechnung.MonthlyBilling(client).build(2026, 4)}
    r = rows[300]
    assert r.tax == 15.0
    assert r.payment_charge == 5.0
    assert client.get_price_elements_calls == 1


def test_preiselemente_endpoint_wird_nicht_angerufen_wenn_in_reservierung_vorhanden():
    client = FakeClient(APARTMENTS, RESERVATIONS)
    abrechnung.MonthlyBilling(client).build(2026, 4)
    assert client.get_price_elements_calls == 0


# ---------------------------------------------------------------------- #
# Channel & Auszahlungsbetrag (Formel)
# ---------------------------------------------------------------------- #
def test_channel_wird_aus_reservierung_ermittelt():
    rows = {r.booking_id: r for r in make_billing().build(2026, 4)}
    assert rows[101].channel == "Airbnb"
    assert rows[103].channel == "Airbnb"


def test_provision_wird_separat_erfasst():
    rows = {r.booking_id: r for r in make_billing().build(2026, 4)}
    # Buchung 101 hat commission 50; payment_charge bleibt 10 (nicht mehr summiert)
    r = rows[101]
    assert r.commission == 50.0
    assert r.payment_charge == 10.0
    # Buchung 103 ohne commission -> 0
    assert rows[103].commission == 0.0


def test_channel_payout_airbnb_formel():
    rows = {r.booking_id: r for r in make_billing().build(2026, 4)}
    r = rows[101]
    # Airbnb: Preis(500) - Provision(50) * 1,19 = 500 - 59,5 = 440,50
    assert r.channel_payout == f"{500.0 - 50.0 * 1.19:.2f}"
    assert r.channel_payout == "440.50"


def test_channel_payout_booking_formel():
    reservation = _reservation(
        400, 1, "2026-04-01", "2026-04-05", price=300.0, prepayment=300.0,
        channel_id=9, channel_name="Booking.com",
        price_elements=[{"type": "commission", "amount": 30.0}],
    )
    client = FakeClient(APARTMENTS, [reservation])
    rows = {r.booking_id: r for r in abrechnung.MonthlyBilling(client).build(2026, 4)}
    r = rows[400]
    # Booking.com: 300 - (300 * 0,014 + 30 * 1,19) = 300 - (4,2 + 35,7) = 260,10
    expected = 300.0 - (300.0 * 0.014 + 30.0 * 1.19)
    assert r.channel_payout == f"{expected:.2f}"
    assert r.channel_payout == "260.10"


def test_channel_payout_unbekannt():
    reservation = _reservation(
        500, 1, "2026-04-01", "2026-04-05", price=200.0, prepayment=200.0,
        channel_name="Expedia",
    )
    client = FakeClient(APARTMENTS, [reservation])
    rows = {r.booking_id: r for r in abrechnung.MonthlyBilling(client).build(2026, 4)}
    assert rows[500].channel_payout == "Unklar"


def test_channel_payout_fallback_ueber_channel_id():
    # Kein channelName, nur channelId -> Fallback über Mapping.
    reservation = _reservation(
        600, 1, "2026-04-01", "2026-04-05", price=200.0, prepayment=200.0,
        channel_id=9, channel_name=None,
        price_elements=[{"type": "commission", "amount": 20.0}],
    )
    client = FakeClient(APARTMENTS, [reservation])
    rows = {r.booking_id: r for r in abrechnung.MonthlyBilling(client).build(2026, 4)}
    r = rows[600]
    assert r.channel == "Booking.com"
    assert r.channel_payout == f"{200.0 - (200.0 * 0.014 + 20.0 * 1.19):.2f}"


def test_channel_payout_direct_booking_wie_airbnb():
    # Direct booking wird (versuchsweise) wie Airbnb berechnet: Preis - Provision*1,19
    reservation = _reservation(
        700, 1, "2026-04-01", "2026-04-05", price=200.0, prepayment=200.0,
        channel_id=13, channel_name="Direct booking",
        price_elements=[{"type": "commission", "amount": 20.0}],
    )
    client = FakeClient(APARTMENTS, [reservation])
    rows = {r.booking_id: r for r in abrechnung.MonthlyBilling(client).build(2026, 4)}
    r = rows[700]
    assert r.channel == "Direct booking"
    assert r.channel_payout == f"{200.0 - 20.0 * 1.19:.2f}"


def test_channel_payout_website_wie_airbnb():
    # Website wird (versuchsweise) wie Airbnb berechnet: Preis - Provision*1,19
    reservation = _reservation(
        701, 1, "2026-04-01", "2026-04-05", price=200.0, prepayment=200.0,
        channel_name="Website",
        price_elements=[{"type": "commission", "amount": 20.0}],
    )
    client = FakeClient(APARTMENTS, [reservation])
    rows = {r.booking_id: r for r in abrechnung.MonthlyBilling(client).build(2026, 4)}
    r = rows[701]
    assert r.channel == "Website"
    assert r.channel_payout == f"{200.0 - 20.0 * 1.19:.2f}"


def test_channel_payout_direct_booking_fallback_ueber_channel_id():
    # channel_id=13 ohne channelName -> Fallback "Direct booking" -> Airbnb-Formel
    reservation = _reservation(
        702, 1, "2026-04-01", "2026-04-05", price=200.0, prepayment=200.0,
        channel_id=13, channel_name=None,
        price_elements=[{"type": "commission", "amount": 20.0}],
    )
    client = FakeClient(APARTMENTS, [reservation])
    rows = {r.booking_id: r for r in abrechnung.MonthlyBilling(client).build(2026, 4)}
    r = rows[702]
    assert r.channel == "Direct booking"
    assert r.channel_payout == f"{200.0 - 20.0 * 1.19:.2f}"


def test_status_filter_verwirft_stornos():
    # Stornierte Buchungen (status != 'booked') duerfen nicht in der Abrechnung landen.
    booked = _reservation(
        800, 1, "2026-04-01", "2026-04-05", price=100.0, prepayment=100.0,
    )
    cancelled = _reservation(
        801, 1, "2026-04-02", "2026-04-06", price=999.0, prepayment=0.0,
        prepayment_status=0, price_status=0,
    )
    cancelled["status"] = "cancelled"
    booked["status"] = "booked"
    client = FakeClient(APARTMENTS, [booked, cancelled])
    rows = {r.booking_id: r for r in abrechnung.MonthlyBilling(client).build(2026, 4)}
    assert 800 in rows
    assert 801 not in rows


def test_status_fehlend_wird_behalten():
    # Fehlt das status-Feld, wird die Buchung (defensiv) weiter beruecksichtigt.
    reservation = _reservation(
        802, 1, "2026-04-01", "2026-04-05", price=100.0, prepayment=100.0,
    )
    assert "status" not in reservation
    client = FakeClient(APARTMENTS, [reservation])
    rows = {r.booking_id: r for r in abrechnung.MonthlyBilling(client).build(2026, 4)}
    assert 802 in rows


def test_storno_typ_und_sperrung_werden_ausgefiltert():
    cancelled = _reservation(810, 1, "2026-04-01", "2026-04-05", price=100.0, prepayment=100.0)
    cancelled["type"] = "cancellation"
    blocked = _reservation(811, 1, "2026-04-02", "2026-04-06", price=100.0, prepayment=100.0)
    blocked["is-blocked-booking"] = True
    booked = _reservation(812, 1, "2026-04-03", "2026-04-07", price=100.0, prepayment=100.0)
    booked["status"] = "booked"
    client = FakeClient(APARTMENTS, [cancelled, blocked, booked])
    rows = {r.booking_id: r for r in abrechnung.MonthlyBilling(client).build(2026, 4)}
    assert 810 not in rows
    assert 811 not in rows
    assert 812 in rows


def test_gast_und_unterkunft_sind_gesetzt():
    rows = {r.booking_id: r for r in make_billing().build(2026, 4)}
    r = rows[101]
    assert r.guest_name == "Max Mustermann"
    assert r.apartment_name == "Ferienwohnung Nord"


def test_smoobu_listenformat_liefert_gast_unterkunft_channel():
    reservation = {
        "id": 900,
        "arrival": "2026-04-01",
        "departure": "2026-04-05",
        "adults": 2,
        "children": 0,
        "price": 180.0,
        "prepayment": 180.0,
        "prepaymentStatus": 1,
        "priceStatus": 1,
        "priceCurrency": "EUR",
        "apartment": {"id": 1, "name": "Ferienwohnung Nord"},
        "guest-name": "Erika Muster",
        "channel": {"id": 63, "name": "Airbnb"},
        "priceElements": [{"type": "commission", "amount": 20.0}],
        "status": "booked",
    }
    client = FakeClient(APARTMENTS, [reservation])
    rows = {r.booking_id: r for r in abrechnung.MonthlyBilling(client).build(2026, 4)}
    r = rows[900]
    assert r.guest_name == "Erika Muster"
    assert r.apartment_name == "Ferienwohnung Nord"
    assert r.apartment_id == 1
    assert r.channel == "Airbnb"


def test_ermittelte_einnahme_booking_com_formel():
    reservation = _reservation(
        400, 1, "2026-04-01", "2026-04-05", price=300.0, prepayment=300.0,
        channel_id=9, channel_name="Booking.com",
        price_elements=[{"type": "commission", "amount": 30.0}],
    )
    client = FakeClient(APARTMENTS, [reservation])
    rows = {r.booking_id: r for r in abrechnung.MonthlyBilling(client).build(2026, 4)}
    r = rows[400]
    # Excel: P3-(P3*1,4%+R3*1,19) = 300 - (300*0,014 + 30*1,19) = 260,10
    expected = 300.0 - (300.0 * 0.014 + 30.0 * 1.19)
    assert r.net_revenue == round(expected, 2)
    assert r.net_revenue == 260.10


def test_ermittelte_einnahme_airbnb_formel():
    rows = {r.booking_id: r for r in make_billing().build(2026, 4)}
    r = rows[101]
    # Airbnb: Preis(500) - Provision(50)*1,19 = 440,50
    assert r.net_revenue == round(500.0 - 50.0 * 1.19, 2)
    assert rows[103].net_revenue == 200.0



# ---------------------------------------------------------------------- #
# CSV-Export
# ---------------------------------------------------------------------- #
def test_csv_export_enthält_personennächte_spalte():
    rows = make_billing().build(2026, 4)
    path = "/tmp/test_abrechnung.csv"
    abrechnung.write_csv(rows, path)
    with open(path, encoding="utf-8-sig") as fh:
        reader = csv.reader(fh, delimiter=";")
        header = next(reader)
        data = list(reader)

    assert "Personen" in header
    assert "Personennächte" in header
    assert "Ermittelte Einnahme" in header
    assert "Preisstatus" not in header
    assert header.index("Ermittelte Einnahme") == header.index("Gesamtpreis") - 1
    assert header == abrechnung.CSV_HEADERS
    dep_index = header.index("Abreise")
    assert data[-2][dep_index] == "Summe"
    assert data[-1][dep_index] == "Steuer 5%"
    assert data[-2][0] == ""
    assert data[-1][0] == ""
    bookings = data[:-2]
    assert len(bookings) == 2  # zwei Buchungen im April
    # Personennächte-Spalte folgt auf Personen, Ermittelte Einnahme folgt darauf
    personen_index = header.index("Personen")
    pn_index = header.index("Personennächte")
    rev_index = header.index("Ermittelte Einnahme")
    assert pn_index == personen_index + 1
    assert rev_index == pn_index + 1
    person_nights = sorted(int(row[pn_index]) for row in bookings)
    assert person_nights == [10, 15]
    assert int(data[-2][pn_index]) == 25
    assert data[-2][rev_index] == abrechnung._csv_money(440.50 + 200.0)
    assert data[-1][pn_index] == ""
    assert data[-1][rev_index] == abrechnung._csv_money((440.50 + 200.0) * 0.05)
    # Geldbeträge im CSV mit Dezimalkomma, Trenner bleibt Semikolon
    price_index = header.index("Gesamtpreis")
    assert "," in bookings[0][price_index]
    assert "." not in bookings[0][price_index]


# ---------------------------------------------------------------------- #
# CLI / Monatsparser
# ---------------------------------------------------------------------- #
def test_monatsparser_formate():
    assert abrechnung._parse_month("2026-04") == (2026, 4)
    assert abrechnung._parse_month("04.2026") == (2026, 4)
    assert abrechnung._parse_month("202604") == (2026, 4)


def test_monatsparser_ungültig():
    import argparse

    for bad in ["2026-13", "2026-00", "abc", "2026"]:
        try:
            abrechnung._parse_month(bad)
        except argparse.ArgumentTypeError:
            continue
        raise AssertionError(f"Ungültiger Monat '{bad}' wurde akzeptiert")


def test_nights_und_parse_date_hilfsfunktionen():
    assert abrechnung._nights(date(2026, 4, 1), date(2026, 4, 5)) == 4
    assert abrechnung._nights(date(2026, 4, 5), date(2026, 4, 5)) == 0
    assert abrechnung._parse_date("2026-04-30") == date(2026, 4, 30)
    assert abrechnung._parse_date("2026-04-30T10:00:00Z") == date(2026, 4, 30)
    assert abrechnung._parse_date(None) is None


def test_beherbergungsteuer_pdf_fuellt_relevante_felder():
    from pypdf import PdfReader

    rows = make_billing().build(2026, 4)
    path = "/tmp/test_beherbergungsteuer.pdf"
    abrechnung.write_beherbergungsteuer_pdf(
        rows, 2026, 4, path, filing_date=date(2026, 8, 18)
    )
    fields = PdfReader(path).get_fields()
    revenue = 440.50 + 200.0
    assert fields["2"].get("/V") == "2026"
    assert fields["PK"].get("/V") == "06200376"
    assert str(fields["1"].get("/V")) == "/0"  # Anmeldung
    assert str(fields["6"].get("/V")) == "/Ja"  # April
    assert str(fields["9"].get("/V")) == "/Off"  # Juli aus der Vorlage abgewählt
    page = PdfReader(path).pages[0]
    anmeldung_as = None
    korrektur_as = None
    for annot in page["/Annots"]:
        obj = annot.get_object()
        parent = obj.get("/Parent")
        if parent is None or str(parent.get("/T") or "") != "1":
            continue
        appearance = (obj.get("/AP") or {}).get("/N")
        keys = [str(k) for k in appearance.keys()] if appearance is not None and hasattr(appearance, "keys") else []
        if "/0" in keys:
            anmeldung_as = str(obj.get("/AS"))
        elif "/1" in keys:
            korrektur_as = str(obj.get("/AS"))
    assert anmeldung_as == "/0"
    assert korrektur_as == "/Off"
    assert fields["B_9"].get("/V") == "25"
    assert fields["B_10"].get("/V") == abrechnung._csv_money(revenue)
    assert fields["B_11"].get("/V") in ("", None)
    assert fields["B_12"].get("/V") == abrechnung._csv_money(revenue)
    assert fields["B_13"].get("/V") == abrechnung._csv_money(revenue * 0.05)
    assert fields["B_14"].get("/V") == abrechnung._csv_money(revenue * 0.05)
    assert fields["Datum"].get("/V") == "18.8.2026"
    assert fields["B_1"].get("/V") == "Junghans"
    assert fields["B_4"].get("/V") == "09126 Chemnitz"


def test_beherbergungsteuer_pdf_hakt_juni_an():
    from pypdf import PdfReader

    rows = make_billing().build(2026, 4)
    path = "/tmp/test_beherbergungsteuer_juni.pdf"
    abrechnung.write_beherbergungsteuer_pdf(
        rows, 2026, 6, path, filing_date=date(2026, 7, 3)
    )
    fields = PdfReader(path).get_fields()
    assert str(fields["1"].get("/V")) == "/0"
    assert str(fields["8"].get("/V")) == "/Ja"  # Juni
    assert str(fields["9"].get("/V")) == "/Off"
    assert fields["Datum"].get("/V") == "3.7.2026"
