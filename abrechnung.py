"""Monatsabrechnung für Smoobu.

Dieses Modul ruft alle Buchungen aus Smoobu ab, deren Abrechnedatum
(``departureDate``) in einem vorgegebenen Monat liegt, und erstellt daraus
einen CSV-Report mit den für die Monatsabrechnung relevanten Kennzahlen:

- Unterkunft (Apartment)
- Gast, Anreise, Abreise
- Nächte (= Abreise - Anreise)
- Personen (= adults + children)
- Personennächte (= Personen * Nächte)
- Gesamtpreis, Steuer, Payment-Charge, überwiesener Betrag, bezahlter Betrag

Die Authentifizierung erfolgt über das von Smoobu empfohlene HMAC-Verfahren.
"""

from __future__ import annotations

import argparse
import base64
import calendar
import csv
import hashlib
import hmac
import json
import logging
import os
import sys
import time
import uuid
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone
from typing import Any, Iterable
from urllib.parse import urlencode, urlsplit

# Detailliertes Logging, damit Endlosschleifen und API-Antworten nachvollziehbar
# sind. Die Ausgaben sind bewusst nicht abschaltbar, da sie der Fehlersuche dienen.
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
log = logging.getLogger("abrechnung")

try:  # ``requests`` ist optional; ohne Live-Credentials nutzt der Client urllib.
    import requests  # type: ignore
except Exception:  # pragma: no cover - nur relevant in nackten Umgebungen
    requests = None

try:
    from dotenv import load_dotenv  # type: ignore
except Exception:  # pragma: no cover

    def load_dotenv(*_args: Any, **_kwargs: Any) -> bool:  # type: ignore[misc]
        return False


try:
    from pypdf import PdfReader, PdfWriter
    from pypdf.generic import NameObject
except Exception:  # pragma: no cover
    PdfReader = None  # type: ignore[misc, assignment]
    PdfWriter = None  # type: ignore[misc, assignment]
    NameObject = None  # type: ignore[misc, assignment]


BASE_URL = "https://login.smoobu.com"

# Belegung des Zahlungsstatus laut Smoobu-Doku: 0 = offen/unbezahlt, 1 = bezahlt.
PAID = 1


@dataclass
class SmoobuConfig:
    """Laufzeit-Konfiguration für den Smoobu-Client.

    Werte können über Umgebungsvariablen oder den Konstruktor gesetzt werden.
    """

    api_key: str = field(default_factory=lambda: os.getenv("SMOOBU_LABEL", ""))
    api_secret: str = field(default_factory=lambda: os.getenv("SMOOBU_SECRET", ""))
    base_url: str = field(default_factory=lambda: os.getenv("SMOOBU_BASE_URL", BASE_URL))

    def validate(self) -> None:
        if not self.api_key or not self.api_secret:
            raise ValueError(
                "SMOOBU_LABEL und SMOOBU_SECRET müssen gesetzt sein "
                "(Umgebungsvariablen oder Konstruktor)."
            )


class SmoobuError(RuntimeError):
    """Fehler bei der Kommunikation mit der Smoobu-API."""

    def __init__(self, message: str, status_code: int | None = None, body: str = ""):
        super().__init__(message)
        self.status_code = status_code
        self.body = body


class SmoobuClient:
    """Minimaler HTTP-Client für die Smoobu-REST-API mit HMAC-Signatur.

    Jeder Request wird gemäß der Smoobu-Doku signiert::

        canonical = METHOD \n PATH \n QUERY \n TIMESTAMP \n NONCE \n BODY_HASH \n API_KEY
        signature = base64(HMAC-SHA256(canonical, api_secret))
    """

    def __init__(self, config: SmoobuConfig | None = None, *, timeout: float = 30.0):
        self.config = config or SmoobuConfig()
        self.config.validate()
        self.timeout = timeout

    # ------------------------------------------------------------------ #
    # Signatur
    # ------------------------------------------------------------------ #
    @staticmethod
    def _canonical_query(query: str) -> str:
        """Sortiert Query-Parameter alphabetisch (sofern vorhanden).

        Smoobu erwartet die Parameter im kanonischen String alphabetisch
        sortiert; der Query-String der eigentlichen URL darf beliebig sein.
        """
        if not query:
            return ""
        params: list[tuple[str, str]] = []
        for part in query.split("&"):
            if not part:
                continue
            if "=" in part:
                key, value = part.split("=", 1)
            else:
                key, value = part, ""
            params.append((key, value))
        params.sort(key=lambda kv: kv[0])
        return "&".join(f"{k}={v}" for k, v in params)

    def _sign(self, method: str, path: str, query: str, body: bytes) -> dict[str, str]:
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        nonce = str(uuid.uuid4())
        body_hash = hashlib.sha256(body).hexdigest()
        canonical_query = self._canonical_query(query)
        canonical = "\n".join(
            [method.upper(), path, canonical_query, timestamp, nonce, body_hash, self.config.api_key]
        )
        signature = base64.b64encode(
            hmac.new(self.config.api_secret.encode("utf-8"), canonical.encode("utf-8"), hashlib.sha256).digest()
        ).decode("ascii")
        return {
            "X-API-Key": self.config.api_key,
            "X-Timestamp": timestamp,
            "X-Nonce": nonce,
            "X-Signature": signature,
        }

    # ------------------------------------------------------------------ #
    # HTTP
    # ------------------------------------------------------------------ #
    def request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        body: Any = None,
    ) -> Any:
        if not path.startswith("/"):
            path = "/" + path
        split = urlsplit(path)
        path_only = split.path
        query = split.query
        if params:
            extra = urlencode(params, doseq=True)
            query = f"{query}&{extra}" if query else extra

        body_bytes = b""
        headers: dict[str, str] = {}
        if body is not None:
            body_bytes = json.dumps(body, separators=(",", ":")).encode("utf-8")
            headers["Content-Type"] = "application/json"

        headers.update(self._sign(method, path_only, query, body_bytes))

        url = self.config.base_url + path_only + (f"?{query}" if query else "")
        log.info("HTTP %s %s (body=%d bytes)", method.upper(), url, len(body_bytes))
        response = self._http(method, url, headers, body_bytes)
        log.info(
            "Antwort %s %s -> status=%d, %d bytes",
            method.upper(), url, response.status_code, len(response.text or ""),
        )
        return self._handle(response, path_only)

    def _http(self, method: str, url: str, headers: dict[str, str], body: bytes) -> "Response":
        if requests is not None:
            resp = requests.request(method, url, headers=headers, data=body, timeout=self.timeout)
            return Response(resp.status_code, resp.text, dict(resp.headers))
        # Fallback ohne ``requests``.
        import urllib.request

        req = urllib.request.Request(url, data=body if body else None, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:  # noqa: S310
                return Response(r.status, r.read().decode("utf-8", "replace"), dict(r.headers))
        except urllib.error.HTTPError as e:  # noqa: PERF203
            return Response(e.code, e.read().decode("utf-8", "replace"), dict(e.headers))

    @staticmethod
    def _handle(response: "Response", path: str = "") -> Any:
        # 404 auf /api/booking/{id}/price-elements ist ein erwarteter Fall:
        # nicht jede Buchung hat Preiselemente. Daher nur INFO statt WARNING;
        # get_price_elements faengt die Ausnahme ab und liefert [].
        expected_404 = path.endswith("/price-elements") and response.status_code == 404
        if response.status_code == 429:
            retry = response.headers.get("X-RateLimit-Retry-After")
            log.warning("Smoobu Rate-Limit (429). Retry-After=%s", retry)
            raise SmoobuError(
                f"Rate-Limit überschritten (429). Retry-After: {retry}",
                status_code=429,
                body=response.text,
            )
        if response.status_code >= 400:
            snippet = response.text[:500]
            # Smoobu liefert bei Fehlern (z. B. 404) oft eine HTML-Seite statt JSON.
            # Diese nicht als Text ins Log schreiben, sondern nur grob kennzeichnen.
            stripped = snippet.lstrip().lower()
            is_html = stripped.startswith("<!doctype") or stripped.startswith("<html")
            if expected_404:
                if is_html:
                    log.info(
                        "price-elements: 404 fuer %s, HTML-Antwort (%d bytes) - erwartet, "
                        "keine Preiselemente.",
                        path, len(response.text or ""),
                    )
                else:
                    log.info("price-elements: 404 fuer %s - erwartet, keine Preiselemente.", path)
            else:
                if is_html:
                    log.warning(
                        "Smoobu-API-Fehler %d: HTML-Antwort (%d bytes) statt JSON.",
                        response.status_code, len(response.text or ""),
                    )
                else:
                    log.warning("Smoobu-API-Fehler %d: %s", response.status_code, snippet)
            raise SmoobuError(
                f"Smoobu-API-Fehler {response.status_code}: {response.text[:500]}",
                status_code=response.status_code,
                body=response.text,
            )
        if not response.text:
            return None
        try:
            return json.loads(response.text)
        except json.JSONDecodeError:
            return response.text

    # ------------------------------------------------------------------ #
    # Endpoints
    # ------------------------------------------------------------------ #
    def get_apartments(self) -> list[dict[str, Any]]:
        data = self.request("GET", "/api/apartments")
        body = data.get("body", data) if isinstance(data, dict) else data
        if isinstance(body, dict):
            apartments = body.get("apartments") or body.get("data") or []
        elif isinstance(body, list):
            apartments = body
        else:
            apartments = []
        return [a for a in apartments if isinstance(a, dict)]

    def get_reservations(self, from_date: str, to_date: str) -> list[dict[str, Any]]:
        """Liefert alle Reservierungen im Zeitraum ``from_date``..``to_date``.

        Paginierung mit mehreren Sicherheitsnetzen gegen Endlosschleifen:

        - Abbruch, sobald eine Seite keine *neuen* Buchungen mehr liefert
          (die API wiederholt dieselbe Seite => sonst Endlosschleife).
        - Abbruch bei ``len(bookings) < requested_page_size`` (letzte Seite).
        - Abbruch, sobald ``total`` erreicht ist (falls gemeldet).
        - harte Begrenzung auf ``MAX_PAGES`` Seiten.
        """
        requested_page_size = 100
        max_pages = 1000  # Sicherheitsbremse
        results: list[dict[str, Any]] = []
        seen_ids: set[Any] = set()
        page = 1
        log.info(
            "get_reservations: von=%s bis=%s, pageSize=%d, maxPages=%d",
            from_date, to_date, requested_page_size, max_pages,
        )
        while page <= max_pages:
            data = self.request(
                "GET",
                "/api/reservations",
                params={
                    "from": from_date,
                    "to": to_date,
                    "page": page,
                    "pageSize": requested_page_size,
                    "includePriceElements": "true",
                    "excludeBlocked": "true",
                },
            )
            body = data.get("body", data) if isinstance(data, dict) else data
            bookings = []
            if isinstance(body, dict):
                bookings = (
                    body.get("bookings")
                    or body.get("reservations")
                    or body.get("data")
                    or []
                )
            elif isinstance(body, list):
                bookings = body

            new_bookings = []
            for b in bookings:
                if not isinstance(b, dict):
                    continue
                bid = b.get("id")
                if bid is not None and bid in seen_ids:
                    continue
                if bid is not None:
                    seen_ids.add(bid)
                new_bookings.append(b)
            results.extend(new_bookings)

            total = _as_int(_get(body, "total")) if isinstance(body, dict) else None
            # pageSize aus der Antwort ist unzuverlässig (oft konstant); wir setzen
            # die Obergrenze auf den angeforderten Wert, damit der "letzte Seite"-
            # Abbruch verlässlich greift.
            page_size = min(_as_int(_get(body, "pageSize")) or requested_page_size, requested_page_size)

            log.info(
                "get_reservations: Seite %d -> %d Buchungen (%d neu, %d dup), kum.=%d, total=%s",
                page, len(bookings), len(new_bookings), len(bookings) - len(new_bookings),
                len(results), total,
            )

            # Abbruchbedingungen (jede einzeln geloggt zur Diagnose):
            if not bookings:
                log.info("get_reservations: Abbruch, Seite %d leer.", page)
                break
            if not new_bookings:
                log.warning(
                    "get_reservations: Abbruch, Seite %d brachte keine neuen Buchungen "
                    "(moegliche Endlosschleife durch API verhindert).", page,
                )
                break
            if total is not None and len(results) >= total:
                log.info("get_reservations: Abbruch, total=%d erreicht (kum=%d).", total, len(results))
                break
            if len(bookings) < page_size:
                log.info("get_reservations: Abbruch, letzte Seite (%d < %d).", len(bookings), page_size)
                break
            page += 1

        if page > max_pages:
            log.warning(
                "get_reservations: Sicherheitsbremse bei %d Seiten erreicht (%d Buchungen). "
                "Abbruch erzwungen, um Endlosschleife zu vermeiden.",
                max_pages, len(results),
            )
        log.info("get_reservations: fertig, %d Buchungen gesamt.", len(results))
        return results

    def get_booking(self, booking_id: int) -> dict[str, Any]:
        data = self.request("GET", f"/api/reservations/{booking_id}")
        body = data.get("body", data) if isinstance(data, dict) else data
        return body if isinstance(body, dict) else {}

    def get_price_elements(self, booking_id: int) -> list[dict[str, Any]]:
        """Preiselemente (Basispreis, Reinigung, Steuer, Payment-Charge ...) einer Buchung.

        Die Smoobu-Doku nennt ``/api/reservations/{id}/price-elements``; ältere
        Integrationen nutzen ``/api/booking/{id}/price-elements``. Beide Pfade
        werden versucht; 404 ist ein erwarteter Fall.
        """
        last_404: SmoobuError | None = None
        for path in (
            f"/api/reservations/{booking_id}/price-elements",
            f"/api/booking/{booking_id}/price-elements",
        ):
            try:
                data = self.request("GET", path)
            except SmoobuError as err:
                if err.status_code == 404:
                    last_404 = err
                    continue
                raise
            body = data.get("body", data) if isinstance(data, dict) else data
            if isinstance(body, dict):
                elements = body.get("priceElements") or body.get("data") or body.get("elements") or []
            elif isinstance(body, list):
                elements = body
            else:
                elements = []
            return [e for e in elements if isinstance(e, dict)]
        if last_404 is not None:
            return []
        return []


@dataclass
class Response:
    status_code: int
    text: str
    headers: dict[str, str]


# ---------------------------------------------------------------------- #
# Hilfsfunktionen
# ---------------------------------------------------------------------- #
def _get(obj: Any, key: str, default: Any = None) -> Any:
    if isinstance(obj, dict):
        return obj.get(key, default)
    return default


def _as_number(value: Any) -> float:
    if value is None:
        return 0.0
    if isinstance(value, bool):  # bool ist Subtyp von int → absichern
        return 0.0
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _as_int(value: Any) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        try:
            return int(float(value))
        except (TypeError, ValueError):
            return None


def _parse_date(value: Any) -> date | None:
    if value is None:
        return None
    if isinstance(value, date) and not isinstance(value, datetime):
        return value
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, str):
        for fmt in ("%Y-%m-%d", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S"):
            try:
                return datetime.strptime(value[: len("2026-04-01") + 9 if "T" in value else 10], fmt).date()
            except ValueError:
                continue
        # Letzter Versuch: nur Datumsanteil.
        try:
            return datetime.strptime(value[:10], "%Y-%m-%d").date()
        except ValueError:
            return None
    return None


def _nights(arrival: date, departure: date) -> int:
    delta = (departure - arrival).days
    return delta if delta > 0 else 0


# Bekannte Smoobu-Channel-IDs (Auszug) für den Fallback, falls channelName fehlt.
_CHANNEL_NAMES = {
    63: "Airbnb",
    9: "Booking.com",
    24: "Booking.com",
    13: "Direct booking",
    70: "Direkt/Smoobu",
}


def _channel_name(channel_id: Any) -> str:
    cid = _as_int(channel_id)
    if cid is None:
        return ""
    return _CHANNEL_NAMES.get(cid, "")


def _channel_payout_amount(channel: str, price: float, commission: float) -> float | None:
    """Numerischer Auszahlungsbetrag je Kanal, oder None wenn unbekannt.

    Booking.com: Preis - (Preis * 1,4 % + Provision * 1,19)
    Airbnb / Direct booking / Website: Preis - Provision * 1,19
    """
    name = (channel or "").lower()
    if "airbnb" in name or "direct" in name or "website" in name:
        return price - commission * 1.19
    if "booking" in name:
        return price - (price * 0.014 + commission * 1.19)
    return None


def _channel_payout(channel: str, price: float, commission: float) -> str:
    """Auszahlungsbetrag je nach Buchungskanal.

    Entspricht der Excel-Formel:
      Airbnb:            Preis - Provision * 1,19
      Direct booking:    Preis - Provision * 1,19   (versuchsweise wie Airbnb)
      Website:           Preis - Provision * 1,19   (versuchsweise wie Airbnb)
      Booking.com:       Preis - (Preis * 1,4 % + Provision * 1,19)
      sonst:             "Unklar"

    Die Zuordnung erfolgt groß-/kleinschreibungsunabhängig anhand des
    Channel-Namens (z. B. ``channelName`` der Reservierung).
    """
    amount = _channel_payout_amount(channel, price, commission)
    if amount is None:
        return "Unklar"
    return f"{amount:.2f}"


def _net_revenue(
    channel: str,
    price: float,
    commission: float,
    tax: float,
    payment_charge: float,
) -> float:
    """Ermittelte Einnahme: kanalspezifische Formel, sonst Preis minus Gebühren."""
    amount = _channel_payout_amount(channel, price, commission)
    if amount is not None:
        return round(amount, 2)
    return round(price - tax - payment_charge - commission, 2)


def _persons(reservation: dict[str, Any]) -> int:
    """Personen = Erwachsene + Kinder; Fallback auf ``guests``."""
    adults = _as_int(reservation.get("adults")) if "adults" in reservation else None
    children = None
    for key in ("children", "kids", "childs"):
        if key in reservation and reservation.get(key) is not None:
            children = _as_int(reservation.get(key))
            break
    if adults is not None or children is not None:
        return (adults or 0) + (children or 0)
    for key in ("guests", "guestCount", "numberOfGuests", "guest-count"):
        count = _as_int(reservation.get(key))
        if count:
            return count
    return 0


def _month_range(year: int, month: int) -> tuple[str, str, date, date]:
    """Liefert den Abfragezeitraum für einen Monat.

    Smoobu filtert Reservierungen nach Anreise/Abreise im Zeitraum. Um auch
    Buchungen zu erfassen, die im Zielmonat *enden*, fragen wir einen großzügigen
    Zeitraum ab und filtern anschließend anhand des ``departureDate``.
    """
    first = date(year, month, 1)
    last_day = calendar.monthrange(year, month)[1]
    last = date(year, month, last_day)
    # Einen Monat vor und nach, damit überlappende Buchungen sicher enthalten sind.
    start_query = (first - timedelta(days=62)).isoformat()
    end_query = (last + timedelta(days=62)).isoformat()
    return start_query, end_query, first, last


# ---------------------------------------------------------------------- #
# Abrechnung
# ---------------------------------------------------------------------- #
@dataclass
class BillingRow:
    booking_id: int
    apartment_id: int
    apartment_name: str
    guest_name: str
    arrival: str
    departure: str
    nights: int
    persons: int
    person_nights: int  # Personen * Nächte
    total_price: float
    tax: float
    payment_charge: float
    commission: float  # Provision (Channel-Provision)
    channel: str  # Buchungskanal (Airbnb, Booking.com, ...)
    channel_payout: str  # Auszahlungsbetrag je nach Channel (Formel) oder "Unklar"
    paid_amount: float  # bezahlter Betrag
    transferred_amount: float  # überwiesener Betrag
    net_revenue: float  # Ermittelte Einnahme (kanalspezifische Formel)
    currency: str

    def as_csv_row(self) -> list[Any]:
        return [
            self.booking_id,
            self.apartment_id,
            self.apartment_name,
            self.guest_name,
            self.arrival,
            self.departure,
            self.nights,
            self.persons,
            self.person_nights,
            _csv_money(self.net_revenue),
            _csv_money(self.total_price),
            _csv_money(self.tax),
            _csv_money(self.payment_charge),
            _csv_money(self.commission),
            self.channel,
            _csv_money_or_text(self.channel_payout),
            _csv_money(self.paid_amount),
            _csv_money(self.transferred_amount),
            self.currency,
        ]


CSV_HEADERS = [
    "Buchungs-ID",
    "Unterkunft-ID",
    "Unterkunft",
    "Gast",
    "Anreise",
    "Abreise",
    "Nächte",
    "Personen",
    "Personennächte",
    "Ermittelte Einnahme",
    "Gesamtpreis",
    "Steuer",
    "Payment-Charge",
    "Provision",
    "Channel",
    "Auszahlungsbetrag (Channel)",
    "Bezahlter Betrag",
    "Überwiesener Betrag",
    "Währung",
]


class MonthlyBilling:
    """Erstellt die Monatsabrechnung aus Smoobu-Buchungen."""

    def __init__(self, client: SmoobuClient):
        self.client = client
        self._apartment_names: dict[int, str] = {}

    # ------------------------------------------------------------------ #
    def _load_apartment_names(self) -> dict[int, str]:
        if self._apartment_names:
            return self._apartment_names
        try:
            apartments = self.client.get_apartments()
        except SmoobuError:
            apartments = []
        for apt in apartments:
            apt_id = _as_int(apt.get("id"))
            if apt_id is not None:
                name = apt.get("name") or apt.get("title") or f"Apartment {apt_id}"
                self._apartment_names[apt_id] = str(name)
        return self._apartment_names

    # ------------------------------------------------------------------ #
    def build(self, year: int, month: int) -> list[BillingRow]:
        start_q, end_q, first, last = _month_range(year, month)
        log.info("build: Abrechnung %04d-%02d, Abfragezeitraum %s..%s", year, month, start_q, end_q)
        apartments = self._load_apartment_names()
        log.info("build: %d Wohnung(en) geladen.", len(apartments))
        reservations = self.client.get_reservations(start_q, end_q)
        log.info("build: %d Reservierung(en) geladen, filtere auf Abreise im Zielmonat.", len(reservations))

        rows: list[BillingRow] = []
        skipped = 0
        skipped_status = 0
        for res in reservations:
            # Nur aktive Buchungen beruecksichtigen. Smoobu liefert 'status'
            # (z. B. 'booked', 'cancelled'). Stornierungen werden verworfen.
            # Fehlt das Feld, wird die Buchung dennoch beruecksichtigt.
            if not _was_carried_out(res):
                skipped_status += 1
                continue  # keine Stornos, Sperren oder sonstigen Nicht-Aufenthalte

            departure = _parse_date(res.get("departureDate") or res.get("departure"))
            if departure is None or not (first <= departure <= last):
                skipped += 1
                continue  # nur Buchungen, die im Zielmonat ENDEN

            arrival = _parse_date(res.get("arrivalDate") or res.get("arrival")) or departure
            nights = _nights(arrival, departure)
            persons = _persons(res)
            person_nights = persons * nights

            apartment_id, apartment_name = _apartment_fields(res, apartments)
            guest_name = _guest_name(res)

            # Smoobu liefert in der Listen-Antwort (/api/reservations) haeufig nur
            # gekuerzte Daten: apartmentName, guestName und teils apartmentId fehlen.
            # In diesem Fall rufen wir die Einzelbuchung (/api/reservations/{id}) ab
            # und ergaenzen die fehlenden Felder daraus.
            bid = _as_int(res.get("id")) or 0
            if (not apartment_name or not guest_name or not apartment_id or not persons) and bid:
                log.info(
                    "build: Buchung %s: Liste liefert apartmentId=%s, apartmentName=%r, "
                    "guestName=%r -> lade Buchungsdetails.",
                    bid, apartment_id, apartment_name, guest_name,
                )
                try:
                    detail = self.client.get_booking(bid)
                except SmoobuError as err:
                    log.warning("build: Buchung %s: Detailabruf fehlgeschlagen: %s", bid, err)
                    detail = {}
                if isinstance(detail, dict):
                    d_id, d_name = _apartment_fields(detail, apartments)
                    if not apartment_id:
                        apartment_id = d_id
                    if not apartment_name:
                        apartment_name = d_name
                    if not guest_name:
                        guest_name = _guest_name(detail)
                    if not persons:
                        persons = _persons(detail)
                        person_nights = persons * nights

            if not apartment_name:
                apartment_name = apartments.get(apartment_id) or f"Apartment {apartment_id}"

            total_price = _as_number(res.get("price"))
            currency = str(res.get("priceCurrency") or res.get("currency") or res.get("currencyCode") or "EUR")

            # Bezahlter Betrag: ``prepayment`` ist die geleistete Anzahlung/Zahlung.
            paid_amount = _as_number(res.get("prepayment"))
            prepayment_status = _as_int(res.get("prepaymentStatus"))

            # Preiselemente (Steuer, Payment-Charge, Provision) abrufen.
            tax, payment_charge, commission = self._price_breakdown(res, res.get("id"))

            # Buchungskanal ermitteln. Smoobu liefert channelId und teilweise
            # channelName bzw. ein verschachteltes channel-Objekt.
            channel = _channel_from(res)

            # Auszahlungsbetrag je nach Channel:
            #   Airbnb:      Preis - Provision * 1,19
            #   Booking.com: Preis - (Preis * 1,4 % + Provision * 1,19)
            #   sonst:       "Unklar"
            channel_payout = _channel_payout(channel, total_price, commission)

            # Überwiesener Betrag: Gesamtpreis abzüglich Gebühren/Steuer
            # (Nettoauszahlung an den Vermieter).
            transferred_amount = total_price - tax - payment_charge
            # Falls die Buchung (noch) nicht bezahlt wurde, ist nichts überwiesen.
            if prepayment_status is not None and prepayment_status != PAID:
                transferred_amount = 0.0
                paid_amount = 0.0

            # Ermittelte Einnahme: Booking.com = Preis - (Preis*1,4% + Provision*1,19)
            net_revenue = _net_revenue(channel, total_price, commission, tax, payment_charge)

            rows.append(
                BillingRow(
                    booking_id=_as_int(res.get("id")) or 0,
                    apartment_id=apartment_id,
                    apartment_name=str(apartment_name),
                    guest_name=str(guest_name),
                    arrival=arrival.isoformat(),
                    departure=departure.isoformat(),
                    nights=nights,
                    persons=persons,
                    person_nights=person_nights,
                    total_price=total_price,
                    tax=tax,
                    payment_charge=payment_charge,
                    commission=commission,
                    channel=channel,
                    channel_payout=channel_payout,
                    paid_amount=paid_amount,
                    transferred_amount=transferred_amount,
                    net_revenue=net_revenue,
                    currency=currency,
                )
            )

        rows.sort(key=lambda r: (r.departure, r.apartment_name))
        log.info(
            "build: %d Zeile(n) gebaut, %d Reservierung(en) ausserhalb des Zielmonats, "
            "%d wegen Status != booked verworfen.",
            len(rows), skipped, skipped_status,
        )
        return rows

    # ------------------------------------------------------------------ #
    def _price_breakdown(self, reservation: dict[str, Any], booking_id: Any) -> tuple[float, float, float]:
        """Ermittelt Steuer und Payment-Charge aus den Preiselementen.

        Smoobu liefert pro Preiselement ein ``type``-Feld (z. B. ``basePrice``,
        ``cleaningFee``, ``tax``, ``paymentCharge``, ``commission``). Wir summieren
        die Beträge der Typen ``tax`` und ``paymentCharge``; Provisionen
        (``commission``) werden separat zurückgegeben.
        """
        elements = reservation.get("priceElements") or reservation.get("price-elements")
        if isinstance(elements, list) and elements:
            price_elements = [e for e in elements if isinstance(e, dict)]
        else:
            price_elements = []
            if booking_id:
                price_elements = self.client.get_price_elements(_as_int(booking_id) or 0)

        tax = 0.0
        payment_charge = 0.0
        commission = 0.0
        for elem in price_elements:
            etype = str(elem.get("type", "")).lower()
            amount = _as_number(elem.get("amount"))
            if etype in ("tax", "vat", "steuer"):
                tax += amount
            elif etype in ("commission", "provision"):
                commission += amount
            elif etype in ("paymentcharge", "payment_charge", "payment-charge", "gebuehr"):
                payment_charge += amount
        return tax, payment_charge, commission


def _was_carried_out(reservation: dict[str, Any]) -> bool:
    """True, wenn die Buchung als durchgeführter Aufenthalt zählt.

    Stornierungen, Sperr-Buchungen und andere Status als ``booked`` werden
    ausgefiltert. Fehlt ``status``, bleibt die Buchung (defensiv) enthalten.
    """
    if reservation.get("is-blocked-booking") is True or reservation.get("isBlockedBooking") is True:
        return False
    booking_type = str(reservation.get("type") or "").lower()
    if booking_type in {"cancellation", "cancelled", "canceled"}:
        return False
    status = reservation.get("status")
    if status is not None and str(status).lower() != "booked":
        return False
    return True


def _apartment_fields(reservation: dict[str, Any], apartments: dict[int, str]) -> tuple[int, str]:
    apt = reservation.get("apartment")
    apt_id = _as_int(
        reservation.get("apartmentId")
        or reservation.get("apartment_id")
        or (apt.get("id") if isinstance(apt, dict) else None)
    ) or 0
    apt_name = (
        reservation.get("apartmentName")
        or (apt.get("name") if isinstance(apt, dict) else None)
        or apartments.get(apt_id)
        or ""
    )
    return apt_id, str(apt_name) if apt_name else ""


def _guest_name(reservation: dict[str, Any]) -> str:
    name = reservation.get("guestName") or reservation.get("guest-name") or _full_name(reservation)
    return str(name).strip() if name else ""


def _channel_from(reservation: dict[str, Any]) -> str:
    channel = reservation.get("channel")
    name = reservation.get("channelName")
    channel_id = reservation.get("channelId")
    if isinstance(channel, dict):
        name = name or channel.get("name")
        channel_id = channel_id or channel.get("id")
    elif isinstance(channel, str) and not name:
        name = channel
    return str(name or _channel_name(channel_id) or "Unbekannt")


def _full_name(reservation: dict[str, Any]) -> str:
    first = reservation.get("firstName") or reservation.get("firstname") or ""
    last = reservation.get("lastName") or reservation.get("lastname") or ""
    return f"{first} {last}".strip()


# ---------------------------------------------------------------------- #
# CSV-Export
# ---------------------------------------------------------------------- #
def _csv_money(value: float) -> str:
    """CSV-Geldbetrag mit Dezimalkomma, Trenner bleibt Semikolon."""
    return f"{value:.2f}".replace(".", ",")


def _csv_money_or_text(value: str) -> str:
    if not value or value == "Unklar":
        return value
    return value.replace(".", ",")


def write_csv(rows: Iterable[BillingRow], output_path: str) -> None:
    directory = os.path.dirname(output_path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    rows = list(rows)
    with open(output_path, "w", newline="", encoding="utf-8-sig") as fh:
        writer = csv.writer(fh, delimiter=";")
        writer.writerow(CSV_HEADERS)
        for row in rows:
            writer.writerow(row.as_csv_row())
        for extra in _csv_footer_rows(rows):
            writer.writerow(extra)


def _csv_footer_rows(rows: list[BillingRow]) -> list[list[Any]]:
    """Komfortzeilen: Summe (Personennächte + Ermittelte Einnahme) und Steuer 5 %."""
    person_nights = sum(row.person_nights for row in rows)
    revenue = sum(row.net_revenue for row in rows)
    pn_index = CSV_HEADERS.index("Personennächte")
    revenue_index = CSV_HEADERS.index("Ermittelte Einnahme")
    departure_index = CSV_HEADERS.index("Abreise")

    sum_row = [""] * len(CSV_HEADERS)
    sum_row[departure_index] = "Summe"
    sum_row[pn_index] = person_nights
    sum_row[revenue_index] = _csv_money(revenue)

    tax_row = [""] * len(CSV_HEADERS)
    tax_row[departure_index] = "Steuer 5%"
    tax_row[revenue_index] = _csv_money(revenue * 0.05)
    return [sum_row, tax_row]


# ---------------------------------------------------------------------- #
# Beherbergungsteuer-PDF (Stadt Chemnitz)
# ---------------------------------------------------------------------- #
_MONTH_CHECKBOX = {m: str(m + 2) for m in range(1, 13)}  # Jan="3" … Dez="14"


def default_beherbergung_template() -> str:
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "templates", "beherbergungsteuer.pdf")


def default_betreiber_json() -> str:
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "templates", "betreiber.json")


def load_betreiber(path: str | None = None) -> dict[str, Any]:
    path = path or os.getenv("BEHERBERGUNG_BETREIBER") or default_betreiber_json()
    with open(path, encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise ValueError(f"Betreiber-JSON muss ein Objekt sein: {path}")
    return data


def _german_date(value: date) -> str:
    return f"{value.day}.{value.month}.{value.year}"


def write_beherbergungsteuer_pdf(
    rows: Iterable[BillingRow],
    year: int,
    month: int,
    output_path: str,
    *,
    filing_date: date | None = None,
    template_path: str | None = None,
    betreiber_path: str | None = None,
) -> str:
    """Füllt die amtliche Anmeldung und schreibt sie nach ``output_path``."""
    if PdfReader is None or PdfWriter is None:
        raise RuntimeError("pypdf ist nicht installiert (pip install pypdf).")

    rows = list(rows)
    template_path = template_path or os.getenv("BEHERBERGUNG_TEMPLATE") or default_beherbergung_template()
    if not os.path.isfile(template_path):
        raise FileNotFoundError(f"Beherbergungsteuer-Vorlage nicht gefunden: {template_path}")
    betreiber = load_betreiber(betreiber_path)

    person_nights = sum(row.person_nights for row in rows)
    revenue = sum(row.net_revenue for row in rows)
    tax = revenue * 0.05
    filing_date = filing_date or date.today()

    reader = PdfReader(template_path)
    writer = PdfWriter()
    writer.append(reader)
    page = writer.pages[0]

    writer.update_page_form_field_values(
        page,
        {
            "PK": str(betreiber.get("personenkonto") or ""),
            "2": str(year),
            "B_1": str(betreiber.get("name") or ""),
            "B_2": str(betreiber.get("vorname") or ""),
            "B_3": str(betreiber.get("strasse") or ""),
            "B_4": str(betreiber.get("plz_ort") or ""),
            "B_5": str(betreiber.get("telefon_email") or ""),
            "B_6": str(betreiber.get("einrichtung") or ""),
            "B_7": str(betreiber.get("einrichtung_strasse") or ""),
            "B_8": str(betreiber.get("einrichtung_plz_ort") or ""),
            "B_9": str(person_nights),
            "B_10": _csv_money(revenue),
            "B_11": "",
            "B_12": _csv_money(revenue),
            "B_13": _csv_money(tax),
            "B_14": _csv_money(tax),
            "Datum": _german_date(filing_date),
        },
        auto_regenerate=False,
    )
    _set_anmeldung_checkbox(page)
    _set_month_checkboxes(page, month)

    writer.set_need_appearances_writer(True)

    directory = os.path.dirname(output_path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    with open(output_path, "wb") as handle:
        writer.write(handle)
    return output_path


def _set_month_checkboxes(page, month: int) -> None:
    """Hakt nur den Zielmonat an. Fehlende /Ja-Optik wird von Juli übernommen."""
    widgets: dict[str, Any] = {}
    for annot in page.get("/Annots") or []:
        obj = annot.get_object()
        name = obj.get("/T")
        if name:
            widgets[str(name)] = obj

    donor = None
    for candidate in ("9", "3", "10", "12"):
        widget = widgets.get(candidate)
        if widget is None:
            continue
        appearance = (widget.get("/AP") or {}).get("/N")
        if appearance is not None and hasattr(appearance, "get") and appearance.get("/Ja"):
            donor = widget
            break

    target = _MONTH_CHECKBOX[month]
    for number in range(1, 13):
        name = _MONTH_CHECKBOX[number]
        widget = widgets.get(name)
        if widget is None:
            continue
        if name == target and donor is not None:
            widget[NameObject("/AP")] = donor.get("/AP")
            widget[NameObject("/V")] = NameObject("/Ja")
            widget[NameObject("/AS")] = NameObject("/Ja")
        else:
            widget[NameObject("/V")] = NameObject("/Off")
            widget[NameObject("/AS")] = NameObject("/Off")


def _set_anmeldung_checkbox(page) -> None:
    """Hakt immer die Checkbox „Anmeldung“ (Feld 1, Zustand /0) an."""
    parent = None
    kids: list[Any] = []
    for annot in page.get("/Annots") or []:
        obj = annot.get_object()
        if str(obj.get("/T") or "") == "1":
            parent = obj
        linked = obj.get("/Parent")
        if linked is not None and str(linked.get("/T") or "") == "1":
            kids.append(obj)
            if parent is None:
                parent = linked.get_object() if hasattr(linked, "get_object") else linked
    if parent is not None:
        parent[NameObject("/V")] = NameObject("/0")
    for kid in kids:
        appearance = (kid.get("/AP") or {}).get("/N")
        keys = [str(key) for key in appearance.keys()] if appearance is not None and hasattr(appearance, "keys") else []
        if "/0" in keys:
            kid[NameObject("/AS")] = NameObject("/0")
            kid[NameObject("/V")] = NameObject("/0")
        else:
            kid[NameObject("/AS")] = NameObject("/Off")
            kid[NameObject("/V")] = NameObject("/Off")


def print_summary(rows: list[BillingRow], year: int, month: int) -> None:
    if not rows:
        print(f"Keine Buchungen gefunden, die im {month:02d}/{year} enden.")
        return
    print(
        f"Monatsabrechnung {month:02d}/{year}: {len(rows)} Buchung(en)\n"
        f"  Gesamtpreis gesamt:        {sum(r.total_price for r in rows):.2f}\n"
        f"  Steuer gesamt:             {sum(r.tax for r in rows):.2f}\n"
        f"  Payment-Charge gesamt:     {sum(r.payment_charge for r in rows):.2f}\n"
        f"  Provision gesamt:          {sum(r.commission for r in rows):.2f}\n"
        f"  Ermittelte Einnahme:       {sum(r.net_revenue for r in rows):.2f}\n"
        f"  Steuer 5%:                 {sum(r.net_revenue for r in rows) * 0.05:.2f}\n"
        f"  Bezahlter Betrag gesamt:   {sum(r.paid_amount for r in rows):.2f}\n"
        f"  Überwiesener Betrag gesamt:{sum(r.transferred_amount for r in rows):.2f}\n"
        f"  Personennächte gesamt:     {sum(r.person_nights for r in rows)}"
    )


# ---------------------------------------------------------------------- #
# CLI
# ---------------------------------------------------------------------- #
def _parse_month(value: str) -> tuple[int, int]:
    try:
        if "-" in value:
            year_s, month_s = value.split("-", 1)
        elif "." in value:
            month_s, year_s = value.split(".", 1)
        else:
            if len(value) == 6:  # YYYYMM
                year_s, month_s = value[:4], value[4:]
            else:
                raise ValueError
        year, month = int(year_s), int(month_s)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            'Monat im Format "YYYY-MM", "MM.YYYY" oder "YYYYMM" erwartet.'
        ) from exc
    if not (1 <= month <= 12):
        raise argparse.ArgumentTypeError("Monat muss zwischen 1 und 12 liegen.")
    if year < 2000 or year > 2100:
        raise argparse.ArgumentTypeError("Jahr scheint unplausibel.")
    return year, month


def main(argv: list[str] | None = None) -> int:
    load_dotenv()
    parser = argparse.ArgumentParser(
        description="Monatsabrechnung für Smoobu (Buchungen, die im Zielmonat enden)."
    )
    parser.add_argument("monat", help='Monat, z. B. "2026-04", "04.2026" oder "202604"')
    parser.add_argument(
        "-o",
        "--output",
        default=None,
        help="Pfad zur CSV-Ausgabedatei (Standard: abrechnung_YYYY-MM.csv).",
    )
    parser.add_argument(
        "--api-key",
        default=None,
        help="Smoobu API-Key/Label (überschreibt SMOOBU_LABEL).",
    )
    parser.add_argument(
        "--api-secret",
        default=None,
        help="Smoobu API-Secret (überschreibt SMOOBU_SECRET).",
    )
    args = parser.parse_args(argv)

    year, month = _parse_month(args.monat)
    output = args.output or f"abrechnung_{year:04d}-{month:02d}.csv"

    config = SmoobuConfig()
    if args.api_key:
        config.api_key = args.api_key
    if args.api_secret:
        config.api_secret = args.api_secret
    try:
        config.validate()
    except ValueError as err:
        print(f"Fehler: {err}", file=sys.stderr)
        return 2

    client = SmoobuClient(config)
    billing = MonthlyBilling(client)
    print(f"Lade Buchungen, die im {month:02d}/{year} enden ...")
    rows = billing.build(year, month)
    write_csv(rows, output)
    print_summary(rows, year, month)
    print(f"\nCSV-Report geschrieben: {output}")
    pdf_output = os.path.join(
        os.path.dirname(output) or ".",
        f"beherbergungsteuer_{year:04d}-{month:02d}.pdf",
    )
    write_beherbergungsteuer_pdf(rows, year, month, pdf_output)
    print(f"Beherbergungsteuer-Anmeldung: {pdf_output}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
