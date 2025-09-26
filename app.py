import os, re, time, json
import socket
import ipaddress
from urllib.parse import urljoin
from typing import Optional, List, Dict, Tuple
from fastapi import FastAPI, Request, Query, HTTPException
from fastapi.responses import JSONResponse, HTMLResponse
from fastapi.templating import Jinja2Templates
import httpx

# tldextract (opcjonalny – jeśli brak, użyjemy fallbacku)
try:
    import tldextract  # type: ignore
    _HAS_TLDEXTRACT = True
except Exception:
    tldextract = None  # type: ignore
    _HAS_TLDEXTRACT = False

app = FastAPI(title="RDAP WHOIS")
templates = Jinja2Templates(directory="templates")

RDAP_HEADERS = {
    "Accept": "application/rdap+json, application/json, */*;q=0.1",
    "User-Agent": "rdap-whois/1.1 (+https://example.local)"
}

# Cache na bootstrap IANA
_BOOTSTRAP_DNS: Optional[dict] = None
_BOOTSTRAP_FETCHED_AT: float = 0.0
_BOOTSTRAP_TTL: float = 24 * 3600  # 24h


# ---------------------------
# Pomocnicze: role / vCard
# ---------------------------
def _roles(entity):
    r = entity.get("roles")
    if r is None: return []
    if isinstance(r, list): return r
    if isinstance(r, str): return [r]
    return []


def _vcard(entity, field):
    try:
        for item in entity["vcardArray"][1]:
            if item[0] == field:
                return item[3]
    except Exception:
        pass
    return ""


def _vcard_addr_parts(entity) -> Tuple[str, str, str, str, str, str]:
    """
    Zwraca (street, ext, city, region, postal, country_name) z vCard 'adr'.
    Jeśli brak 'adr' – zwraca puste stringi.
    """
    try:
        for item in entity["vcardArray"][1]:
            if item[0] == "adr":
                adr = item[3] or []
                po, ext, street, locality, region, code, country = (adr + [None]*7)[:7]
                return (street or "", ext or "", locality or "", region or "", code or "", country or "")
    except Exception:
        pass
    return ("", "", "", "", "", "")


def _vcard_addr_cc(entity) -> str:
    """
    Zwraca country code z parametrów 'adr' (np. {'cc': 'PL'}) jeżeli jest.
    """
    try:
        for item in entity["vcardArray"][1]:
            if item[0] == "adr":
                params = item[1] or {}
                cc = params.get("cc")
                if isinstance(cc, str) and cc:
                    return cc
    except Exception:
        pass
    return ""


# ---------------------------
# Wykrywanie typu zapytania
# ---------------------------
def _detect_kind(q: str) -> str:
    if re.fullmatch(r'(?i)AS?\d+', q) or re.fullmatch(r'\d+', q):
        return "autnum"
    if re.fullmatch(r'[0-9a-fA-F:.]+', q):
        return "ip"
    return "domain"


def _is_ip(value: str) -> bool:
    """Dokładna walidacja IP (IPv4/IPv6)."""
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


# ---------------------------
# Domeny / subdomeny
# ---------------------------
def _base_domain(host: str) -> str:
    """
    Zwraca domenę rejestrowalną (np. 'epaka.plus' dla 'pl.epaka.plus').
    Preferuje tldextract (Public Suffix List). Fallback: ostatnie 2-3 etykiety.
    """
    h = (host or "").strip().lower().rstrip(".")
    if _is_ip(h):
        return h
    if _HAS_TLDEXTRACT:
        ext = tldextract.extract(h)  # type: ignore
        if ext.domain and ext.suffix:
            return f"{ext.domain}.{ext.suffix}"
        return h
    parts = h.split(".")
    if len(parts) <= 2:
        return h
    two_label_tlds = {"co.uk", "com.au", "co.jp", "com.br", "co.nz", "org.uk", "gov.uk"}
    last2 = ".".join(parts[-2:])
    last3 = ".".join(parts[-3:])
    if last2 in two_label_tlds and len(parts) >= 3:
        return ".".join(parts[-3:])
    return last2


def _public_suffix(host: str) -> str:
    """
    Zwraca PSL-suffix (np. 'com', 'br', 'com.br' jeśli PSL tak definiuje).
    """
    h = (host or "").strip().lower().rstrip(".")
    if _HAS_TLDEXTRACT:
        ext = tldextract.extract(h)  # type: ignore
        return ext.suffix or ""
    parts = h.split(".")
    if len(parts) <= 1:
        return ""
    two_label_tlds = {"co.uk", "com.au", "co.jp", "com.br", "co.nz", "org.uk", "gov.uk"}
    last2 = ".".join(parts[-2:])
    if last2 in two_label_tlds:
        return last2
    return parts[-1]


# ---------------------------
# Rozwiązywanie IP dla hostów
# ---------------------------
def _resolve_ips(hostname: str) -> List[str]:
    """
    Zwraca unikalne adresy IP (A/AAAA) dla nazwy hosta.
    W przypadku błędu – pusta lista. IPv4 najpierw, potem IPv6.
    """
    hostname = (hostname or "").strip().rstrip(".")
    if not hostname or _is_ip(hostname):
        return []
    ips = set()
    try:
        for res in socket.getaddrinfo(hostname, None):
            addr = res[4][0]
            try:
                ipaddress.ip_address(addr)
                ips.add(addr)
            except ValueError:
                continue
    except socket.gaierror:
        pass

    def _key(ip: str):
        return (0 if ":" not in ip else 1, ip)
    return sorted(ips, key=_key)


# ---------------------------
# IANA RDAP bootstrap (DNS)
# ---------------------------
async def _get_bootstrap_dns(client: httpx.AsyncClient) -> Optional[dict]:
    global _BOOTSTRAP_DNS, _BOOTSTRAP_FETCHED_AT
    now = time.time()
    if _BOOTSTRAP_DNS and (now - _BOOTSTRAP_FETCHED_AT) < _BOOTSTRAP_TTL:
        return _BOOTSTRAP_DNS
    try:
        r = await client.get("https://data.iana.org/rdap/dns.json", headers=RDAP_HEADERS, timeout=15)
        if r.status_code == 200 and "json" in (r.headers.get("content-type") or "").lower():
            _BOOTSTRAP_DNS = r.json()
            _BOOTSTRAP_FETCHED_AT = now
            return _BOOTSTRAP_DNS
    except Exception:
        pass
    return _BOOTSTRAP_DNS  # może być None


def _rdap_bases_for_suffix(bootstrap: dict, suffix: str) -> List[str]:
    """
    Zwraca listę bazowych URL-i RDAP dla danego suffixu na podstawie bootstrapu IANA.
    """
    if not bootstrap or not suffix:
        return []
    services = bootstrap.get("services") or []
    # najpierw próbuj idealnego dopasowania (np. 'com.br'), potem krótszych (np. 'br')
    candidates = [suffix]
    if "." in suffix:
        candidates.append(suffix.split(".")[-1])

    bases: List[str] = []
    for cand in candidates:
        for item in services:
            tlds = item[0] if len(item) > 0 else []
            urls = item[1] if len(item) > 1 else []
            if any(cand == (t or "").lower() for t in tlds):
                for u in urls:
                    if isinstance(u, str) and u.startswith("http"):
                        u = u.rstrip("/") + "/"
                        if u not in bases:
                            bases.append(u)
        if bases:
            break
    return bases


def _extract_alt_rdap_urls(err_json: dict) -> List[str]:
    """
    Wyciąga potencjalne alternatywne linki RDAP z pól 'links' i 'notices[].links'.
    """
    links: List[str] = []
    for lk in (err_json.get("links") or []):
        href = lk.get("href")
        if isinstance(href, str) and href.startswith("http"):
            links.append(href)
    for n in (err_json.get("notices") or []):
        for lk in (n.get("links") or []):
            href = lk.get("href")
            if isinstance(href, str) and href.startswith("http"):
                links.append(href)
    cleaned = [u for u in links if "/domain/" in u]
    seen = set(); uniq = []
    for u in cleaned:
        if u not in seen:
            seen.add(u); uniq.append(u)
    return uniq


# ---------------------------
# Pobieranie RDAP (manualne 302 + auto-follow + bootstrap)
# ---------------------------
async def _get_json_with_redirects(client: httpx.AsyncClient, url: str, attempts: List[dict], max_hops: int = 6) -> Optional[dict]:
    """
    Pętla GET bez automatycznych redirectów. Jeśli 3xx + Location → przechodzimy ręcznie (również relatywne URL-e).
    Dodatkowo, jeśli 2xx nie zwraca JSON-a, robimy drugą próbę z follow_redirects=True.
    """
    current = url
    for hop in range(max_hops):
        try:
            r = await client.get(current, headers=RDAP_HEADERS, follow_redirects=False)
            attempts.append({"url": current, "status": r.status_code, "location": r.headers.get("location") or r.headers.get("Location")})
        except Exception as ex:
            attempts.append({"url": current, "status": "EXC", "error": str(ex)})
            return None

        # 2xx -> spróbuj JSON; jeśli się nie da, zrób ponownie auto-follow (na wszelki wypadek)
        if 200 <= r.status_code < 300:
            try:
                return r.json()
            except Exception:
                try:
                    rr = await client.get(current, headers=RDAP_HEADERS, follow_redirects=True)
                    attempts.append({"url": current, "status": f"retry-follow:{rr.status_code}"})
                    if 200 <= rr.status_code < 300:
                        try:
                            return rr.json()
                        except Exception:
                            try:
                                return json.loads(rr.text or "null")
                            except Exception:
                                return {}
                except Exception as ex:
                    attempts.append({"url": current, "status": "EXC-follow", "error": str(ex)})
                    return None
                return {}

        # 3xx -> ręcznie przeskocz po Location (absolutny/relatywny)
        if 300 <= r.status_code < 400:
            loc = r.headers.get("location") or r.headers.get("Location")
            if not loc:
                return None
            if not loc.lower().startswith("http"):
                loc = urljoin(current, loc)
            current = loc
            continue

        # 4xx/5xx: spróbuj linków alternatywnych z payloadu
        try:
            data_err = r.json()
            for au in _extract_alt_rdap_urls(data_err):
                data = await _get_json_with_redirects(client, au, attempts, max_hops=max_hops-1)
                if data is not None:
                    return data
        except Exception:
            pass

        return None  # nic nie wyszło

    return None  # za dużo hopów


async def _fetch_rdap(q: str, debug_attempts: Optional[List[dict]] = None) -> dict:
    kind = _detect_kind(q)

    # UWAGA: bez http2=True, żeby nie wymagać pakietu 'h2'
    async with httpx.AsyncClient(timeout=20) as client:
        urls: List[str] = []

        if kind == "ip":
            urls = [f"https://rdap.org/ip/{q}"]

        elif kind == "autnum":
            num = re.sub(r'(?i)^AS', '', q)
            urls = [f"https://rdap.org/autnum/{num}"]

        else:
            # DOMENA: 1) bootstrap IANA (precyzyjny dla com.br, itp.)
            suffix = _public_suffix(q)
            bootstrap = await _get_bootstrap_dns(client)
            bases = _rdap_bases_for_suffix(bootstrap or {}, suffix)

            # 2) rdap.org i zapasowy identitydigital
            urls = [f"{b}domain/{q}" for b in bases] + [
                f"https://rdap.org/domain/{q}",
                f"https://rdap.identitydigital.services/rdap/domain/{q}",
            ]

        for u in urls:
            attempts = [] if debug_attempts is None else debug_attempts
            data = await _get_json_with_redirects(client, u, attempts)
            if data is not None:
                return data

            # last-chance: spróbuj to samo, ale z auto-follow (czasem wystarczy)
            try:
                r = await client.get(u, headers=RDAP_HEADERS, follow_redirects=True)
                if debug_attempts is not None:
                    debug_attempts.append({"url": u, "status": f"auto-follow:{r.status_code}", "location": r.headers.get("location")})
                if 200 <= r.status_code < 300:
                    try:
                        return r.json()
                    except Exception:
                        try:
                            return json.loads(r.text or "null")
                        except Exception:
                            return {}
            except Exception as ex:
                if debug_attempts is not None:
                    debug_attempts.append({"url": u, "status": "EXC-auto", "error": str(ex)})

    raise HTTPException(status_code=502, detail="Nie udało się pobrać danych RDAP")


# ---------------------------
# Parsowanie / normalizacja
# ---------------------------
def _event(data: dict, action: str) -> str:
    for ev in (data.get("events") or []):
        if ev.get("eventAction") == action:
            return ev.get("eventDate", "")
    return ""


def _camel_epp(s: str) -> str:
    parts = s.split()
    if not parts: return ""
    return parts[0] + "".join(p[:1].upper() + p[1:] for p in parts[1:])


def _registrar_entity(entities):
    for e in (entities or []):
        if "registrar" in _roles(e):
            return e
    return None


def _abuse_entity(entity):
    for e in (entity.get("entities") or []):
        if "abuse" in _roles(e):
            return e
    return None


def _find_registrant_entity(entities):
    for e in (entities or []):
        if "registrant" in _roles(e):
            return e
    return None


def _registrant_info_for_pl(entities) -> Dict[str, str]:
    ent = _find_registrant_entity(entities or [])
    if not ent:
        return {}
    name = _vcard(ent, "fn") or ""
    street, ext, city, region, postal, country_name = _vcard_addr_parts(ent)
    cc = _vcard_addr_cc(ent) or ""
    lines = []
    if name: lines.append(name)
    if street: lines.append(street)
    if city: lines.append(city)
    if postal: lines.append(postal)
    if cc or country_name:
        lines.append(cc or country_name)
    formatted = "\n".join(lines)
    return {
        "name": name,
        "street": street,
        "city": city,
        "postal": postal,
        "countryCode": cc or "",
        "formatted": formatted
    }


def _parse_domain(data: dict) -> dict:
    reg = _registrar_entity(data.get("entities") or [])
    reg_name = _vcard(reg, "fn") if reg else ""
    # IANA Registrar ID
    reg_iana = ""
    if reg:
        for pid in (reg.get("publicIds") or []):
            if pid.get("type") == "IANA Registrar ID":
                reg_iana = pid.get("identifier", "")
                break
    if not reg_iana:
        for pid in (data.get("publicIds") or []):
            if pid.get("type") == "IANA Registrar ID":
                reg_iana = pid.get("identifier", "")
                break
    # Registrar URL (rel=about)
    reg_url = ""
    if reg:
        for link in (reg.get("links") or []):
            if link.get("rel") == "about" and isinstance(link.get("href"), str):
                reg_url = link["href"]; break
    # Abuse contact
    abuse = _abuse_entity(reg) if reg else None
    abuse_email = _vcard(abuse, "email") if abuse else ""
    abuse_tel   = _vcard(abuse, "tel") if abuse else ""

    statuses = data.get("status") or []
    if isinstance(statuses, str):
        statuses = [statuses]

    nameservers = []
    for ns in (data.get("nameservers") or []):
        n = ns.get("ldhName") or ns.get("unicodeName")
        if n: nameservers.append(n.upper())

    dnssec = "signed" if data.get("secureDNS", {}).get("delegationSigned") else "unsigned"

    dom = (data.get("ldhName") or data.get("unicodeName") or "")
    is_pl = dom.lower().endswith(".pl")
    registrant = _registrant_info_for_pl(data.get("entities") or []) if is_pl else {}

    return {
        "objectClassName": "domain",
        "domainName": (dom or "").upper(),
        "registryDomainId": data.get("handle") or "",
        "updatedDate": _event(data, "last changed"),
        "creationDate": _event(data, "registration"),
        "expiryDate": _event(data, "expiration"),
        "registrar": reg_name,
        "registrarIanaId": reg_iana,
        "registrarUrl": reg_url,
        "statuses": [{"raw": s, "epp": _camel_epp(s)} for s in statuses],
        "nameServers": nameservers,
        "dnssec": dnssec,
        "abuseContact": {"email": abuse_email, "phone": abuse_tel},
        "registrant": registrant,
        # 'ips' / 'subdomainIps' dokładamy w routingu
    }


def _collect_status_list(data: dict) -> List[str]:
    st = data.get("status") or []
    if isinstance(st, str): st = [st]
    return st


def _remarks_as_lines(data: dict) -> List[str]:
    lines: List[str] = []
    for r in (data.get("remarks") or []):
        for d in (r.get("description") or []):
            if isinstance(d, str):
                for ln in d.splitlines():
                    ln = ln.strip()
                    if ln:
                        lines.append(ln)
    return lines


def _extract_mnt_fields_from_remarks(data: dict) -> Dict[str, List[str]]:
    wanted = ["mnt-by", "mnt-lower", "mnt-routes", "mnt-domains", "mnt-ref"]
    acc: Dict[str, List[str]] = {k: [] for k in wanted}
    for ln in _remarks_as_lines(data):
        m = re.match(r'(?i)^(mnt-by|mnt-lower|mnt-routes|mnt-domains|mnt-ref)\s*:\s*(.+)$', ln)
        if m:
            key = m.group(1).lower()
            val = m.group(2).strip()
            if val and val not in acc[key]:
                acc[key].append(val)
    return acc


def _extract_descr_and_geofeed(data: dict):
    descr_list: List[str] = []
    geofeed_url = ""
    for ln in _remarks_as_lines(data):
        if re.match(r'(?i)^geofeed\s*:\s*(\S+)$', ln):
            geofeed_url = re.sub(r'(?i)^geofeed\s*:\s*', '', ln).strip()
        if re.match(r'(?i)^descr\s*:\s*(.+)$', ln):
            descr_list.append(re.sub(r'(?i)^descr\s*:\s*', '', ln).strip())
    for link in (data.get("links") or []):
        if link.get("rel") == "geofeed" and isinstance(link.get("href"), str):
            geofeed_url = link["href"]
    if not descr_list:
        for r in (data.get("remarks") or []):
            if (r.get("title") or "").lower() in ("description", "descr"):
                for d in (r.get("description") or []):
                    if d: descr_list.append(d.strip())
    return descr_list, geofeed_url


def _org_info_from_entities(entities) -> Tuple[str, str, str]:
    org_name = ""
    org_handle = ""
    org_address = ""
    for e in (entities or []):
        r = _roles(e)
        h = e.get("handle") or ""
        fn = _vcard(e, "fn")
        if fn and not org_name:
            org_name = fn
        if (h.startswith("ORG-") or "-RIPE" in h) and not org_handle:
            org_handle = h
    if org_handle:
        for e in (entities or []):
            if e.get("handle") == org_handle:
                street, ext, city, region, postal, country_name = _vcard_addr_parts(e)
                parts = [street, ext, city, region, postal, country_name]
                org_address = ", ".join([p for p in parts if p])
                if org_address:
                    break
    if not org_address:
        for e in (entities or []):
            street, ext, city, region, postal, country_name = _vcard_addr_parts(e)
            parts = [street, ext, city, region, postal, country_name]
            org_address = ", ".join([p for p in parts if p])
            if org_address:
                break
    return org_name, org_handle, org_address


def _ip_version(data: dict) -> str:
    v = data.get("ipVersion", "")
    if v: return v
    sa = data.get("startAddress", "")
    if ":" in sa: return "v6"
    return "v4" if sa else ""


def _parse_ip(data: dict) -> dict:
    cidrs: List[str] = []
    for c in (data.get("cidr0_cidrs") or []):
        length = c.get("length", 0)
        if c.get("v4prefix"):
            cidrs.append(f"{c['v4prefix']}/{length}")
        elif c.get("v6prefix"):
            cidrs.append(f"{c['v6prefix']}/{length}")
    sa, ea = data.get("startAddress"), data.get("endAddress")
    ip_range = ""
    if sa and ea: ip_range = f"{sa} - {ea}"
    entities = data.get("entities") or []
    org_name, org_handle, org_addr = _org_info_from_entities(entities)
    abuse_email = ""; abuse_tel = ""
    for e in entities:
        if "abuse" in _roles(e):
            abuse_email = _vcard(e, "email") or abuse_email
            abuse_tel   = _vcard(e, "tel") or abuse_tel

    def _first_handle_with_role(role_name: str) -> str:
        for e in (entities or []):
            if role_name in _roles(e):
                h = e.get("handle")
                if h: return h
        return ""

    admin_c = _first_handle_with_role("administrative")
    tech_c  = _first_handle_with_role("technical")
    abuse_c = _first_handle_with_role("abuse")
    mnt = _extract_mnt_fields_from_remarks(data)
    descr_list, geofeed_url = _extract_descr_and_geofeed(data)
    statuses = _collect_status_list(data)
    return {
        "objectClassName": "ip network",
        "handle": data.get("handle", ""),
        "parentHandle": data.get("parentHandle", ""),
        "cidr": ", ".join(cidrs) if cidrs else "",
        "range": ip_range,
        "startAddress": sa or "",
        "endAddress": ea or "",
        "prefix": cidrs[0] if cidrs else "",
        "ipVersion": _ip_version(data),
        "name": data.get("name", ""),
        "type": data.get("type", ""),
        "country": data.get("country", ""),
        "status": statuses,
        "org": org_name,
        "orgHandle": org_handle,
        "orgAddress": org_addr,
        "adminC": admin_c,
        "techC": tech_c,
        "abuseC": abuse_c,
        "abuseContact": {"email": abuse_email, "phone": abuse_tel},
        "mntBy": mnt.get("mnt-by") or [],
        "mntLower": mnt.get("mnt-lower") or [],
        "mntRoutes": mnt.get("mnt-routes") or [],
        "mntDomains": mnt.get("mnt-domains") or [],
        "mntRef": mnt.get("mnt-ref") or [],
        "descr": descr_list,
        "geofeed": geofeed_url,
        "updatedDate": _event(data, "last changed"),
        "creationDate": _event(data, "registration"),
        "events": data.get("events") or [],
        "entities": entities,
        "links": data.get("links") or [],
        "remarks": data.get("remarks") or [],
    }


def _parse_autnum(data: dict) -> dict:
    org = ""; abuse_email = ""; abuse_tel = ""
    for e in (data.get("entities") or []):
        r = _roles(e)
        if any(x in r for x in ["registrant", "administrative", "technical", "abuse"]):
            fn = _vcard(e, "fn")
            if fn and not org: org = fn
        if "abuse" in r:
            abuse_email = _vcard(e, "email") or abuse_email
            abuse_tel   = _vcard(e, "tel") or abuse_tel
    rng = ""
    if data.get("startAutnum") and data.get("endAutnum"):
        rng = f"AS{data['startAutnum']} - AS{data['endAutnum']}"
    return {
        "objectClassName": "autnum",
        "asNumber": data.get("handle", ""),
        "range": rng,
        "name": data.get("name", ""),
        "type": data.get("type", ""),
        "country": data.get("country", ""),
        "org": org,
        "abuseContact": {"email": abuse_email, "phone": abuse_tel},
    }


def _normalize(data: dict) -> dict:
    obj = data.get("objectClassName") or ""
    if not obj:
        if data.get("startAddress") and data.get("endAddress"): obj = "ip network"
        if data.get("startAutnum") and data.get("endAutnum"): obj = "autnum"
    if obj == "domain": return _parse_domain(data)
    if obj == "ip network": return _parse_ip(data)
    if obj == "autnum": return _parse_autnum(data)
    return data


# ---------------------------
# ROUTES
# ---------------------------
@app.get("/api/rdap")
async def api_rdap(
    q: str = Query(..., description="domena / subdomena / IP / AS12345"),
    debug: bool = Query(False, description="dodaj debug z listą prób")
):
    q = q.strip().rstrip(".")
    kind = _detect_kind(q)
    dbg: List[dict] = [] if debug else None  # type: ignore

    if kind == "domain" and not _is_ip(q):
        base = _base_domain(q)
        data = await _fetch_rdap(base, debug_attempts=dbg)
        result = _normalize(data)
        result["baseDomain"] = base
        result["queriedHost"] = q
        result["ips"] = _resolve_ips(base)  # może być []
        if q != base:
            result["subdomainIps"] = _resolve_ips(q)  # może być []
        if debug:
            result["_debugAttempts"] = dbg
        return JSONResponse(result)

    data = await _fetch_rdap(q, debug_attempts=dbg)
    result = _normalize(data)
    if debug:
        result["_debugAttempts"] = dbg
    return JSONResponse(result)


@app.get("/", response_class=HTMLResponse)
async def home(request: Request, q: Optional[str] = None, debug: bool = False):
    result = None
    rdap_raw = None
    error = None
    dbg: List[dict] = [] if debug else None  # type: ignore
    if q:
        try:
            q_clean = q.strip().rstrip(".")
            kind = _detect_kind(q_clean)
            if kind == "domain" and not _is_ip(q_clean):
                base = _base_domain(q_clean)
                rdap_raw = await _fetch_rdap(base, debug_attempts=dbg)
                result = _normalize(rdap_raw)
                result["baseDomain"] = base
                result["queriedHost"] = q_clean
                result["ips"] = _resolve_ips(base)
                if q_clean != base:
                    result["subdomainIps"] = _resolve_ips(q_clean)
                if debug:
                    result["_debugAttempts"] = dbg
            else:
                rdap_raw = await _fetch_rdap(q_clean, debug_attempts=dbg)
                result = _normalize(rdap_raw)
                if debug:
                    result["_debugAttempts"] = dbg
        except HTTPException as e:
            error = f"Błąd: {e.detail}"
        except Exception as ex:
            error = f"Wystąpił nieoczekiwany błąd: {ex}"

    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "q": q or "",
            "result": result,
            "error": error,
            "rdap_raw": rdap_raw,
        },
    )
