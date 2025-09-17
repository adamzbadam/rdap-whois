import os, re
from typing import Optional, List, Dict, Tuple
from fastapi import FastAPI, Request, Query, HTTPException
from fastapi.responses import JSONResponse, HTMLResponse
from fastapi.templating import Jinja2Templates
import httpx

app = FastAPI(title="RDAP WHOIS")
templates = Jinja2Templates(directory="templates")

USER_AGENT = "rdap-whois/1.0 (+https://github.com/adamzbadam/rdap-whois)"
RDAP_HEADERS = {
    "Accept": "application/rdap+json, application/json;q=0.9, */*;q=0.1",
    "User-Agent": USER_AGENT,
}

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

def _detect_kind(q: str) -> str:
    if re.fullmatch(r'(?i)AS?\d+', q) or re.fullmatch(r'\d+', q):
        return "autnum"
    if re.fullmatch(r'[0-9a-fA-F:.]+', q):
        return "ip"
    return "domain"

def _extract_rdap_error(json_obj: Dict) -> str:
    """
    Wyciąga możliwie czytelną wiadomość z odpowiedzi błędnej RDAP.
    """
    title = json_obj.get("title")
    desc = None
    if isinstance(json_obj.get("description"), list) and json_obj["description"]:
        desc = json_obj["description"][0]
    if isinstance(json_obj.get("notices"), list):
        for n in json_obj["notices"]:
            ds = n.get("description") or []
            for d in ds:
                if isinstance(d, str) and d.strip():
                    desc = desc or d.strip()
                    break
    parts = [p for p in [title, desc] if p]
    return " — ".join(parts) if parts else "RDAP: obiekt nie znaleziony"

async def _fetch_rdap(q: str) -> dict:
    """
    Pobiera RDAP dla domeny/IP/AS.
    - Pierwszy strzał: rdap.org (bootstrap) — **śledzimy przekierowania** do rejestru.
    - Dla domen: opcjonalny fallback do Identity Digital, jeśli pierwszy endpoint zwróci błąd (poza 404).
    - 404 z JSON RDAP -> rzucamy HTTPException(404) z czytelnym opisem (to „nie istnieje”, nie błąd transportu).
    """
    kind = _detect_kind(q)
    if kind == "ip":
        primary = f"https://rdap.org/ip/{q}"
        fallbacks: List[str] = []
    elif kind == "autnum":
        num = re.sub(r'(?i)^AS', '', q)
        primary = f"https://rdap.org/autnum/{num}"
        fallbacks = []
    else:
        primary = f"https://rdap.org/domain/{q}"
        fallbacks = [f"https://rdap.identitydigital.services/rdap/domain/{q}"]

    last_error: Optional[Tuple[int, str]] = None

    # WAŻNE: bez http2=True (może rzucać wyjątek jeśli h2 nie jest zainstalowane)
    async with httpx.AsyncClient(timeout=15, follow_redirects=True, headers=RDAP_HEADERS) as client:
        # 1) primary
        try:
            r = await client.get(primary)
        except httpx.HTTPError as e:
            last_error = (502, f"Błąd sieci: {e!s}")
        else:
            if r.status_code < 400:
                try:
                    return r.json()
                except ValueError:
                    raise HTTPException(status_code=502, detail="Błędny JSON z serwera RDAP")
            if r.status_code == 404:
                try:
                    data = r.json()
                    msg = _extract_rdap_error(data)
                except ValueError:
                    msg = "RDAP: obiekt nie znaleziony"
                raise HTTPException(status_code=404, detail=msg)
            try:
                data = r.json()
                msg = _extract_rdap_error(data)
                last_error = (r.status_code, msg)
            except ValueError:
                last_error = (r.status_code, f"RDAP HTTP {r.status_code}")

        # 2) fallbacks (tylko domeny)
        for url in fallbacks:
            try:
                r2 = await client.get(url)
            except httpx.HTTPError:
                continue
            if r2.status_code < 400:
                try:
                    return r2.json()
                except ValueError:
                    raise HTTPException(status_code=502, detail="Błędny JSON z serwera RDAP (fallback)")
            if r2.status_code == 404:
                try:
                    data = r2.json()
                    msg = _extract_rdap_error(data)
                except ValueError:
                    msg = "RDAP: obiekt nie znaleziony"
                raise HTTPException(status_code=404, detail=msg)
            try:
                data = r2.json()
                msg = _extract_rdap_error(data)
                last_error = (r2.status_code, msg)
            except ValueError:
                last_error = (r2.status_code, f"RDAP HTTP {r2.status_code}")

    if last_error:
        code, msg = last_error
        raise HTTPException(status_code=code if 400 <= code < 600 else 502, detail=msg)
    raise HTTPException(status_code=502, detail="Nie udało się pobrać danych RDAP")

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
    """
    Zwraca słownik z informacjami o rejestrancie dla .PL.
    """
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
    reg_url = ""
    if reg:
        for link in (reg.get("links") or []):
            if link.get("rel") == "about" and isinstance(link.get("href"), str):
                reg_url = link["href"]; break
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

@app.get("/api/rdap")
async def api_rdap(q: str = Query(..., description="domena / IP / AS12345")):
    data = await _fetch_rdap(q.strip())
    return JSONResponse(_normalize(data))

@app.get("/", response_class=HTMLResponse)
async def home(request: Request, q: Optional[str] = None):
    result = None
    rdap_raw = None
    error = None
    if q:
        try:
            rdap_raw = await _fetch_rdap(q.strip())
            result = _normalize(rdap_raw)
        except HTTPException as e:
            error = f"Błąd: {e.detail}"
        except Exception as e:
            # pokaż treść błędu, żeby łatwiej diagnozować środowisko
            error = f"Wystąpił nieoczekiwany błąd: {e!s}"

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
