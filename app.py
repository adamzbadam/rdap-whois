import os, re
from typing import Optional
from fastapi import FastAPI, Request, Query, HTTPException
from fastapi.responses import JSONResponse, HTMLResponse
from fastapi.templating import Jinja2Templates
import httpx

app = FastAPI(title="RDAP WHOIS")
templates = Jinja2Templates(directory="templates")

RDAP_HEADERS = {"Accept": "application/rdap+json, application/json"}

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

def _detect_kind(q: str) -> str:
    if re.fullmatch(r'(?i)AS?\d+', q) or re.fullmatch(r'\d+', q):
        return "autnum"
    if re.fullmatch(r'[0-9a-fA-F:.]+', q):
        return "ip"
    return "domain"

async def _fetch_rdap(q: str) -> dict:
    kind = _detect_kind(q)
    urls = []
    if kind == "ip":
        urls = [f"https://rdap.org/ip/{q}"]
    elif kind == "autnum":
        num = re.sub(r'(?i)^AS', '', q)
        urls = [f"https://rdap.org/autnum/{num}"]
    else:
        urls = [
            f"https://rdap.org/domain/{q}",
            f"https://rdap.identitydigital.services/rdap/domain/{q}",
        ]

    async with httpx.AsyncClient(timeout=15, follow_redirects=True) as client:
        for url in urls:
            try:
                r = await client.get(url, headers=RDAP_HEADERS)
                if r.status_code < 400:
                    return r.json()
            except Exception:
                continue
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

    return {
        "objectClassName": "domain",
        "domainName": (data.get("ldhName") or data.get("unicodeName") or "").upper(),
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
    }

def _parse_ip(data: dict) -> dict:
    # CIDR list or range
    cidrs = []
    for c in (data.get("cidr0_cidrs") or []):
        length = c.get("length", 0)
        if c.get("v4prefix"):
            cidrs.append(f"{c['v4prefix']}/{length}")
        elif c.get("v6prefix"):
            cidrs.append(f"{c['v6prefix']}/{length}")
    ip_range = ""
    if not cidrs:
        sa, ea = data.get("startAddress"), data.get("endAddress")
        if sa and ea: ip_range = f"{sa} - {ea}"

    org = ""; abuse_email = ""; abuse_tel = ""
    for e in (data.get("entities") or []):
        r = _roles(e)
        if any(x in r for x in ["registrant", "administrative", "technical", "abuse"]):
            fn = _vcard(e, "fn")
            if fn and not org: org = fn
        if "abuse" in r:
            abuse_email = _vcard(e, "email") or abuse_email
            abuse_tel   = _vcard(e, "tel") or abuse_tel

    return {
        "objectClassName": "ip network",
        "handle": data.get("handle", ""),
        "cidr": ", ".join(cidrs) if cidrs else "",
        "range": ip_range,
        "ipVersion": data.get("ipVersion", ""),
        "name": data.get("name", ""),
        "type": data.get("type", ""),
        "country": data.get("country", ""),
        "org": org,
        "abuseContact": {"email": abuse_email, "phone": abuse_tel},
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
    result = None; error = None
    if q:
        try:
            data = await _fetch_rdap(q.strip())
            result = _normalize(data)
        except HTTPException as e:
            error = f"Błąd: {e.detail}"
        except Exception:
            error = "Wystąpił nieoczekiwany błąd"
    return templates.TemplateResponse("index.html", {"request": request, "q": q or "", "result": result, "error": error})
