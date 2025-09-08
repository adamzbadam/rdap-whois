# RDAP WHOIS (Render)

Prosta aplikacja FastAPI z UI i API, która pobiera RDAP dla domen, IP i AS. 
Korzysta z `rdap.org` + fallback do `identitydigital` dla domen. Pola znormalizowane do czytelnego formatu.

## Uruchomienie lokalne
```bash
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
uvicorn app:app --reload
# http://127.0.0.1:8000/  lub  /api/rdap?q=example.com
