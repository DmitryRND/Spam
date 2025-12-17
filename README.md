# SpamCheck

Domain spam readiness and mailbox analysis toolkit.

## Features
- Simple checks: SPF, DKIM (selector), DMARC, MX, rDNS, HELO/EHLO alignment.
- Reputation checks: RBL/DNSBL + SURBL (domain URI lists).
- Advanced checks: temporary inbox on your domain, inbound SPF/DKIM/DMARC + content flags.
- Optional AI summary and red/green flags (OpenAI).

## Local run (simple checks)
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

python app.py example.com
python app.py --web --host 127.0.0.1 --port 5000
```

## Advanced inbox (production)
You need a public SMTP receiver for `scheck.<your-domain>`.

DNS:
- `A` and/or `AAAA` for `scheck.<your-domain>` -> your server IP
- `MX` for `scheck.<your-domain>` -> `scheck.<your-domain>`

SMTP receiver:
```bash
python smtp_server.py \
  --domain scheck.<your-domain> \
  --host 0.0.0.0 \
  --port 25 \
  --db-path data/spamcheck.db
```

Web UI:
```bash
export SCHECK_DOMAIN=scheck.<your-domain>
export SCHECK_DB_PATH=/opt/spamcheck/data/spamcheck.db
python app.py --web --host 127.0.0.1 --port 5000
```

### TLS for SMTP (optional)
If you have a TLS cert:
```bash
python smtp_server.py \
  --domain scheck.<your-domain> \
  --host 0.0.0.0 \
  --port 25 \
  --db-path data/spamcheck.db \
  --tls-cert /etc/letsencrypt/live/scheck.<your-domain>/fullchain.pem \
  --tls-key /etc/letsencrypt/live/scheck.<your-domain>/privkey.pem
```

## Environment variables
- `SCHECK_DOMAIN` (default: `scheck.ml-analytic.online`)
- `SCHECK_DB_PATH` (default: `data/spamcheck.db`)
- `SCHECK_TTL_SECONDS` (default: `600`)
- `ENABLE_AI` (default: `1`)
- `OPENAI_API_KEY` (optional)
- `OPENAI_MODEL` (default: `gpt-4o-mini`)

## Notes
- Port 25 must be open for inbound mail.
- Temporary inboxes expire after 10 minutes.
