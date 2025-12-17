import argparse
import json
import os
import re
import socket
import time
from dataclasses import dataclass, asdict
from email import policy
from email.header import decode_header, make_header
from email.parser import BytesParser
from email.utils import parseaddr
from pathlib import Path
from typing import List, Optional, Tuple

from flask import Flask, render_template_string, request

import dns.exception
import dns.reversename
import dns.resolver
import dkim
import spf

from storage import (
    create_mailbox,
    get_latest_message,
    get_mailbox_by_token,
    init_db,
    purge_expired,
    update_message_analysis,
)


@dataclass
class CheckResult:
    name: str
    status: str  # PASS / WARN / FAIL / INFO
    detail: str


def checks_to_json(checks: List[CheckResult]) -> List[dict]:
    return [asdict(check) for check in checks]


def checks_from_json(data: List[dict]) -> List[CheckResult]:
    return [CheckResult(**item) for item in data]


RBL_ZONES = [
    "zen.spamhaus.org",
    "bl.spamcop.net",
    "dnsbl.sorbs.net",
    "b.barracudacentral.org",
    "dnsbl-1.uceprotect.net",
    "dnsbl-2.uceprotect.net",
    "dnsbl-3.uceprotect.net",
    "psbl.surriel.com",
    "spam.dnsbl.sorbs.net",
    "all.spamrats.com",
]

RBL_NAMESERVERS = [
    # OpenDNS
    "208.67.222.222",
    "208.67.220.220",
    # Additional public recursors (regional mix; availability not guaranteed)
    "208.91.112.53",   # US
    "205.171.202.66",  # US
    "5.11.11.11",      # SA
    "87.213.100.113",  # NL
    "83.145.86.7",     # FR
    "83.137.41.9",     # AU
    "200.33.3.123",    # MX
    "139.130.4.4",     # AU
    "203.236.1.12",    # SK
    "114.114.115.115", # CN
    "103.99.150.10",   # IN
    "194.125.133.10",  # IR
]

SURBL_ZONES = ["multi.surbl.org"]

SCHECK_DOMAIN = os.getenv("SCHECK_DOMAIN", "scheck.ml-analytic.online")
MAILBOX_TTL_SECONDS = int(os.getenv("SCHECK_TTL_SECONDS", "600"))
DB_PATH = Path(os.getenv("SCHECK_DB_PATH", "data/spamcheck.db"))
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
ENABLE_AI = os.getenv("ENABLE_AI", "1") != "0"

ADVANCED_GUIDANCE = [
    "Generate a temporary inbox address on this service.",
    "Send a test email from your domain to that address.",
    "Wait up to 10 minutes for delivery; refresh to see results.",
    "We analyze headers (SPF/DKIM/DMARC) and content for spam signals.",
]

PAGE_TEMPLATE = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Domain spam check</title>
  <style>
    :root {
      --bg: #0c1326;
      --panel: #101a33;
      --muted: #8ea3b7;
      --accent: #6af59a;
      --warn: #f4d35e;
      --fail: #ff7b7b;
      --info: #7bc3ff;
      --text: #e9eff7;
      --border: rgba(255,255,255,0.06);
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: "Space Grotesk", "DM Sans", "Segoe UI", sans-serif;
      background: radial-gradient(circle at 15% 20%, #152750, #0b1020 40%), linear-gradient(135deg, #0b1327, #0b0f1c);
      color: var(--text);
      min-height: 100vh;
    }
    main.shell {
      max-width: 980px;
      margin: 0 auto;
      padding: 32px 20px 48px;
    }
    h1 {
      margin: 0 0 8px 0;
      font-weight: 700;
      letter-spacing: -0.02em;
    }
    p.lead {
      color: var(--muted);
      margin: 0 0 18px 0;
    }
    .card {
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 16px;
      padding: 18px 20px;
      margin-bottom: 16px;
      box-shadow: 0 14px 50px rgba(0,0,0,0.35);
    }
    .tabs {
      display: flex;
      gap: 8px;
      margin-bottom: 14px;
    }
    .tab-button {
      padding: 8px 14px;
      border-radius: 999px;
      border: 1px solid var(--border);
      background: #0b1224;
      color: var(--muted);
      cursor: pointer;
      font-weight: 600;
    }
    .tab-button.active {
      color: #0a1220;
      background: linear-gradient(120deg, #2fd17a, #62f5c5);
      border-color: transparent;
    }
    .tab-panel { display: none; }
    .tab-panel.active { display: block; }
    form.grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
      gap: 12px;
      align-items: end;
    }
    label {
      display: block;
      font-size: 13px;
      color: var(--muted);
      margin-bottom: 6px;
    }
    input[type="text"] {
      width: 100%;
      padding: 10px 12px;
      background: #0c1224;
      border: 1px solid var(--border);
      border-radius: 10px;
      color: var(--text);
      font-size: 15px;
    }
    input[type="text"]::placeholder { color: #56647a; }
    .actions {
      display: flex;
      align-items: center;
      gap: 10px;
    }
    button {
      padding: 12px 16px;
      border: none;
      border-radius: 10px;
      background: linear-gradient(120deg, #2fd17a, #62f5c5);
      color: #0a1220;
      font-weight: 700;
      cursor: pointer;
      transition: transform 120ms ease, box-shadow 120ms ease;
    }
    button:hover { transform: translateY(-1px); box-shadow: 0 8px 20px rgba(0,0,0,0.25); }
    .checkbox {
      display: flex;
      align-items: center;
      gap: 8px;
      font-size: 14px;
      color: var(--muted);
    }
    .notice {
      padding: 10px 12px;
      border-radius: 10px;
      background: rgba(255,255,255,0.05);
      border: 1px solid var(--border);
      margin: 10px 0;
      color: var(--text);
    }
    .notice.error { border-color: rgba(255,123,123,0.5); color: var(--fail); }
    .result-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
      gap: 10px;
    }
    .pill {
      border-radius: 12px;
      border: 1px solid var(--border);
      padding: 12px;
      background: #0b1224;
    }
    .pill .title { font-weight: 700; }
    .pill .detail { color: var(--muted); margin-top: 4px; font-size: 14px; }
    .pill.pass { border-color: rgba(106,245,154,0.6); }
    .pill.warn { border-color: rgba(244,211,94,0.7); }
    .pill.fail { border-color: rgba(255,123,123,0.7); }
    .pill.info { border-color: rgba(123,195,255,0.7); }
    .pill .status {
      font-size: 12px;
      padding: 2px 8px;
      border-radius: 999px;
      display: inline-block;
      margin-left: 8px;
      color: #0b1020;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }
    .pill.pass .status { background: var(--accent); }
    .pill.warn .status { background: var(--warn); }
    .pill.fail .status { background: var(--fail); }
    .pill.info .status { background: var(--info); }
    .muted { color: var(--muted); }
    ol { padding-left: 18px; margin: 0; }
    ol li { margin: 6px 0; color: var(--muted); }
    .result-meta { display: flex; flex-wrap: wrap; gap: 14px; margin: 8px 0 12px; color: var(--muted); }
    textarea {
      width: 100%;
      min-height: 120px;
      padding: 10px 12px;
      background: #0c1224;
      border: 1px solid var(--border);
      border-radius: 10px;
      color: var(--text);
      font-size: 14px;
      resize: vertical;
    }
    .timer {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 4px 10px;
      border-radius: 999px;
      background: rgba(255,255,255,0.06);
      border: 1px solid var(--border);
      font-size: 12px;
      color: var(--muted);
    }
    .timer strong { color: var(--text); }
  </style>
</head>
<body>
  <main class="shell">
    <header>
      <h1>Domain spam check</h1>
      <p class="lead">Evaluate SPF, DKIM, DMARC, rDNS/HELO, MX, RBL/SURBL, and optional mailbox analysis.</p>
    </header>

    <section class="card">
      <form method="POST">
        <input type="hidden" id="tab" name="tab" value="{{ active_tab }}">
        <input type="hidden" id="action_auto" name="action_auto" value="">
        <div class="tabs">
          <button type="button" class="tab-button" data-tab="simple">Simple check</button>
          <button type="button" class="tab-button" data-tab="advanced">Advanced inbox</button>
        </div>
        <div class="tab-panel" data-panel="simple">
          <div class="grid">
            <div>
              <label for="domain">Domain *</label>
              <input id="domain" name="domain" type="text" placeholder="example.com" value="{{ form.domain }}">
            </div>
            <div>
              <label for="ip">IP (optional, used for PTR/RBL)</label>
              <input id="ip" name="ip" type="text" placeholder="auto from A/AAAA" value="{{ form.ip }}">
            </div>
            <div>
              <label for="dkim_selector">DKIM selector (optional)</label>
              <input id="dkim_selector" name="dkim_selector" type="text" placeholder="default, mail, etc." value="{{ form.dkim_selector }}">
            </div>
            <div>
              <label for="nameservers">Custom nameservers (comma separated)</label>
              <input id="nameservers" name="nameservers" type="text" placeholder="8.8.8.8,1.1.1.1" value="{{ form.nameservers }}">
            </div>
            <div class="actions">
              <button type="submit" name="action" value="checks" onclick="setAction('checks')">Run checks</button>
              <label class="checkbox">
                <input type="checkbox" name="skip_rbl" {% if form.skip_rbl %}checked{% endif %}>
                Skip RBL lookups
              </label>
            </div>
          </div>
        </div>
        <div class="tab-panel" data-panel="advanced">
          <div class="grid">
            <div style="grid-column: 1 / -1;">
              <h3>Advanced check (temporary inbox)</h3>
              <p class="muted">Generate a temporary inbox on {{ service_domain }} and send a test message to it.</p>
            </div>
            <div>
              <label for="advanced_token">Temp inbox token</label>
              <input id="advanced_token" name="advanced_token" type="text" placeholder="token" value="{{ form.advanced_token }}">
            </div>
            <div class="actions">
              <button type="submit" name="action" value="advanced_create" onclick="setAction('advanced_create')">Generate inbox</button>
              <button type="submit" name="action" value="advanced_check" onclick="setAction('advanced_check')">Check inbox</button>
            </div>
            {% if results and results.advanced_meta %}
            <div style="grid-column: 1 / -1;">
              <span class="timer">Expires in: <strong id="countdown">--:--</strong></span>
              <span class="muted" style="margin-left:10px;">{{ results.advanced_meta.address }}</span>
            </div>
            {% endif %}
          </div>
        </div>
      </form>
      {% if error %}
        <div class="notice error">{{ error }}</div>
      {% endif %}
    </section>

    {% if results %}
      <section class="card">
        {% if active_tab == "simple" %}
          {% if results.domain or results.ip %}
          <div class="result-meta">
            {% if results.domain %}
            <div><span class="muted">Domain:</span> {{ results.domain }}</div>
            {% endif %}
            {% if results.ip %}
            <div><span class="muted">IP used:</span> {{ results.ip }}</div>
            {% endif %}
          </div>
          {% endif %}
          {% if results.technical %}
          <div class="result-grid">
            {% for check in results.technical %}
              <div class="pill {{ check.status|lower }}">
                <div class="title">{{ check.name }} <span class="status">{{ check.status }}</span></div>
                <div class="detail">{{ check.detail }}</div>
              </div>
            {% endfor %}
          </div>
          {% endif %}
          {% if results.rbl %}
          <h3>RBL / DNSBL</h3>
          <div class="result-grid">
            {% for check in results.rbl %}
              <div class="pill {{ check.status|lower }}">
                <div class="title">{{ check.name }} <span class="status">{{ check.status }}</span></div>
                <div class="detail">{{ check.detail }}</div>
              </div>
            {% endfor %}
          </div>
          {% endif %}
          {% if results.surbl %}
          <h3>SURBL (domain URI lists)</h3>
          <div class="result-grid">
            {% for check in results.surbl %}
              <div class="pill {{ check.status|lower }}">
                <div class="title">{{ check.name }} <span class="status">{{ check.status }}</span></div>
                <div class="detail">{{ check.detail }}</div>
              </div>
            {% endfor %}
          </div>
          {% endif %}
        {% endif %}
        {% if active_tab == "advanced" %}
          {% if results.advanced %}
          <h3>Advanced analysis</h3>
          <div class="result-grid">
            {% for check in results.advanced %}
              <div class="pill {{ check.status|lower }}">
                <div class="title">{{ check.name }} <span class="status">{{ check.status }}</span></div>
                <div class="detail">{{ check.detail }}</div>
              </div>
            {% endfor %}
          </div>
          {% endif %}
          {% if results.flags_red or results.flags_green %}
          <div class="result-grid" style="margin-top: 12px;">
            {% if results.flags_red %}
            <div class="pill fail">
              <div class="title">Red flags</div>
              <div class="detail">
                {{ results.flags_red|join(' | ') }}
              </div>
            </div>
            {% endif %}
            {% if results.flags_green %}
            <div class="pill pass">
              <div class="title">Green flags</div>
              <div class="detail">
                {{ results.flags_green|join(' | ') }}
              </div>
            </div>
            {% endif %}
          </div>
          {% endif %}
          {% if results.ai_summary %}
            <p class="muted">AI summary: {{ results.ai_summary }}</p>
          {% endif %}
          {% if results.advanced_meta %}
            <p class="muted">Inbox: {{ results.advanced_meta.address }} | Expires: {{ results.advanced_meta.expires_at }}</p>
          {% endif %}
        {% endif %}
      </section>
    {% endif %}

    <section class="card">
      <h3>Advanced check guide</h3>
      <ol>
        {% for step in guidance_advanced %}
          <li>{{ step }}</li>
        {% endfor %}
      </ol>
      <p class="muted">Temporary inboxes expire after 10 minutes. Send one test message per token.</p>
    </section>
  </main>
  <script>
    const activeTab = "{{ active_tab }}";
    const tabInput = document.getElementById("tab");
    const actionAuto = document.getElementById("action_auto");
    const formEl = tabInput ? tabInput.closest("form") : null;

    function setAction(action) {
      if (actionAuto) {
        actionAuto.value = action;
      }
    }

    function setActiveTab(tab) {
      if (tabInput) tabInput.value = tab;
      document.querySelectorAll(".tab-button").forEach((btn) => {
        btn.classList.toggle("active", btn.dataset.tab === tab);
      });
      document.querySelectorAll(".tab-panel").forEach((panel) => {
        panel.classList.toggle("active", panel.dataset.panel === tab);
      });
    }

    document.querySelectorAll(".tab-button").forEach((btn) => {
      btn.addEventListener("click", () => {
        setActiveTab(btn.dataset.tab);
      });
    });

    setActiveTab(activeTab || "simple");

    const expiresAt = {{ results.advanced_meta.expires_at_ts if results and results.advanced_meta else "null" }};
    if (expiresAt) {
      const countdown = document.getElementById("countdown");
      const tick = () => {
        const now = Math.floor(Date.now() / 1000);
        const remaining = Math.max(0, expiresAt - now);
        const minutes = Math.floor(remaining / 60);
        const seconds = remaining % 60;
        if (countdown) {
          countdown.textContent = `${minutes}:${seconds.toString().padStart(2, "0")}`;
        }
      };
      tick();
      setInterval(tick, 1000);
    }

    const autoPoll = {{ "true" if results and results.advanced_pending else "false" }};
    if (autoPoll && activeTab === "advanced" && formEl) {
      setTimeout(() => {
        setAction("advanced_check");
        formEl.submit();
      }, 60000);
    }
  </script>
</body>
</html>
"""


def configure_resolver(
    nameservers: Optional[List[str]], fallback: Optional[List[str]] = None
) -> dns.resolver.Resolver:
    resolver = dns.resolver.Resolver()
    if nameservers:
        resolver.nameservers = nameservers
    elif fallback:
        resolver.nameservers = fallback
    resolver.timeout = 4.0
    resolver.lifetime = 4.0
    return resolver


def resolve_txt_records(
    resolver: dns.resolver.Resolver, name: str
) -> tuple[List[str], Optional[str]]:
    try:
        answers = resolver.resolve(name, "TXT")
        return ["".join(r.strings[0].decode() if r.strings else r.to_text()) for r in answers], None
    except dns.resolver.NXDOMAIN:
        return [], "NXDOMAIN"
    except (dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        return [], None
    except dns.exception.Timeout:
        return [], "timeout"
    except Exception as exc:  # pragma: no cover - defensive
        return [], str(exc)


def resolve_mx(resolver: dns.resolver.Resolver, domain: str) -> tuple[List[str], Optional[str]]:
    try:
        answers = resolver.resolve(domain, "MX")
        mx_hosts = [f"{r.preference} {r.exchange.to_text()}" for r in sorted(answers, key=lambda a: a.preference)]
        return mx_hosts, None
    except dns.resolver.NXDOMAIN:
        return [], "NXDOMAIN"
    except (dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        return [], None
    except dns.exception.Timeout:
        return [], "timeout"
    except Exception as exc:  # pragma: no cover - defensive
        return [], str(exc)


def resolve_ip(resolver: dns.resolver.Resolver, domain: str) -> Optional[str]:
    # Try A first, then AAAA, fallback to socket
    for record_type in ("A", "AAAA"):
        try:
            answers = resolver.resolve(domain, record_type)
            for r in answers:
                return r.address
        except Exception:
            continue
    try:
        return socket.gethostbyname(domain)
    except Exception:
        return None


def check_spf(resolver: dns.resolver.Resolver, domain: str) -> CheckResult:
    txt_records, err = resolve_txt_records(resolver, domain)
    spf = next((r for r in txt_records if r.lower().startswith("v=spf1")), None)
    if spf:
        return CheckResult("SPF", "PASS", f"Found: {spf}")
    if err:
        return CheckResult("SPF", "WARN", f"Lookup issue: {err}")
    return CheckResult("SPF", "FAIL", "No SPF record found in TXT records")


def check_dmarc(resolver: dns.resolver.Resolver, domain: str) -> CheckResult:
    name = f"_dmarc.{domain}"
    txt_records, err = resolve_txt_records(resolver, name)
    dmarc = next((r for r in txt_records if r.lower().startswith("v=dmarc1")), None)
    if dmarc:
        return CheckResult("DMARC", "PASS", f"Found: {dmarc}")
    if err:
        return CheckResult("DMARC", "WARN", f"Lookup issue: {err}")
    return CheckResult("DMARC", "FAIL", "No DMARC record found")


def check_dkim(
    resolver: dns.resolver.Resolver, domain: str, selector: Optional[str]
) -> CheckResult:
    if not selector:
        return CheckResult("DKIM", "INFO", "Selector not provided; supply --dkim-selector to verify")
    name = f"{selector}._domainkey.{domain}"
    txt_records, err = resolve_txt_records(resolver, name)
    dkim = next((r for r in txt_records if "p=" in r), None)
    if dkim:
        return CheckResult("DKIM", "PASS", f"Found at {name}")
    if err:
        return CheckResult("DKIM", "WARN", f"Lookup issue for {name}: {err}")
    return CheckResult("DKIM", "FAIL", f"No DKIM record found for selector {selector}")


def check_mx_records(resolver: dns.resolver.Resolver, domain: str) -> CheckResult:
    mx_hosts, err = resolve_mx(resolver, domain)
    if mx_hosts:
        return CheckResult("MX", "PASS", "; ".join(mx_hosts))
    if err:
        return CheckResult("MX", "WARN", f"Lookup issue: {err}")
    return CheckResult("MX", "FAIL", "No MX records found")


def check_rdns(resolver: dns.resolver.Resolver, ip: Optional[str]) -> CheckResult:
    if not ip:
        return CheckResult("rDNS", "INFO", "IP unknown; provide --ip to verify PTR")
    try:
        reverse_name = dns.reversename.from_address(ip)
        answers = resolver.resolve(reverse_name, "PTR")
        ptrs = [r.to_text().rstrip(".") for r in answers]
        return CheckResult("rDNS", "PASS", f"{ip} -> {', '.join(ptrs)}")
    except dns.resolver.NXDOMAIN:
        return CheckResult("rDNS", "FAIL", f"No PTR record for {ip}")
    except dns.resolver.NoAnswer:
        return CheckResult("rDNS", "FAIL", f"No PTR answer for {ip}")
    except dns.exception.Timeout:
        return CheckResult("rDNS", "WARN", "PTR lookup timed out")
    except Exception as exc:
        return CheckResult("rDNS", "WARN", f"PTR lookup error: {exc}")


def check_helo(domain: str, rdns_result: CheckResult) -> CheckResult:
    if rdns_result.status != "PASS":
        return CheckResult("HELO/EHLO", "INFO", "Cannot evaluate without valid PTR")
    ptrs = rdns_result.detail.split("->")[-1].strip()
    if domain.lower() in ptrs.lower():
        return CheckResult("HELO/EHLO", "PASS", "PTR hostname aligns with domain")
    return CheckResult("HELO/EHLO", "WARN", f"PTR hostname '{ptrs}' differs from domain '{domain}'")


def check_rbls(
    resolver: dns.resolver.Resolver,
    ip: Optional[str],
    zones: List[str],
    fallback_resolver: Optional[dns.resolver.Resolver] = None,
) -> List[CheckResult]:
    if not ip:
        return [CheckResult("RBL", "INFO", "IP unknown; skipping RBL lookups")]
    reversed_ip = ".".join(ip.split(".")[::-1])
    results: List[CheckResult] = []
    for zone in zones:
        query = f"{reversed_ip}.{zone}"
        last_error: Optional[str] = None
        for attempt, res in enumerate([resolver, fallback_resolver]):
            if res is None:
                continue
            try:
                answers = res.resolve(query, "A")
                listed_codes = ", ".join([a.to_text() for a in answers])
                txt, _ = resolve_txt_records(res, query)
                detail = f"Listed ({listed_codes})"
                if txt:
                    detail += f" | TXT: {' | '.join(txt)}"
                if attempt == 1:
                    detail += " (resolved via fallback resolver)"
                results.append(CheckResult(zone, "FAIL", detail))
                break
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                results.append(CheckResult(zone, "PASS", "Not listed"))
                break
            except dns.resolver.NoNameservers as exc:
                extra = ""
                if "spamhaus" in zone:
                    extra = " (Spamhaus often blocks queries from public resolvers; set a private resolver via --nameserver or use a DQS key)"
                last_error = f"No nameserver answered{extra}: {exc}"
                continue  # try fallback if present
            except dns.exception.Timeout:
                last_error = "Lookup timed out"
                continue
            except Exception as exc:
                last_error = f"Lookup error: {exc}"
                continue
        else:
            if last_error:
                results.append(CheckResult(zone, "WARN", last_error))
            else:
                results.append(CheckResult(zone, "WARN", "Lookup failed"))
    return results


def check_surbls(resolver: dns.resolver.Resolver, domain: str, zones: List[str]) -> List[CheckResult]:
    if not domain:
        return [CheckResult("SURBL", "INFO", "Domain is empty; skipping SURBL")]
    cleaned = domain.strip(".")
    results: List[CheckResult] = []
    for zone in zones:
        query = f"{cleaned}.{zone}"
        try:
            answers = resolver.resolve(query, "A")
            listed_codes = ", ".join([a.to_text() for a in answers])
            txt, _ = resolve_txt_records(resolver, query)
            detail = f"Listed ({listed_codes})"
            if txt:
                detail += f" | TXT: {' | '.join(txt)}"
            results.append(CheckResult(zone, "FAIL", detail))
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            results.append(CheckResult(zone, "PASS", "Not listed"))
        except dns.resolver.NoNameservers as exc:
            results.append(CheckResult(zone, "WARN", f"No nameserver answered: {exc}"))
        except dns.exception.Timeout:
            results.append(CheckResult(zone, "WARN", "Lookup timed out"))
        except Exception as exc:
            results.append(CheckResult(zone, "WARN", f"Lookup error: {exc}"))
    return results


def extract_domain_from_address(address: str) -> str:
    if not address:
        return ""
    _, addr = parseaddr(address)
    if "@" in addr:
        return addr.split("@", 1)[1].strip().lower()
    return ""


def decode_header_value(value: str) -> str:
    if not value:
        return ""
    try:
        return str(make_header(decode_header(value)))
    except Exception:
        return value


def extract_text_body(message) -> str:
    if message.is_multipart():
        for part in message.walk():
            if part.get_content_type() == "text/plain":
                try:
                    return part.get_content().strip()
                except Exception:
                    continue
        for part in message.walk():
            if part.get_content_type() == "text/html":
                try:
                    html = part.get_content()
                    return re.sub(r"<[^>]+>", " ", html).strip()
                except Exception:
                    continue
    try:
        return message.get_content().strip()
    except Exception:
        return ""


def is_aligned_domain(candidate: str, target: str) -> bool:
    if not candidate or not target:
        return False
    candidate = candidate.lower()
    target = target.lower()
    return candidate == target or candidate.endswith(f".{target}")


def check_spf_inbound(peer_ip: str, mail_from: str, helo: str) -> Tuple[str, str]:
    if not peer_ip:
        return "WARN", "Missing peer IP for SPF check"
    try:
        result, explanation = spf.check2(i=peer_ip, s=mail_from or "", h=helo or "")
    except Exception as exc:
        return "WARN", f"SPF error: {exc}"
    status = "PASS" if result == "pass" else "FAIL" if result in {"fail", "softfail"} else "WARN"
    detail = f"{result} ({explanation})"
    return status, detail


def check_dkim_inbound(raw_bytes: bytes) -> Tuple[str, str, str]:
    try:
        message = BytesParser(policy=policy.default).parsebytes(raw_bytes)
    except Exception:
        message = None
    dkim_header = ""
    if message:
        dkim_header = message.get("DKIM-Signature", "")
    if not dkim_header:
        return "WARN", "", "DKIM-Signature header not found"
    try:
        is_valid = dkim.verify(raw_bytes)
        tags = dkim.parse_tag_value(dkim_header.encode())
        d_domain = tags.get(b"d", b"").decode(errors="ignore")
        status = "PASS" if is_valid else "FAIL"
        detail = "DKIM signature valid" if is_valid else "DKIM signature failed"
        return status, d_domain, detail
    except Exception as exc:
        return "WARN", "", f"DKIM verification error: {exc}"


def check_dmarc_inbound(
    resolver: dns.resolver.Resolver,
    from_domain: str,
    spf_status: str,
    spf_domain: str,
    dkim_status: str,
    dkim_domain: str,
) -> Tuple[str, str]:
    if not from_domain:
        return "WARN", "From domain missing; DMARC cannot be evaluated"
    record_name = f"_dmarc.{from_domain}"
    txt_records, err = resolve_txt_records(resolver, record_name)
    dmarc_record = next((r for r in txt_records if r.lower().startswith("v=dmarc1")), None)
    if not dmarc_record:
        msg = f"No DMARC record found for {from_domain}"
        if err:
            msg += f" ({err})"
        return "WARN", msg

    spf_aligned = spf_status == "PASS" and is_aligned_domain(spf_domain, from_domain)
    dkim_aligned = dkim_status == "PASS" and is_aligned_domain(dkim_domain, from_domain)
    if spf_aligned or dkim_aligned:
        return "PASS", f"DMARC aligned (policy: {dmarc_record})"
    return "FAIL", f"DMARC alignment failed (policy: {dmarc_record})"


def basic_flag_analysis(
    subject: str,
    from_domain: str,
    return_path_domain: str,
    message_id_domain: str,
    spf_status: str,
    dkim_status: str,
    dmarc_status: str,
    body_text: str,
) -> Tuple[List[str], List[str]]:
    red_flags = []
    green_flags = []
    if spf_status == "PASS":
        green_flags.append("SPF pass")
    elif spf_status != "WARN":
        red_flags.append("SPF fail/softfail")
    if dkim_status == "PASS":
        green_flags.append("DKIM pass")
    elif dkim_status != "WARN":
        red_flags.append("DKIM fail")
    if dmarc_status == "PASS":
        green_flags.append("DMARC aligned")
    elif dmarc_status == "FAIL":
        red_flags.append("DMARC alignment failed")
    else:
        red_flags.append("No DMARC policy")
    if return_path_domain and from_domain:
        if is_aligned_domain(return_path_domain, from_domain):
            green_flags.append("Return-Path aligned with From")
        else:
            red_flags.append("Return-Path not aligned with From")
    if message_id_domain and from_domain:
        if is_aligned_domain(message_id_domain, from_domain):
            green_flags.append("Message-ID domain aligned")
        else:
            red_flags.append("Message-ID domain mismatch")
    subject_lower = subject.lower()
    if any(word in subject_lower for word in ["urgent", "verify", "password", "winner", "free", "act now"]):
        red_flags.append("Suspicious subject keywords")
    link_count = len(re.findall(r"https?://", body_text.lower()))
    if link_count >= 4:
        red_flags.append("High number of links")
    if link_count == 0 and len(body_text) < 40:
        red_flags.append("Very short body")
    return red_flags, green_flags


def analyze_with_openai(subject: str, from_addr: str, body_text: str) -> Optional[dict]:
    if not ENABLE_AI:
        return None
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        return None
    payload = {
        "model": OPENAI_MODEL,
        "messages": [
            {
                "role": "system",
                "content": (
                    "You are an email security analyst. Return JSON with keys: "
                    "red_flags (list of short items), green_flags (list), summary (1-2 sentences)."
                ),
            },
            {
                "role": "user",
                "content": (
                    f"Subject: {subject}\n"
                    f"From: {from_addr}\n"
                    f"Body:\n{body_text[:2000]}"
                ),
            },
        ],
        "temperature": 0.2,
        "response_format": {"type": "json_object"},
    }
    try:
        import urllib.request

        req = urllib.request.Request(
            "https://api.openai.com/v1/chat/completions",
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {api_key}",
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=20) as response:
            data = json.loads(response.read().decode("utf-8"))
        content = data["choices"][0]["message"]["content"]
        return json.loads(content)
    except Exception:
        return None


def analyze_message(raw_bytes: bytes, peer_ip: str, helo: str, mail_from: str) -> dict:
    message = BytesParser(policy=policy.default).parsebytes(raw_bytes)
    subject = decode_header_value(message.get("Subject", ""))
    from_addr = decode_header_value(message.get("From", ""))
    return_path = message.get("Return-Path", "").strip("<>")
    from_domain = extract_domain_from_address(from_addr)
    return_path_domain = extract_domain_from_address(return_path or mail_from)
    message_id = message.get("Message-ID", "").strip().strip("<>")
    message_id_domain = ""
    if "@" in message_id:
        message_id_domain = message_id.split("@", 1)[1].strip()

    body_text = extract_text_body(message)
    spf_status, spf_detail = check_spf_inbound(peer_ip, mail_from, helo)
    dkim_status, dkim_domain, dkim_detail = check_dkim_inbound(raw_bytes)
    resolver = configure_resolver(None)
    dmarc_status, dmarc_detail = check_dmarc_inbound(
        resolver,
        from_domain,
        spf_status,
        return_path_domain,
        dkim_status,
        dkim_domain,
    )

    checks = [
        CheckResult("SPF", spf_status, spf_detail),
        CheckResult("DKIM", dkim_status, dkim_detail),
        CheckResult("DMARC", dmarc_status, dmarc_detail),
        CheckResult("From domain", "INFO", from_domain or "missing"),
        CheckResult("Return-Path domain", "INFO", return_path_domain or "missing"),
        CheckResult("Message-ID domain", "INFO", message_id_domain or "missing"),
    ]

    red_flags, green_flags = basic_flag_analysis(
        subject,
        from_domain,
        return_path_domain,
        message_id_domain,
        spf_status,
        dkim_status,
        dmarc_status,
        body_text,
    )
    ai_result = analyze_with_openai(subject, from_addr, body_text)
    ai_summary = ""
    if ai_result:
        red_flags.extend(ai_result.get("red_flags", []))
        green_flags.extend(ai_result.get("green_flags", []))
        ai_summary = ai_result.get("summary", "")

    return {
        "checks": checks,
        "red_flags": list(dict.fromkeys(red_flags)),
        "green_flags": list(dict.fromkeys(green_flags)),
        "ai_summary": ai_summary,
    }

def run_checks(
    domain: str,
    ip: Optional[str],
    dkim_selector: Optional[str],
    nameservers: Optional[List[str]],
    skip_rbl: bool,
) -> tuple[
    Optional[str],
    List[CheckResult],
    List[CheckResult],
    List[CheckResult],
]:
    resolver = configure_resolver(nameservers)
    rbl_resolver = configure_resolver(nameservers, fallback=RBL_NAMESERVERS)
    domain_ip = ip or resolve_ip(resolver, domain)
    technical_checks = [
        check_spf(resolver, domain),
        check_dkim(resolver, domain, dkim_selector),
        check_dmarc(resolver, domain),
        check_mx_records(resolver, domain),
    ]
    rdns = check_rdns(resolver, domain_ip)
    helo = check_helo(domain, rdns)
    technical_checks.extend([rdns, helo])
    rbl_results = (
        [CheckResult("RBL", "INFO", "Skipped by user request")]
        if skip_rbl
        else check_rbls(rbl_resolver, domain_ip, RBL_ZONES, fallback_resolver=resolver)
    )
    surbl_results = (
        [CheckResult("SURBL", "INFO", "Skipped by user request")]
        if skip_rbl
        else check_surbls(rbl_resolver, domain, SURBL_ZONES)
    )
    return domain_ip, technical_checks, rbl_results, surbl_results


def print_section(title: str, checks: List[CheckResult]) -> None:
    print(f"\n== {title} ==")
    for check in checks:
        print(f"[{check.status}] {check.name}: {check.detail}")


def print_advanced_guidance() -> None:
    print("\n== Advanced Check Guidance ==")
    for idx, step in enumerate(ADVANCED_GUIDANCE, start=1):
        print(f"{idx}) {step}")


def parse_nameservers(raw_value: str) -> List[str]:
    if not raw_value:
        return []
    parts = []
    for piece in raw_value.replace(";", ",").split(","):
        cleaned = piece.strip()
        if cleaned:
            parts.append(cleaned)
    return parts


def create_app() -> Flask:
    app = Flask(__name__)
    init_db(DB_PATH)

    @app.route("/", methods=["GET", "POST"])
    def index():
        action = request.form.get("action") or request.form.get("action_auto") or "checks"
        active_tab = request.form.get("tab") or request.args.get("tab") or "simple"
        if action.startswith("advanced"):
            active_tab = "advanced"
        purge_expired(DB_PATH)
        form = {
            "domain": request.form.get("domain", "").strip(),
            "ip": request.form.get("ip", "").strip(),
            "dkim_selector": request.form.get("dkim_selector", "").strip(),
            "nameservers": request.form.get("nameservers", "").strip(),
            "skip_rbl": bool(request.form.get("skip_rbl")),
            "advanced_token": request.form.get("advanced_token", "").strip(),
        }
        results = None
        error = None
        if request.method == "POST":
            if action == "checks" and not form["domain"]:
                error = "Domain is required."
            else:
                results = {
                    "domain": None,
                    "ip": None,
                    "technical": [],
                    "rbl": [],
                    "surbl": [],
                    "advanced": [],
                    "advanced_meta": None,
                    "advanced_pending": False,
                    "flags_red": [],
                    "flags_green": [],
                    "ai_summary": "",
                }
                if form["domain"]:
                    domain_ip, technical, rbl, surbl = run_checks(
                        form["domain"],
                        form["ip"] or None,
                        form["dkim_selector"] or None,
                        parse_nameservers(form["nameservers"]),
                        form["skip_rbl"],
                    )
                    results.update(
                        {
                            "domain": form["domain"],
                            "ip": domain_ip,
                            "technical": technical,
                            "rbl": rbl,
                            "surbl": surbl,
                        }
                    )
                if action == "advanced_create":
                    mailbox = create_mailbox(DB_PATH, SCHECK_DOMAIN, MAILBOX_TTL_SECONDS)
                    form["advanced_token"] = mailbox["token"]
                    results["advanced_meta"] = {
                        "address": mailbox["address"],
                        "expires_at": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(mailbox["expires_at"])),
                        "expires_at_ts": mailbox["expires_at"],
                    }
                    results["advanced"] = [
                        CheckResult("Inbox", "INFO", "Waiting for message (refresh to check)")
                    ]
                    results["advanced_pending"] = True
                if action == "advanced_check":
                    token = form["advanced_token"]
                    mailbox = get_mailbox_by_token(DB_PATH, token) if token else None
                    if not mailbox:
                        error = "Inbox token not found or expired."
                    else:
                        results["advanced_meta"] = {
                            "address": mailbox["address"],
                            "expires_at": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(mailbox["expires_at"])),
                            "expires_at_ts": mailbox["expires_at"],
                        }
                        message = get_latest_message(DB_PATH, mailbox["id"])
                        if not message:
                            results["advanced"] = [
                                CheckResult("Inbox", "WARN", "No message received yet.")
                            ]
                            results["advanced_pending"] = True
                        else:
                            if message.get("analysis_json"):
                                analysis = json.loads(message["analysis_json"])
                                results["advanced"] = checks_from_json(analysis.get("checks", []))
                                results["flags_red"] = analysis.get("red_flags", [])
                                results["flags_green"] = analysis.get("green_flags", [])
                                results["ai_summary"] = analysis.get("ai_summary", "")
                                results["advanced_pending"] = False
                            else:
                                analysis = analyze_message(
                                    message["raw"],
                                    message.get("peer_ip", ""),
                                    message.get("helo", ""),
                                    message.get("mail_from", ""),
                                )
                                update_message_analysis(
                                    DB_PATH,
                                    message["id"],
                                    json.dumps(
                                        {
                                            "checks": checks_to_json(analysis["checks"]),
                                            "red_flags": analysis["red_flags"],
                                            "green_flags": analysis["green_flags"],
                                            "ai_summary": analysis["ai_summary"],
                                        }
                                    ),
                                )
                                results["advanced"] = analysis["checks"]
                                results["flags_red"] = analysis["red_flags"]
                                results["flags_green"] = analysis["green_flags"]
                                results["ai_summary"] = analysis["ai_summary"]
                                results["advanced_pending"] = False
        return render_template_string(
            PAGE_TEMPLATE,
            form=form,
            results=results,
            guidance_advanced=ADVANCED_GUIDANCE,
            service_domain=SCHECK_DOMAIN,
            active_tab=active_tab,
            error=error,
        )

    return app


def run_cli(args: argparse.Namespace) -> None:
    if not args.domain:
        raise SystemExit("Domain is required in CLI mode. Use --web to start the UI.")

    domain_ip, technical_checks, rbl_results, surbl_results = run_checks(
        args.domain,
        args.ip,
        args.dkim_selector,
        args.nameserver,
        args.skip_rbl,
    )

    print_section("Technical readiness", technical_checks)
    print_section("RBL / DNSBL reputation", rbl_results)
    print_section("SURBL reputation", surbl_results)
    print_advanced_guidance()

    if domain_ip:
        print(f"\nResolved IP used for rDNS/RBL: {domain_ip}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Check domain readiness and spam reputation (DNS + RBL)."
    )
    parser.add_argument("domain", nargs="?", help="Domain to check (example.com)")
    parser.add_argument("--ip", help="Sending IP to use for rDNS/RBL checks; defaults to domain A/AAAA")
    parser.add_argument("--dkim-selector", help="DKIM selector to verify (e.g., default, mail)")
    parser.add_argument(
        "--nameserver",
        action="append",
        help="Custom DNS nameserver to use (can be passed multiple times)",
    )
    parser.add_argument("--skip-rbl", action="store_true", help="Skip RBL lookups")
    parser.add_argument("--web", action="store_true", help="Run a web UI instead of CLI output")
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind for web UI (use with --web)")
    parser.add_argument("--port", type=int, default=5000, help="Port to bind for web UI (use with --web)")

    args = parser.parse_args()

    if args.web:
        app = create_app()
        app.run(host=args.host, port=args.port, debug=False)
        return

    run_cli(args)


if __name__ == "__main__":
    main()
