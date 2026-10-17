# UK Bank Phishing Monitor

Detects newly observed domains impersonating UK banks by watching
Certificate Transparency logs in real time and scanning look-alike
permutations of legitimate bank domains. Every detection is scored with
transparent, explainable reasons, stored, and alerted on when high risk.

> Built as a Cyber Threat Intelligence portfolio project focused on the UK
> financial sector, where bank impersonation and Authorised Push Payment (APP)
> fraud are major threats.

## How it works

```
                 Python (24/7, high volume)                      n8n (orchestration)
CT logs ───┐                                          ┌──────────────────────────────────────┐
           ├─► Scoring ─► SQLite ─► webhook (new ≥40) ─┼─► RDAP ─► DNS ─► Decide ─► Telegram │
dnstwist ──┘                                          └──────────────────────────────────────┘
```

Python does what n8n is not built for: holding a permanent WebSocket to the
Certificate Transparency stream and scoring thousands of domains per minute.
Only new detections at or above the storage threshold leave Python. n8n then
enriches each one and decides whether it deserves a Telegram alert.

1. **Collection**: `certstream` streams every newly issued TLS certificate;
   `dnstwist` generates typos, homoglyphs and TLD swaps of each bank's
   legitimate domains and keeps only registered ones.
2. **Scoring**: each domain is checked against 14 UK banks
   (`config/brands.yaml`). Points are awarded for:

   | Signal | Weight | Example |
   |---|---|---|
   | Brand keyword | 40 | `barclays-help.com` |
   | Brand hidden with look-alike chars | +25 | `natw3st.com`, `bardays.com` |
   | Typosquat (edit distance) | 30 | `santnader.co` |
   | Punycode label | 25 | `xn--mnzo-…` (Cyrillic “о”) |
   | Suspicious words (capped at 45) | 15 each | `verify`, `payee`, `refund`, `hmrc` |
   | Abused TLD | 10 | `.top`, `.xyz`, `.shop` |
   | Deep subdomain | 10 | `barclays.secure.login.example.com` |

   Legitimate bank domains are allowlisted. Domains with no brand signal are
   capped below the storage threshold to limit noise.
3. **Storage**: detections ≥ 40 go to SQLite with first/last seen and hit count.
4. **Enrichment and alerting (n8n)**: the workflow in `n8n/ukphish_workflow.json`
   looks up domain age and registrar via RDAP and the resolving IPs via
   DNS-over-HTTPS. It alerts on Telegram when either:
   - the score is ≥ 60, or
   - the score is lower but the domain was **registered in the last 7 days and
     already resolves**, a strong sign of an imminent campaign (escalation).

   All indicators in alerts are **defanged** (`barclays-verify[.]com`).
   Without n8n, Python can send alerts (score ≥ 60) directly to Telegram.

Weights and thresholds live in `config/settings.yaml`. The rationale for each
weight is part of the analysis: tune them as you review false positives.

## Setup

### 1. Install

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dnstwist]"
cp .env.example .env
docker compose up -d        # certstream on :8080, n8n on :5678
```

### 2. Create the Telegram bot

1. In Telegram, talk to **@BotFather**, send `/newbot` and save the token.
2. Send any message to your new bot (or add it to a group/channel).
3. Open `https://api.telegram.org/bot<TOKEN>/getUpdates` and copy
   `message.chat.id`. That is your chat ID.

### 3. Configure n8n

1. Open http://localhost:5678 and create the owner account.
2. **Workflows → Import from file** → `n8n/ukphish_workflow.json`.
3. Open the **Telegram alert** node: create a Telegram credential with your bot
   token and replace `YOUR_TELEGRAM_CHAT_ID` with your chat ID.
4. Optional: in the **Webhook** node, enable *Header Auth* with header
   `X-UKPhish-Token` and set the same value as `N8N_WEBHOOK_TOKEN` in `.env`.
5. **Activate** the workflow. The production URL is
   `http://localhost:5678/webhook/ukphish-detection` (use `/webhook-test/` while
   clicking *Listen for test event* in the editor).

### 4. Run

```bash
ukphish score hsbc-payee-verify.top     # sanity check, no network needed
ukphish stream                          # real-time CT monitoring
ukphish dnstwist                        # daily permutation scan (cron it)
ukphish top --limit 20
ukphish stats
```

Test the n8n flow end to end without waiting for a real detection:

```bash
curl -X POST http://localhost:5678/webhook-test/ukphish-detection \
  -H "Content-Type: application/json" \
  -d '{"domain":"barclays-verify-payee.top","domain_defanged":"barclays-verify-payee[.]top","brand":"Barclays","score":80,"reasons":["brand keyword barclays"],"source":"manual-test","store_threshold":40,"alert_threshold":60}'
```

### Direct Telegram mode (without n8n)

Leave `N8N_WEBHOOK_URL` empty in `.env` and fill in `TELEGRAM_BOT_TOKEN` and
`TELEGRAM_CHAT_ID`. Detections with score ≥ 60 are sent straight to Telegram
(no enrichment or escalation).

## Running 24/7 on a home server

The repository ships a full Docker stack (certstream, n8n, collector and a
daily dnstwist job). See [docs/homelab-zimablade.md](docs/homelab-zimablade.md).

## Tests

```bash
python -m unittest discover -s tests -v
```

## Roadmap

- [x] Enrichment in n8n: RDAP domain age and registrar, DNS A records
- [x] Telegram alerts with escalation for fresh, live domains
- [ ] More enrichment: MX/NS records, ASN/hosting, urlscan.io screenshot
- [ ] Campaign clustering by shared infrastructure (networkx graph)
- [ ] Streamlit dashboard
- [ ] STIX 2.1 export for MISP / OpenCTI
- [ ] Monthly intelligence report: *UK Banking Phishing Landscape*

## Ethics and safe handling

- Collection is **passive**: no interaction with suspected phishing sites.
  Use urlscan.io for page content rather than visiting sites directly.
- Indicators are always defanged when shared.
- Confirmed phishing is reported to the NCSC Suspicious Email Reporting
  Service (report@phishing.gov.uk) and to Netcraft.
- No victim data is collected, stored or published.

## Disclaimer

Detections are leads for analyst review, not verdicts. A high score does not
prove a domain is malicious.
