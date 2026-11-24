# Phase 2C — Verified TLS assessment

## What this milestone adds

- Menu option 4: TLS Security Assessment.
- One TCP connection and one TLS handshake to the supplied hostname/IP on standard port 443.
- The system trust store, certificate-chain verification and hostname verification remain enabled.
- On a successful verified handshake, record the negotiated TLS protocol and cipher, certificate subject/issuer, validity dates and returned subject alternative names.
- Classify certificates expiring within 7 days as HIGH and within 30 days as MEDIUM.
- Write a standalone HTML report with escaped evidence and owner-only permissions (0600) on supported POSIX filesystems.

## Operator workflow

1. Start ApexRecon with \`python3 apex_recon_v2.py\`.
2. Select menu option \`4\`.
3. Enter one authorized hostname, IP literal, or HTTP(S) URL. The TLS scope is always the hostname/IP on TCP port 443.
4. Review the displayed scope and confirm written authorization for that exact host and port by typing \`YES\`.
5. Review the results and open \`apex_tls_report_*.html\`.

If authorization is declined, no TLS connection is made.

## Security and interpretation boundaries

- One TCP connection and one verified TLS handshake only.
- No insecure/unverified fallback is attempted, including after certificate validation failure.
- No downgrade probing, protocol-version enumeration, cipher enumeration, port scanning, HTTP request, crawling, authentication or exploitation.
- The protocol and cipher shown are the values negotiated by this client. They are not a complete inventory of server-supported versions or ciphers.
- A failed handshake does not establish which other TLS versions or ciphers the server may support.
- An expired certificate may fail verification before certificate details are returned; ApexRecon reports the verification failure rather than bypassing trust checks to inspect it.
- Certificate expiry thresholds are informational triage, not a substitute for the organisation's certificate lifecycle process.

## Offline validation

\`\`\`bash
python3 -m compileall -q apex_recon_v2.py apex_web.py apex_tls.py tests
python3 -m unittest discover -s tests -v
\`\`\`

The TLS tests mock the socket and SSL context. They do not connect to live hosts. A passing suite does not prove Android compatibility, live accuracy, client readiness or release readiness.

## Development status

This milestone is a draft development change stacked on Phase 2B. It does not authorize merge, release, client deployment or live scanning.
