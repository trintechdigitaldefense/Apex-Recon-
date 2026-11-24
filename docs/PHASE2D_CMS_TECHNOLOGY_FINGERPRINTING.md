# Phase 2D — Passive CMS and technology identification

## What this milestone adds

Phase 2D extends the existing HTTP Security Assessment (menu option 3). It does not add a separate scanner or any new target paths.

- Read response headers and a bounded HTML sample from the existing HTTP assessment requests.
- Read at most 8 KiB from each of at most two HTTP responses (16 KiB total).
- Request identity encoding and read only HTML/XHTML response bodies.
- Identify evidence-backed markers for WordPress, Joomla, Drupal, Shopify, Wix and Squarespace.
- Identify selected frontend technologies: React, Vue.js, Angular, jQuery and Bootstrap.
- Preserve observed Server and X-Powered-By headers as header observations.
- Report evidence marker names, source and confidence without storing raw HTML snippets.
- Report a CMS version only when an explicit generator meta tag contains a numeric version token.
- Include fingerprints in the standalone escaped HTML report.

## Interpretation and confidence

- **High:** an explicit CMS generator marker or multiple independent CMS markers; technology-specific high-confidence DOM markers.
- **Medium:** one clear technology asset/runtime marker or multiple corroborating CMS markers where defined.
- **Low:** a single weak CMS marker.
- **Observed:** a literal server/application response header, not a validated software inventory.

A fingerprint is an observation, not proof that a product is installed, current, exploitable or actively used. CDN references, copied templates, cached assets, custom themes and reverse proxies can create false positives. No version is inferred from asset filenames or framework DOM attributes.

No fingerprint result means only that no supported marker was found in the sampled response. It does not prove that a CMS or technology is absent.

## Network and safety boundaries

- Uses the existing one-path HTTP assessment and its authorization gate.
- No additional requests are made for fingerprinting.
- At most two read-only GET requests remain in scope.
- At most 8 KiB of HTML is read per response, with a 16 KiB total body-read ceiling.
- No crawling, directory discovery, CMS admin-path probes, wordlists, fuzzing, authentication, form submission, exploitation or background monitoring.
- Non-HTML response bodies are not read for fingerprinting.
- Query strings remain stripped before requests and report output.
- HTML report fields are escaped; raw page content is not copied into the report.

## Offline validation

Run:

\`\`\`bash
python3 -m compileall -q apex_recon_v2.py apex_web.py apex_tls.py apex_fingerprint.py tests
python3 -m unittest discover -s tests -v
\`\`\`

Tests use synthetic HTML and mocked responses. They do not contact live targets. Passing tests do not establish fingerprint accuracy against real-world sites, platform compatibility, client readiness or release readiness.

## Development status

Phase 2D is a draft development milestone stacked on Phase 2C. It does not authorize merging, release, client deployment or live scanning.
