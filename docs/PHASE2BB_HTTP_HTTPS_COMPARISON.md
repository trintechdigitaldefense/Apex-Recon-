# Phase 2BB — HTTP/HTTPS response comparison

## Objective

Make the HTTP assessment compare the same bounded GET path over HTTP and HTTPS, and explicitly report whether HTTP redirects to HTTPS, returns a response body, or is unavailable.

## Correct the request behavior

The previous HTTP fetch sent `Range: bytes=0-8191`. That asks the server for a partial representation and can itself produce HTTP 206. The observed 206 responses in the example.com report therefore cannot be treated as representative ordinary-GET status codes.

The scanner now omits the Range request header and enforces the response sample cap locally by reading no more than 8 KiB per response. It reads a bounded sample for every content type to establish whether response bytes were observed; only HTML/XHTML samples are passed to passive technology fingerprinting. The combined maximum remains 16 KiB across at most two GET responses.

## Comparison output

Each HTTP assessment includes `http_https_comparison` with:

- The GET method, same-host/same-path scope, and whether a query string was sent.
- An outcome: `HTTP_REDIRECTED_TO_HTTPS`, `HTTP_CONTENT_OBSERVED`, `HTTP_RESPONSE_WITHOUT_BODY`, `HTTP_RESPONSE_BODY_UNREADABLE`, or `HTTP_UNAVAILABLE`.
- HTTP and HTTPS response summaries: status and status class, final URL/scheme, content type, declared content length, bytes sampled, sample-cap state, and bounded redirect metadata.
- For independent HTTP and HTTPS responses, comparison flags for status, content type, and equality of complete bounded body samples.
- Redirect status and destination when HTTP upgrades to HTTPS. The redirected HTTPS response is reused, avoiding a redundant second request.

A body-sample equality result is omitted (null) when either sample may be truncated or could not be read. Even a complete 8 KiB sample comparison is not a full representation comparison. Dynamic pages may legitimately differ between requests.

## Safety and privacy

- At most two read-only GET requests.
- At most 8 KiB read from each response, 16 KiB total.
- No Range header, crawling, forms, fuzzing, exploitation, or query-string transmission.
- Response bodies are retained only in memory for the bounded comparison and optional HTML fingerprinting; the comparison record stores metadata and booleans, not body content.
- Redirect scope remains restricted to one same-host HTTP-to-HTTPS upgrade with the same path.
- Cross-host, downgrade, non-standard-port, and path/query-changing redirects remain blocked.

## Validation

Run:

```bash
python3 -m compileall -q apex_web.py tests
python3 -m unittest discover -s tests -p 'test_http_https_comparison.py' -v
python3 -m unittest discover -s tests -p 'test_web_assessment.py' -v
python3 -m unittest discover -s tests -p 'test_phase2u_http_evidence.py' -v
python3 -m unittest discover -s tests -v
git diff --check
git status --short
```

The example.com assessment should be rerun after validation. Its status code may differ now that the scanner no longer requests a byte range. No finding should be inferred from the old 206 responses alone.
