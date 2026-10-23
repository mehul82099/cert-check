# cert-check

A small linter for X.509 certificates in PEM files. It checks the things that page people
at 3am: expired or not-yet-valid certificates, certificates about to expire, self-signed
leaves, missing `subjectAltName`, hostname mismatches (RFC 6125), issuers that are not in
the bundle, and validity windows longer than the CA/Browser Forum Baseline Requirements cap.

Python 3.9+, standard library only. No network - it never fetches anything, you point it at
files. MIT license.

```
python cert_check.py cert.pem
python cert_check.py fullchain.pem --host www.example.com
python cert_check.py a.pem b.pem --warn-days 14 --json
python cert_check.py cert.pem --strict                  # warnings also give exit 1
python cert_check.py cert.pem --max-validity-days 200   # change the BR validity cap
```

A PEM file may hold several certificates (a bundle). The first certificate is treated as
the leaf: `--host` is verified against the leaf only, not the intermediates after it.
Output is `file: severity [rule] message`. Exit codes: `0` no findings, `1` errors found
(or warnings with `--strict`), `2` unreadable input, no PEM blocks, or nothing decodable.

## What it checks

| Rule id | Severity | Basis |
|---|---|---|
| `expired` | error | RFC 5280 validity: current time is past `notAfter` |
| `not-yet-valid` | error | RFC 5280 validity: current time is before `notBefore` |
| `expires-soon` | warning | `notAfter` is within `--warn-days` (default 30) |
| `hostname-mismatch` | error | RFC 6125 section 6.4: the host matches no DNS name in `subjectAltName` (wildcards only as the complete left-most label, matching one label, section 6.4.3) |
| `cn-fallback` | warning | the host matched only through the Common Name, the fallback RFC 6125 section 6.4.4 describes for certificates without a DNS SAN |
| `missing-san` | warning | no `subjectAltName` extension; the CA/Browser Forum Baseline Requirements require SANs in public TLS certificates |
| `self-signed` | warning | issuer equals subject (RFC 5280 names) |
| `issuer-not-in-bundle` | warning | a non-self-signed certificate whose issuer has no certificate in the same file (only checked in multi-certificate files) |
| `validity-too-long` | warning | validity window exceeds `--max-validity-days` (default 398, the CA/B BR section 6.3.2 cap for public TLS certificates; ballot SC081v3 schedules reductions from 398 down to 47 days between March 2026 and March 2029, so set the flag to match your CA's current limit) |
| `bad-certificate` | error | a `-----BEGIN CERTIFICATE-----` block that does not decode |

## What it does not do

This is a file linter, not a TLS probe. It does not connect to servers, build or verify
chains against a trust store, check revocation (OCSP/CRL), key sizes, or signature
algorithms, and it only reads the PEM armored form (not DER). A certificate that passes can
still fail in a real handshake. Decoding uses CPython's OpenSSL-backed certificate parser
(`ssl._ssl._test_decode_cert`, the same parse path `ssl` uses when loading certificates);
it is a private name in the standard library, which is why CI pins the claim to the
versions tested.

## Tests

```
python -m unittest -v
```

50 tests cover PEM splitting, RFC 6125 name matching (exact, case, wildcards, CN fallback,
SAN precedence), every date rule against fixed clocks (the date tests use fabricated
certificate fields so they never go stale), the bundle checks, real embedded certificates
generated with OpenSSL (a CA, a leaf with SANs valid into 2036, and a no-SAN certificate),
exit codes, and the JSON report. CI runs on Ubuntu and Windows with Python 3.9 and 3.13
(see `.github/workflows/test.yml`); I have not run it on other versions.

## Sources

- RFC 5280, Internet X.509 Public Key Infrastructure Certificate and Certificate Revocation List (CRL) Profile: https://www.rfc-editor.org/rfc/rfc5280
- RFC 6125, Representation and Verification of Domain-Based Application Service Identity (sections 6.4.3 and 6.4.4): https://www.rfc-editor.org/rfc/rfc6125
- CA/Browser Forum, Baseline Requirements for TLS Server Certificates (section 6.3.2 validity cap): https://cabforum.org/working-groups/server/baseline-requirements/
- CA/Browser Forum, Ballot SC081v3 (validity reduction schedule, adopted April 2025): https://cabforum.org/2025/04/11/ballot-sc081v3-introduce-schedule-of-reducing-validity-and-data-reuse-periods/
- Python `ssl` module documentation: https://docs.python.org/3/library/ssl.html

## License

MIT, see `LICENSE`.
