#!/usr/bin/env python3
"""cert_check - lint X.509 certificates and bundles in PEM files.

Checks the things that page people at 3am: expired or not-yet-valid
certificates, certificates about to expire, self-signed leaves, missing
subjectAltName, hostname mismatches (RFC 6125), issuers missing from a
bundle, and validity windows that exceed the CA/Browser Forum Baseline
Requirements cap.

Python 3.9+, standard library only. No network.

Usage:
    python cert_check.py cert.pem
    python cert_check.py fullchain.pem --host www.example.com
    python cert_check.py a.pem b.pem --warn-days 14 --json
    python cert_check.py cert.pem --strict    # warnings also give exit 1

Exit codes: 0 = no findings, 1 = errors found (or warnings with --strict),
2 = unreadable file, no certificates found, or nothing decodable.
"""

import argparse
import json
import os
import ssl
import sys
import tempfile
import time

ERROR = "error"
WARNING = "warning"

CERT_BEGIN = "-----BEGIN CERTIFICATE-----"
CERT_END = "-----END CERTIFICATE-----"


def split_pem_blocks(text):
    """Return the CERTIFICATE blocks (with armor) found in text."""
    blocks = []
    pos = 0
    while True:
        start = text.find(CERT_BEGIN, pos)
        if start < 0:
            break
        end = text.find(CERT_END, start)
        if end < 0:
            blocks.append(text[start:])
            break
        blocks.append(text[start:end + len(CERT_END)])
        pos = end + len(CERT_END)
    return blocks


def decode_cert(pem_block):
    """Decode one PEM block via CPython's certificate parser.

    Uses ssl._ssl._test_decode_cert, the same parser OpenSSL-backed
    certificate loading uses, by way of a temporary file. Returns
    (parsed_dict, error_message).
    """
    fd, tmp = tempfile.mkstemp(suffix=".pem")
    try:
        with os.fdopen(fd, "w") as fh:
            fh.write(pem_block)
        try:
            return ssl._ssl._test_decode_cert(tmp), None
        except (ssl.SSLError, ValueError, OSError) as exc:
            return None, str(exc)
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass


def common_name(name_tuple):
    """First commonName in a parsed subject/issuer tuple, or ''."""
    for rdn in name_tuple:
        for attr, value in rdn:
            if attr == "commonName":
                return value
    return ""


def san_dns_names(parsed):
    return [v for t, v in parsed.get("subjectAltName", ()) if t == "DNS"]


def dnsname_match(pattern, host):
    """RFC 6125 style DNS-ID matching: exact, or a wildcard that is the
    complete left-most label and covers exactly one label."""
    pattern = pattern.lower().rstrip(".")
    host = host.lower().rstrip(".")
    if pattern.startswith("*."):
        suffix = pattern[1:]
        if not host.endswith(suffix):
            return False
        prefix = host[:-len(suffix)]
        return bool(prefix) and "." not in prefix
    return pattern == host


def verify_hostname(host, parsed):
    """Returns 'san', 'cn', or None depending on what matched."""
    sans = san_dns_names(parsed)
    if sans:
        return "san" if any(dnsname_match(p, host) for p in sans) else None
    cn = common_name(parsed.get("subject", ()))
    if cn and dnsname_match(cn, host):
        return "cn"
    return None


def check_cert(parsed, warn_days, max_validity_days, now, host=None,
               br_scope=True):
    """Run the per-certificate checks. Returns a list of findings:
    (rule, severity, message).

    br_scope says the certificate may be a publicly-trusted TLS subscriber
    certificate, so the CA/Browser Forum validity cap applies. Self-signed
    certificates and CA certificates (anything that issued another
    certificate in the same file) are out of BR scope and never get the
    validity-too-long finding."""
    findings = []
    cn = common_name(parsed.get("subject", ())) or "(no CN)"
    try:
        not_before = ssl.cert_time_to_seconds(parsed["notBefore"])
        not_after = ssl.cert_time_to_seconds(parsed["notAfter"])
    except (KeyError, ValueError) as exc:
        return [("bad-validity", ERROR, "%s: unreadable validity dates (%s)"
                 % (cn, exc))]
    expires = time.strftime("%Y-%m-%d", time.gmtime(not_after))

    if now > not_after:
        findings.append(("expired", ERROR,
                         "%s: expired on %s" % (cn, expires)))
    elif not_after - now < warn_days * 86400:
        days = int((not_after - now) // 86400)
        findings.append(("expires-soon", WARNING,
                         "%s: expires on %s (%d days)" % (cn, expires, days)))
    if now < not_before:
        findings.append(("not-yet-valid", ERROR,
                         "%s: not valid before %s"
                         % (cn, time.strftime("%Y-%m-%d",
                                              time.gmtime(not_before)))))
    self_signed = parsed.get("issuer") == parsed.get("subject")
    if self_signed:
        findings.append(("self-signed", WARNING,
                         "%s: issuer equals subject (self-signed)" % cn))
    if not san_dns_names(parsed):
        findings.append(("missing-san", WARNING,
                         "%s: no subjectAltName extension" % cn))
    validity_days = (not_after - not_before) / 86400.0
    if br_scope and not self_signed and validity_days > max_validity_days:
        findings.append(("validity-too-long", WARNING,
                         "%s: validity period %.0f days exceeds the %d-day "
                         "cap for public TLS subscriber certificates"
                         % (cn, validity_days, max_validity_days)))
    if host:
        matched = verify_hostname(host, parsed)
        if matched is None:
            names = san_dns_names(parsed) or [common_name(
                parsed.get("subject", ()))]
            findings.append(("hostname-mismatch", ERROR,
                             "%s: does not match %r (names: %s)"
                             % (cn, host, ", ".join(n for n in names if n))))
        elif matched == "cn":
            findings.append(("cn-fallback", WARNING,
                             "%s: matched %r only via the deprecated "
                             "Common Name fallback" % (cn, host)))
    return findings


def scan_file(path, warn_days, max_validity_days, now, host=None):
    """Scan one PEM file. Returns (findings, cert_count, fatal_error).
    Findings carry the file path."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError as exc:
        return None, 0, "cannot read %s: %s" % (path, exc)
    blocks = split_pem_blocks(text)
    if not blocks:
        return None, 0, "%s: no PEM certificate blocks found" % path

    findings = []
    parsed_certs = []
    for i, block in enumerate(blocks):
        parsed, err = decode_cert(block)
        if err:
            findings.append({
                "file": path, "cert": i + 1, "rule": "bad-certificate",
                "severity": ERROR,
                "message": "certificate #%d does not decode: %s" % (i + 1, err)})
        else:
            parsed_certs.append(parsed)
    issuer_names = {common_name(p.get("issuer", ()))
                    for p in parsed_certs}
    for i, parsed in enumerate(parsed_certs):
        # --host verifies the leaf, which by convention is the first
        # certificate in the file, not the intermediates after it.
        leaf_host = host if i == 0 else None
        # A certificate that issued another certificate in this file is a
        # CA certificate, not a subscriber certificate: the BR validity cap
        # does not apply to it.
        is_ca = common_name(parsed.get("subject", ())) in issuer_names
        for rule, severity, message in check_cert(
                parsed, warn_days, max_validity_days, now, leaf_host,
                br_scope=not is_ca):
            findings.append({
                "file": path, "cert": None, "rule": rule,
                "severity": severity, "message": message})
    if len(parsed_certs) > 1:
        subjects = {common_name(p.get("subject", ())) for p in parsed_certs}
        for parsed in parsed_certs:
            issuer = common_name(parsed.get("issuer", ()))
            subject = common_name(parsed.get("subject", ()))
            if issuer and issuer != subject and issuer not in subjects:
                findings.append({
                    "file": path, "cert": None,
                    "rule": "issuer-not-in-bundle", "severity": WARNING,
                    "message": "%s: issuer %r has no certificate in this "
                               "bundle" % (subject or "(no CN)", issuer)})
    return findings, len(parsed_certs), None


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="cert_check",
        description="Lint X.509 certificates and bundles in PEM files.")
    parser.add_argument("paths", nargs="+", help="PEM files to check")
    parser.add_argument("--host",
                        help="verify the certificate names match this host")
    parser.add_argument("--warn-days", type=int, default=30,
                        help="warn when expiry is within this many days "
                             "(default: 30)")
    parser.add_argument("--max-validity-days", type=int, default=200,
                        help="warn when a subscriber certificate's validity "
                             "window exceeds this many days (default: 200, "
                             "the CA/B BR cap effective 2026-03-15)")
    parser.add_argument("--json", action="store_true",
                        help="emit findings as JSON")
    parser.add_argument("--strict", action="store_true",
                        help="exit 1 on warnings too")
    args = parser.parse_args(argv)

    findings = []
    total_certs = 0
    fatals = []
    for path in args.paths:
        if not os.path.exists(path):
            fatals.append("no such file: %s" % path)
            continue
        if not os.path.isfile(path):
            fatals.append("not a regular file: %s" % path)
            continue
        file_findings, count, fatal = scan_file(
            path, args.warn_days, args.max_validity_days, time.time(),
            args.host)
        if fatal:
            fatals.append(fatal)
        else:
            findings.extend(file_findings)
            total_certs += count
    for msg in fatals:
        print("cert_check: %s" % msg, file=sys.stderr)

    errors = sum(1 for f in findings if f["severity"] == ERROR)
    warnings = sum(1 for f in findings if f["severity"] == WARNING)
    if args.json:
        print(json.dumps({
            "certificates": total_certs,
            "errors": errors,
            "warnings": warnings,
            "findings": findings,
        }, indent=2, ensure_ascii=False))
    else:
        for f in findings:
            print("%s: %s [%s] %s"
                  % (f["file"], f["severity"], f["rule"], f["message"]))
    if fatals or total_certs == 0:
        return 2
    if errors or (args.strict and warnings):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
