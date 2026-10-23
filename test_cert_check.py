import calendar
import contextlib
import datetime
import io
import json
import os
import tempfile
import time
import unittest

import cert_check as cc

LEAF_PEM = """-----BEGIN CERTIFICATE-----
MIIDITCCAgmgAwIBAgIUBOFvpiziRf3oKxeM1sDVdb49bckwDQYJKoZIhvcNAQEL
BQAwEjEQMA4GA1UEAwwHVGVzdCBDQTAeFw0yNjEwMjMwNTI1MjFaFw0zNjEwMjAw
NTI1MjFaMBYxFDASBgNVBAMMC2V4YW1wbGUuY29tMIIBIjANBgkqhkiG9w0BAQEF
AAOCAQ8AMIIBCgKCAQEAmpXqHhJJ5/xgGI63BAR5LskPDT1GgM+fP2hLABSo85CK
iJXqk/ISKZdG5scXVRVrSwNG15prNdJ2KV2Xe12whztSOUOGY3a/99k6wBVxavAh
idpzGKwzHDFxDcxT8Z6khjdOqf+9uYbr/5C3HnyX/aNFeFj8XTCDhzxIjpPEUebu
/yiLT3tJW37CepZ0TpFii7MEbjZ0qCO2Xxk8mVWcp0Gpw7eTgzobEc/ZC23iqVa8
oByBbgKa+qsQ8lj6VG1KZLckECDcB5lvoishy3n7A6d0L+jx792tR/WklnX9GYB0
p9VgBXjfcvlRd4MFAlRVuZ0h0iAHlKJ+VVzOYif/iwIDAQABo2swaTAnBgNVHREE
IDAeggtleGFtcGxlLmNvbYIPd3d3LmV4YW1wbGUuY29tMB0GA1UdDgQWBBREZ1LD
EODAkum2rZhr4YNKWOToITAfBgNVHSMEGDAWgBRrnO1depCzISihN7XwwbLFZ+9L
sjANBgkqhkiG9w0BAQsFAAOCAQEAD63/t2KHZ2v+ZptOVRSLBZYyMEDHO8/i4Guu
mKcsbf9SfZovzbjpA4frHYCAKBSWDNgT0YcsmQQkKeWrgk8OI6TjqYQakA+KF/e5
IhHo7f6Fd3asYwo5oL+d5fTjsXnQBhsKsvpdNi+KyP01lEEkn6bpDUIUb9pMEpH6
SaNCDdpUeCVrWnb5noUXnoDCbTd6a908T3yGW//2LHbzhP5WwQT4y4hQa9uTk1oO
WEUafOESv9mwSFJaES2znDF3BMl3+YYVjT/aAxk/f0XIuWGEKwh2dbCWS8D5Cp0e
gQYLnJC6+a3KI0J4pIklmlDtoOKSr8n5upSZaHPW1WBcPF2gPw==
-----END CERTIFICATE-----"""

CA_PEM = """-----BEGIN CERTIFICATE-----
MIIDBTCCAe2gAwIBAgIUbvn+BBNyFTjWN990CWB0UVkRdiwwDQYJKoZIhvcNAQEL
BQAwEjEQMA4GA1UEAwwHVGVzdCBDQTAeFw0yNjEwMjMwNTI1MjFaFw00NjEwMTgw
NTI1MjFaMBIxEDAOBgNVBAMMB1Rlc3QgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IB
DwAwggEKAoIBAQCvfkuiKGLfJBEM0f0Bx+n/WZCGFm+Jr6tTrbnKKBoHRJOpFWbT
ZBPtWJRHEyEjzyB/xnD4MlG/Ng8IKg/SBLHPJkwx5Bg6aO9LMpCfxf9Bwa59ZeZk
lXHo2fxgVPsNwfIpyHRwWG8KgeFDCjc1xqrzyAdcTVXfhdwII03hIDYfmB5KCyU5
yIjZCda2mvcmNOmJFIakWooRz7eoTPsQnPmpVE1J2Yj8W7/dhAsup2gyIvLG2ELX
bZdcG0BtvPq/XvVoqgWkkO/JmYEi4W5KzdEmqn0aoWyEFMugS4oYxIk47L/gB1sj
UQ2e9RPYgJE++Fa5PnHmkRD4aa0ytaihSCuBAgMBAAGjUzBRMB0GA1UdDgQWBBRr
nO1depCzISihN7XwwbLFZ+9LsjAfBgNVHSMEGDAWgBRrnO1depCzISihN7XwwbLF
Z+9LsjAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQAdzG+k0JuB
Q0bAYCNUzAVs5+dzYWnyNRAPKJ15v/vLYaZBkhZiH7rxIhA2ru8kdIFS6qVVf1Gt
bFicF2o3exy2XzysxCysQQKcs+NP+EEOiPUnav/DNAmi7vqaRy9Q2PVnjnw2yeuL
z7qYX9qwBuO2X51X6/5wQHJGTUK86N/uGGKpJhErn+Ksz09W5R76ZzzEMRA/egiL
mG9KHmQguPJP2xoYmf2hp7qBs5+1hVHNLFsq4ou28mLNF57Ant5fv+ekeebZCV8q
xIk1CBVafPRta3UNzIGupQIWX+C+Vd5izWXTo2iMWEYokvoQeq9LOXUx8pBM0zEc
kCTx5ajonpK1
-----END CERTIFICATE-----"""

INT_PEM = """-----BEGIN CERTIFICATE-----
MIICtTCCAZ0CFCZjYLyj5rpK1IaHPvdgBhNY3OSOMA0GCSqGSIb3DQEBCwUAMBIx
EDAOBgNVBAMMB1Rlc3QgQ0EwHhcNMjYxMDIzMDUzNDE2WhcNMzYxMDIwMDUzNDE2
WjAcMRowGAYDVQQDDBFUZXN0IEludGVybWVkaWF0ZTCCASIwDQYJKoZIhvcNAQEB
BQADggEPADCCAQoCggEBAMVZIR0E9ZXckD8jBy5ObFq7Kf4lUFhJNnTxbqKT10ln
hxM3IWkS5w5NpV+QCWUZCJX/4F7OcPhOtaJ/70EcULwmj8Fk/0LqgOwkXZb3HOHN
upoI0rukPjMFoNO3v8b/ZJgsKDuBN6YoAmy0KPcDTYziE5eYDT75cFFNG9qZ38CF
v6u+89CCJzZ1/KCjfxCVEXFs+ExNt/FZm6x2RO1LRN9Fv4YwEgBl3m711dNsr3Yy
rLhQc5kShK1RRnFMFynbEAgY41h7QOIQPcz9vjComc3wWIDJ7Aoc8WvnCV03S30n
ANl4WwjMd3EPdBaS3yqVzN2yMeOpgEygmDaf84j2gsECAwEAATANBgkqhkiG9w0B
AQsFAAOCAQEAJ35MtdtnhdUGtToC5iheRLoAlRMj2tK1VrWoANOluCg+Jus30CaU
vqVTChZBfvrgCUzz6DZpr4IMvW3dbAJ8vYSoRLMSZpxC7jKk4y7ZZ1kHmkkUb8WA
bAaWTsYOKIzRqRzue/XTs8gVvgLgt/ogcbs5rrARIRu0cGo4AygreOryY4J2E8Bj
5uUDJGpOptE7bqXBI7HsxA08mmofg52PPwN1q8beixiCpzN/uBS82cpt3ataIssj
F+s0C0BkVCV7+2z3c2bzUD3H6RNYqOQKdHEENVYUUyJTEcOarzF7gJVgQScTKkCU
jtlhcjISgShjeSYcsij6LzPzjx7w8O/yvw==
-----END CERTIFICATE-----"""

LEAF2_PEM = """-----BEGIN CERTIFICATE-----
MIIDOjCCAiKgAwIBAgIUPzP+9smPzE92FWFp1eR0kdTK0JQwDQYJKoZIhvcNAQEL
BQAwHDEaMBgGA1UEAwwRVGVzdCBJbnRlcm1lZGlhdGUwHhcNMjYxMDIzMDUzNDE3
WhcNMzYxMDIwMDUzNDE3WjAaMRgwFgYDVQQDDA9hcHAuZXhhbXBsZS5jb20wggEi
MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDAm3cU3vVOHBgC7ZC5FiZXldfZ
lEDeOFjk/6QoEvFmhQkcJnj/hGpGZnHzA+Zh15+kEpcdEy4XiTcWrGimtToGgWo/
qZLWQ16uNWI5BONo2znWgPWWxsfLhxSltxwglghWUuSR+Vwtaj9MKH/C5Y8G4yMb
o0zLXl0oDlOOzehI0KVP5qjpUgnDh3DhzRubHwTG9sWTqEQgd53QrGbOq7/PYJdX
cl/9OOuYYWQkagHnOk+KdD4Uu6LoLb1Sfc0vvBNPXgBKuoXRXC+j1QHnXlSi5UeS
XzZEuWViu71EAtGN+RZAEmNyO/AVsq+Ik/bye582t3tidscT+6by/4OY5OvjAgMB
AAGjdjB0MBoGA1UdEQQTMBGCD2FwcC5leGFtcGxlLmNvbTAdBgNVHQ4EFgQUe2pI
ZVp5QwbhUdvjH8I9ohZDIT8wNwYDVR0jBDAwLqEWpBQwEjEQMA4GA1UEAwwHVGVz
dCBDQYIUJmNgvKPmukrUhoc+92AGE1jc5I4wDQYJKoZIhvcNAQELBQADggEBAHVo
Dym6HkXgJyX3j/gZzAVDrk7Qn/J6OsIEgdLUgk/sSbcg4/3CUbwodUrxT75gZ1MC
AO5ELrRGrYROtyyUpZTA53ap3g/yu++RnMHV2eNTWSXwniIJLU7AT1m0BSMN8Yeo
prc9rsAY0yJBiPz9EpOz1dNbguQtYVfzyuDj1zEhtg0SzJiwMkwnx1s7yJBC7L2o
QyvGxiOpMFHviJr+t9bHA8bpzxjEAW7ToZOQ+rpAjc7n+6SjjPHyxOfOUZJGC4xQ
a+k7f4QiglaUvxQ3RHWu7kWNzCnoq2Z2FB+c4yYJ2mrVRBq1Q1wdlA7xbBpn0NOW
kbooxb/wB7Ao08L2BoM=
-----END CERTIFICATE-----"""

NOSAN_PEM = """-----BEGIN CERTIFICATE-----
MIIDGTCCAgGgAwIBAgIUZwxj7oOS5scaV5zg5EoDXWjSIKYwDQYJKoZIhvcNAQEL
BQAwHDEaMBgGA1UEAwwRbm9zYW4uZXhhbXBsZS5jb20wHhcNMjYxMDIzMDUyNTIy
WhcNMzYxMDIwMDUyNTIyWjAcMRowGAYDVQQDDBFub3Nhbi5leGFtcGxlLmNvbTCC
ASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAOssqK/tM97k2qmIIMqp7/Ib
7G5gC8UL2Z4sKdqCJSdWjAUpsTHGmS2zdsvXiUyxbYf4amx0N07s/YYNfZzvpDak
WOEe+E0qlQWPZ4BdkeitmvThK++S9eWkTPftJXCMJFIyOeAmpsUvLIZ5Vxmfyc8e
VEOp3bJODMuO5egCpTxYrPxQgR5SuSFmZlYA5wL1sq3Xsczr5uCcxeqD/12adf1V
b8MzvfQrAnJvShalcvQ58uYpQgPL3p+zfzTLTNB6Y0K0/4S6y1aDaZt6Pcpfzn+2
jvxU2S0fATeN9yvKZEmKsAvVn1CWDCR+0gEJU5S96jCsiy4Nn3XH9+0/22UQPP8C
AwEAAaNTMFEwHQYDVR0OBBYEFIsF0IpbQRB4PngY+BSZxjjrOPRNMB8GA1UdIwQY
MBaAFIsF0IpbQRB4PngY+BSZxjjrOPRNMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZI
hvcNAQELBQADggEBADw78is88QeZ+NPdYvo1lCjR2hnk4/rSLWVY3uENfNFd28jV
YISOqTrhHn6opXi5PLCkXFcDpjIy6w487McehMGSc5O4TD4ZKpoPKMtrMW/mVYa8
xfLufTWtL98lDlathDwI/ltP4w3jrNbM1jh6D2Y5A0e6e7xut9VKTIxPQ8LaEUGh
VXFtP69a7dURzrXI/UPlr/tEDpjSGWI5zTru/N6hNp7L2eP3B7ahbzI/mU9l/Cfh
+Jhx/f9/+zTg995IOeeg54CBAmC/3M/B6GVdFIk28TbvofWJPdZa/uOoc4Cqrukl
sBBRAzawBdFJd/dyXxNZ7TIyUn5k0IlBtmLfdYY=
-----END CERTIFICATE-----"""

BAD_PEM = """-----BEGIN CERTIFICATE-----
bm90IGEgcmVhbCBjZXJ0aWZpY2F0ZQ==
-----END CERTIFICATE-----"""


def fake(subject_cn="x.example.com", issuer_cn="Fake CA",
         not_before="Jun 15 00:00:00 2024 GMT",
         not_after="Jun 15 00:00:00 2025 GMT",
         san=("x.example.com",)):
    parsed = {
        "subject": ((("commonName", subject_cn),),),
        "issuer": ((("commonName", issuer_cn),),),
        "notBefore": not_before,
        "notAfter": not_after,
    }
    if san is not None:
        parsed["subjectAltName"] = tuple(("DNS", n) for n in san)
    return parsed


NOW = calendar.timegm(datetime.datetime(2024, 6, 20).timetuple())


def run_cli(argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = cc.main(argv)
    return code, out.getvalue(), err.getvalue()


class PemSplitTests(unittest.TestCase):
    def test_single(self):
        self.assertEqual(cc.split_pem_blocks(LEAF_PEM), [LEAF_PEM])

    def test_two_with_text_around(self):
        text = "junk before\n" + LEAF_PEM + "\nbetween\n" + CA_PEM + "\nafter"
        blocks = cc.split_pem_blocks(text)
        self.assertEqual(len(blocks), 2)

    def test_none(self):
        self.assertEqual(cc.split_pem_blocks("no certs here"), [])

    def test_missing_end_keeps_block(self):
        head = LEAF_PEM.split("\n")[0] + "\nabc"
        self.assertEqual(len(cc.split_pem_blocks(head)), 1)


class NameTests(unittest.TestCase):
    def test_dnsname_exact(self):
        self.assertTrue(cc.dnsname_match("example.com", "example.com"))

    def test_dnsname_case_and_trailing_dot(self):
        self.assertTrue(cc.dnsname_match("EXAMPLE.com", "example.COM."))

    def test_dnsname_no_substring(self):
        self.assertFalse(cc.dnsname_match("example.com", "www.example.com"))

    def test_wildcard_one_label(self):
        self.assertTrue(cc.dnsname_match("*.example.com", "www.example.com"))

    def test_wildcard_not_apex(self):
        self.assertFalse(cc.dnsname_match("*.example.com", "example.com"))

    def test_wildcard_not_multi_level(self):
        self.assertFalse(cc.dnsname_match("*.example.com", "a.b.example.com"))

    def test_wildcard_fragment_is_literal(self):
        self.assertFalse(cc.dnsname_match("f*o.example.com", "foo.example.com"))

    def test_verify_san(self):
        parsed = fake(san=("www.example.com",))
        self.assertEqual(cc.verify_hostname("www.example.com", parsed), "san")

    def test_verify_san_ignores_cn(self):
        parsed = fake(subject_cn="other.example.com",
                      san=("www.example.com",))
        self.assertIsNone(cc.verify_hostname("other.example.com", parsed))

    def test_verify_cn_fallback(self):
        parsed = fake(san=None)
        self.assertEqual(cc.verify_hostname("x.example.com", parsed), "cn")

    def test_verify_no_match(self):
        self.assertIsNone(cc.verify_hostname("nope.com", fake()))

    def test_common_name(self):
        parsed = fake()
        self.assertEqual(cc.common_name(parsed["subject"]), "x.example.com")
        self.assertEqual(cc.common_name((())), "")


class CheckCertTests(unittest.TestCase):
    def rules(self, findings):
        return sorted(r for r, _, _ in findings)

    def test_clean(self):
        self.assertEqual(cc.check_cert(fake(), 30, 398, NOW), [])

    def test_expired(self):
        f = cc.check_cert(fake(not_after="Jun 15 00:00:00 2024 GMT"),
                          30, 398, NOW)
        self.assertIn("expired", self.rules(f))
        err = [x for x in f if x[0] == "expired"][0]
        self.assertEqual(err[1], "error")
        self.assertIn("2024-06-15", err[2])

    def test_expired_not_also_expires_soon(self):
        f = cc.check_cert(fake(not_after="Jun 15 00:00:00 2024 GMT"),
                          30, 398, NOW)
        self.assertNotIn("expires-soon", self.rules(f))

    def test_not_yet_valid(self):
        f = cc.check_cert(fake(not_before="Jul  1 00:00:00 2024 GMT"),
                          30, 398, NOW)
        self.assertIn("not-yet-valid", self.rules(f))

    def test_expires_soon_inside_window(self):
        f = cc.check_cert(fake(not_after="Jul  1 00:00:00 2024 GMT"),
                          30, 398, NOW)
        self.assertIn("expires-soon", self.rules(f))
        self.assertEqual([x for x in f if x[0] == "expires-soon"][0][1],
                         "warning")

    def test_expires_soon_outside_window(self):
        f = cc.check_cert(fake(not_after="Aug  1 00:00:00 2024 GMT"),
                          30, 398, NOW)
        self.assertNotIn("expires-soon", self.rules(f))

    def test_self_signed(self):
        f = cc.check_cert(fake(issuer_cn="x.example.com"), 30, 398, NOW)
        self.assertIn("self-signed", self.rules(f))

    def test_missing_san(self):
        f = cc.check_cert(fake(san=None), 30, 398, NOW)
        self.assertIn("missing-san", self.rules(f))

    def test_validity_exactly_max_ok(self):
        nb = datetime.datetime(2024, 1, 1)
        na = nb + datetime.timedelta(days=398)
        f = cc.check_cert(fake(not_before=nb.strftime("%b %d %H:%M:%S %Y GMT"),
                               not_after=na.strftime("%b %d %H:%M:%S %Y GMT")),
                          0, 398, NOW)
        self.assertNotIn("validity-too-long", self.rules(f))

    def test_validity_over_max(self):
        nb = datetime.datetime(2024, 1, 1)
        na = nb + datetime.timedelta(days=399)
        f = cc.check_cert(fake(not_before=nb.strftime("%b %d %H:%M:%S %Y GMT"),
                               not_after=na.strftime("%b %d %H:%M:%S %Y GMT")),
                          0, 398, NOW)
        self.assertIn("validity-too-long", self.rules(f))

    def test_hostname_mismatch(self):
        f = cc.check_cert(fake(), 30, 398, NOW, host="nope.com")
        self.assertIn("hostname-mismatch", self.rules(f))
        self.assertEqual([x for x in f if x[0] == "hostname-mismatch"][0][1],
                         "error")

    def test_hostname_match_san_clean(self):
        self.assertEqual(cc.check_cert(fake(), 30, 398, NOW,
                                       host="x.example.com"), [])

    def test_validity_250_days_flagged_at_200_cap(self):
        nb = datetime.datetime(2024, 1, 1)
        na = nb + datetime.timedelta(days=250)
        f = cc.check_cert(fake(not_before=nb.strftime("%b %d %H:%M:%S %Y GMT"),
                               not_after=na.strftime("%b %d %H:%M:%S %Y GMT")),
                          0, 200, NOW)
        self.assertIn("validity-too-long", self.rules(f))

    def test_validity_skipped_when_not_br_scope(self):
        nb = datetime.datetime(2024, 1, 1)
        na = nb + datetime.timedelta(days=3650)
        f = cc.check_cert(fake(not_before=nb.strftime("%b %d %H:%M:%S %Y GMT"),
                               not_after=na.strftime("%b %d %H:%M:%S %Y GMT")),
                          0, 200, NOW, br_scope=False)
        self.assertNotIn("validity-too-long", self.rules(f))

    def test_validity_skipped_for_self_signed(self):
        nb = datetime.datetime(2014, 1, 1)
        na = nb + datetime.timedelta(days=7300)
        f = cc.check_cert(fake(issuer_cn="x.example.com",
                               not_before=nb.strftime("%b %d %H:%M:%S %Y GMT"),
                               not_after=na.strftime("%b %d %H:%M:%S %Y GMT")),
                          0, 200, NOW)
        self.assertNotIn("validity-too-long", self.rules(f))
        self.assertIn("self-signed", self.rules(f))

    def test_hostname_cn_fallback_warns(self):
        f = cc.check_cert(fake(san=None), 30, 398, NOW, host="x.example.com")
        self.assertEqual(self.rules(f), ["cn-fallback", "missing-san"])


class RealCertTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = self.tmp.name

    def write(self, name, text):
        path = os.path.join(self.dir, name)
        with open(path, "w") as fh:
            fh.write(text)
        return path

    def test_decode_leaf(self):
        parsed, err = cc.decode_cert(LEAF_PEM)
        self.assertIsNone(err)
        self.assertEqual(cc.common_name(parsed["subject"]), "example.com")
        self.assertEqual(cc.common_name(parsed["issuer"]), "Test CA")
        self.assertEqual(cc.san_dns_names(parsed),
                         ["example.com", "www.example.com"])

    def test_decode_nosan(self):
        parsed, _ = cc.decode_cert(NOSAN_PEM)
        self.assertEqual(cc.san_dns_names(parsed), [])

    def test_decode_bad(self):
        parsed, err = cc.decode_cert(BAD_PEM)
        self.assertIsNone(parsed)
        self.assertIsNotNone(err)

    def test_scan_leaf_clean_with_big_validity_cap(self):
        path = self.write("leaf.pem", LEAF_PEM)
        findings, count, fatal = cc.scan_file(path, 30, 10000, time.time())
        self.assertIsNone(fatal)
        self.assertEqual(count, 1)
        self.assertEqual(findings, [])

    def test_scan_bundle_no_missing_issuer(self):
        path = self.write("bundle.pem", LEAF_PEM + "\n" + CA_PEM)
        findings, count, _ = cc.scan_file(path, 0, 10000, time.time())
        self.assertEqual(count, 2)
        rules = [f["rule"] for f in findings]
        self.assertNotIn("issuer-not-in-bundle", rules)

    def test_scan_bundle_missing_issuer(self):
        path = self.write("bundle.pem", LEAF_PEM + "\n" + NOSAN_PEM)
        findings, count, _ = cc.scan_file(path, 0, 10000, time.time())
        hits = [f for f in findings if f["rule"] == "issuer-not-in-bundle"]
        self.assertEqual(len(hits), 1)
        self.assertIn("Test CA", hits[0]["message"])

    def test_host_applies_to_first_cert_only(self):
        path = self.write("bundle.pem", LEAF_PEM + "\n" + CA_PEM)
        findings, _, _ = cc.scan_file(path, 0, 10000, time.time(),
                                      host="example.com")
        self.assertNotIn("hostname-mismatch",
                         [f["rule"] for f in findings])

    def test_host_mismatch_on_leaf_in_bundle(self):
        path = self.write("bundle.pem", CA_PEM + "\n" + LEAF_PEM)
        findings, _, _ = cc.scan_file(path, 0, 10000, time.time(),
                                      host="example.com")
        self.assertIn("hostname-mismatch", [f["rule"] for f in findings])

    def test_intermediate_not_flagged_in_bundle(self):
        path = self.write("bundle.pem", LEAF2_PEM + "\n" + INT_PEM)
        findings, count, _ = cc.scan_file(path, 0, 200, time.time())
        self.assertEqual(count, 2)
        hits = [f for f in findings if f["rule"] == "validity-too-long"]
        self.assertEqual(len(hits), 1)
        self.assertIn("app.example.com", hits[0]["message"])
        self.assertNotIn("Test Intermediate", hits[0]["message"])

    def test_bad_cert_is_error_finding(self):
        path = self.write("bad.pem", BAD_PEM)
        findings, count, fatal = cc.scan_file(path, 30, 398, time.time())
        self.assertIsNone(fatal)
        self.assertEqual(count, 0)
        self.assertEqual(findings[0]["rule"], "bad-certificate")
        self.assertEqual(findings[0]["severity"], "error")


class CliTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = self.tmp.name

    def write(self, name, text):
        path = os.path.join(self.dir, name)
        with open(path, "w") as fh:
            fh.write(text)
        return path

    def test_clean_exit_0(self):
        path = self.write("leaf.pem", LEAF_PEM)
        code, out, _ = run_cli([path, "--max-validity-days", "10000"])
        self.assertEqual(code, 0)
        self.assertEqual(out, "")

    def test_error_exit_1(self):
        path = self.write("leaf.pem", LEAF_PEM)
        code, out, _ = run_cli([path, "--host", "nope.com"])
        self.assertEqual(code, 1)
        self.assertIn("hostname-mismatch", out)

    def test_warning_exit_0_without_strict(self):
        path = self.write("nosan.pem", NOSAN_PEM)
        code, out, _ = run_cli([path])
        self.assertEqual(code, 0)
        self.assertIn("missing-san", out)

    def test_strict_warning_exit_1(self):
        path = self.write("nosan.pem", NOSAN_PEM)
        code, _, _ = run_cli([path, "--strict"])
        self.assertEqual(code, 1)

    def test_missing_file_exit_2(self):
        code, _, err = run_cli([os.path.join(self.dir, "nope.pem")])
        self.assertEqual(code, 2)
        self.assertIn("no such file", err)

    def test_no_pem_blocks_exit_2(self):
        path = self.write("notes.txt", "nothing here")
        code, _, err = run_cli([path])
        self.assertEqual(code, 2)
        self.assertIn("no PEM certificate blocks", err)

    def test_only_bad_cert_exit_2(self):
        path = self.write("bad.pem", BAD_PEM)
        code, out, _ = run_cli([path])
        self.assertEqual(code, 2)
        self.assertIn("bad-certificate", out)

    def test_good_plus_missing_exit_2(self):
        path = self.write("leaf.pem", LEAF_PEM)
        code, out, err = run_cli(
            [path, os.path.join(self.dir, "nope.pem"),
             "--max-validity-days", "10000"])
        self.assertEqual(code, 2)

    def test_output_format(self):
        path = self.write("leaf.pem", LEAF_PEM)
        _, out, _ = run_cli([path, "--host", "nope.com"])
        line = [l for l in out.splitlines() if "hostname-mismatch" in l][0]
        self.assertRegex(
            line, r"leaf\.pem: error \[hostname-mismatch\] "
                  r"example\.com: does not match 'nope\.com'")

    def test_json_shape(self):
        path = self.write("leaf.pem", LEAF_PEM)
        code, out, _ = run_cli([path, "--host", "nope.com", "--json"])
        self.assertEqual(code, 1)
        report = json.loads(out)
        self.assertEqual(report["certificates"], 1)
        self.assertEqual(report["errors"], 1)
        rules = [f["rule"] for f in report["findings"]]
        self.assertIn("hostname-mismatch", rules)

    def test_multiple_files(self):
        p1 = self.write("leaf.pem", LEAF_PEM)
        p2 = self.write("ca.pem", CA_PEM)
        code, out, _ = run_cli([p1, p2, "--max-validity-days", "10000"])
        self.assertEqual(code, 0)
        self.assertIn("self-signed", out)

    def test_default_cap_is_200_days(self):
        path = self.write("leaf.pem", LEAF_PEM)
        code, out, _ = run_cli([path])
        self.assertEqual(code, 0)
        self.assertIn("validity-too-long", out)
        self.assertIn("200-day cap", out)

    def test_warn_days_flag(self):
        path = self.write("leaf.pem", LEAF_PEM)
        _, out1, _ = run_cli([path, "--max-validity-days", "10000",
                              "--warn-days", "1"])
        _, out2, _ = run_cli([path, "--max-validity-days", "10000",
                              "--warn-days", "100000"])
        self.assertNotIn("expires-soon", out1)
        self.assertIn("expires-soon", out2)


if __name__ == "__main__":
    unittest.main()
