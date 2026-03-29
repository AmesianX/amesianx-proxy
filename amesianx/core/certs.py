"""Certificate management: embedded default cert and openssl generation."""

import tempfile
import os
import subprocess


EMBEDDED_CERT_PEM = """\
-----BEGIN CERTIFICATE-----
MIIDLzCCAhegAwIBAgIUXDtdSfpaOm2PrGT++eTk2m0aBmkwDQYJKoZIhvcNAQEL
BQAwGDEWMBQGA1UEAwwNQW1lc2lhbnhQcm94eTAgFw0yNjAzMjMwNzA4MjFaGA8y
MTI2MDIyNzA3MDgyMVowGDEWMBQGA1UEAwwNQW1lc2lhbnhQcm94eTCCASIwDQYJ
KoZIhvcNAQEBBQADggEPADCCAQoCggEBAMKKE2AzAgWpmn2+osGIWa7MhafXOdUv
iUcGV9vYL4FPdLgTMDxMGSSnOZ2FDNnS5hXMzjN+ZTNNu2xne1VdN7FwzyD/qG3V
840w6p3Bb6vqnP/k+C+94LmuGnsLvSRe2ICz/D2lTsvLsDzyWUjU3wsqvBy0gffN
2RA67EjuupT0/hBDCeA5Gsa35k2wPKjpTFJpRCfNlIHvVzMqITaGqcdwb7YecwD1
LwN8gDzpoFQhRJ8TcU/Y19T5Kt1liN6AKLD7ZAkcuLdGDACx26+eQD7NFryoQStv
VqdNEiFLSdpIduBmRUfO7SFp/aYLbO80PQGqfRvM4o+zTzGCDQSxRNsCAwEAAaNv
MG0wHQYDVR0OBBYEFP3lTkFxe+IZ/y/ueuIOu19IK7t2MB8GA1UdIwQYMBaAFP3l
TkFxe+IZ/y/ueuIOu19IK7t2MA8GA1UdEwEB/wQFMAMBAf8wGgYDVR0RBBMwEYIJ
bG9jYWxob3N0hwR/AAABMA0GCSqGSIb3DQEBCwUAA4IBAQCSCEBjGurD3kvkgF03
aPEXle2OcesS3MngfX4zJIt6+TTCS1e375NFim61XEL98NTxlCbJ8aMgGWeoIt5Y
ihum84jeBka1jlsGiMxFlmzemfKkJio34KbMcA2+SB3CRClQ/+WYFScU9vzK1bp9
78OXYR+TtHC9v+8tA5LJZSGEwuyKStLHeT/PDl4knwNLa2ZRLhxDH2n/2YA7BG1T
/Mrvb9rX1KKGHo++HDvfxK57NXjM6euCwO07Ew04XUeUdp7kcaqCO7QWR8HyGKwT
qwMhw0ZTY6vuRIED2Yd+b8aWxHil+v9MqSMnqVC5sUcgeh0po1vTwy+CX82jaXIu
1ya+
-----END CERTIFICATE-----
"""

EMBEDDED_KEY_PEM = """\
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDCihNgMwIFqZp9
vqLBiFmuzIWn1znVL4lHBlfb2C+BT3S4EzA8TBkkpzmdhQzZ0uYVzM4zfmUzTbts
Z3tVXTexcM8g/6ht1fONMOqdwW+r6pz/5PgvveC5rhp7C70kXtiAs/w9pU7Ly7A8
8llI1N8LKrwctIH3zdkQOuxI7rqU9P4QQwngORrGt+ZNsDyo6UxSaUQnzZSB71cz
KiE2hqnHcG+2HnMA9S8DfIA86aBUIUSfE3FP2NfU+SrdZYjegCiw+2QJHLi3RgwA
sduvnkA+zRa8qEErb1anTRIhS0naSHbgZkVHzu0haf2mC2zvND0Bqn0bzOKPs08x
gg0EsUTbAgMBAAECggEAJ6PO8ukx3kmC62Bu9ZR9Abs2+M5IQIJhLJHEEU2p0GWK
WP+/8mlnLirM+KXlynTI4WRMF/4HTP7n09z6KpjGAmgELKsrfMX9zKVNCTwjLxqt
Rw826zN7mRo61xu7PK/+2arTGRSYC7rDfIe9XbPShwn8LrUxTncpZb876liKuFMg
bpLmsLgKHQQb/1f6r+IKSZGb3uOcjZLtg7f4XG+hioCpjliWMLUmusLRxxailT/7
3pwQNbE+nGqaQcgLcCuzfVdTUisb5awSAOfjJ+93xKnzDnQZRUuZGslsmKGFIccU
r9Kh8h+UTvIO2g+AounB2UHaCXi1P8ePxrFB7YS/QQKBgQDpwObF6s85IumRRZoC
FreoB2XaOcsdCQZ6ozo8SvgYqcKD8LibtKksA2WZoEUIAae/zuMWkLgYq4Y0msyL
OxrL3q+4+GG5pMXx/fcxKzsNG3+WHyxcFOKQ9GEfwu4u9EZKq3squ8CNKCT0W76b
lftTbwsKVXDy710G5Kr3NescUQKBgQDVDcXBJdyyCfq2CzFfkoZo1ZQBv7RDOs7O
tXt9n3N15D3GEB7wYuRjUESrTQBtTmZTudZuHP8ATx1VpOWmBqNKA71CNq3rxaDP
9NBJ+p4sWV5NChSmJPzVhrRxAadp5L06ONeXwL7Fhx9tlj72pVvw6ij9T/L77J6G
Sr/+BYy/awKBgQCJe82/xrWO83vQ19EXPWlTyNYdHjTapP5Mj0inQajeSKqBk8ng
usdtfan6S4uOg/q4E+T41rGQwQG0Wv/HPEIsepN8BYrk94b9J9SF9NlMgknub/NV
TWtcun+NgMc6kq3tKSLOJZPA8kWZ+4QGWpZxojQqJcrC+AoNDd2IfQwFoQKBgD2m
YpblcdtC7/1Fd+AD8kjbpJxs8KiTl8xQz48mWK7AgO+TMqC0vQnP7E71VS5MBWgs
2lO6qD9apU5nDNziBtYgBt/mGqWi5knGuY7uql6C7bq1NAxvn4naFNSuedc2jVsP
n7MV3x4hX4LCey2748LuvzWtsM4dRjHt52iGCphJAoGAAstwhn5T4z/EcR40WWYW
wKYJu2n9AITmeJeEUanWqfd/EiGl9JG9wf96g27ArSs3z14GTj4StMcnhR8qLoY6
SPfN9JO5iphXJAwHfa7xnXOnEOG7yb6w3xHtpebRLOHyLGHKHsHqhv/YkgpwznJB
0GAcxsFrfioXgx6FSIvR5AM=
-----END PRIVATE KEY-----
"""


def write_embedded_cert():
    """Write embedded PEM cert/key to temp files and return (certfile, keyfile) paths."""
    cert_dir = tempfile.mkdtemp(prefix="amesianx_proxy_")
    cert_path = os.path.join(cert_dir, "proxy.crt")
    key_path = os.path.join(cert_dir, "proxy.key")

    with open(cert_path, "w") as f:
        f.write(EMBEDDED_CERT_PEM)
    with open(key_path, "w") as f:
        f.write(EMBEDDED_KEY_PEM)

    return cert_path, key_path


def generate_cert_openssl():
    """Generate a fresh self-signed cert via openssl CLI, return (certfile, keyfile) paths."""
    cert_dir = tempfile.mkdtemp(prefix="amesianx_proxy_")
    cert_path = os.path.join(cert_dir, "proxy.crt")
    key_path = os.path.join(cert_dir, "proxy.key")

    subprocess.run([
        "openssl", "req", "-x509", "-newkey", "rsa:2048",
        "-keyout", key_path, "-out", cert_path,
        "-days", "36500", "-nodes",
        "-subj", "/CN=AmesianxProxy",
        "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
    ], check=True, capture_output=True)

    return cert_path, key_path
