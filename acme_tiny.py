#!/usr/bin/python -OO
import argparse, subprocess, json, os, sys, base64, binascii, time, hashlib
import re, copy, textwrap, logging
try:
    from urllib.request import urlopen # Python 3
except ImportError:
    from urllib2 import urlopen # Python 2
logging.basicConfig(level=logging.DEBUG if __debug__ else logging.INFO)
CA = "https://acme-v01.api.letsencrypt.org"
HEADER = {'alg': 'RS256', 'jwk': {'kty': 'RSA'}}  # 'e' and 'n' filled in later

def send_signed_request(url, account_key, payload):
    'helper function to make signed requests'
    payload64 = b64(json.dumps(payload).encode('utf8'))
    protected = copy.deepcopy(HEADER)
    protected["nonce"] = urlopen(CA + "/directory").headers['Replay-Nonce']
    protected64 = b64(json.dumps(protected).encode('utf8'))
    proc = subprocess.Popen(
        ["openssl", "dgst", "-sha256", "-sign", account_key],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = (proc.communicate("{0}.{1}".format(protected64, payload64)
        .encode('utf8')))
    if proc.returncode != 0:
        raise IOError("OpenSSL Error: {0}".format(err))
    data = json.dumps({
        "header": HEADER, "protected": protected64,
        "payload": payload64, "signature": b64(out),
    })
    try:
        resp = urlopen(url, data.encode('utf8'))
        return resp.getcode(), resp.read()
    except IOError as e:
        return None, str(e)

def b64(b):
    'helper function base64 encode for jose spec'
    return base64.urlsafe_b64encode(b).decode('utf8').replace("=", "")

def init(account_key):
    'initialize global header and return thumbprint'
    logging.debug("Parsing account key to get public key")
    proc = subprocess.Popen(
        ["openssl", "rsa", "-in", account_key, "-noout", "-text"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = proc.communicate()
    if proc.returncode != 0:
        raise IOError("OpenSSL Error: {0}".format(err))
    pub_hex, pub_exp = re.search(
        r"modulus:\n\s+00:([a-f0-9\:\s]+?)\npublicExponent: ([0-9]+)",
        out.decode('utf8'), re.MULTILINE|re.DOTALL).groups()
    pub_exp = "{0:x}".format(int(pub_exp))
    # zero-pad to even number of characters
    pub_exp = "0{0}".format(pub_exp) if len(pub_exp) % 2 else pub_exp
    HEADER['jwk']['e'] = b64(binascii.unhexlify(pub_exp.encode("utf-8")))
    HEADER['jwk']['n'] = b64(binascii.unhexlify(
        re.sub(r"(\s|:)", "", pub_hex).encode("utf-8")))
    accountkey_json = json.dumps(HEADER['jwk'], sort_keys=True,
        separators=(',', ':'))
    thumbprint = b64(hashlib.sha256(accountkey_json.encode('utf8')).digest())
    return thumbprint

def get_crt(account_key, csr, acme_dir):
    'get cert from letsencrypt'
    thumbprint = init(account_key)
    logging.debug("Parsing CSR to find domains")
    proc = subprocess.Popen(["openssl", "req", "-in", csr, "-noout", "-text"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = proc.communicate()
    if proc.returncode != 0:
        raise IOError("Error loading {0}: {1}".format(csr, err))
    domains = set([])
    common_name = re.search(r"Subject:.*? CN=([^\s,;/]+)", out.decode('utf8'))
    if common_name is not None:
        domains.add(common_name.group(1))
    subject_alt_names = re.search(r"X509v3 Subject Alternative Name: \n +([^\n]+)\n", out.decode('utf8'), re.MULTILINE|re.DOTALL)
    if subject_alt_names is not None:
        for san in subject_alt_names.group(1).split(", "):
            if san.startswith("DNS:"):
                domains.add(san[4:])

    # get the certificate domains and expiration
    logging.debug("Registering account...")
    code, result = send_signed_request(CA + "/acme/new-reg", account_key, {
        "resource": "new-reg",
        "agreement": "https://letsencrypt.org/documents/LE-SA-v1.1.1-August-1-2016.pdf",
    })
    if code == 201:
        logging.debug("Registered!")
    elif code == 409:
        logging.debug("Already registered!")
    else:
        raise ValueError("Error registering: {0} {1}".format(code, result))

    # verify each domain
    for domain in domains:
        logging.debug("Verifying {0}...".format(domain))

        # get new challenge
        code, result = send_signed_request(
            CA + "/acme/new-authz", account_key, {
                "resource": "new-authz",
                "identifier": {"type": "dns", "value": domain},
        })
        if code != 201:
            raise ValueError("Error requesting challenges: {0} {1}".format(code, result))

        # make the challenge file
        challenge = [c for c in json.loads(result.decode('utf8'))['challenges'] if c['type'] == "http-01"][0]
        token = re.sub(r"[^A-Za-z0-9_\-]", "_", challenge['token'])
        keyauthorization = "{0}.{1}".format(token, thumbprint)
        wellknown_path = os.path.join(acme_dir, token)
        with open(wellknown_path, "w") as wellknown_file:
            wellknown_file.write(keyauthorization)

        # check that the file is in place
        wellknown_url = "http://{0}/.well-known/acme-challenge/{1}".format(domain, token)
        try:
            resp = urlopen(wellknown_url)
            resp_data = resp.read().decode('utf8').strip()
            assert resp_data == keyauthorization
        except (IOError, AssertionError):
            os.remove(wellknown_path)
            raise ValueError("Wrote file to {0}, but couldn't download {1}".format(
                wellknown_path, wellknown_url))

        # notify challenge are met
        code, result = send_signed_request(challenge['uri'], account_key, {
            "resource": "challenge",
            "keyAuthorization": keyauthorization,
        })
        if code != 202:
            raise ValueError("Error triggering challenge: {0} {1}".format(code, result))

        # wait for challenge to be verified
        while True:
            try:
                resp = urlopen(challenge['uri'])
                challenge_status = json.loads(resp.read().decode('utf8'))
            except IOError as e:
                raise ValueError("Error checking challenge: {0} {1}".format(
                    e.code, json.loads(e.read().decode('utf8'))))
            if challenge_status['status'] == "pending":
                time.sleep(2)
            elif challenge_status['status'] == "valid":
                logging.debug("{0} verified!".format(domain))
                os.remove(wellknown_path)
                break
            else:
                raise ValueError("{0} challenge did not pass: {1}".format(
                    domain, challenge_status))

    # get the new certificate
    logging.debug("Signing certificate...")
    proc = subprocess.Popen(["openssl", "req", "-in", csr, "-outform", "DER"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    csr_der, err = proc.communicate()
    code, result = send_signed_request(CA + "/acme/new-cert", account_key, {
        "resource": "new-cert",
        "csr": b64(csr_der),
    })
    if code != 201:
        raise ValueError("Error signing certificate: {0} {1}".format(code, result))

    # return signed certificate!
    logging.debug("Certificate signed!")
    return """-----BEGIN CERTIFICATE-----\n{0}\n-----END CERTIFICATE-----\n""".format(
        "\n".join(textwrap.wrap(base64.b64encode(result).decode('utf8'), 64)))

def main(argv):
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent("""\
            This script automates the process of getting a signed TLS certificate from
            Let's Encrypt using the ACME protocol. It will need to be run on your server
            and have access to your private account key, so PLEASE READ THROUGH IT! It's
            only ~200 lines, so it won't take long.

            ===Example Usage===
            python acme_tiny.py --account-key ./account.key --csr ./domain.csr --acme-dir /usr/share/nginx/html/.well-known/acme-challenge/ > signed.crt
            ===================

            ===Example Crontab Renewal (once per month)===
            0 0 1 * * python /path/to/acme_tiny.py --account-key /path/to/account.key --csr /path/to/domain.csr --acme-dir /usr/share/nginx/html/.well-known/acme-challenge/ > /path/to/signed.crt 2>> /var/log/acme_tiny.log
            ==============================================
            """)
    )
    parser.add_argument("--account-key", required=True, help="path to your Let's Encrypt account private key")
    parser.add_argument("--csr", required=True, help="path to your certificate signing request")
    parser.add_argument("--acme-dir", required=True, help="path to the .well-known/acme-challenge/ directory")

    args = parser.parse_args(argv)
    signed_crt = get_crt(args.account_key, args.csr, args.acme_dir)
    sys.stdout.write(signed_crt)

if __name__ == "__main__": # pragma: no cover
    main(sys.argv[1:])
