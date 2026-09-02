"""
engine/client.py
================
The BROWSER + AUTHENTICATOR client the attacks drive.

In a real login the browser is an HONEST notary: it stamps the true origin into
clientDataJSON and refuses to use a credential on the wrong site. This client
exposes those honest defaults -- and the knobs an attacker would need to subvert
them: override the origin (phishing), swap in a cloned device, or replay an old
assertion. A real browser grants an attacker none of these; that is exactly why
the attacks only work against a server that forgets to check.

It speaks HTTP to the relying party. The base URL is the ONLY thing that differs
between the "attacks succeed" run (vulnerable :5006) and the "attacks fail" run
(hardened :5007) -- same attacker, same code.
"""

import requests

from authenticator import SoftwareAuthenticator, build_client_data, b64url_decode


class Client:
    def __init__(self, base_url, true_origin):
        self.base_url = base_url.rstrip("/")
        self.true_origin = true_origin       # what an honest browser would stamp
        self.rp_id = None
        self.devices = {}                    # username -> SoftwareAuthenticator

    # -- tiny HTTP helper -----------------------------------------------------

    def _post(self, path, payload):
        r = requests.post(self.base_url + path, json=payload, timeout=10)
        return r.json()

    # -- registration ceremony -----------------------------------------------

    def register(self, username):
        """Full navigator.credentials.create() round-trip against the server."""
        begin = self._post("/register/begin", {"username": username})
        challenge = b64url_decode(begin["challenge"])
        self.rp_id = begin["rp_id"]

        device = SoftwareAuthenticator()
        self.devices[username] = device

        client_data = build_client_data("webauthn.create", challenge, self.true_origin)
        credential = device.create(self.rp_id, client_data)

        return self._post("/register/finish",
                          {"username": username, "credential": credential})

    # -- authentication ceremony ---------------------------------------------

    def login(self, username, origin=None, device=None):
        """
        One honest navigator.credentials.get() round-trip.

        origin : the origin stamped into clientDataJSON. Defaults to the client's
                 true origin (what an honest browser writes); override it to
                 simulate a phished victim (attack 2).
        device : the authenticator that signs. Defaults to the user's genuine
                 registered device; pass a clone to simulate a stolen key (attack 3).

        Returns (server_response_json, captured_assertion). The captured assertion
        is the exact credential sent to the server -- retained so attack 1 can
        replay the very same signed bytes later.
        """
        origin = origin or self.true_origin
        device = device or self.devices[username]

        begin = self._post("/login/begin", {"username": username})
        challenge = b64url_decode(begin["challenge"])
        rp_id = begin["rp_id"]

        client_data = build_client_data("webauthn.get", challenge, origin)
        assertion = device.get(rp_id, client_data)

        resp = self._post("/login/finish",
                          {"username": username, "credential": assertion})
        return resp, assertion

    # -- the attacker's extra move -------------------------------------------

    def replay(self, username, captured):
        """
        Re-send a previously captured assertion VERBATIM -- the same signed bytes,
        a second time, with no fresh /login/begin. The attacker simply repeats what
        they recorded (from a network tap, malware, or logs).

        A server that binds each login to a single-use challenge has already
        consumed the matching challenge, so the stale assertion is rejected. A
        server that never checks the challenge accepts it again.
        """
        return self._post("/login/finish",
                          {"username": username, "credential": captured})


def clone_device(device):
    """
    Forge a CLONED authenticator: the SAME private key and credential id as the
    original, but its own signature counter starting at zero.

    This models an attacker who extracted the secret key from a device. Both the
    original and the clone produce perfectly valid signatures -- identical key,
    identical credential id -- so signature verification alone cannot tell them
    apart. The only protocol-level tripwire is the counter: the clone counts from
    its own zero, so its signCount lands BELOW what the server last saw from the
    real device, and a server that tracks the counter spots the regression.
    """
    clone = SoftwareAuthenticator.__new__(SoftwareAuthenticator)  # skip key generation
    clone._private_key = device._private_key                      # same signet ring
    clone.credential_id = device.credential_id                    # same handle
    clone.sign_count = 0                                          # its own fresh counter
    return clone
