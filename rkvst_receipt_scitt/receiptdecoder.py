"""Support decoding of the receipt response from the RKVST /v1/notary/receipts end point

The format of the receipt follows this *draft* standard draft-birkholz-scitt-receipts-02_

draft-birkholz-scitt-receipts-02_ [3. Generic Receipt Structure]::

    [ protected, contents ]

We define the RKVST tree algorithm 'EIP1186NamedSlotProofs' based on EIP1186_ formatted merkle proofs

The protected field is dictated by the standard. The contents field is define by EIP1186NamedSlotProofs


.. _draft-birkholz-scitt-receipts-02: https://datatracker.ietf.org/doc/draft-birkholz-scitt-receipts/

.. _EIP1186: https://eips.ethereum.org/EIPS/eip-1186

"""

# [receipts-02]:
# TODO: check format of docstrings is compatible with sphynx. need ci support adding to check this
import base64
import json
import re
import requests
from typing import Any
import cbor2.decoder
from pycose.messages.sign1message import Sign1Message
from pycose.headers import KID
from jwcrypto import jwk
from pycose.algorithms import Es256
from pycose.keys.curves import P256, P384
from pycose.keys.keyparam import KpKty, EC2KpX, EC2KpY, KpKeyOps, EC2KpCurve
from pycose.keys.keytype import KtyEC2
from pycose.keys.keyops import VerifyOp


def receipt_trie_alg_contents(receiptb64: str) -> Any:
    """decode the protected header, the signature and the tree-alg contents from the receipt.

    The semantics of the contents are defined by the EIP1186NamedSlotProofs tree
    alg.

    :param str receipt: base64 encoded CBOR Cose Sign1 receipt value obtained from the receipts api

    """
    cbor_msg = base64.standard_b64decode(receiptb64)

    # first attempt to decode into pycose cose sign1
    try:
        decoded_msg = Sign1Message.decode(cbor_msg)
        payload = decoded_msg.payload

    except AttributeError:
        # if we can't decode the message into the pycose cose sign1,
        #   attempt to decode it into our notary representation
        decoded_msg = cbor2.decoder.loads(cbor_msg)

        # the notary receipt is in the form: [sign_protected, [signature, payload]]
        payload = decoded_msg[1][1]

    contents = json.loads(payload)
    return contents

def verify_signature(receiptb64: str) -> Any: 
    cbor_msg = base64.standard_b64decode(receiptb64)
    # try:
    decoded_msg = Sign1Message.decode(cbor_msg)
    protected_header = decoded_msg.phdr
    kid = protected_header[KID]
    did = protected_header[391]

    pattern = r"did:web:(?P<host>[a-zA-Z0-9/.\-_]+)(?:%3A(?P<port>[0-9]+))?(:*)(?P<path>[a-zA-Z0-9/.:\-_]*)"
    match = re.match(pattern, did)

    if not match:
        raise ValueError("DID is not a valid did:web")

    groups = match.groupdict()
    host = groups["host"]
    port = groups.get("port")  # might be None
    path = groups["path"]

    origin = f"{host}:{port}" if port else host

    protocol = "https"

    decoded_partial_path = path.replace(":", "/")

    endpoint = (
        f"{protocol}://{origin}/{decoded_partial_path}/did.json"
        if path
        else f"{protocol}://{origin}/.well-known/did.json"
    )

    resp = requests.get(endpoint)
    if resp.status_code != 200:
        raise Exception()  # TODO: Specify.

    did_document = resp.json()

    x = ""
    y = ""
    for verification_method in did_document["verificationMethod"]:
        if verification_method["publicKeyJwk"]["kid"] != kid.decode("utf-8"):
            continue

        x = verification_method["publicKeyJwk"]["x"]
        y = verification_method["publicKeyJwk"]["y"]
        break

    if not (x or y):
        raise Exception()  # TODO: Specify.

    cose_key = {
        KpKty: KtyEC2,
        EC2KpCurve: P384,
        KpKeyOps: [VerifyOp],
        EC2KpX: jwk.base64url_decode(x),
        EC2KpY: jwk.base64url_decode(y),
    }

    cose_key = CoseKey.from_dict(cose_key)

    decoded_msg.key = cose_key
    return decoded_msg.verify_signature()


def receipt_verify_envelope(
    key, sign_protected: bytes, contents: bytes, signature: bytes
):
    """Verify the signature and protected header for the partially decoded receipt

    See unittests/wellknownkey.py for why this is only by way of example and not required.

    This does _NOT_ verify the contents according to the trie alg, simply that
    the contents, treated as an opaque blob, have been signed by the trusted
    service, along with the protected headers.

    There are currently no unprotected headers defined

    :param bytes sign_protected: protected headers identifying the service and the
    trie alg, decoded from the receipt.
    :param bytes signature: trust services signature over the protected header and the content

    """

    # "sign_protected is included in the Receipt contents to enable the Verifier
    # to re-construct the Countersign_structure" -- _draft-birkholz-scitt-receipts-02 #4
    # sign_protected is [service-id, tree-alg, issued-at]

    phdr = cbor2.decoder.loads(sign_protected)
    msg = Sign1Message(phdr, None, contents, key=key)
    # XXX: TODO: This fails because the backend failed to include the Algorithm header
    msg.verify_signature(signature)
