"""
Support decoding of the receipt response from the RKVST /v1/notary/receipts end point

The format of the receipt follows this *draft* standard draft-birkholz-scitt-receipts-02_

draft-birkholz-scitt-receipts-02_ [3. Generic Receipt Structure]

    [ protected, contents ]

We define the RKVST tree algorithm 'EIP1186NamedSlotProofs' based on EIP1186_ formatted merkle proofs

The protected field is dictated by the standard. The contents field is define by EIP1186NamedSlotProofs

contents::


.. _draft-birkholz-scitt-receipts-02: https://datatracker.ietf.org/doc/draft-birkholz-scitt-receipts/

.. _EIP1186: https://eips.ethereum.org/EIPS/eip-1186

"""

# [receipts-02]: 
# TODO: check format of docstrings is compatible with sphynx. need ci support adding to check this
from typing import Tuple
import base64
import cbor2.decoder
from pycose.messages.sign1message import Sign1Message
from pycose import headers


def receipt_trie_alg_contents(receiptb64: str) -> Tuple[Sign1Message, bytes]:
    """
    decode the protected header, the signature and the tree-alg contents from the receipt.
    
    The semantics of the contents are defined by the EIP1186NamedSlotProofs tree
    alg.

    :param receipt: base64 encoded CBOR Cose Sign1 receipt value obtained from the receipts api
    """
    receiptbytes = base64.standard_b64decode(receiptb64)

    [sign_protected, [signature, contents]] = cbor2.decoder.loads(receiptbytes)

    return sign_protected, contents, signature


def receipt_verify_envelope(key, sign_protected: bytes, contents: bytes, signature: bytes):
    """
    Verify the signature and protected header for the partially decoded receipt

    See unittests/wellknownkey.py for why this is only by way of example and not required.

    This does _NOT_ verify the contents according to the trie alg, simply that
    the contents, treated as an opaque blob, have been signed by the TS, along
    with the protected headers.

    There are currently no unprotected headers defined

    :param sign_protected: protected headers identifying the service and the
    trie alg, decoded from the receipt.
    :param signature: trust services signature over the protected header and the content
    """

    # "sign_protected is included in the Receipt contents to enable the Verifier
    # to re-construct the Countersign_structure" -- _draft-birkholz-scitt-receipts-02 #4
    # sign_protected is [service-id, tree-alg, issued-at]

    phdr = cbor2.decoder.loads(sign_protected)
    msg = Sign1Message(phdr, None, contents, key=key)
    # XXX: TODO: This fails because the backend failed to include the Algorithm header
    msg.verify_signature(signature)


