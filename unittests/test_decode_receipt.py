"""
Test decoding of RKVST receipts
"""

import json
from importlib.resources import read_text  # 3.9 + we should use 'files' instead
from unittest import TestCase

from rkvst_receipt_scitt.receiptdecoder import (
    receipt_trie_alg_contents,
    # , receipt_verify_envelope
)
from rkvst_receipt_scitt import trie_alg, khipureceipt

from .wellknown import key


class TestReceiptDecoder(TestCase):
    """
    Receipt decode tests
    """

    def test_payload_extraction(self):
        """
        Test we can get at the payload and that it is valid json
        """
        b64 = read_text("unittests.data", "khipu_receipt_happy_default.b64")
        contents = json.loads(receipt_trie_alg_contents(b64)[1])
        for k in trie_alg.PAYLOAD_KEYS:
            self.assertIn(k, contents)
        for k in khipureceipt.APPLICATION_PARAMETERS:
            self.assertIn(k, contents["application_parameters"])
        for k in khipureceipt.MANIFEST_ELEMENTS:
            self.assertIn(k, contents["application_parameters"]["element_manifest"])

    def test_verify_envelope(self):
        """
        Test we can get at the payload and that it is valid json
        """
        b64 = read_text("unittests.data", "khipu_receipt_happy_default.b64")
        [phdr, sig, contents] = receipt_trie_alg_contents(b64)
        k = key()

        # XXX:TODO We are missing the header.Algorithm that pycose needs in
        # order to decide how to deal with the key.

        # receipt_verify_envelope(k, phdr, sig, contents)
        print(phdr, sig, contents, k)  # XXX: reference the vars
