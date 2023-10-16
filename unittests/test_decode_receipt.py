"""
Test decoding of RKVST receipts
"""

from importlib.resources import read_text  # 3.9 + we should use 'files' instead
from unittest import TestCase

from rkvst_receipt_scitt.receiptdecoder import (
    receipt_trie_alg_contents,
    # , receipt_verify_envelope
)
from rkvst_receipt_scitt import trie_alg, khipureceipt, simplehashreceipt

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
        contents = receipt_trie_alg_contents(b64)
        for k in trie_alg.PAYLOAD_KEYS:
            self.assertIn(k, contents)
        for k in khipureceipt.APPLICATION_PARAMETERS:
            self.assertIn(k, contents["application_parameters"])
        for k in khipureceipt.MANIFEST_ELEMENTS:
            self.assertIn(k, contents["application_parameters"]["element_manifest"])

    def test_payload_extraction_cose_sign1(self):
        """
        Test we can get at the payload and that it is valid json from a cose sign1 structure
        """
        b64 = read_text("unittests.data", "simplehash_receipt_happy_cose_sign1.b64")
        contents = receipt_trie_alg_contents(b64)
        for k in trie_alg.PAYLOAD_KEYS:
            self.assertIn(k, contents)
        for k in simplehashreceipt.MANIFEST_ELEMENTS:
            self.assertIn(k, contents["application_parameters"]["element_manifest"])

    def test_verify_envelope(self):
        """
        Test we can get at the payload and that it is valid json
        """
        b64 = read_text("unittests.data", "khipu_receipt_happy_default.b64")

        # XXX:TODO we should make a different funtion that returns all that
        # is needed to verify a signature, as receipt_trie_alg_contents
        # now returns just the payload
        contents = receipt_trie_alg_contents(b64)
        k = key()

        # XXX:TODO We are missing the header.Algorithm that pycose needs in
        # order to decide how to deal with the key.

        # receipt_verify_envelope(k, phdr, sig, contents)
        print(contents, k)  # XXX: reference the vars
