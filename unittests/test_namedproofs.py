"""
Test handling of the named proofs in the contents of the receipts
"""

from unittest import TestCase

from rkvst_receipt_scitt.namedproofs import NamedProofs, NamedProofsMissingProof
from rkvst_receipt_scitt.khipureceipt import EXTRA_PARAMETERS, MANIFEST_ELEMENTS

from .datautils import json_loads_receipt_contents


class TestNamedProofs(TestCase):
    """TestNamedProofs"""

    def test_have_expected_khipu_proofs(self):
        """
        test that we get the expected named proofs from our standard encoded receipt test data
        """
        contents = json_loads_receipt_contents("khipu_receipt_happy_default.b64")
        np = NamedProofs(contents)
        np.check_payload_keys()
        np.check_application_parameters(*EXTRA_PARAMETERS)
        np.collect_proofs(*MANIFEST_ELEMENTS)
        kk = list(np.proofs)
        self.assertEqual(MANIFEST_ELEMENTS, kk)

    def test_raise_missing_khipu_proofs(self):
        """
        test that we get the expected named proofs from our standard encoded receipt test data
        """
        contents = json_loads_receipt_contents("khipu_receipt_happy_default.b64")
        np = NamedProofs(contents)
        np.check_payload_keys()
        np.check_application_parameters(*EXTRA_PARAMETERS)
        with self.assertRaises(NamedProofsMissingProof):
            np.collect_proofs("xxx", "yyy")

    def test_verify_proofs(self):
        """
        basic proof verification test
        """
        contents = json_loads_receipt_contents("khipu_receipt_happy_default.b64")
        np = NamedProofs(contents)
        np.collect_proofs(*MANIFEST_ELEMENTS)
        np.verify_proofs(None, None)

    def test_decode_proofs(self):
        """
        test proof verification with extra elements
        """
        contents = json_loads_receipt_contents("khipu_receipt_happy_default.b64")
        np = NamedProofs(contents)
        np.collect_proofs(*MANIFEST_ELEMENTS)
        np.decode()
        want = dict.fromkeys(MANIFEST_ELEMENTS)
        for name in np.decodedvalues:
            want.pop(name)

        self.assertEqual(len(want), 0)
