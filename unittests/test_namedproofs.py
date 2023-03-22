"""
Test handling of the named proofs in the contents of the receipts
"""

from unittest import TestCase

from .datautils import json_loads_receipt_contents

from rkvst_receipt_scitt.namedproofs import NamedProofs, NamedProofsMissingProof
from rkvst_receipt_scitt.khipureceipt import EXTRA_PARAMETERS, MANIFEST_ELEMENTS


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
        kk = list(np._proofs.keys())
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
        """ """
        contents = json_loads_receipt_contents("khipu_receipt_happy_default.b64")
        np = NamedProofs(contents)
        np.collect_proofs(*MANIFEST_ELEMENTS)
        np.verify_proofs(None)

    def test_decode_proofs(self):
        """ """
        contents = json_loads_receipt_contents("khipu_receipt_happy_default.b64")
        np = NamedProofs(contents)
        np.collect_proofs(*MANIFEST_ELEMENTS)
        np.decode()
        want = dict.fromkeys(MANIFEST_ELEMENTS)
        for name in np._decoded.keys():
            want.pop(name)

        self.assertEqual(len(want), 0)
