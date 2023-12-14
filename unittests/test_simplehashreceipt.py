"""
Test DataTrails specific proof handling for khipu events
"""

import json

from unittest import TestCase

from datatrails_receipt_scitt.simplehashreceipt import SimpleHashReceipt

from .datautils import json_loads_receipt_contents


class TestSimpleHashReceipt(TestCase):
    """TestSimpleHashReceipt"""

    def test_decode_receipt(self):
        """
        test that we can verify and decode the receipt
        """
        contents = json_loads_receipt_contents("simplehash_receipt_happy_default.b64")
        sr = SimpleHashReceipt(contents)
        anchor = sr.decode()
        self.assertEqual(
            anchor["tenant"], "tenant/c8c51acf-5084-48ba-9e76-2c3cd9439818"
        )
        self.assertEqual(
            anchor["anchor"],
            "f29b54ec5f183ba17a434809bef8a06e457aa63cd99deab3bcb54715901f0910",
        )
        self.assertEqual(anchor["hashSchemaVersion"], 2)
        self.assertEqual(anchor["eventCount"], 1)
        self.assertEqual(anchor["proofMechanism"], 2)
        self.assertEqual(anchor["startTimeRFC3339"], "2023-06-01T13:33:00Z")
        self.assertEqual(anchor["endTimeRFC3339"], "2023-06-08T11:18:02Z")
        self.assertEqual(anchor["startTimeUnix"], 1685626380)
        self.assertEqual(anchor["endTimeUnix"], 1686223082)
        print(json.dumps(anchor, sort_keys=True, indent="  "))

    def test_decode_receipt_cose_sign1(self):
        """
        test that we can verify and decode the receipt in the cose_sign1 format
        """
        contents = json_loads_receipt_contents(
            "simplehash_receipt_happy_cose_sign1.cbor"
        )
        sr = SimpleHashReceipt(contents)
        anchor = sr.decode()
        self.assertEqual(
            anchor["tenant"], "tenant/f47baab2-443c-9b01-6585-48940b552475"
        )
        self.assertEqual(
            anchor["anchor"],
            "d2183df567cf7703362986fdbd8944507ae657a2c8fcccc65932469957f4fbca",
        )
        self.assertEqual(anchor["hashSchemaVersion"], 2)
        self.assertEqual(anchor["eventCount"], 1)
        self.assertEqual(anchor["proofMechanism"], 2)
        self.assertEqual(anchor["startTimeRFC3339"], "2023-12-05T11:04:26Z")
        self.assertEqual(anchor["endTimeRFC3339"], "2023-12-05T11:29:24Z")
        self.assertEqual(
            anchor["startTimeUnix"],
            1701774266,
        )
        self.assertEqual(
            anchor["endTimeUnix"],
            1701775764,
        )
        print(json.dumps(anchor, sort_keys=True, indent="  "))

    def test_verify_receipt(self):
        """
        test that we can verify the receipt. this is really just a regression
        test, its not a proper KAT.
        """
        contents = json_loads_receipt_contents("simplehash_receipt_happy_default.b64")
        sr = SimpleHashReceipt(contents)
        # Note: remember this is the public .stateRoot for simple hash (rather
        # than .privateStateRoot as it is for khipu)
        sr.verify("0x35ac20316361c00015ee4e8ebd0a023afa3b99ee5d47b82f201cfa5086c82034")
