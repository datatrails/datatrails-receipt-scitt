"""
Test rkvst specific proof handling for khipu events
"""

import json

from unittest import TestCase

from .datautils import json_loads_receipt_contents

from rkvst_receipt_scitt.khipureceipt import KhipuReceipt

LONG_ANIMAL_NAME_KEY="animal xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"


class TestKhipuReceipt(TestCase):
    """TestNamedProofs"""

    def test_decode_receipt(self):
        """ """
        contents = json_loads_receipt_contents("khipu_receipt_happy_default.b64")
        kr = KhipuReceipt(contents)
        kr.verify()
        event = kr.decode()
        self.assertIn("asset_attributes", event)
        self.assertIn(LONG_ANIMAL_NAME_KEY, event["asset_attributes"])
        self.assertIn("event_attributes", event)
        self.assertIn("principal_accepted", event)
        self.assertIn("principal_declared", event)
        self.assertIn("timestamp_accepted", event)
        self.assertIn("timestamp_declared", event)
        self.assertIn("timestamp_committed", event)
        self.assertEqual(event["asset_attributes"][LONG_ANIMAL_NAME_KEY], "giraffe")
        print(json.dumps(event, sort_keys=True, indent="  "))
