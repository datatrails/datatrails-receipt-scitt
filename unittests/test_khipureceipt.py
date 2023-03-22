"""
Test rkvst specific proof handling for khipu events
"""

import json

from unittest import TestCase

from rkvst_receipt_scitt.khipureceipt import KhipuReceipt

from .datautils import json_loads_receipt_contents


LONG_ANIMAL_NAME_KEY = "animal xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
DISPLAY_NAME = "test rkvst"
EMAIL = "test@jitsuin.com"
ISSUER = "jitsuin-d"
SUBJECT = "test-subject-d"


class TestKhipuReceipt(TestCase):
    """TestNamedProofs"""

    def test_decode_receipt(self):
        """
        test that we can verify and decode the receipt
        """
        contents = json_loads_receipt_contents("khipu_receipt_happy_default.b64")
        kr = KhipuReceipt(contents)
        kr.verify()
        event = kr.decode()
        self.assertIn("asset_attributes", event)
        self.assertIn(LONG_ANIMAL_NAME_KEY, event["asset_attributes"])
        self.assertIn("event_attributes", event)
        self.assertIn("principal_accepted", event)
        self.assertIn("principal_declared", event)
        for k, v in [
            ("issuer", ISSUER),
            ("subject", SUBJECT),
            ("email", EMAIL),
            ("display_name", DISPLAY_NAME),
        ]:
            self.assertEqual(event["principal_declared"][k], v)
            self.assertEqual(event["principal_accepted"][k], v)

        self.assertIn("timestamp_accepted", event)
        self.assertEqual(event["timestamp_accepted"], "2023-02-10T08:14:49+00:00")
        self.assertIn("timestamp_declared", event)
        self.assertEqual(event["timestamp_declared"], "2023-02-10T08:14:20+00:00")
        self.assertIn("timestamp_committed", event)
        self.assertEqual(event["timestamp_committed"], "2023-03-21T22:07:28+00:00")
        self.assertEqual(event["asset_attributes"][LONG_ANIMAL_NAME_KEY], "giraffe")
        print(json.dumps(event, sort_keys=True, indent="  "))
