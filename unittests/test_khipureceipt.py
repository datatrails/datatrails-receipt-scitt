"""
Test rkvst specific proof handling for khipu events
"""

import json

from unittest import TestCase

from .datautils import json_loads_receipt_contents

from rkvst_receipt_scitt.khipureceipt import KhipuReceipt


class TestKhipuReceipt(TestCase):
    """TestNamedProofs"""

    def test_decode_receipt(self):
        """ """
        contents = json_loads_receipt_contents("khipu_receipt_happy_default.b64")
        kr = KhipuReceipt(contents)
        kr.verify()
        event = kr.decode()
        print(json.dumps(event, sort_keys=True, indent="  "))
