"""
helpers for getting at the test data
"""
from importlib.resources import read_text  # 3.9 + we should use 'files' instead
import json

from rkvst_receipt_scitt.receiptdecoder import (
    receipt_trie_alg_contents
)

def json_loads_receipt_contents(datafilename) -> dict:
    """json_loads_contents

    Read datafilename assuming it is a base64 receipt and get the contents.
    apply json.loads to the contents and return the result.

    :param datafilename: base name of a file packaged in the data sub package
    """
    b64 = read_text("unittests.data", datafilename)
    contents = json.loads(receipt_trie_alg_contents(b64)[1])
    return contents
