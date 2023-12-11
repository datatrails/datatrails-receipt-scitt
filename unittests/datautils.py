"""
helpers for getting at the test data
"""

from datatrails_receipt_scitt.receiptdecoder import receipt_trie_alg_contents


def json_loads_receipt_contents(datafilename) -> dict:
    """json_loads_contents

    Read datafilename assuming it is a base64 receipt and get the contents.
    apply json.loads to the contents and return the result.

    :param datafilename: base name of a file packaged in the data sub package
    """

    # we run the unittests from the top level directory,
    # so ensure we add the correct path to the files

    datafilepath = f"unittests/data/{datafilename}"

    with open(datafilepath, "rb") as datafile:
        b64 = datafile.read()
        contents, _ = receipt_trie_alg_contents(b64)
        return contents
