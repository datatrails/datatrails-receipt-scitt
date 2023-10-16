""" Module for implementation of rkvst scitt receipt verification"""
import sys
import argparse
import json
from rkvst_receipt_scitt.receiptdecoder import receipt_trie_alg_contents
from rkvst_receipt_scitt.khipureceipt import KhipuReceipt
from rkvst_receipt_scitt.simplehashreceipt import SimpleHashReceipt

SIMPLE_HASH_ELEMENT = "simplehash"


def receipt_verify(opts):
    """
    sub command implementation for verifying, and optionally decoding, a receipt
    """
    b64 = opts.receipt.read()
    contents = receipt_trie_alg_contents(b64)
    r = load_receipt_contents(contents)
    r.verify(opts.worldroot)
    if opts.decode:
        decoded = r.decode()
        if isinstance(r, SimpleHashReceipt):
            decoded["api_query"] = api_query(decoded, opts.fqdn)

        print(json.dumps(decoded, sort_keys=True, indent="  "))


def load_receipt_contents(contents: dict):
    """inspect the json decoded contents of a receipt and instantiate the appropriate verifier."""

    if SIMPLE_HASH_ELEMENT in contents["application_parameters"]["element_manifest"]:
        return SimpleHashReceipt(contents)

    return KhipuReceipt(contents)


def api_query(decoded: dict, fqdn: str):
    """recover the simple hash api query from the anchor receipt decoded values"""

    # Note: this MUST align with rkvst-simplehash-python's approach
    path = f"https://{fqdn}/archivist/v2/assets/-/events"
    path += "?order_by=SIMPLEHASHV2&proof_mechanism=SIMPLE_HASH"
    path += f"&timestamp_accepted_since={decoded['startTimeRFC3339']}"
    path += f"&timestamp_accepted_before={decoded['endTimeRFC3339']}"
    return path


def main(args=None):  # pragma: no cover
    """main"""

    if args is None:
        args = sys.argv[1:]

    p = argparse.ArgumentParser()
    subs = p.add_subparsers(help="receipt verification and decoding")
    s = subs.add_parser("verify")
    s.add_argument(
        "-d",
        "--decode",
        action="store_true",
        help="also decode the RKVST event from the proven values",
    )
    s.add_argument(
        "-w",
        "--worldroot",
        help="""
The storageroot for the ethereum world state, required to verify the contract
account exists.  This value is obtained from archivist/v1/archivist/block. If
not supplied the account existence is not verified.
""",
    )
    s.add_argument(
        "--fqdn",
        help="The fully qualified domain name of the rkvst deployment",
        default="app.rkvst.io",
    )
    s.add_argument(
        "receipt",
        nargs="?",
        type=argparse.FileType("r"),
        default=(None if sys.stdin.isatty() else sys.stdin),
    )
    s.set_defaults(func=receipt_verify)

    opts = p.parse_args(args)
    try:
        opts.func(opts)
        return 0
    except Exception as e:
        print(str(e))
        return 1


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
