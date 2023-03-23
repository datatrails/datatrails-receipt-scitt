""" Module for implementation of rkvst scitt receipt verification"""
import sys
import argparse
import json
from rkvst_receipt_scitt.receiptdecoder import receipt_trie_alg_contents
from rkvst_receipt_scitt.khipureceipt import KhipuReceipt


def receipt_verify(opts):
    """
    sub command implementation for verifying, and optionally decoding, a receipt
    """
    b64 = opts.receipt.read()
    contents = json.loads(receipt_trie_alg_contents(b64)[1])
    r = KhipuReceipt(contents)
    r.verify(opts.worldroot, opts.stateroot)
    if opts.decode:
        event = r.decode()
        print(json.dumps(event, sort_keys=True, indent="  "))


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
The storageroot for the etherum world state, required to verify the contract
account exists.  This value is obtained from archivist/v1/archivist/block. If
not supplied the account existence is not verified.
""",
    )
    s.add_argument(
        "-s",
        "--stateroot",
        help="""
expected storage stateRoot for the contract address. if supplied verification
confirms the storageProofs are all rooted with this value. otherwise
verification simply shows the receipt is self consistent
""",
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
