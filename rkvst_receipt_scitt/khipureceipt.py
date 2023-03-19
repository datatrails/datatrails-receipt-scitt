"""
RKVST Khipu event specifics
"""
from datetime import datetime
import rfc3339

from . import trie_alg
from .namedproofs import NamedProofs
from .attribute_decoder import (
    decode_attribute_key,
    decode_attribute_value,
    AttributeType,
)


class KhipuReceiptMalformedAttributes(ValueError):
    """
    The receipt encoding of the rkvst attributes is malformed
    """


EXTRA_PARAMETERS = ["monotonic_version"]
APPLICATION_PARAMETERS = trie_alg.APPLICATION_PARAMETERS + EXTRA_PARAMETERS
MANIFEST_ELEMENTS = "who_declared who_accepted essentials attribute_kindnames attribute_values when".split()

ATTRIBUTE_KINDNAMES = "attribute_kindnames"
ATTRIBUTE_VALUES = "attribute_values"

iWHO_ISSUER = 0
iWHO_SUBJECT = 1
iWHO_DISPLAY_NAME = 2
iWHO_EMAIL = 3

iWHEN_DECLARED = 0
iWHEN_ACCEPTED = 1
iWHEN_COMMITTED = 2


def _principal_from_rawstorage(rawstorage):
    """
    :param rawstorage: the 4 element list of strings representing a principal
    """
    return {
        "issuer": rawstorage[iWHO_ISSUER].decode("utf-8"),
        "subject": rawstorage[iWHO_SUBJECT].decode("utf-8"),
        "display_name": rawstorage[iWHO_DISPLAY_NAME].decode("utf-8"),
        "email": rawstorage[iWHO_EMAIL].decode("utf-8"),
    }


def _bto3339(b: bytes, scale=1):
    """
    convert a bytes array, interpreted as a big endian integer, to a utc timestamp RFC 3339
    :param b: bytes
    :param scale: the timestamp from the block chain has a consensus specific scale factor in the case of raft
    """
    unix = int.from_bytes(b, "big") / scale
    return rfc3339.rfc3339(datetime.utcfromtimestamp(unix))


def _whens_from_rawstorage(rawstorage):
    """
    :param rawstorage: the 3 element list of slot values from the 'when' proof
    """
    # rkvst_simplehash.V1_FIELDS (in v1.py) defines constants for these dict
    # keys these in alignment with the public rkvst events api
    return {
        "timestamp_declared": _bto3339(rawstorage[iWHEN_DECLARED]),
        "timestamp_accepted": _bto3339(rawstorage[iWHEN_ACCEPTED]),
        # scale down by 1000,000,000 due to use of raft
        "timestamp_committed": _bto3339(rawstorage[iWHEN_COMMITTED], scale=1000000000),
    }


class KhipuReceipt:
    def __init__(self, contents, serviceparams=None):
        self.namedproofs = NamedProofs(contents, serviceparams=serviceparams)

    def verify(self):
        self.namedproofs.collect_proofs(*MANIFEST_ELEMENTS)
        self.namedproofs.verify_proofs(None)

    def decode(self):
        self.namedproofs.decode()

        # Now use RKVST API assumptions to rebuild the event and asset attributes map

        kindnames = self.namedproofs.decoded(ATTRIBUTE_KINDNAMES).arrays
        values = self.namedproofs.decoded(ATTRIBUTE_VALUES).arrays
        if len(kindnames) != len(values):
            raise KhipuReceiptMalformedAttributes(
                "number of names inconsistent with number of values"
            )

        assetattributes = {}
        eventattributes = {}

        for i in range(len(kindnames)):

            kindname, rlpvalue = kindnames[i], values[i]

            if len(kindname) == 0 and len(rlpvalue) == 0:
                continue

            kind, name = decode_attribute_key(kindname)

            value = decode_attribute_value(rlpvalue)
            if kind == AttributeType.ASSET:
                assetattributes[name] = value
            elif kind == AttributeType.EVENT:
                eventattributes[name] = value
            else:
                raise KhipuReceiptMalformedAttributes(
                    f"unsupported kind '{kind}' for attribute '{name}'"
                )

            # Note we don't currently include the aggregate sharing policy
            # attributes in the receipt. We may do in future.

        # TODO: missing the khipu schema version number 'monotonicversion'
        who_declared = self.namedproofs.decoded("who_declared")
        who_accepted = self.namedproofs.decoded("who_accepted")
        whens = _whens_from_rawstorage(self.namedproofs.decoded("when").values)

        # Note: this dict is aligned with the constants and event structure we
        # work with in the rkvst-simplehash-python package.  see
        # rkvst_simplehash.V1_FIELDS (in v1.py)
        event = {
            "principal_declared": _principal_from_rawstorage(who_declared.arrays),
            "principal_accepted": _principal_from_rawstorage(who_accepted.arrays),
            "asset_attributes": assetattributes,
            "event_attributes": eventattributes,
        }
        event.update(whens)
        return event
