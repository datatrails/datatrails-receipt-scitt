"""
RKVST Khipu event specifics
"""
from eth_utils import to_checksum_address

from . import trie_alg
from .attribute_decoder import (
    decode_attribute_key,
    decode_attribute_value,
    AttributeType,
)

from .receipt import bto3339, u256touuid, Receipt


class KhipuReceiptMalformedAttributes(ValueError):
    """
    The receipt encoding of the rkvst attributes is malformed
    """


EXTRA_PARAMETERS = ["monotonic_version"]
APPLICATION_PARAMETERS = trie_alg.APPLICATION_PARAMETERS + EXTRA_PARAMETERS
MANIFEST_ELEMENTS = "who_declared who_accepted essentials attribute_kindnames attribute_values when".split()

ATTRIBUTE_KINDNAMES = "attribute_kindnames"
ATTRIBUTE_VALUES = "attribute_values"
ESSENTIALS = "essentials"
ESSENTIALS_CREATOR = "creator"
ESSENTIALS_KHIPUIDENTITY = "khipuIdentity"
ESSENTIALS_ASSETIDENTITY = "assetIdentity"

WHO_ISSUER = 0
WHO_SUBJECT = 1
WHO_DISPLAY_NAME = 2
WHO_EMAIL = 3

WHEN_DECLARED = 0
WHEN_ACCEPTED = 1
WHEN_COMMITTED = 2


def _principal_from_rawstorage(rawstorage):
    """
    :param rawstorage: the 4 element list of strings representing a principal
    """
    return {
        "issuer": rawstorage[WHO_ISSUER].decode("utf-8"),
        "subject": rawstorage[WHO_SUBJECT].decode("utf-8"),
        "display_name": rawstorage[WHO_DISPLAY_NAME].decode("utf-8"),
        "email": rawstorage[WHO_EMAIL].decode("utf-8"),
    }


def _whens_from_rawstorage(rawstorage):
    """
    :param rawstorage: the 3 element list of slot values from the 'when' proof
    """
    # rkvst_simplehash.V1_FIELDS (in v1.py) defines constants for these dict
    # keys these in alignment with the public rkvst events api
    return {
        "timestamp_declared": bto3339(rawstorage[WHEN_DECLARED]),
        "timestamp_accepted": bto3339(rawstorage[WHEN_ACCEPTED]),
        # scale down by 1000,000,000. raft block time stamps are in nanoseconds
        # and we need seconds to do the RFC 3339 conversion
        "timestamp_committed": bto3339(rawstorage[WHEN_COMMITTED], scale=1000000000),
    }


class KhipuReceipt(Receipt):
    """
    This class adds khipu specific receipt handling. See :class:`Receipt` for a general description.

    """

    def verify(self, worldroot: str = None):
        """Verify the named proofs

        * If the worldroot is supplied, the presence of the contract storage account is verified

        If no parameters are supplied this method simple verifies the storage
        proofs are consistent with the storage roots in the proof itself.

        :param worldroot: ethereum world state root from the block header
        """
        super().verify(MANIFEST_ELEMENTS, worldroot)

    def decode(self):
        """decode the application values from the proof"""

        # ensure we have the proofs from the contents collected
        if not self.namedproofs.proofs:
            self.namedproofs.collect_proofs(*MANIFEST_ELEMENTS)

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

        for kindname, rlpvalue in zip(kindnames, values):

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

        essentials = self.namedproofs.decoded(ESSENTIALS)
        creator = to_checksum_address(
            essentials.value(ESSENTIALS_CREATOR)
        )  # aka from address
        eventUUID = u256touuid(essentials.value(ESSENTIALS_KHIPUIDENTITY))
        assetUUID = u256touuid(essentials.value(ESSENTIALS_ASSETIDENTITY))

        # TODO: missing the khipu schema version number 'monotonicversion'
        who_declared = self.namedproofs.decoded("who_declared")
        who_accepted = self.namedproofs.decoded("who_accepted")
        whens = _whens_from_rawstorage(self.namedproofs.decoded("when").values)

        # Note: this dict is aligned with the constants and event structure we
        # work with in the rkvst-simplehash-python package.  see
        # rkvst_simplehash.V1_FIELDS (in v1.py)
        event = {
            "identity": f"assets/{assetUUID}/events/{eventUUID}",
            "asset_identity": f"assets/{assetUUID}",
            "from": creator,
            "principal_declared": _principal_from_rawstorage(who_declared.arrays),
            "principal_accepted": _principal_from_rawstorage(who_accepted.arrays),
            "asset_attributes": assetattributes,
            "event_attributes": eventattributes,
        }
        event.update(whens)
        return event
