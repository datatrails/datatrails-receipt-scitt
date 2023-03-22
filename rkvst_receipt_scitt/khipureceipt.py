"""
RKVST Khipu event specifics
"""
import uuid
from datetime import datetime
import rfc3339
from eth_utils import to_checksum_address

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


class KhipuReceiptMalformedValue(ValueError):
    """
    The receipt encoding of a storage value is not as expected
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
        "timestamp_declared": _bto3339(rawstorage[WHEN_DECLARED]),
        "timestamp_accepted": _bto3339(rawstorage[WHEN_ACCEPTED]),
        # scale down by 1000,000,000. raft block time stamps are in nanoseconds
        # and we need seconds to do the RFC 3339 conversion
        "timestamp_committed": _bto3339(rawstorage[WHEN_COMMITTED], scale=1000000000),
    }


def _u256touuid(b: bytes) -> str:
    """
    convert a 32 byte value from khipu event storage to a uuid
    """
    if len(b) != 32:
        raise KhipuReceiptMalformedValue(
            f"expected 32 bytes for a uuid storage value not {len(b)}"
        )

    b = b[16:]  # the high bytes are zero

    return uuid.UUID(int=int.from_bytes(b, "big"))


class KhipuReceipt:
    """
    This class uses the EIP1186 *neutral* receipt format to encode a receipt for an RKVST 'khipu' event.
    """

    def __init__(self, contents, serviceparams=None):
        """
        serviceparams and contents are as per draft-birkholz-scitt-receipts 2. "Common parameters" & 3. "Generic Receipt Structure".

        But in essence the serviceparams identify the service and the appropriate interpretation of contents. Here,
        our trie-alg is cEIP1186NamedProofs and the basic structure of the contents is:

        {
          application_parameters: {
             app_id: trusted service application identifier,
             app_content_ref: trusted service application references,
             element_manifest: [] the complete set of app-defined-names, 1:1 associative with named_proofs
          },
          block: hex-str block number the proof was read from
          account: the contract account the proof was read from
          named_proofs: [ list of named proofs, 1 per entry in element_manifest
             {
                name: app-defined-name
                id: proof-element-id - one of the three trie alg intrinsics defined in elementmetadata.py or app specific defined by app_content_ref

                ... one or more EIP 1186 merkle inclusion proofs and supporting
                metadata
             }
          ]
        ]

        For serviceparams to be fully compliant we need at least two items here:
        * a permanent service identifier (likely app.rkvst.io)
        * the trie alg defining the format of contents, currently EIP1186NamedProofs

        But the implementation simply assumes this for now.

        :param contents: this is the trie-alg "EIP1186NamedProofs" defined receipt contents
        :param serviceparams: the service parameters required by draft-birkholz-scitt-receipts 2. "Common parameters"
        """
        self.namedproofs = NamedProofs(contents, serviceparams=serviceparams)

    def verify(self, worldroot: str = None, stateroot: str = None):
        """Verify the named proofs

        * If the worldroot is supplied, the presence of the contract storage account is verified
        * If the stateroot is supplied, the contract storage root in the proof is verified

        If no parameters are supplied this method simple verifies the storage
        proofs are consistent with the storage roots in the proof itself.

        :param worldroot: ethereum world state root from the block header
        :param stateroot: contract storage root from eth_getStorageRoot
        """
        # TODO: pass in stateroot and timestamp so caller can provide it from block header
        self.namedproofs.check_payload_keys()
        self.namedproofs.check_application_parameters()
        self.namedproofs.collect_proofs(*MANIFEST_ELEMENTS)
        self.namedproofs.verify_proofs(worldroot, stateroot)

    def decode(self):
        """decode the application values from the proof"""
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
        eventUUID = _u256touuid(essentials.value(ESSENTIALS_KHIPUIDENTITY))
        assetUUID = _u256touuid(essentials.value(ESSENTIALS_ASSETIDENTITY))

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
