"""
RKVST Receipt support common for both khipu and simplehash specifics
"""
import uuid
from datetime import datetime
import rfc3339

from .namedproofs import NamedProofs


class ReceiptMalformedValue(ValueError):
    """
    The receipt encoding of a storage value is not as expected
    """


def utf8bytes32decode(b: bytes):
    """When a string, often an RFC 3339 timestamp, is packed into a bytes32 storage slot use this."""

    # This seems to be the most robust thing we can do here
    end = b.index(0x00)
    return b[:end].decode("utf-8")


def bto3339(b: bytes, scale=1):
    """
    convert a bytes array, interpreted as a big endian integer, to a utc timestamp RFC 3339
    :param b: bytes
    :param scale: the timestamp from the block chain has a consensus specific scale factor in the case of raft
    """
    unix = int.from_bytes(b, "big") / scale
    return rfc3339.rfc3339(datetime.utcfromtimestamp(unix))


def u256touuid(b: bytes) -> str:
    """
    convert a 32 byte value from khipu event storage to a uuid
    """
    if len(b) != 32:
        raise ReceiptMalformedValue(
            f"expected 32 bytes for a uuid storage value not {len(b)}"
        )

    b = b[16:]  # the high bytes are zero

    return uuid.UUID(int=int.from_bytes(b, "big"))


def u256touuidhi(b: bytes) -> str:
    """
    convert a 32 byte value from khipu event storage to a uuid
    """
    if len(b) != 32:
        raise ReceiptMalformedValue(
            f"expected 32 bytes for a uuid storage value not {len(b)}"
        )

    b = b[:16]  # the low bytes are zero

    return uuid.UUID(int=int.from_bytes(b, "big"))


class Receipt:
    """
    This class uses the EIP1186 *neutral* receipt format to encode a receipt for an RKVST event.

    serviceparams and contents are as per draft-birkholz-scitt-receipts 2. "Common parameters" & 3. "Generic Receipt Structure".

    But in essence the serviceparams identify the service and the appropriate interpretation of contents. Here,
    our trie-alg is cEIP1186NamedProofs and the basic structure of the contents is:

    .. code-block::

        {
          application_parameters: {
             app_id: trusted service application identifier,
             app_content_ref: trusted service application references,
             element_manifest: [] the complete set of app-defined-names,
                1:1 associative with named_proofs
          },
          block: hex-str block number the proof was read from
          account: the contract account the proof was read from
          named_proofs: [ list of named proofs, 1 per entry in element_manifest
             {
                name: app-defined-name
                id: proof-element-id - one of the three trie alg intrinsics defined
                    in elementmetadata.py or app specific defined by app_content_ref

                ... one or more EIP 1186 merkle inclusion proofs and supporting
                metadata
             }
          ]
        ]

    For serviceparams to be fully compliant we need at least two items here:
    * a permanent service identifier (likely app.rkvst.io)
    * the trie alg defining the format of contents, currently EIP1186NamedProofs

    But the implementation simply assumes this for now.
    """

    def __init__(self, contents, serviceparams=None):
        """
        :param contents: this is the trie-alg "EIP1186NamedProofs" defined receipt contents
        :param serviceparams: the service parameters required by draft-birkholz-scitt-receipts 2. "Common parameters"
        """
        self.namedproofs = NamedProofs(contents, serviceparams=serviceparams)

    def verify(self, elements, worldroot: str = None):
        """Verify the named proofs

        * If the worldroot is supplied, the presence of the contract storage account is verified

        If no parameters are supplied this method simple verifies the storage
        proofs are consistent with the storage roots in the proof itself.

        :param worldroot: ethereum world state root from the block header
        """
        # TODO: pass in stateroot and timestamp so caller can provide it from block header
        self.namedproofs.check_payload_keys()
        self.namedproofs.check_application_parameters()
        self.namedproofs.collect_proofs(*elements)
        self.namedproofs.verify_proofs(worldroot)
