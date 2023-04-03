"""
This file deals in a generic way with the name_proofs component of the contents
defined for the receipt by the RKVST  EIP1186namedProofs Tree algorithm.

See khipureceipt.py or simplehashreceipt.py for rkvst specific conveniences.
"""
from eth_utils import decode_hex
from . import trie_alg
from . import ethproofs
from . import elementmetadata


class NamedProofsMissingPayloadKey(KeyError):
    """An expected payload key was missing from the receipt contents"""


class NamedProofsMissingProof(KeyError):
    """An expected payload key was missing from the receipt contents"""


class NamedProofsMissingApplicationParameter(KeyError):
    """An expected application parameter was missing from the receipt contents[application_parameters]"""


class NamedProofs:
    """NamedProofs

    Access the proven values referred to by the named proofs in an EIP1186NamedProofs receipt
    """

    def __init__(self, contents, serviceparams=None):
        """
        :param contents: json object representation of the trie-alg specific 'contents' of a receipt
        :param serviceparams: the trusted service parameters
        """
        self.contents = contents
        self.serviceprams = serviceparams

        # name -> the proof elements from the receipt
        self._proofs = {}

        # the raw proof values decoded into (closer) to application format
        self._decoded = {}

    @property
    def proofs(self):
        """property accessor for _proofs"""
        return self._proofs.copy()

    @property
    def decodedvalues(self):
        """property accessor for decoded proven values"""
        return self._decoded.copy()

    def check_payload_keys(self):
        """checks the payload has the required top level keys"""

        for k in trie_alg.PAYLOAD_KEYS:
            if k not in self.contents:
                raise NamedProofsMissingPayloadKey(f"{k} not found in contents")

    def check_application_parameters(self, *extras):
        """
        Check the expected application_parameters are present
        :param extras: any additional application specific parameters (described by app_id, app_content_ref)
        """
        for k in trie_alg.APPLICATION_PARAMETERS + list(extras):
            if k not in self.contents[trie_alg.APPLICATION_PARAMETERS_KEY]:
                raise NamedProofsMissingApplicationParameter(
                    f"{k} not found in contents[application_parameters]"
                )

    def collect_proofs(self, *required):
        """
        process the contents collecting each of the named proofs

        Note: assumes the check methods have been called

        :param required: the required set of names, there may be more but this
            list is required.
        """

        # Note: the format allows for multiple proofs with the same name. RKVST
        # khipu proofs do not make use of that so all names are known to be
        # unique.

        required = set(required)

        for proof in self.contents[trie_alg.NAMED_PROOFS_KEY]:
            name = proof["name"]
            self._proofs[name] = proof
            try:
                required.remove(name)
            except KeyError:
                pass

        if required:
            raise NamedProofsMissingProof(f"{', '.join(list(required))}")

    def verify_proofs(self, worldroot):
        """
        * If the worldroot is supplied, the presence of the contract storage account is verified

        If no parameters are supplied this method simple verifies the storage
        proofs are consistent with the storage roots in the proof itself.

        :param worldroot: ethereum world state root from the block header
        """

        # pylint: disable="unused-argument"

        for name, proofelement in self._proofs.items():
            try:
                ethproofs.verify_eth_storage_proof(proofelement["proof"])
            except ethproofs.VerifyFailed:
                # pylint: disable="raise-missing-from"
                raise ethproofs.VerifyFailed(f"Failed to verify {name}")

            if worldroot:
                ethproofs.verify_eth_account_proof(
                    self.contents["account"],
                    proofelement["proof"],
                    decode_hex(worldroot),
                )

    def decode(self):
        """
        decode all the proven values using the metadata from the receipt.

        typically called after verifying in order to reconstruct application
        data from the proven values.
        """

        for name, proofelement in self._proofs.items():
            sp = proofelement["proof"]["storageProof"]
            if proofelement["id"] == elementmetadata.ELEMENT_ID_SLOTARRAY:
                decoded = elementmetadata.SlotArray(sp, lenlast=None)
            elif proofelement["id"] == elementmetadata.ELEMENT_ID_FIELDVALUES:
                decoded = elementmetadata.FieldValues(sp, proofelement["metadata"])
            elif proofelement["id"] == elementmetadata.ELEMENT_ID_BYTESLIST:
                decoded = elementmetadata.ByteArrays(sp, proofelement["metadata"])

            self._decoded[name] = decoded

    def decoded(self, name):
        """
        returns the decoded value container.

        Which will be a SlotArray, a FieldValues or a ByteArrays instance.
        Typically, the caller will know which type to expect based on context.
        """

        return self._decoded[name]
