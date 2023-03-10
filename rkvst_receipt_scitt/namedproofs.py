"""
This file deals in a generic way with the name_proofs component of the contents
defined for the receipt by the RKVST  EIP1186namedProofs Tree algorithm.

See khipureceipt.py or simplehashreceipt.py for rkvst specific conveniences.
"""
from . import trie_alg

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
        :param contents json object representation of the trie-alg specific 'contents' of a receipt
        :param the trusted service parameters
        """
        self.contents = contents
        self.serviceprams = serviceparams
        self._named = {}

    def check_payload_keys(self):

        for k in trie_alg.PAYLOAD_KEYS:
            if k not in self.contents:
                raise NamedProofsMissingPayloadKey(f"{k} not found in contents")
            
    def check_application_parameters(self, *extras):
        """
        Check the expected application_parameters are present
        :param extras: any additional application specific parameters (described by app_id, app_content_ref)
        """
        for k in (trie_alg.APPLICATION_PARAMETERS + list(extras)):
            if k not in self.contents[trie_alg.APPLICATION_PARAMETERS_KEY]:
                raise NamedProofsMissingApplicationParameter(f"{k} not found in contents[application_parameters]")
            
    def collect_proofs(self, *required):
        """
        process the contents collecting each of the named proofs

        Note: assumes the _check methods have been called

        :param required: the required set of names, there may be more but this list is required.
        """

        # Note: the format allows for multiple proofs with the same name. RKVST
        # khipu proofs do not make use of that so all names are known to be
        # unique.

        required = set(required)

        for proof in self.contents[trie_alg.NAMED_PROOFS_KEY]:
            name = proof["name"]
            self._named[name] = proof
            try:
                required.remove(name)
            except KeyError:
                pass

        if required:
            raise NamedProofsMissingProof(f"{', '.join(list(required))}")


