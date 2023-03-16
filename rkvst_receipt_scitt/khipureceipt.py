"""
RKVST Khipu event specifics
"""

from . import trie_alg
from .namedproofs import NamedProofs


EXTRA_PARAMETERS = ["monotonic_version"]
APPLICATION_PARAMETERS = trie_alg.APPLICATION_PARAMETERS + EXTRA_PARAMETERS
MANIFEST_ELEMENTS = "who_declared who_accepted essentials attribute_kindnames attribute_values when".split()


class KhipuReceipt:
    def __init__(self, contents, serviceparams=None):
        self.namedproofs = NamedProofs(contents, serviceprams=serviceprams)

    def verify(self):
        self.namedproofs.collect_proofs(*MANIFEST_ELEMENTS)
        self.namedproofs.verify_proofs(None)

    def decode(self):
        self.namedproofs.decode()

        # Now use RKVST API assumptions to rebuild the event and asset attributes map
