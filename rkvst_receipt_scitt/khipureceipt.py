"""
RKVST Khipu event specifics
"""

from rkvst_receipt_scitt import (
    trie_alg
)

EXTRA_PARAMETERS = ["monotonic_version"]
APPLICATION_PARAMETERS = trie_alg.APPLICATION_PARAMETERS + EXTRA_PARAMETERS
MANIFEST_ELEMENTS = "who_declared who_accepted essentials attribute_kindnames attribute_values when".split()
