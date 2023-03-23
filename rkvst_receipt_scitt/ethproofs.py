"""
# code based on example found:
# https://web3py.readthedocs.io/en/v5/web3.eth.html


# for imports we need to do the following pip installs:
#   trie
"""

from eth_utils import keccak, to_checksum_address
import rlp
from rlp.sedes import (
    Binary,
    big_endian_int,
)
from trie import HexaryTrie
from trie.exceptions import BadTrieProof

from hexbytes import HexBytes


class VerifyFailed(Exception):
    """raised if a proof verification operation fails"""


def verify_eth_account_proof(account: str, ethproof: dict, root: HexBytes):
    """
    verifies the given account proof with the given root

    :param dict proof: the merkle proof as per the response
                              from `eth_getProof`

    :param HexBytes root: the state root of the block to verify the
                          account proof against
    """
    trie_root = Binary.fixed_length(32, allow_empty=True)
    hash32 = Binary.fixed_length(32)

    class _Account(rlp.Serializable):
        fields = [
            ("nonce", big_endian_int),
            ("balance", big_endian_int),
            ("storage", trie_root),
            ("code_hash", hash32),
        ]

    acc = _Account(
        int(ethproof["nonce"], 16),
        int(ethproof["balance"], 16),
        HexBytes(ethproof["storageHash"]),
        HexBytes(ethproof["codeHash"]),
    )
    rlp_account = rlp.encode(acc)
    account = to_checksum_address(account)
    trie_key = keccak(hexstr=account)

    proof = [rlp.decode(bytes(HexBytes(node))) for node in ethproof["accountProof"]]

    try:
        if rlp_account != HexaryTrie.get_from_proof(root, trie_key, proof):
            raise VerifyFailed(f"Failed to verify account proof for {account}")
    except BadTrieProof as e:
        raise VerifyFailed(f"Failed to verify account proof for {account}") from e


def verify_eth_storage_proof(ethproof):
    """
    verifies the given account proof with the given root

    :param ethproof: the merkle proof as per the
                              response from `eth_getProof`
    """

    for storage_proof in ethproof["storageProof"]:
        trie_key = keccak(HexBytes(storage_proof["key"]).rjust(32, b"\x00"))
        root = HexBytes(ethproof["storageHash"])
        value = HexBytes(storage_proof["value"])
        if value == b"\x00":
            rlp_value = b""
        else:
            rlp_value = rlp.encode(value)

        proof = [rlp.decode(bytes(HexBytes(node))) for node in storage_proof["proof"]]

        if rlp_value != HexaryTrie.get_from_proof(root, trie_key, proof):
            raise VerifyFailed(f"Failed to verify storage proof {storage_proof['key']}")

    return True
