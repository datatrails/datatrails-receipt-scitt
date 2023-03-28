"""
The EIP1186NamedProofs trie algorithm defines three proof metadata formats.

Note that the proofs are always for the raw storage values. Those are proven to
be 'on-chain' regardless of the metadata. The metadata provides for round
tripping between the raw storage values and its application level
representation.

The three formats defined here are intrinsic to this trie algorithm. They are
defined to be application neutral. They focus on recovering the proven application
values from the receipts without :192
recourse to application domain knowledge. Just
knowledge of the EVM and the solidity compiler abi.

Applications (including the RKVST) are free to define new element types but
SHOULD only do so if the intrinsics are insufficient.

In the case of extended types, The app_id and the app_content_ref properties in
the application_parameters in the receipt MUST reference the information
necessary to interpret the proven values.

In many cases we would expect the raw proof values to be sufficient from an
evidentiary perspective.
"""
from hexbytes import HexBytes

ELEMENT_ID_SLOTARRAY = "eip1186sp:1:sa"
ELEMENT_ID_FIELDVALUES = "eip1186sp:2:fv"
ELEMENT_ID_BYTESLIST = (
    "eip1186sp:3:loba"  # TODO change all these suffixes to sensibly literate values
)


class MetadataError(Exception):
    """
    Raised when there is an unexpected formatting or content issue with the metadata.
    """


# pylint


class SlotArray:
    """
    Helper for eip1186:1:sa

    After construction the concatenation of all slot values is available on .value
    The individual slot values are available in .values

    No extra metadata is required for this type. However, if the number of
    significant bytes for the last slot is known it can be supplied via the
    `lenlast` constructor param. This does not impact the proof, that is for the
    full slot contents regardless of storage layout within that slot.

    This accommodates:
     * a storage proof for a solidity dynamic array of bytes (string or bytes)
     * a storage proof for a struct whose fields are all uint256
    """

    def __init__(self, storageproofs: list, lenlast: int = None):
        """
        The list of proofs in storageproof is treated a list of slots where the
        raw values are the application bytes.


        :param storageproof: The storageProofs field from the EIP1186 response,
        its a list of merkle proofs
        :param lenlast: If the number of bytes stored in the last slot is known
        the last slot can be trimmed
        """

        self.values = [bytes(HexBytes(proof["value"])) for proof in storageproofs]
        if lenlast is not None and len(storageproofs):
            self.values[-1] = self.values[-1][:lenlast]

        self.value = b"".join(self.values)


class ByteArrays:
    """
    Helper for eip1186:3:loba

    The list of proofs in storage proof proves the presence of a *list* of byte
    arrays. The metadata contains a slot count for
    *each* byte array.

    For example

    .. code-block::

        metadata: {
            slots: [3, 2, 5],
            lenlasts: [28, 3, 32]
        }

    Describes 3 distinct byte arrays. The first consumes the values for the
    first 3 proofs, the second proof values 3 & 4, and the last takes the
    remaining 5 proof values.

    The last slot of each respective array has 28 bytes, 3 bytes and finally
    exactly  32 bytes
    """

    def __init__(self, storageproofs: list, metadata: dict):
        """
        :param storageproofs: the list of storage proofs, typically
        ["proof"]["storageProof"] from the EIP 1186 response
        :param metadata: the metadata for id eip1186:loba describing the layout
        of the proven values
        """

        # The metadata uses associative arrays rather than structured objects as
        # it keeps the size of the metadata down. It also makes it more
        # composable and open for extension.
        if len(metadata["slots"]) != len(metadata["lenlasts"]):
            raise MetadataError("mismatched slots and 'length last slot' counts")

        self.arrays = []
        start = 0
        for count, lenlast in zip(metadata["slots"], metadata["lenlasts"]):
            self.arrays.append(
                SlotArray(storageproofs[start : start + count], lenlast=lenlast).value
            )
            start += count


class FieldValues:
    """
    Helper for eip1186:2:fv

    The list of proofs in storage proof proves the presence of an array of
    storage slots backing a solidity ABI structure. The metadata defines the
    variable field structure in those slots (but does not currently contain
    the original type info)

    For example:

    .. code-block::

        metadata: {
            fields: [
                { "name": "foo", "slot": 0, "offset": 0, "size": 2},
                { "name": "bar", "slot": 0, "offset": 2, "size": 4},
                { "name": "baz", "slot": 1, "offset": 0, "size": 32}
            }
        }

    Defines the variables foo, bar and baz. foo and bar are packed into the
    first slot. Due to occupying a full 32 byte slot, baz.

    Notes:
        a) In the current rkvst useage fields occupied by nested slots are
        typically omitted and dealt with as a special case (who & when). We
        may in future allow size to be a multiple of 32 to allow for inline
        nested structs.

        b) the offset is from the low register address, which frustratingly
        is at the right end of the word. Eg the offsets should actually be
        visualized like this. (We intend to change the backend to make this
        more intuitive)

            `|31|30 ... 2|1|0|`

        c) we plan to add the original solidity type names in a future
        backend release.

    """

    def __init__(self, storageproofs: list, metadata: dict):
        """Apply the metadata interpretation to the storageproofs

        :param storageproofs: the list of storage proofs, typically ["proof"]["storageProof"] from the EIP 1186 response
        :param metadata: the metadata for id eip1186:fv describing the layout of the proven values
        """

        self._fields = {}
        self._slotvalues = []
        for proof in storageproofs:
            # Notice: the proof values omit the 0's from the big end, so we must put them back.
            self._slotvalues.append(bytes(HexBytes(proof["value"])).rjust(32, b"\x00"))

        # Notice: the slot number in the metadata is the original storage slot
        # relative to the base storage location of the struct.

        islotvalue = 0
        storageslot = 0
        for field in metadata["fields"]:

            # every time the storage slot changes we bump the index into our
            # slotvalues array. This is a bit awkward, we will likely change the
            # metadata to make it less so.
            if field["slot"] != storageslot:
                islotvalue += 1

            slotvalue = self._slotvalues[islotvalue]
            name, offset, size = field["name"], field["offset"], field["size"]
            # we should do this in the backend, the low address of the 32 byte word is on the 'right'
            offset = 32 - offset - size
            fieldvalue = slotvalue[offset : offset + size]

            self._fields[name] = dict(
                islot=islotvalue,
                value=fieldvalue
                # we don't currently include the solidity abi type in the metadata but we may do
            )

    def fields(self):
        """return the list of field names"""
        return list(self._fields)

    def value(self, name: str):
        """
        return the value of the field
        """
        return self._fields[name]["value"]

    def __getattr__(self, name: str):
        """
        dynamic attribute access to the fields by name
        """
        if name in self._fields:
            return self._fields[name]["value"]

        raise AttributeError(f"{name} is not a field or an attribute")
