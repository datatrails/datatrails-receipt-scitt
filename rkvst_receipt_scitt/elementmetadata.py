"""
The EIP1186NamedProofs trie algorithm defines three proof metadata formats.

Note that the proofs are always for the raw storage values. Those are proven to
be 'on-chain' regardless of the metadata. The metadata provides for round
tripping between the raw storage values and its application level
representation.

The three formats defined here are intrinsic to this trie algorithm. They are
defined to be application neutral. They focus on recovering the proven application
values from the receipts without recourse to application domain knowledge. Just
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


class SlotArray:
    """
    Helper for eip1186:1:sa
    """

    def __init__(self, storageproofs, lenlast=None):
        """
        The list of proofs in storageproof is treated a list of slots where the
        raw values are the application bytes. No extra metadata is required for
        this type. However, if the number of significant bytes for the last slot
        is known it can be supplied via lenlast. This does not impact the proof,
        that is for the full slot contents regardless of storage layout within
        that slot.

        This accommodates:
         * a storage proof for a solidity dynamic array of bytes (string or bytes)
         * a storage proof for a struct whose fields are all uint256

        :param storageproof: The storageProofs field from the EIP1186 response, its a list of merkle proofs
        :param lenlast: If the number of bytes stored in the last slot is known the last slot can be trimmed
        """

        values = []
        for proof in storageproofs:
            # Notice: the proof values omit the 0's from the big end, so we must put them back.
            values.append(bytes(HexBytes(proof["value"])).rjust(32, b"\x00"))
        if lenlast != None and len(storageproofs):
            # Note that lenlast is relative to the full 32 byte slot length and
            # we padded appropriate above.
            values[-1] = values[-1][:lenlast]

        self.value = b"".join(values)


class ByteArrays:
    """
    Helper for eip1186:3:loba
    """

    def __init__(self, storageproofs, metadata):
        """
        The list of proofs in storage proof proves the presence of a *list* of
        byte arrays. The metadata contains a slot count for *each* byte array.

        For example:

            metadata: {slots: [3, 2, 5]}

        Describes 3 distinct byte arrays. The first consumes the values for the
        first 3 proofs, the second proof values 3 & 4, and the last takes the
        remaining 5 proof values.

        """

        self.arrays = []
        start = 0
        for count in metadata["slots"]:
            # TODO: we might actually need the lastlen's here
            self.arrays.append(
                SlotArray(storageproofs[start:count], lenlast=None).value
            )
            start += count


class FieldValues:
    """
    Helper for eip1186:2:fv
    """

    def __init__(self, storageproofs, metadata):

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
            fieldvalue = slotvalue[offset : offset + size]

            self._fields[name] = dict(
                islot=islotvalue,
                value=fieldvalue
                # we don't currently include the solidity abi type in the metadata but we may do
            )

    def fields(self):
        """return the list of field names"""
        return list(self._fields.keys())

    def value(self, name):
        """
        return the value of the field
        """
        return self._fields[name]["value"]

    def __getattr__(self, name):
        """
        dynamic attribute access to the fields by name
        """
        if name in self._fields:
            return self._fields[name]["value"]

        raise AttributeError(f"{name} is not a field or an attribute")
