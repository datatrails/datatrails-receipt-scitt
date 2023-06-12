"""_summary_

RKVST SimpleHash event receipt specifics
"""

from .receipt import utf8bytes32decode, u256touuidhi, Receipt


MANIFEST_ELEMENTS = ["simplehash"]


class SimpleHashReceipt(Receipt):
    """
    This class adds SimpleHash receipt specifics
    """

    def verify(self, worldroot: str = None):
        """Verify the simplehash anchor named proofs

        :param worldroot: ethereum world state root from the block header, defaults to None
        :type worldroot: str, optional
        """
        super().verify(MANIFEST_ELEMENTS, worldroot)

    def decode(self):
        """
        decode the application values from the proof
        """
        # ensure we have the proofs from the contents collected
        if not self.namedproofs.proofs:
            self.namedproofs.collect_proofs(*MANIFEST_ELEMENTS)

        self.namedproofs.decode()
        fields = self.namedproofs.decoded("simplehash")

        anchor = dict(
            tenant=f"tenant/{u256touuidhi(fields.value('tenant'))}",
            anchor=fields.value("anchor").hex(),
            hashSchemaVersion=int.from_bytes(fields.value("hashSchemaVersion"), "big"),
            eventCount=int.from_bytes(fields.value("eventCount"), "big"),
            proofMechanism=int.from_bytes(fields.value("proofMechanism"), "big"),
            startTimeRFC3339=utf8bytes32decode(fields.value("startTimeRFC3339")),
            endTimeRFC3339=utf8bytes32decode(fields.value("endTimeRFC3339")),
            startTimeUnix=int.from_bytes(fields.value("startTimeUnix"), "big"),
            endTimeUnix=int.from_bytes(fields.value("endTimeUnix"), "big"),
            startOperator=utf8bytes32decode(fields.value("startOperator")),
            endOperator=utf8bytes32decode(fields.value("endOperator")),
        )
        return anchor
