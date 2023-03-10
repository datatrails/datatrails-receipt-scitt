"""This is a wellknown and completely untrusted signing key

We use this by way of example for alignment with the wider standards effort.

RKVST does not currently sign receipts with any meaningful key.  It is
implausible that the merkle proofs in combination with captured block headers
could be spoofed.

We MAY in future sign claims with a meaningful key to grant authority in
perpetuity to redeem the claim for a receipt. But once the receipt is in
your hands its testimony is completely independent of the RKVST platform.

"""

from cryptography.hazmat.primitives.serialization import load_pem_private_key
from pycose.keys import ec2
from pycose.keys.curves import P256
from pycose.algorithms import Es256

WELLKNOWN_PEM_KEY='''
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIAGU/cL6L/zAQdP/EgRbc8huT/lf9mKl7ugqvfRKLQt1oAoGCCqGSM49
AwEHoUQDQgAEVMRP6xMBm7XfepD9X4i1PgNgXEW3VuOYvlBpWOLZmy9EdxKpndAa
brYHLKDmmHq8IWbhiLrMnvxWLEvVZIRSTQ==
-----END EC PRIVATE KEY-----
'''


def _itobig(n):
    """
    converts a python integer to big endian bytes
    """
    return n.to_bytes((n.bit_length() + 7) // 8, 'big')



def key():
    """
    Returns a key object for the well known pem
    """
    key = load_pem_private_key(WELLKNOWN_PEM_KEY.encode() , password=None)

    if key.curve.name != 'secp256r1':
        raise ValueError('unexpected key type')

    # TODO: There must be a better way to load a PEM for pycose, this is super
    # frustrating. I imagine it is to avoid the osl dependency.
    d = _itobig(key.private_numbers().private_value)
    x = _itobig(key.public_key().public_numbers().x)
    y = _itobig(key.public_key().public_numbers().y)
    eckey = ec2.EC2(crv=P256, d=d, x=x, y=y)
    eckey.alg = Es256
    return eckey
