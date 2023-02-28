"""
Test anchor_events method
"""

from unittest import TestCase

from rkvst_receipt_scitt.attribute_decoder import (
    decode_attribute_key,
    decode_attribute_value,
    AttributeType
)


class TestKATAttributeDecoder(TestCase):
    """
    Known Answer Tests (KAT) for attribute decoding
    """

    # asset attribute with key: animal
    known_kindname = "0xcd85617373657486616e696d616c"
    known_attribute_type = AttributeType.ASSET
    known_attribute_key = "animal"

    # attribute value: giraffe
    known_encoded_attribute_string = "0x8767697261666665"
    known_attribute_string = "giraffe"


    # attribute value: [{'giraffe': 'tall'}, {'elephant': 'big'}]
    known_encoded_attribute_list = "0xe5866c6973747632cecd87676972616666658474616c6ccecd88656c657068616e7483626967"
    known_attribute_list = [{'giraffe': 'tall'}, {'elephant': 'big'}]

    # attribute value: {'giraffe': 'tall', 'elephant': 'big'}
    known_encoded_attribute_dict = "0xe386646963747632cd87676972616666658474616c6ccd88656c657068616e7483626967"
    known_attribute_dict = {'giraffe': 'tall', 'elephant': 'big'}

    def test_attribute_key(self):
        """
        tests we can get an attribute type and attribute key
        from a known rlp encoded kindname.
        """

        attribute_type, attribute_key = decode_attribute_key(self.known_kindname)

        self.assertEqual(self.known_attribute_type, attribute_type,
            msg="unexpected attribute type")
        
        self.assertEqual(self.known_attribute_key, attribute_key,
            msg="unexpected attribute key")

    def test_attribute_value_string(self):
        """
        tests we can get an attribute value of type string
        from a known rlp encoded attribute value.
        """

        attribute_value = decode_attribute_value(self.known_encoded_attribute_string)

        self.assertEqual(self.known_attribute_string, attribute_value,
            msg="unexpected attribute value")

    def test_attribute_value_list(self):
        """
        tests we can get an attribute value of type list
        from a known rlp encoded attribute value.
        """

        attribute_value = decode_attribute_value(self.known_encoded_attribute_list)

        self.assertEqual(self.known_attribute_list, attribute_value,
            msg="unexpected attribute value")

    def test_attribute_value_dict(self):
        """
        tests we can get an attribute value of type dict
        from a known rlp encoded attribute value.
        """

        attribute_value = decode_attribute_value(self.known_encoded_attribute_dict)

        self.assertEqual(self.known_attribute_dict, attribute_value,
            msg="unexpected attribute value")
        