"""
Module for decoding on chain attributes into the format returned from the event api
"""

from __future__ import annotations

from enum import Enum

from rlp.sedes import binary, List

from rlp import decode, decode_lazy, peek, DeserializationError

from .exceptions import InvalidAttributeType

VALUE_TYPE_LIST = "listv2"
VALUE_TYPE_DICT = "dictv2"


class AttributeType(Enum):
    """
    Attribute type is the type of attributes supported by rkvst events
    """

    ASSET = 1
    EVENT = 2


def decode_attribute_value(attrvalue: bytes) -> str | list | dict:
    """
    decode an rlp encoded attribute value

    :param str hex: an rlp encoded hexadecimal string,
                    e.g. 0xe5866c6973747632cecd87676972...

    :returns: one of:

        * a string value
        * a dictionary value
        * a list of dictionary values

    the rlp encoded list value is of the shape::

      [][][]string {
        [
          "listv2"
        ],
        [
          [
            [
              "giraffe", <- key
              "tall" <- value
            ],
          ],
        ],
        [
          [
            [
              "elephant", <- key
              "big" <- value
            ],
          ],
        ]
      }

    the rlp encoded dict value is of the shape::

      [][]string {
        [
          [
            "dictv2",
          ],
          [
            "giraffe", <- key
            "tall" <- value
          ],
          [
            "elephant", <- key
            "big" <- value
          ]
        ]
      }
    """

    # first see if its a string value
    try:
        value = decode(attrvalue, binary).decode("utf-8")
        return value
    except DeserializationError:
        # if we have a deserialization error here, it means we are not dealing with a string value
        pass

    # if its not a string value it must be a list or a dictionary

    listv2_attribute_value = List([List([binary, binary])])
    dictv2_attribute_value = List([binary, binary])

    # if we lazily decode the rlp without a sedes, we can iterate through
    #  each list element decoding them one at a time
    decoded_value = decode_lazy(attrvalue, None)

    value_type = None

    list_value = []
    dict_value = {}

    for index, element in enumerate(decoded_value):
        # first index determines which value type we have,
        #   list or dict
        if index == 0:
            value_type = element.decode("utf-8")
            continue

        # attribute value is a list
        if value_type == VALUE_TYPE_LIST:
            value = peek(element.rlp, index, listv2_attribute_value)

            value_dict = {value[0][0].decode("utf-8"): value[0][1].decode("utf-8")}

            list_value.append(value_dict)
            continue

        # attribute value is a dict
        if value_type == VALUE_TYPE_DICT:
            value = peek(element.rlp, index, dictv2_attribute_value)

            dict_value[value[0].decode("utf-8")] = value[1].decode("utf-8")
            continue

    # determine whether we should return a list or dict
    if len(list_value) == 0:
        return dict_value
    return list_value


def decode_attribute_key(kind_name: bytes) -> tuple[AttributeType, str]:
    """Decodes the attribute kind<->name pairing into the attribute kind and keys

    :param str kind_name: the rlp encoded attribute kind concatenated with the attribute key encoded as a hex string, e.g. 0x8767697261666665...


    :return: a tuple of (attribute type, attribute key)

    """

    # """
    # :param kind_name: str the rlp encoded attribute kind concatenated with the attribute key encoded as a hex string, e.g. 0x8767697261666665...
    # :return: a tuple of (attribute type, attribute key)
    # """
    kind_name_sedes = List([binary, binary])

    decoded_kind_name = decode(kind_name, kind_name_sedes)

    if decoded_kind_name[0].decode("utf-8") == AttributeType.ASSET.name.lower():
        kind = AttributeType.ASSET
        key = decoded_kind_name[1].decode("utf-8")

    elif decoded_kind_name[0].decode("utf-8") == AttributeType.EVENT.name.lower():
        kind = AttributeType.EVENT
        key = decoded_kind_name[1].decode("utf-8")

    else:
        raise InvalidAttributeType

    return (kind, key)
