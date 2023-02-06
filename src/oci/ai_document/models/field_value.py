# coding: utf-8
# Copyright (c) 2016, 2023, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.


from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class FieldValue(object):
    """
    The value of a form field.
    """

    #: A constant which can be used with the value_type property of a FieldValue.
    #: This constant has a value of "STRING"
    VALUE_TYPE_STRING = "STRING"

    #: A constant which can be used with the value_type property of a FieldValue.
    #: This constant has a value of "DATE"
    VALUE_TYPE_DATE = "DATE"

    #: A constant which can be used with the value_type property of a FieldValue.
    #: This constant has a value of "TIME"
    VALUE_TYPE_TIME = "TIME"

    #: A constant which can be used with the value_type property of a FieldValue.
    #: This constant has a value of "PHONE_NUMBER"
    VALUE_TYPE_PHONE_NUMBER = "PHONE_NUMBER"

    #: A constant which can be used with the value_type property of a FieldValue.
    #: This constant has a value of "NUMBER"
    VALUE_TYPE_NUMBER = "NUMBER"

    #: A constant which can be used with the value_type property of a FieldValue.
    #: This constant has a value of "INTEGER"
    VALUE_TYPE_INTEGER = "INTEGER"

    #: A constant which can be used with the value_type property of a FieldValue.
    #: This constant has a value of "ARRAY"
    VALUE_TYPE_ARRAY = "ARRAY"

    def __init__(self, **kwargs):
        """
        Initializes a new FieldValue object with values from keyword arguments. This class has the following subclasses and if you are using this class as input
        to a service operations then you should favor using a subclass over the base class:

        * :class:`~oci.ai_document.models.ValueTime`
        * :class:`~oci.ai_document.models.ValueInteger`
        * :class:`~oci.ai_document.models.ValueDate`
        * :class:`~oci.ai_document.models.ValueNumber`
        * :class:`~oci.ai_document.models.ValueString`
        * :class:`~oci.ai_document.models.ValuePhoneNumber`
        * :class:`~oci.ai_document.models.ValueArray`

        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param value_type:
            The value to assign to the value_type property of this FieldValue.
            Allowed values for this property are: "STRING", "DATE", "TIME", "PHONE_NUMBER", "NUMBER", "INTEGER", "ARRAY"
        :type value_type: str

        :param text:
            The value to assign to the text property of this FieldValue.
        :type text: str

        :param confidence:
            The value to assign to the confidence property of this FieldValue.
        :type confidence: float

        :param bounding_polygon:
            The value to assign to the bounding_polygon property of this FieldValue.
        :type bounding_polygon: oci.ai_document.models.BoundingPolygon

        :param word_indexes:
            The value to assign to the word_indexes property of this FieldValue.
        :type word_indexes: list[int]

        """
        self.swagger_types = {
            'value_type': 'str',
            'text': 'str',
            'confidence': 'float',
            'bounding_polygon': 'BoundingPolygon',
            'word_indexes': 'list[int]'
        }

        self.attribute_map = {
            'value_type': 'valueType',
            'text': 'text',
            'confidence': 'confidence',
            'bounding_polygon': 'boundingPolygon',
            'word_indexes': 'wordIndexes'
        }

        self._value_type = None
        self._text = None
        self._confidence = None
        self._bounding_polygon = None
        self._word_indexes = None

    @staticmethod
    def get_subtype(object_dictionary):
        """
        Given the hash representation of a subtype of this class,
        use the info in the hash to return the class of the subtype.
        """
        type = object_dictionary['valueType']

        if type == 'TIME':
            return 'ValueTime'

        if type == 'INTEGER':
            return 'ValueInteger'

        if type == 'DATE':
            return 'ValueDate'

        if type == 'NUMBER':
            return 'ValueNumber'

        if type == 'STRING':
            return 'ValueString'

        if type == 'PHONE_NUMBER':
            return 'ValuePhoneNumber'

        if type == 'ARRAY':
            return 'ValueArray'
        else:
            return 'FieldValue'

    @property
    def value_type(self):
        """
        **[Required]** Gets the value_type of this FieldValue.
        The type of data detected.

        Allowed values for this property are: "STRING", "DATE", "TIME", "PHONE_NUMBER", "NUMBER", "INTEGER", "ARRAY"


        :return: The value_type of this FieldValue.
        :rtype: str
        """
        return self._value_type

    @value_type.setter
    def value_type(self, value_type):
        """
        Sets the value_type of this FieldValue.
        The type of data detected.


        :param value_type: The value_type of this FieldValue.
        :type: str
        """
        allowed_values = ["STRING", "DATE", "TIME", "PHONE_NUMBER", "NUMBER", "INTEGER", "ARRAY"]
        if not value_allowed_none_or_none_sentinel(value_type, allowed_values):
            raise ValueError(
                "Invalid value for `value_type`, must be None or one of {0}"
                .format(allowed_values)
            )
        self._value_type = value_type

    @property
    def text(self):
        """
        Gets the text of this FieldValue.
        The detected text of a field.


        :return: The text of this FieldValue.
        :rtype: str
        """
        return self._text

    @text.setter
    def text(self, text):
        """
        Sets the text of this FieldValue.
        The detected text of a field.


        :param text: The text of this FieldValue.
        :type: str
        """
        self._text = text

    @property
    def confidence(self):
        """
        **[Required]** Gets the confidence of this FieldValue.
        The confidence score between 0 and 1.


        :return: The confidence of this FieldValue.
        :rtype: float
        """
        return self._confidence

    @confidence.setter
    def confidence(self, confidence):
        """
        Sets the confidence of this FieldValue.
        The confidence score between 0 and 1.


        :param confidence: The confidence of this FieldValue.
        :type: float
        """
        self._confidence = confidence

    @property
    def bounding_polygon(self):
        """
        **[Required]** Gets the bounding_polygon of this FieldValue.

        :return: The bounding_polygon of this FieldValue.
        :rtype: oci.ai_document.models.BoundingPolygon
        """
        return self._bounding_polygon

    @bounding_polygon.setter
    def bounding_polygon(self, bounding_polygon):
        """
        Sets the bounding_polygon of this FieldValue.

        :param bounding_polygon: The bounding_polygon of this FieldValue.
        :type: oci.ai_document.models.BoundingPolygon
        """
        self._bounding_polygon = bounding_polygon

    @property
    def word_indexes(self):
        """
        **[Required]** Gets the word_indexes of this FieldValue.
        The indexes of the words in the field value.


        :return: The word_indexes of this FieldValue.
        :rtype: list[int]
        """
        return self._word_indexes

    @word_indexes.setter
    def word_indexes(self, word_indexes):
        """
        Sets the word_indexes of this FieldValue.
        The indexes of the words in the field value.


        :param word_indexes: The word_indexes of this FieldValue.
        :type: list[int]
        """
        self._word_indexes = word_indexes

    def __repr__(self):
        return formatted_flat_dict(self)

    def __eq__(self, other):
        if other is None:
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not self == other
