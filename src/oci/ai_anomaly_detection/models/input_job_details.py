# coding: utf-8
# Copyright (c) 2016, 2023, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.


from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class InputJobDetails(object):
    """
    Input details for detect anomaly job.
    """

    #: A constant which can be used with the input_type property of a InputJobDetails.
    #: This constant has a value of "INLINE"
    INPUT_TYPE_INLINE = "INLINE"

    #: A constant which can be used with the input_type property of a InputJobDetails.
    #: This constant has a value of "OBJECT_LIST"
    INPUT_TYPE_OBJECT_LIST = "OBJECT_LIST"

    def __init__(self, **kwargs):
        """
        Initializes a new InputJobDetails object with values from keyword arguments. This class has the following subclasses and if you are using this class as input
        to a service operations then you should favor using a subclass over the base class:

        * :class:`~oci.ai_anomaly_detection.models.InlineInputJobDetails`
        * :class:`~oci.ai_anomaly_detection.models.ObjectListInputJobDetails`

        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param input_type:
            The value to assign to the input_type property of this InputJobDetails.
            Allowed values for this property are: "INLINE", "OBJECT_LIST", 'UNKNOWN_ENUM_VALUE'.
            Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.
        :type input_type: str

        """
        self.swagger_types = {
            'input_type': 'str'
        }

        self.attribute_map = {
            'input_type': 'inputType'
        }

        self._input_type = None

    @staticmethod
    def get_subtype(object_dictionary):
        """
        Given the hash representation of a subtype of this class,
        use the info in the hash to return the class of the subtype.
        """
        type = object_dictionary['inputType']

        if type == 'INLINE':
            return 'InlineInputJobDetails'

        if type == 'OBJECT_LIST':
            return 'ObjectListInputJobDetails'
        else:
            return 'InputJobDetails'

    @property
    def input_type(self):
        """
        **[Required]** Gets the input_type of this InputJobDetails.
        The type of input location
        Allowed values are:
        - `INLINE`: Inline input data.
        - `OBJECT_LIST`: Object store output location.

        Allowed values for this property are: "INLINE", "OBJECT_LIST", 'UNKNOWN_ENUM_VALUE'.
        Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.


        :return: The input_type of this InputJobDetails.
        :rtype: str
        """
        return self._input_type

    @input_type.setter
    def input_type(self, input_type):
        """
        Sets the input_type of this InputJobDetails.
        The type of input location
        Allowed values are:
        - `INLINE`: Inline input data.
        - `OBJECT_LIST`: Object store output location.


        :param input_type: The input_type of this InputJobDetails.
        :type: str
        """
        allowed_values = ["INLINE", "OBJECT_LIST"]
        if not value_allowed_none_or_none_sentinel(input_type, allowed_values):
            input_type = 'UNKNOWN_ENUM_VALUE'
        self._input_type = input_type

    def __repr__(self):
        return formatted_flat_dict(self)

    def __eq__(self, other):
        if other is None:
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not self == other
