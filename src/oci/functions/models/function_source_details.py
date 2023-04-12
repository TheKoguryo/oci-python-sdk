# coding: utf-8
# Copyright (c) 2016, 2023, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.


from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class FunctionSourceDetails(object):
    """
    The source details for the Function. The function can be created from various sources.
    """

    #: A constant which can be used with the source_type property of a FunctionSourceDetails.
    #: This constant has a value of "PRE_BUILT_FUNCTIONS"
    SOURCE_TYPE_PRE_BUILT_FUNCTIONS = "PRE_BUILT_FUNCTIONS"

    def __init__(self, **kwargs):
        """
        Initializes a new FunctionSourceDetails object with values from keyword arguments. This class has the following subclasses and if you are using this class as input
        to a service operations then you should favor using a subclass over the base class:

        * :class:`~oci.functions.models.PreBuiltFunctionSourceDetails`

        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param source_type:
            The value to assign to the source_type property of this FunctionSourceDetails.
            Allowed values for this property are: "PRE_BUILT_FUNCTIONS", 'UNKNOWN_ENUM_VALUE'.
            Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.
        :type source_type: str

        """
        self.swagger_types = {
            'source_type': 'str'
        }

        self.attribute_map = {
            'source_type': 'sourceType'
        }

        self._source_type = None

    @staticmethod
    def get_subtype(object_dictionary):
        """
        Given the hash representation of a subtype of this class,
        use the info in the hash to return the class of the subtype.
        """
        type = object_dictionary['sourceType']

        if type == 'PRE_BUILT_FUNCTIONS':
            return 'PreBuiltFunctionSourceDetails'
        else:
            return 'FunctionSourceDetails'

    @property
    def source_type(self):
        """
        **[Required]** Gets the source_type of this FunctionSourceDetails.
        Type of the Function Source. Possible values: PBF.

        Allowed values for this property are: "PRE_BUILT_FUNCTIONS", 'UNKNOWN_ENUM_VALUE'.
        Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.


        :return: The source_type of this FunctionSourceDetails.
        :rtype: str
        """
        return self._source_type

    @source_type.setter
    def source_type(self, source_type):
        """
        Sets the source_type of this FunctionSourceDetails.
        Type of the Function Source. Possible values: PBF.


        :param source_type: The source_type of this FunctionSourceDetails.
        :type: str
        """
        allowed_values = ["PRE_BUILT_FUNCTIONS"]
        if not value_allowed_none_or_none_sentinel(source_type, allowed_values):
            source_type = 'UNKNOWN_ENUM_VALUE'
        self._source_type = source_type

    def __repr__(self):
        return formatted_flat_dict(self)

    def __eq__(self, other):
        if other is None:
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not self == other