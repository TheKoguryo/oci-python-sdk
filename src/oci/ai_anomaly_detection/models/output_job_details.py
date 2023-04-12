# coding: utf-8
# Copyright (c) 2016, 2023, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.


from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class OutputJobDetails(object):
    """
    Output details for detect anomaly job.
    """

    #: A constant which can be used with the output_type property of a OutputJobDetails.
    #: This constant has a value of "OBJECT_STORAGE"
    OUTPUT_TYPE_OBJECT_STORAGE = "OBJECT_STORAGE"

    def __init__(self, **kwargs):
        """
        Initializes a new OutputJobDetails object with values from keyword arguments. This class has the following subclasses and if you are using this class as input
        to a service operations then you should favor using a subclass over the base class:

        * :class:`~oci.ai_anomaly_detection.models.ObjectStorageLocation`

        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param output_type:
            The value to assign to the output_type property of this OutputJobDetails.
            Allowed values for this property are: "OBJECT_STORAGE", 'UNKNOWN_ENUM_VALUE'.
            Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.
        :type output_type: str

        """
        self.swagger_types = {
            'output_type': 'str'
        }

        self.attribute_map = {
            'output_type': 'outputType'
        }

        self._output_type = None

    @staticmethod
    def get_subtype(object_dictionary):
        """
        Given the hash representation of a subtype of this class,
        use the info in the hash to return the class of the subtype.
        """
        type = object_dictionary['outputType']

        if type == 'OBJECT_STORAGE':
            return 'ObjectStorageLocation'
        else:
            return 'OutputJobDetails'

    @property
    def output_type(self):
        """
        **[Required]** Gets the output_type of this OutputJobDetails.
        The type of output location
        Allowed values are:
        - `OBJECT_STORAGE`: Object store output location.

        Allowed values for this property are: "OBJECT_STORAGE", 'UNKNOWN_ENUM_VALUE'.
        Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.


        :return: The output_type of this OutputJobDetails.
        :rtype: str
        """
        return self._output_type

    @output_type.setter
    def output_type(self, output_type):
        """
        Sets the output_type of this OutputJobDetails.
        The type of output location
        Allowed values are:
        - `OBJECT_STORAGE`: Object store output location.


        :param output_type: The output_type of this OutputJobDetails.
        :type: str
        """
        allowed_values = ["OBJECT_STORAGE"]
        if not value_allowed_none_or_none_sentinel(output_type, allowed_values):
            output_type = 'UNKNOWN_ENUM_VALUE'
        self._output_type = output_type

    def __repr__(self):
        return formatted_flat_dict(self)

    def __eq__(self, other):
        if other is None:
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not self == other