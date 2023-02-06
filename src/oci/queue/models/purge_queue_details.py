# coding: utf-8
# Copyright (c) 2016, 2023, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.


from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class PurgeQueueDetails(object):
    """
    Purge parameters.
    """

    #: A constant which can be used with the purge_type property of a PurgeQueueDetails.
    #: This constant has a value of "NORMAL"
    PURGE_TYPE_NORMAL = "NORMAL"

    #: A constant which can be used with the purge_type property of a PurgeQueueDetails.
    #: This constant has a value of "DLQ"
    PURGE_TYPE_DLQ = "DLQ"

    #: A constant which can be used with the purge_type property of a PurgeQueueDetails.
    #: This constant has a value of "BOTH"
    PURGE_TYPE_BOTH = "BOTH"

    def __init__(self, **kwargs):
        """
        Initializes a new PurgeQueueDetails object with values from keyword arguments.
        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param purge_type:
            The value to assign to the purge_type property of this PurgeQueueDetails.
            Allowed values for this property are: "NORMAL", "DLQ", "BOTH"
        :type purge_type: str

        """
        self.swagger_types = {
            'purge_type': 'str'
        }

        self.attribute_map = {
            'purge_type': 'purgeType'
        }

        self._purge_type = None

    @property
    def purge_type(self):
        """
        **[Required]** Gets the purge_type of this PurgeQueueDetails.
        Type of the purge to perform:
        - NORMAL - purge only normal queue
        - DLQ - purge only DLQ
        - BOTH - purge both normal queue and DLQ

        Allowed values for this property are: "NORMAL", "DLQ", "BOTH"


        :return: The purge_type of this PurgeQueueDetails.
        :rtype: str
        """
        return self._purge_type

    @purge_type.setter
    def purge_type(self, purge_type):
        """
        Sets the purge_type of this PurgeQueueDetails.
        Type of the purge to perform:
        - NORMAL - purge only normal queue
        - DLQ - purge only DLQ
        - BOTH - purge both normal queue and DLQ


        :param purge_type: The purge_type of this PurgeQueueDetails.
        :type: str
        """
        allowed_values = ["NORMAL", "DLQ", "BOTH"]
        if not value_allowed_none_or_none_sentinel(purge_type, allowed_values):
            raise ValueError(
                "Invalid value for `purge_type`, must be None or one of {0}"
                .format(allowed_values)
            )
        self._purge_type = purge_type

    def __repr__(self):
        return formatted_flat_dict(self)

    def __eq__(self, other):
        if other is None:
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not self == other
