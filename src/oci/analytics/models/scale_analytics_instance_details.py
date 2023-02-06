# coding: utf-8
# Copyright (c) 2016, 2023, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.


from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class ScaleAnalyticsInstanceDetails(object):
    """
    Input payload to scale an Analytics instance up or down.
    """

    def __init__(self, **kwargs):
        """
        Initializes a new ScaleAnalyticsInstanceDetails object with values from keyword arguments.
        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param capacity:
            The value to assign to the capacity property of this ScaleAnalyticsInstanceDetails.
        :type capacity: oci.analytics.models.Capacity

        """
        self.swagger_types = {
            'capacity': 'Capacity'
        }

        self.attribute_map = {
            'capacity': 'capacity'
        }

        self._capacity = None

    @property
    def capacity(self):
        """
        **[Required]** Gets the capacity of this ScaleAnalyticsInstanceDetails.

        :return: The capacity of this ScaleAnalyticsInstanceDetails.
        :rtype: oci.analytics.models.Capacity
        """
        return self._capacity

    @capacity.setter
    def capacity(self, capacity):
        """
        Sets the capacity of this ScaleAnalyticsInstanceDetails.

        :param capacity: The capacity of this ScaleAnalyticsInstanceDetails.
        :type: oci.analytics.models.Capacity
        """
        self._capacity = capacity

    def __repr__(self):
        return formatted_flat_dict(self)

    def __eq__(self, other):
        if other is None:
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not self == other
