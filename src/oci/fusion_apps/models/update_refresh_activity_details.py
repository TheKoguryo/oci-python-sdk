# coding: utf-8
# Copyright (c) 2016, 2023, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.


from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class UpdateRefreshActivityDetails(object):
    """
    The information about scheduled refresh.
    """

    def __init__(self, **kwargs):
        """
        Initializes a new UpdateRefreshActivityDetails object with values from keyword arguments.
        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param time_scheduled_start:
            The value to assign to the time_scheduled_start property of this UpdateRefreshActivityDetails.
        :type time_scheduled_start: datetime

        """
        self.swagger_types = {
            'time_scheduled_start': 'datetime'
        }

        self.attribute_map = {
            'time_scheduled_start': 'timeScheduledStart'
        }

        self._time_scheduled_start = None

    @property
    def time_scheduled_start(self):
        """
        Gets the time_scheduled_start of this UpdateRefreshActivityDetails.
        Time the refresh activity is scheduled to start. An RFC3339 formatted datetime string.


        :return: The time_scheduled_start of this UpdateRefreshActivityDetails.
        :rtype: datetime
        """
        return self._time_scheduled_start

    @time_scheduled_start.setter
    def time_scheduled_start(self, time_scheduled_start):
        """
        Sets the time_scheduled_start of this UpdateRefreshActivityDetails.
        Time the refresh activity is scheduled to start. An RFC3339 formatted datetime string.


        :param time_scheduled_start: The time_scheduled_start of this UpdateRefreshActivityDetails.
        :type: datetime
        """
        self._time_scheduled_start = time_scheduled_start

    def __repr__(self):
        return formatted_flat_dict(self)

    def __eq__(self, other):
        if other is None:
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not self == other
