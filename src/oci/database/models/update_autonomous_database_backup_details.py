# coding: utf-8
# Copyright (c) 2016, 2023, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.


from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class UpdateAutonomousDatabaseBackupDetails(object):
    """
    Details for updating the Autonomous Database backup.

    **Warning:** Oracle recommends avoiding using confidential information when you supply string values using the API.
    """

    def __init__(self, **kwargs):
        """
        Initializes a new UpdateAutonomousDatabaseBackupDetails object with values from keyword arguments.
        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param retention_period_in_days:
            The value to assign to the retention_period_in_days property of this UpdateAutonomousDatabaseBackupDetails.
        :type retention_period_in_days: int

        """
        self.swagger_types = {
            'retention_period_in_days': 'int'
        }

        self.attribute_map = {
            'retention_period_in_days': 'retentionPeriodInDays'
        }

        self._retention_period_in_days = None

    @property
    def retention_period_in_days(self):
        """
        Gets the retention_period_in_days of this UpdateAutonomousDatabaseBackupDetails.
        Retention period, in days, for long-term backups


        :return: The retention_period_in_days of this UpdateAutonomousDatabaseBackupDetails.
        :rtype: int
        """
        return self._retention_period_in_days

    @retention_period_in_days.setter
    def retention_period_in_days(self, retention_period_in_days):
        """
        Sets the retention_period_in_days of this UpdateAutonomousDatabaseBackupDetails.
        Retention period, in days, for long-term backups


        :param retention_period_in_days: The retention_period_in_days of this UpdateAutonomousDatabaseBackupDetails.
        :type: int
        """
        self._retention_period_in_days = retention_period_in_days

    def __repr__(self):
        return formatted_flat_dict(self)

    def __eq__(self, other):
        if other is None:
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not self == other