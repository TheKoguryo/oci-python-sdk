# coding: utf-8
# Copyright (c) 2016, 2022, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.


from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class UpdateMigrationAssetDetails(object):
    """
    Details of the updated migration asset.
    """

    def __init__(self, **kwargs):
        """
        Initializes a new UpdateMigrationAssetDetails object with values from keyword arguments.
        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param display_name:
            The value to assign to the display_name property of this UpdateMigrationAssetDetails.
        :type display_name: str

        :param replication_schedule_id:
            The value to assign to the replication_schedule_id property of this UpdateMigrationAssetDetails.
        :type replication_schedule_id: str

        :param depends_on:
            The value to assign to the depends_on property of this UpdateMigrationAssetDetails.
        :type depends_on: list[str]

        """
        self.swagger_types = {
            'display_name': 'str',
            'replication_schedule_id': 'str',
            'depends_on': 'list[str]'
        }

        self.attribute_map = {
            'display_name': 'displayName',
            'replication_schedule_id': 'replicationScheduleId',
            'depends_on': 'dependsOn'
        }

        self._display_name = None
        self._replication_schedule_id = None
        self._depends_on = None

    @property
    def display_name(self):
        """
        Gets the display_name of this UpdateMigrationAssetDetails.
        A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.


        :return: The display_name of this UpdateMigrationAssetDetails.
        :rtype: str
        """
        return self._display_name

    @display_name.setter
    def display_name(self, display_name):
        """
        Sets the display_name of this UpdateMigrationAssetDetails.
        A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.


        :param display_name: The display_name of this UpdateMigrationAssetDetails.
        :type: str
        """
        self._display_name = display_name

    @property
    def replication_schedule_id(self):
        """
        Gets the replication_schedule_id of this UpdateMigrationAssetDetails.
        Replication schedule identifier


        :return: The replication_schedule_id of this UpdateMigrationAssetDetails.
        :rtype: str
        """
        return self._replication_schedule_id

    @replication_schedule_id.setter
    def replication_schedule_id(self, replication_schedule_id):
        """
        Sets the replication_schedule_id of this UpdateMigrationAssetDetails.
        Replication schedule identifier


        :param replication_schedule_id: The replication_schedule_id of this UpdateMigrationAssetDetails.
        :type: str
        """
        self._replication_schedule_id = replication_schedule_id

    @property
    def depends_on(self):
        """
        Gets the depends_on of this UpdateMigrationAssetDetails.
        List of migration assets that depends on this asset.


        :return: The depends_on of this UpdateMigrationAssetDetails.
        :rtype: list[str]
        """
        return self._depends_on

    @depends_on.setter
    def depends_on(self, depends_on):
        """
        Sets the depends_on of this UpdateMigrationAssetDetails.
        List of migration assets that depends on this asset.


        :param depends_on: The depends_on of this UpdateMigrationAssetDetails.
        :type: list[str]
        """
        self._depends_on = depends_on

    def __repr__(self):
        return formatted_flat_dict(self)

    def __eq__(self, other):
        if other is None:
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not self == other
