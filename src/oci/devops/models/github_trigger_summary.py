# coding: utf-8
# Copyright (c) 2016, 2023, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

from .trigger_summary import TriggerSummary
from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class GithubTriggerSummary(TriggerSummary):
    """
    Summary of the GitHub trigger.
    """

    def __init__(self, **kwargs):
        """
        Initializes a new GithubTriggerSummary object with values from keyword arguments. The default value of the :py:attr:`~oci.devops.models.GithubTriggerSummary.trigger_source` attribute
        of this class is ``GITHUB`` and it should not be changed.
        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param id:
            The value to assign to the id property of this GithubTriggerSummary.
        :type id: str

        :param display_name:
            The value to assign to the display_name property of this GithubTriggerSummary.
        :type display_name: str

        :param description:
            The value to assign to the description property of this GithubTriggerSummary.
        :type description: str

        :param project_id:
            The value to assign to the project_id property of this GithubTriggerSummary.
        :type project_id: str

        :param compartment_id:
            The value to assign to the compartment_id property of this GithubTriggerSummary.
        :type compartment_id: str

        :param trigger_source:
            The value to assign to the trigger_source property of this GithubTriggerSummary.
        :type trigger_source: str

        :param time_created:
            The value to assign to the time_created property of this GithubTriggerSummary.
        :type time_created: datetime

        :param time_updated:
            The value to assign to the time_updated property of this GithubTriggerSummary.
        :type time_updated: datetime

        :param lifecycle_state:
            The value to assign to the lifecycle_state property of this GithubTriggerSummary.
        :type lifecycle_state: str

        :param lifecycle_details:
            The value to assign to the lifecycle_details property of this GithubTriggerSummary.
        :type lifecycle_details: str

        :param freeform_tags:
            The value to assign to the freeform_tags property of this GithubTriggerSummary.
        :type freeform_tags: dict(str, str)

        :param defined_tags:
            The value to assign to the defined_tags property of this GithubTriggerSummary.
        :type defined_tags: dict(str, dict(str, object))

        :param system_tags:
            The value to assign to the system_tags property of this GithubTriggerSummary.
        :type system_tags: dict(str, dict(str, object))

        :param connection_id:
            The value to assign to the connection_id property of this GithubTriggerSummary.
        :type connection_id: str

        """
        self.swagger_types = {
            'id': 'str',
            'display_name': 'str',
            'description': 'str',
            'project_id': 'str',
            'compartment_id': 'str',
            'trigger_source': 'str',
            'time_created': 'datetime',
            'time_updated': 'datetime',
            'lifecycle_state': 'str',
            'lifecycle_details': 'str',
            'freeform_tags': 'dict(str, str)',
            'defined_tags': 'dict(str, dict(str, object))',
            'system_tags': 'dict(str, dict(str, object))',
            'connection_id': 'str'
        }

        self.attribute_map = {
            'id': 'id',
            'display_name': 'displayName',
            'description': 'description',
            'project_id': 'projectId',
            'compartment_id': 'compartmentId',
            'trigger_source': 'triggerSource',
            'time_created': 'timeCreated',
            'time_updated': 'timeUpdated',
            'lifecycle_state': 'lifecycleState',
            'lifecycle_details': 'lifecycleDetails',
            'freeform_tags': 'freeformTags',
            'defined_tags': 'definedTags',
            'system_tags': 'systemTags',
            'connection_id': 'connectionId'
        }

        self._id = None
        self._display_name = None
        self._description = None
        self._project_id = None
        self._compartment_id = None
        self._trigger_source = None
        self._time_created = None
        self._time_updated = None
        self._lifecycle_state = None
        self._lifecycle_details = None
        self._freeform_tags = None
        self._defined_tags = None
        self._system_tags = None
        self._connection_id = None
        self._trigger_source = 'GITHUB'

    @property
    def connection_id(self):
        """
        Gets the connection_id of this GithubTriggerSummary.
        The OCID of the connection resource used to get details for triggered events.


        :return: The connection_id of this GithubTriggerSummary.
        :rtype: str
        """
        return self._connection_id

    @connection_id.setter
    def connection_id(self, connection_id):
        """
        Sets the connection_id of this GithubTriggerSummary.
        The OCID of the connection resource used to get details for triggered events.


        :param connection_id: The connection_id of this GithubTriggerSummary.
        :type: str
        """
        self._connection_id = connection_id

    def __repr__(self):
        return formatted_flat_dict(self)

    def __eq__(self, other):
        if other is None:
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not self == other
