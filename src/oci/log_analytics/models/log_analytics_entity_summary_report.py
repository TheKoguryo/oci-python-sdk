# coding: utf-8
# Copyright (c) 2016, 2020, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.


from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class LogAnalyticsEntitySummaryReport(object):
    """
    Log-Analytics entity counts summary.
    """

    def __init__(self, **kwargs):
        """
        Initializes a new LogAnalyticsEntitySummaryReport object with values from keyword arguments.
        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param active_entities_count:
            The value to assign to the active_entities_count property of this LogAnalyticsEntitySummaryReport.
        :type active_entities_count: int

        :param entities_with_has_logs_collected_count:
            The value to assign to the entities_with_has_logs_collected_count property of this LogAnalyticsEntitySummaryReport.
        :type entities_with_has_logs_collected_count: int

        :param entities_with_management_agent_count:
            The value to assign to the entities_with_management_agent_count property of this LogAnalyticsEntitySummaryReport.
        :type entities_with_management_agent_count: int

        :param compartment_id:
            The value to assign to the compartment_id property of this LogAnalyticsEntitySummaryReport.
        :type compartment_id: str

        """
        self.swagger_types = {
            'active_entities_count': 'int',
            'entities_with_has_logs_collected_count': 'int',
            'entities_with_management_agent_count': 'int',
            'compartment_id': 'str'
        }

        self.attribute_map = {
            'active_entities_count': 'activeEntitiesCount',
            'entities_with_has_logs_collected_count': 'entitiesWithHasLogsCollectedCount',
            'entities_with_management_agent_count': 'entitiesWithManagementAgentCount',
            'compartment_id': 'compartmentId'
        }

        self._active_entities_count = None
        self._entities_with_has_logs_collected_count = None
        self._entities_with_management_agent_count = None
        self._compartment_id = None

    @property
    def active_entities_count(self):
        """
        **[Required]** Gets the active_entities_count of this LogAnalyticsEntitySummaryReport.
        Total number of ACTIVE entities


        :return: The active_entities_count of this LogAnalyticsEntitySummaryReport.
        :rtype: int
        """
        return self._active_entities_count

    @active_entities_count.setter
    def active_entities_count(self, active_entities_count):
        """
        Sets the active_entities_count of this LogAnalyticsEntitySummaryReport.
        Total number of ACTIVE entities


        :param active_entities_count: The active_entities_count of this LogAnalyticsEntitySummaryReport.
        :type: int
        """
        self._active_entities_count = active_entities_count

    @property
    def entities_with_has_logs_collected_count(self):
        """
        **[Required]** Gets the entities_with_has_logs_collected_count of this LogAnalyticsEntitySummaryReport.
        Entities with log collection enabled


        :return: The entities_with_has_logs_collected_count of this LogAnalyticsEntitySummaryReport.
        :rtype: int
        """
        return self._entities_with_has_logs_collected_count

    @entities_with_has_logs_collected_count.setter
    def entities_with_has_logs_collected_count(self, entities_with_has_logs_collected_count):
        """
        Sets the entities_with_has_logs_collected_count of this LogAnalyticsEntitySummaryReport.
        Entities with log collection enabled


        :param entities_with_has_logs_collected_count: The entities_with_has_logs_collected_count of this LogAnalyticsEntitySummaryReport.
        :type: int
        """
        self._entities_with_has_logs_collected_count = entities_with_has_logs_collected_count

    @property
    def entities_with_management_agent_count(self):
        """
        **[Required]** Gets the entities_with_management_agent_count of this LogAnalyticsEntitySummaryReport.
        Entities with management agent


        :return: The entities_with_management_agent_count of this LogAnalyticsEntitySummaryReport.
        :rtype: int
        """
        return self._entities_with_management_agent_count

    @entities_with_management_agent_count.setter
    def entities_with_management_agent_count(self, entities_with_management_agent_count):
        """
        Sets the entities_with_management_agent_count of this LogAnalyticsEntitySummaryReport.
        Entities with management agent


        :param entities_with_management_agent_count: The entities_with_management_agent_count of this LogAnalyticsEntitySummaryReport.
        :type: int
        """
        self._entities_with_management_agent_count = entities_with_management_agent_count

    @property
    def compartment_id(self):
        """
        **[Required]** Gets the compartment_id of this LogAnalyticsEntitySummaryReport.
        Compartment Identifier `OCID]`__.

        __ https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm


        :return: The compartment_id of this LogAnalyticsEntitySummaryReport.
        :rtype: str
        """
        return self._compartment_id

    @compartment_id.setter
    def compartment_id(self, compartment_id):
        """
        Sets the compartment_id of this LogAnalyticsEntitySummaryReport.
        Compartment Identifier `OCID]`__.

        __ https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm


        :param compartment_id: The compartment_id of this LogAnalyticsEntitySummaryReport.
        :type: str
        """
        self._compartment_id = compartment_id

    def __repr__(self):
        return formatted_flat_dict(self)

    def __eq__(self, other):
        if other is None:
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not self == other
