# coding: utf-8
# Copyright (c) 2016, 2023, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.


from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class DataCollectionOptions(object):
    """
    Indicates user preferences for the various diagnostic collection options for the VM cluster/Cloud VM cluster/VMBM DBCS.
    """

    def __init__(self, **kwargs):
        """
        Initializes a new DataCollectionOptions object with values from keyword arguments.
        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param is_diagnostics_events_enabled:
            The value to assign to the is_diagnostics_events_enabled property of this DataCollectionOptions.
        :type is_diagnostics_events_enabled: bool

        :param is_health_monitoring_enabled:
            The value to assign to the is_health_monitoring_enabled property of this DataCollectionOptions.
        :type is_health_monitoring_enabled: bool

        :param is_incident_logs_enabled:
            The value to assign to the is_incident_logs_enabled property of this DataCollectionOptions.
        :type is_incident_logs_enabled: bool

        """
        self.swagger_types = {
            'is_diagnostics_events_enabled': 'bool',
            'is_health_monitoring_enabled': 'bool',
            'is_incident_logs_enabled': 'bool'
        }

        self.attribute_map = {
            'is_diagnostics_events_enabled': 'isDiagnosticsEventsEnabled',
            'is_health_monitoring_enabled': 'isHealthMonitoringEnabled',
            'is_incident_logs_enabled': 'isIncidentLogsEnabled'
        }

        self._is_diagnostics_events_enabled = None
        self._is_health_monitoring_enabled = None
        self._is_incident_logs_enabled = None

    @property
    def is_diagnostics_events_enabled(self):
        """
        Gets the is_diagnostics_events_enabled of this DataCollectionOptions.
        Indicates whether diagnostic collection is enabled for the VM cluster/Cloud VM cluster/VMBM DBCS. Enabling diagnostic collection allows you to receive Events service notifications for guest VM issues. Diagnostic collection also allows Oracle to provide enhanced service and proactive support for your Exadata system. You can enable diagnostic collection during VM cluster/Cloud VM cluster provisioning. You can also disable or enable it at any time using the `UpdateVmCluster` or `updateCloudVmCluster` API.


        :return: The is_diagnostics_events_enabled of this DataCollectionOptions.
        :rtype: bool
        """
        return self._is_diagnostics_events_enabled

    @is_diagnostics_events_enabled.setter
    def is_diagnostics_events_enabled(self, is_diagnostics_events_enabled):
        """
        Sets the is_diagnostics_events_enabled of this DataCollectionOptions.
        Indicates whether diagnostic collection is enabled for the VM cluster/Cloud VM cluster/VMBM DBCS. Enabling diagnostic collection allows you to receive Events service notifications for guest VM issues. Diagnostic collection also allows Oracle to provide enhanced service and proactive support for your Exadata system. You can enable diagnostic collection during VM cluster/Cloud VM cluster provisioning. You can also disable or enable it at any time using the `UpdateVmCluster` or `updateCloudVmCluster` API.


        :param is_diagnostics_events_enabled: The is_diagnostics_events_enabled of this DataCollectionOptions.
        :type: bool
        """
        self._is_diagnostics_events_enabled = is_diagnostics_events_enabled

    @property
    def is_health_monitoring_enabled(self):
        """
        Gets the is_health_monitoring_enabled of this DataCollectionOptions.
        Indicates whether health monitoring is enabled for the VM cluster / Cloud VM cluster / VMBM DBCS. Enabling health monitoring allows Oracle to collect diagnostic data and share it with its operations and support personnel. You may also receive notifications for some events. Collecting health diagnostics enables Oracle to provide proactive support and enhanced service for your system.
        Optionally enable health monitoring while provisioning a system. You can also disable or enable health monitoring anytime using the `UpdateVmCluster`, `UpdateCloudVmCluster` or `updateDbsystem` API.


        :return: The is_health_monitoring_enabled of this DataCollectionOptions.
        :rtype: bool
        """
        return self._is_health_monitoring_enabled

    @is_health_monitoring_enabled.setter
    def is_health_monitoring_enabled(self, is_health_monitoring_enabled):
        """
        Sets the is_health_monitoring_enabled of this DataCollectionOptions.
        Indicates whether health monitoring is enabled for the VM cluster / Cloud VM cluster / VMBM DBCS. Enabling health monitoring allows Oracle to collect diagnostic data and share it with its operations and support personnel. You may also receive notifications for some events. Collecting health diagnostics enables Oracle to provide proactive support and enhanced service for your system.
        Optionally enable health monitoring while provisioning a system. You can also disable or enable health monitoring anytime using the `UpdateVmCluster`, `UpdateCloudVmCluster` or `updateDbsystem` API.


        :param is_health_monitoring_enabled: The is_health_monitoring_enabled of this DataCollectionOptions.
        :type: bool
        """
        self._is_health_monitoring_enabled = is_health_monitoring_enabled

    @property
    def is_incident_logs_enabled(self):
        """
        Gets the is_incident_logs_enabled of this DataCollectionOptions.
        Indicates whether incident logs and trace collection are enabled for the VM cluster / Cloud VM cluster / VMBM DBCS. Enabling incident logs collection allows Oracle to receive Events service notifications for guest VM issues, collect incident logs and traces, and use them to diagnose issues and resolve them.
        Optionally enable incident logs collection while provisioning a system. You can also disable or enable incident logs collection anytime using the `UpdateVmCluster`, `updateCloudVmCluster` or `updateDbsystem` API.


        :return: The is_incident_logs_enabled of this DataCollectionOptions.
        :rtype: bool
        """
        return self._is_incident_logs_enabled

    @is_incident_logs_enabled.setter
    def is_incident_logs_enabled(self, is_incident_logs_enabled):
        """
        Sets the is_incident_logs_enabled of this DataCollectionOptions.
        Indicates whether incident logs and trace collection are enabled for the VM cluster / Cloud VM cluster / VMBM DBCS. Enabling incident logs collection allows Oracle to receive Events service notifications for guest VM issues, collect incident logs and traces, and use them to diagnose issues and resolve them.
        Optionally enable incident logs collection while provisioning a system. You can also disable or enable incident logs collection anytime using the `UpdateVmCluster`, `updateCloudVmCluster` or `updateDbsystem` API.


        :param is_incident_logs_enabled: The is_incident_logs_enabled of this DataCollectionOptions.
        :type: bool
        """
        self._is_incident_logs_enabled = is_incident_logs_enabled

    def __repr__(self):
        return formatted_flat_dict(self)

    def __eq__(self, other):
        if other is None:
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not self == other
