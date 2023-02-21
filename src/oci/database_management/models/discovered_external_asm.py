# coding: utf-8
# Copyright (c) 2016, 2023, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

from .discovered_external_db_system_component import DiscoveredExternalDbSystemComponent
from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class DiscoveredExternalAsm(DiscoveredExternalDbSystemComponent):
    """
    The details of an ASM discovered in an external DB system discovery run.
    """

    def __init__(self, **kwargs):
        """
        Initializes a new DiscoveredExternalAsm object with values from keyword arguments. The default value of the :py:attr:`~oci.database_management.models.DiscoveredExternalAsm.component_type` attribute
        of this class is ``ASM`` and it should not be changed.
        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param component_id:
            The value to assign to the component_id property of this DiscoveredExternalAsm.
        :type component_id: str

        :param display_name:
            The value to assign to the display_name property of this DiscoveredExternalAsm.
        :type display_name: str

        :param component_name:
            The value to assign to the component_name property of this DiscoveredExternalAsm.
        :type component_name: str

        :param component_type:
            The value to assign to the component_type property of this DiscoveredExternalAsm.
            Allowed values for this property are: "ASM", "ASM_INSTANCE", "CLUSTER", "CLUSTER_INSTANCE", "DATABASE", "DATABASE_INSTANCE", "DATABASE_HOME", "DATABASE_NODE", "DBSYSTEM", "LISTENER", "PLUGGABLE_DATABASE"
        :type component_type: str

        :param resource_id:
            The value to assign to the resource_id property of this DiscoveredExternalAsm.
        :type resource_id: str

        :param is_selected_for_monitoring:
            The value to assign to the is_selected_for_monitoring property of this DiscoveredExternalAsm.
        :type is_selected_for_monitoring: bool

        :param status:
            The value to assign to the status property of this DiscoveredExternalAsm.
            Allowed values for this property are: "NEW", "EXISTING", "MARKED_FOR_DELETION", "UNKNOWN"
        :type status: str

        :param associated_components:
            The value to assign to the associated_components property of this DiscoveredExternalAsm.
        :type associated_components: list[oci.database_management.models.AssociatedComponent]

        :param grid_home:
            The value to assign to the grid_home property of this DiscoveredExternalAsm.
        :type grid_home: str

        :param is_flex_enabled:
            The value to assign to the is_flex_enabled property of this DiscoveredExternalAsm.
        :type is_flex_enabled: bool

        :param version:
            The value to assign to the version property of this DiscoveredExternalAsm.
        :type version: str

        :param asm_instances:
            The value to assign to the asm_instances property of this DiscoveredExternalAsm.
        :type asm_instances: list[oci.database_management.models.DiscoveredExternalAsmInstance]

        :param connector:
            The value to assign to the connector property of this DiscoveredExternalAsm.
        :type connector: oci.database_management.models.ExternalDbSystemDiscoveryConnector

        """
        self.swagger_types = {
            'component_id': 'str',
            'display_name': 'str',
            'component_name': 'str',
            'component_type': 'str',
            'resource_id': 'str',
            'is_selected_for_monitoring': 'bool',
            'status': 'str',
            'associated_components': 'list[AssociatedComponent]',
            'grid_home': 'str',
            'is_flex_enabled': 'bool',
            'version': 'str',
            'asm_instances': 'list[DiscoveredExternalAsmInstance]',
            'connector': 'ExternalDbSystemDiscoveryConnector'
        }

        self.attribute_map = {
            'component_id': 'componentId',
            'display_name': 'displayName',
            'component_name': 'componentName',
            'component_type': 'componentType',
            'resource_id': 'resourceId',
            'is_selected_for_monitoring': 'isSelectedForMonitoring',
            'status': 'status',
            'associated_components': 'associatedComponents',
            'grid_home': 'gridHome',
            'is_flex_enabled': 'isFlexEnabled',
            'version': 'version',
            'asm_instances': 'asmInstances',
            'connector': 'connector'
        }

        self._component_id = None
        self._display_name = None
        self._component_name = None
        self._component_type = None
        self._resource_id = None
        self._is_selected_for_monitoring = None
        self._status = None
        self._associated_components = None
        self._grid_home = None
        self._is_flex_enabled = None
        self._version = None
        self._asm_instances = None
        self._connector = None
        self._component_type = 'ASM'

    @property
    def grid_home(self):
        """
        Gets the grid_home of this DiscoveredExternalAsm.
        The directory in which ASM is installed. This is the same directory in which Oracle Grid Infrastructure is installed.


        :return: The grid_home of this DiscoveredExternalAsm.
        :rtype: str
        """
        return self._grid_home

    @grid_home.setter
    def grid_home(self, grid_home):
        """
        Sets the grid_home of this DiscoveredExternalAsm.
        The directory in which ASM is installed. This is the same directory in which Oracle Grid Infrastructure is installed.


        :param grid_home: The grid_home of this DiscoveredExternalAsm.
        :type: str
        """
        self._grid_home = grid_home

    @property
    def is_flex_enabled(self):
        """
        Gets the is_flex_enabled of this DiscoveredExternalAsm.
        Indicates whether Oracle Flex ASM is enabled or not.


        :return: The is_flex_enabled of this DiscoveredExternalAsm.
        :rtype: bool
        """
        return self._is_flex_enabled

    @is_flex_enabled.setter
    def is_flex_enabled(self, is_flex_enabled):
        """
        Sets the is_flex_enabled of this DiscoveredExternalAsm.
        Indicates whether Oracle Flex ASM is enabled or not.


        :param is_flex_enabled: The is_flex_enabled of this DiscoveredExternalAsm.
        :type: bool
        """
        self._is_flex_enabled = is_flex_enabled

    @property
    def version(self):
        """
        Gets the version of this DiscoveredExternalAsm.
        The ASM version.


        :return: The version of this DiscoveredExternalAsm.
        :rtype: str
        """
        return self._version

    @version.setter
    def version(self, version):
        """
        Sets the version of this DiscoveredExternalAsm.
        The ASM version.


        :param version: The version of this DiscoveredExternalAsm.
        :type: str
        """
        self._version = version

    @property
    def asm_instances(self):
        """
        Gets the asm_instances of this DiscoveredExternalAsm.

        :return: The asm_instances of this DiscoveredExternalAsm.
        :rtype: list[oci.database_management.models.DiscoveredExternalAsmInstance]
        """
        return self._asm_instances

    @asm_instances.setter
    def asm_instances(self, asm_instances):
        """
        Sets the asm_instances of this DiscoveredExternalAsm.

        :param asm_instances: The asm_instances of this DiscoveredExternalAsm.
        :type: list[oci.database_management.models.DiscoveredExternalAsmInstance]
        """
        self._asm_instances = asm_instances

    @property
    def connector(self):
        """
        Gets the connector of this DiscoveredExternalAsm.

        :return: The connector of this DiscoveredExternalAsm.
        :rtype: oci.database_management.models.ExternalDbSystemDiscoveryConnector
        """
        return self._connector

    @connector.setter
    def connector(self, connector):
        """
        Sets the connector of this DiscoveredExternalAsm.

        :param connector: The connector of this DiscoveredExternalAsm.
        :type: oci.database_management.models.ExternalDbSystemDiscoveryConnector
        """
        self._connector = connector

    def __repr__(self):
        return formatted_flat_dict(self)

    def __eq__(self, other):
        if other is None:
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not self == other
