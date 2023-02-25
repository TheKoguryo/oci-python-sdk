# coding: utf-8
# Copyright (c) 2016, 2023, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

from .discovered_external_db_system_component import DiscoveredExternalDbSystemComponent
from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class DiscoveredExternalCluster(DiscoveredExternalDbSystemComponent):
    """
    The details of an external cluster discovered in an external DB system discovery run.
    """

    def __init__(self, **kwargs):
        """
        Initializes a new DiscoveredExternalCluster object with values from keyword arguments. The default value of the :py:attr:`~oci.database_management.models.DiscoveredExternalCluster.component_type` attribute
        of this class is ``CLUSTER`` and it should not be changed.
        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param component_id:
            The value to assign to the component_id property of this DiscoveredExternalCluster.
        :type component_id: str

        :param display_name:
            The value to assign to the display_name property of this DiscoveredExternalCluster.
        :type display_name: str

        :param component_name:
            The value to assign to the component_name property of this DiscoveredExternalCluster.
        :type component_name: str

        :param component_type:
            The value to assign to the component_type property of this DiscoveredExternalCluster.
            Allowed values for this property are: "ASM", "ASM_INSTANCE", "CLUSTER", "CLUSTER_INSTANCE", "DATABASE", "DATABASE_INSTANCE", "DATABASE_HOME", "DATABASE_NODE", "DBSYSTEM", "LISTENER", "PLUGGABLE_DATABASE"
        :type component_type: str

        :param resource_id:
            The value to assign to the resource_id property of this DiscoveredExternalCluster.
        :type resource_id: str

        :param is_selected_for_monitoring:
            The value to assign to the is_selected_for_monitoring property of this DiscoveredExternalCluster.
        :type is_selected_for_monitoring: bool

        :param status:
            The value to assign to the status property of this DiscoveredExternalCluster.
            Allowed values for this property are: "NEW", "EXISTING", "MARKED_FOR_DELETION", "UNKNOWN"
        :type status: str

        :param associated_components:
            The value to assign to the associated_components property of this DiscoveredExternalCluster.
        :type associated_components: list[oci.database_management.models.AssociatedComponent]

        :param grid_home:
            The value to assign to the grid_home property of this DiscoveredExternalCluster.
        :type grid_home: str

        :param version:
            The value to assign to the version property of this DiscoveredExternalCluster.
        :type version: str

        :param is_flex_cluster:
            The value to assign to the is_flex_cluster property of this DiscoveredExternalCluster.
        :type is_flex_cluster: bool

        :param network_configurations:
            The value to assign to the network_configurations property of this DiscoveredExternalCluster.
        :type network_configurations: list[oci.database_management.models.ExternalClusterNetworkConfiguration]

        :param vip_configurations:
            The value to assign to the vip_configurations property of this DiscoveredExternalCluster.
        :type vip_configurations: list[oci.database_management.models.ExternalClusterVipConfiguration]

        :param scan_configurations:
            The value to assign to the scan_configurations property of this DiscoveredExternalCluster.
        :type scan_configurations: list[oci.database_management.models.ExternalClusterScanListenerConfiguration]

        :param ocr_file_location:
            The value to assign to the ocr_file_location property of this DiscoveredExternalCluster.
        :type ocr_file_location: str

        :param cluster_instances:
            The value to assign to the cluster_instances property of this DiscoveredExternalCluster.
        :type cluster_instances: list[oci.database_management.models.DiscoveredExternalClusterInstance]

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
            'version': 'str',
            'is_flex_cluster': 'bool',
            'network_configurations': 'list[ExternalClusterNetworkConfiguration]',
            'vip_configurations': 'list[ExternalClusterVipConfiguration]',
            'scan_configurations': 'list[ExternalClusterScanListenerConfiguration]',
            'ocr_file_location': 'str',
            'cluster_instances': 'list[DiscoveredExternalClusterInstance]'
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
            'version': 'version',
            'is_flex_cluster': 'isFlexCluster',
            'network_configurations': 'networkConfigurations',
            'vip_configurations': 'vipConfigurations',
            'scan_configurations': 'scanConfigurations',
            'ocr_file_location': 'ocrFileLocation',
            'cluster_instances': 'clusterInstances'
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
        self._version = None
        self._is_flex_cluster = None
        self._network_configurations = None
        self._vip_configurations = None
        self._scan_configurations = None
        self._ocr_file_location = None
        self._cluster_instances = None
        self._component_type = 'CLUSTER'

    @property
    def grid_home(self):
        """
        Gets the grid_home of this DiscoveredExternalCluster.
        The directory in which Oracle Grid Infrastructure is installed.


        :return: The grid_home of this DiscoveredExternalCluster.
        :rtype: str
        """
        return self._grid_home

    @grid_home.setter
    def grid_home(self, grid_home):
        """
        Sets the grid_home of this DiscoveredExternalCluster.
        The directory in which Oracle Grid Infrastructure is installed.


        :param grid_home: The grid_home of this DiscoveredExternalCluster.
        :type: str
        """
        self._grid_home = grid_home

    @property
    def version(self):
        """
        Gets the version of this DiscoveredExternalCluster.
        The version of Oracle Clusterware running in the cluster.


        :return: The version of this DiscoveredExternalCluster.
        :rtype: str
        """
        return self._version

    @version.setter
    def version(self, version):
        """
        Sets the version of this DiscoveredExternalCluster.
        The version of Oracle Clusterware running in the cluster.


        :param version: The version of this DiscoveredExternalCluster.
        :type: str
        """
        self._version = version

    @property
    def is_flex_cluster(self):
        """
        Gets the is_flex_cluster of this DiscoveredExternalCluster.
        Indicates whether the cluster is an Oracle Flex Cluster or not.


        :return: The is_flex_cluster of this DiscoveredExternalCluster.
        :rtype: bool
        """
        return self._is_flex_cluster

    @is_flex_cluster.setter
    def is_flex_cluster(self, is_flex_cluster):
        """
        Sets the is_flex_cluster of this DiscoveredExternalCluster.
        Indicates whether the cluster is an Oracle Flex Cluster or not.


        :param is_flex_cluster: The is_flex_cluster of this DiscoveredExternalCluster.
        :type: bool
        """
        self._is_flex_cluster = is_flex_cluster

    @property
    def network_configurations(self):
        """
        Gets the network_configurations of this DiscoveredExternalCluster.
        The list of network address configurations of the external cluster.


        :return: The network_configurations of this DiscoveredExternalCluster.
        :rtype: list[oci.database_management.models.ExternalClusterNetworkConfiguration]
        """
        return self._network_configurations

    @network_configurations.setter
    def network_configurations(self, network_configurations):
        """
        Sets the network_configurations of this DiscoveredExternalCluster.
        The list of network address configurations of the external cluster.


        :param network_configurations: The network_configurations of this DiscoveredExternalCluster.
        :type: list[oci.database_management.models.ExternalClusterNetworkConfiguration]
        """
        self._network_configurations = network_configurations

    @property
    def vip_configurations(self):
        """
        Gets the vip_configurations of this DiscoveredExternalCluster.
        The list of Virtual IP (VIP) configurations of the external cluster.


        :return: The vip_configurations of this DiscoveredExternalCluster.
        :rtype: list[oci.database_management.models.ExternalClusterVipConfiguration]
        """
        return self._vip_configurations

    @vip_configurations.setter
    def vip_configurations(self, vip_configurations):
        """
        Sets the vip_configurations of this DiscoveredExternalCluster.
        The list of Virtual IP (VIP) configurations of the external cluster.


        :param vip_configurations: The vip_configurations of this DiscoveredExternalCluster.
        :type: list[oci.database_management.models.ExternalClusterVipConfiguration]
        """
        self._vip_configurations = vip_configurations

    @property
    def scan_configurations(self):
        """
        Gets the scan_configurations of this DiscoveredExternalCluster.
        The list of Single Client Access Name (SCAN) configurations of the external cluster.


        :return: The scan_configurations of this DiscoveredExternalCluster.
        :rtype: list[oci.database_management.models.ExternalClusterScanListenerConfiguration]
        """
        return self._scan_configurations

    @scan_configurations.setter
    def scan_configurations(self, scan_configurations):
        """
        Sets the scan_configurations of this DiscoveredExternalCluster.
        The list of Single Client Access Name (SCAN) configurations of the external cluster.


        :param scan_configurations: The scan_configurations of this DiscoveredExternalCluster.
        :type: list[oci.database_management.models.ExternalClusterScanListenerConfiguration]
        """
        self._scan_configurations = scan_configurations

    @property
    def ocr_file_location(self):
        """
        Gets the ocr_file_location of this DiscoveredExternalCluster.
        The location of the Oracle Cluster Registry (OCR) file.


        :return: The ocr_file_location of this DiscoveredExternalCluster.
        :rtype: str
        """
        return self._ocr_file_location

    @ocr_file_location.setter
    def ocr_file_location(self, ocr_file_location):
        """
        Sets the ocr_file_location of this DiscoveredExternalCluster.
        The location of the Oracle Cluster Registry (OCR) file.


        :param ocr_file_location: The ocr_file_location of this DiscoveredExternalCluster.
        :type: str
        """
        self._ocr_file_location = ocr_file_location

    @property
    def cluster_instances(self):
        """
        Gets the cluster_instances of this DiscoveredExternalCluster.

        :return: The cluster_instances of this DiscoveredExternalCluster.
        :rtype: list[oci.database_management.models.DiscoveredExternalClusterInstance]
        """
        return self._cluster_instances

    @cluster_instances.setter
    def cluster_instances(self, cluster_instances):
        """
        Sets the cluster_instances of this DiscoveredExternalCluster.

        :param cluster_instances: The cluster_instances of this DiscoveredExternalCluster.
        :type: list[oci.database_management.models.DiscoveredExternalClusterInstance]
        """
        self._cluster_instances = cluster_instances

    def __repr__(self):
        return formatted_flat_dict(self)

    def __eq__(self, other):
        if other is None:
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not self == other
