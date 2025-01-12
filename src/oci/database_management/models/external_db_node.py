# coding: utf-8
# Copyright (c) 2016, 2023, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.


from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class ExternalDbNode(object):
    """
    The details of an external database node.
    """

    #: A constant which can be used with the lifecycle_state property of a ExternalDbNode.
    #: This constant has a value of "CREATING"
    LIFECYCLE_STATE_CREATING = "CREATING"

    #: A constant which can be used with the lifecycle_state property of a ExternalDbNode.
    #: This constant has a value of "NOT_CONNECTED"
    LIFECYCLE_STATE_NOT_CONNECTED = "NOT_CONNECTED"

    #: A constant which can be used with the lifecycle_state property of a ExternalDbNode.
    #: This constant has a value of "ACTIVE"
    LIFECYCLE_STATE_ACTIVE = "ACTIVE"

    #: A constant which can be used with the lifecycle_state property of a ExternalDbNode.
    #: This constant has a value of "INACTIVE"
    LIFECYCLE_STATE_INACTIVE = "INACTIVE"

    #: A constant which can be used with the lifecycle_state property of a ExternalDbNode.
    #: This constant has a value of "UPDATING"
    LIFECYCLE_STATE_UPDATING = "UPDATING"

    #: A constant which can be used with the lifecycle_state property of a ExternalDbNode.
    #: This constant has a value of "DELETING"
    LIFECYCLE_STATE_DELETING = "DELETING"

    #: A constant which can be used with the lifecycle_state property of a ExternalDbNode.
    #: This constant has a value of "DELETED"
    LIFECYCLE_STATE_DELETED = "DELETED"

    #: A constant which can be used with the lifecycle_state property of a ExternalDbNode.
    #: This constant has a value of "FAILED"
    LIFECYCLE_STATE_FAILED = "FAILED"

    def __init__(self, **kwargs):
        """
        Initializes a new ExternalDbNode object with values from keyword arguments.
        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param id:
            The value to assign to the id property of this ExternalDbNode.
        :type id: str

        :param display_name:
            The value to assign to the display_name property of this ExternalDbNode.
        :type display_name: str

        :param component_name:
            The value to assign to the component_name property of this ExternalDbNode.
        :type component_name: str

        :param compartment_id:
            The value to assign to the compartment_id property of this ExternalDbNode.
        :type compartment_id: str

        :param external_db_system_id:
            The value to assign to the external_db_system_id property of this ExternalDbNode.
        :type external_db_system_id: str

        :param external_connector_id:
            The value to assign to the external_connector_id property of this ExternalDbNode.
        :type external_connector_id: str

        :param host_name:
            The value to assign to the host_name property of this ExternalDbNode.
        :type host_name: str

        :param cpu_core_count:
            The value to assign to the cpu_core_count property of this ExternalDbNode.
        :type cpu_core_count: float

        :param memory_size_in_gbs:
            The value to assign to the memory_size_in_gbs property of this ExternalDbNode.
        :type memory_size_in_gbs: float

        :param additional_details:
            The value to assign to the additional_details property of this ExternalDbNode.
        :type additional_details: dict(str, str)

        :param lifecycle_state:
            The value to assign to the lifecycle_state property of this ExternalDbNode.
            Allowed values for this property are: "CREATING", "NOT_CONNECTED", "ACTIVE", "INACTIVE", "UPDATING", "DELETING", "DELETED", "FAILED", 'UNKNOWN_ENUM_VALUE'.
            Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.
        :type lifecycle_state: str

        :param lifecycle_details:
            The value to assign to the lifecycle_details property of this ExternalDbNode.
        :type lifecycle_details: str

        :param time_created:
            The value to assign to the time_created property of this ExternalDbNode.
        :type time_created: datetime

        :param time_updated:
            The value to assign to the time_updated property of this ExternalDbNode.
        :type time_updated: datetime

        """
        self.swagger_types = {
            'id': 'str',
            'display_name': 'str',
            'component_name': 'str',
            'compartment_id': 'str',
            'external_db_system_id': 'str',
            'external_connector_id': 'str',
            'host_name': 'str',
            'cpu_core_count': 'float',
            'memory_size_in_gbs': 'float',
            'additional_details': 'dict(str, str)',
            'lifecycle_state': 'str',
            'lifecycle_details': 'str',
            'time_created': 'datetime',
            'time_updated': 'datetime'
        }

        self.attribute_map = {
            'id': 'id',
            'display_name': 'displayName',
            'component_name': 'componentName',
            'compartment_id': 'compartmentId',
            'external_db_system_id': 'externalDbSystemId',
            'external_connector_id': 'externalConnectorId',
            'host_name': 'hostName',
            'cpu_core_count': 'cpuCoreCount',
            'memory_size_in_gbs': 'memorySizeInGBs',
            'additional_details': 'additionalDetails',
            'lifecycle_state': 'lifecycleState',
            'lifecycle_details': 'lifecycleDetails',
            'time_created': 'timeCreated',
            'time_updated': 'timeUpdated'
        }

        self._id = None
        self._display_name = None
        self._component_name = None
        self._compartment_id = None
        self._external_db_system_id = None
        self._external_connector_id = None
        self._host_name = None
        self._cpu_core_count = None
        self._memory_size_in_gbs = None
        self._additional_details = None
        self._lifecycle_state = None
        self._lifecycle_details = None
        self._time_created = None
        self._time_updated = None

    @property
    def id(self):
        """
        **[Required]** Gets the id of this ExternalDbNode.
        The `OCID`__ of the external DB node.

        __ https://docs.cloud.oracle.com/Content/General/Concepts/identifiers.htm


        :return: The id of this ExternalDbNode.
        :rtype: str
        """
        return self._id

    @id.setter
    def id(self, id):
        """
        Sets the id of this ExternalDbNode.
        The `OCID`__ of the external DB node.

        __ https://docs.cloud.oracle.com/Content/General/Concepts/identifiers.htm


        :param id: The id of this ExternalDbNode.
        :type: str
        """
        self._id = id

    @property
    def display_name(self):
        """
        **[Required]** Gets the display_name of this ExternalDbNode.
        The user-friendly name for the external DB node. The name does not have to be unique.


        :return: The display_name of this ExternalDbNode.
        :rtype: str
        """
        return self._display_name

    @display_name.setter
    def display_name(self, display_name):
        """
        Sets the display_name of this ExternalDbNode.
        The user-friendly name for the external DB node. The name does not have to be unique.


        :param display_name: The display_name of this ExternalDbNode.
        :type: str
        """
        self._display_name = display_name

    @property
    def component_name(self):
        """
        **[Required]** Gets the component_name of this ExternalDbNode.
        The name of the external DB node.


        :return: The component_name of this ExternalDbNode.
        :rtype: str
        """
        return self._component_name

    @component_name.setter
    def component_name(self, component_name):
        """
        Sets the component_name of this ExternalDbNode.
        The name of the external DB node.


        :param component_name: The component_name of this ExternalDbNode.
        :type: str
        """
        self._component_name = component_name

    @property
    def compartment_id(self):
        """
        **[Required]** Gets the compartment_id of this ExternalDbNode.
        The `OCID`__ of the compartment.

        __ https://docs.cloud.oracle.com/Content/General/Concepts/identifiers.htm


        :return: The compartment_id of this ExternalDbNode.
        :rtype: str
        """
        return self._compartment_id

    @compartment_id.setter
    def compartment_id(self, compartment_id):
        """
        Sets the compartment_id of this ExternalDbNode.
        The `OCID`__ of the compartment.

        __ https://docs.cloud.oracle.com/Content/General/Concepts/identifiers.htm


        :param compartment_id: The compartment_id of this ExternalDbNode.
        :type: str
        """
        self._compartment_id = compartment_id

    @property
    def external_db_system_id(self):
        """
        **[Required]** Gets the external_db_system_id of this ExternalDbNode.
        The `OCID`__ of the external DB system that the DB node is a part of.

        __ https://docs.cloud.oracle.com/Content/General/Concepts/identifiers.htm


        :return: The external_db_system_id of this ExternalDbNode.
        :rtype: str
        """
        return self._external_db_system_id

    @external_db_system_id.setter
    def external_db_system_id(self, external_db_system_id):
        """
        Sets the external_db_system_id of this ExternalDbNode.
        The `OCID`__ of the external DB system that the DB node is a part of.

        __ https://docs.cloud.oracle.com/Content/General/Concepts/identifiers.htm


        :param external_db_system_id: The external_db_system_id of this ExternalDbNode.
        :type: str
        """
        self._external_db_system_id = external_db_system_id

    @property
    def external_connector_id(self):
        """
        Gets the external_connector_id of this ExternalDbNode.
        The `OCID`__ of the external connector.

        __ https://docs.cloud.oracle.com/Content/General/Concepts/identifiers.htm


        :return: The external_connector_id of this ExternalDbNode.
        :rtype: str
        """
        return self._external_connector_id

    @external_connector_id.setter
    def external_connector_id(self, external_connector_id):
        """
        Sets the external_connector_id of this ExternalDbNode.
        The `OCID`__ of the external connector.

        __ https://docs.cloud.oracle.com/Content/General/Concepts/identifiers.htm


        :param external_connector_id: The external_connector_id of this ExternalDbNode.
        :type: str
        """
        self._external_connector_id = external_connector_id

    @property
    def host_name(self):
        """
        Gets the host_name of this ExternalDbNode.
        The host name for the DB node.


        :return: The host_name of this ExternalDbNode.
        :rtype: str
        """
        return self._host_name

    @host_name.setter
    def host_name(self, host_name):
        """
        Sets the host_name of this ExternalDbNode.
        The host name for the DB node.


        :param host_name: The host_name of this ExternalDbNode.
        :type: str
        """
        self._host_name = host_name

    @property
    def cpu_core_count(self):
        """
        Gets the cpu_core_count of this ExternalDbNode.
        The number of CPU cores available on the DB node.


        :return: The cpu_core_count of this ExternalDbNode.
        :rtype: float
        """
        return self._cpu_core_count

    @cpu_core_count.setter
    def cpu_core_count(self, cpu_core_count):
        """
        Sets the cpu_core_count of this ExternalDbNode.
        The number of CPU cores available on the DB node.


        :param cpu_core_count: The cpu_core_count of this ExternalDbNode.
        :type: float
        """
        self._cpu_core_count = cpu_core_count

    @property
    def memory_size_in_gbs(self):
        """
        Gets the memory_size_in_gbs of this ExternalDbNode.
        The total memory in gigabytes (GB) on the DB node.


        :return: The memory_size_in_gbs of this ExternalDbNode.
        :rtype: float
        """
        return self._memory_size_in_gbs

    @memory_size_in_gbs.setter
    def memory_size_in_gbs(self, memory_size_in_gbs):
        """
        Sets the memory_size_in_gbs of this ExternalDbNode.
        The total memory in gigabytes (GB) on the DB node.


        :param memory_size_in_gbs: The memory_size_in_gbs of this ExternalDbNode.
        :type: float
        """
        self._memory_size_in_gbs = memory_size_in_gbs

    @property
    def additional_details(self):
        """
        Gets the additional_details of this ExternalDbNode.
        The additional details of the external DB node defined in `{\"key\": \"value\"}` format.
        Example: `{\"bar-key\": \"value\"}`


        :return: The additional_details of this ExternalDbNode.
        :rtype: dict(str, str)
        """
        return self._additional_details

    @additional_details.setter
    def additional_details(self, additional_details):
        """
        Sets the additional_details of this ExternalDbNode.
        The additional details of the external DB node defined in `{\"key\": \"value\"}` format.
        Example: `{\"bar-key\": \"value\"}`


        :param additional_details: The additional_details of this ExternalDbNode.
        :type: dict(str, str)
        """
        self._additional_details = additional_details

    @property
    def lifecycle_state(self):
        """
        **[Required]** Gets the lifecycle_state of this ExternalDbNode.
        The current lifecycle state of the external DB node.

        Allowed values for this property are: "CREATING", "NOT_CONNECTED", "ACTIVE", "INACTIVE", "UPDATING", "DELETING", "DELETED", "FAILED", 'UNKNOWN_ENUM_VALUE'.
        Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.


        :return: The lifecycle_state of this ExternalDbNode.
        :rtype: str
        """
        return self._lifecycle_state

    @lifecycle_state.setter
    def lifecycle_state(self, lifecycle_state):
        """
        Sets the lifecycle_state of this ExternalDbNode.
        The current lifecycle state of the external DB node.


        :param lifecycle_state: The lifecycle_state of this ExternalDbNode.
        :type: str
        """
        allowed_values = ["CREATING", "NOT_CONNECTED", "ACTIVE", "INACTIVE", "UPDATING", "DELETING", "DELETED", "FAILED"]
        if not value_allowed_none_or_none_sentinel(lifecycle_state, allowed_values):
            lifecycle_state = 'UNKNOWN_ENUM_VALUE'
        self._lifecycle_state = lifecycle_state

    @property
    def lifecycle_details(self):
        """
        Gets the lifecycle_details of this ExternalDbNode.
        Additional information about the current lifecycle state.


        :return: The lifecycle_details of this ExternalDbNode.
        :rtype: str
        """
        return self._lifecycle_details

    @lifecycle_details.setter
    def lifecycle_details(self, lifecycle_details):
        """
        Sets the lifecycle_details of this ExternalDbNode.
        Additional information about the current lifecycle state.


        :param lifecycle_details: The lifecycle_details of this ExternalDbNode.
        :type: str
        """
        self._lifecycle_details = lifecycle_details

    @property
    def time_created(self):
        """
        **[Required]** Gets the time_created of this ExternalDbNode.
        The date and time the external DB node was created.


        :return: The time_created of this ExternalDbNode.
        :rtype: datetime
        """
        return self._time_created

    @time_created.setter
    def time_created(self, time_created):
        """
        Sets the time_created of this ExternalDbNode.
        The date and time the external DB node was created.


        :param time_created: The time_created of this ExternalDbNode.
        :type: datetime
        """
        self._time_created = time_created

    @property
    def time_updated(self):
        """
        **[Required]** Gets the time_updated of this ExternalDbNode.
        The date and time the external DB node was last updated.


        :return: The time_updated of this ExternalDbNode.
        :rtype: datetime
        """
        return self._time_updated

    @time_updated.setter
    def time_updated(self, time_updated):
        """
        Sets the time_updated of this ExternalDbNode.
        The date and time the external DB node was last updated.


        :param time_updated: The time_updated of this ExternalDbNode.
        :type: datetime
        """
        self._time_updated = time_updated

    def __repr__(self):
        return formatted_flat_dict(self)

    def __eq__(self, other):
        if other is None:
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not self == other
