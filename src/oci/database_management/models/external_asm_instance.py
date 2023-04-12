# coding: utf-8
# Copyright (c) 2016, 2023, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.


from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class ExternalAsmInstance(object):
    """
    The details of an external ASM instance.
    """

    #: A constant which can be used with the lifecycle_state property of a ExternalAsmInstance.
    #: This constant has a value of "CREATING"
    LIFECYCLE_STATE_CREATING = "CREATING"

    #: A constant which can be used with the lifecycle_state property of a ExternalAsmInstance.
    #: This constant has a value of "ACTIVE"
    LIFECYCLE_STATE_ACTIVE = "ACTIVE"

    #: A constant which can be used with the lifecycle_state property of a ExternalAsmInstance.
    #: This constant has a value of "INACTIVE"
    LIFECYCLE_STATE_INACTIVE = "INACTIVE"

    #: A constant which can be used with the lifecycle_state property of a ExternalAsmInstance.
    #: This constant has a value of "UPDATING"
    LIFECYCLE_STATE_UPDATING = "UPDATING"

    #: A constant which can be used with the lifecycle_state property of a ExternalAsmInstance.
    #: This constant has a value of "DELETING"
    LIFECYCLE_STATE_DELETING = "DELETING"

    #: A constant which can be used with the lifecycle_state property of a ExternalAsmInstance.
    #: This constant has a value of "DELETED"
    LIFECYCLE_STATE_DELETED = "DELETED"

    def __init__(self, **kwargs):
        """
        Initializes a new ExternalAsmInstance object with values from keyword arguments.
        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param id:
            The value to assign to the id property of this ExternalAsmInstance.
        :type id: str

        :param display_name:
            The value to assign to the display_name property of this ExternalAsmInstance.
        :type display_name: str

        :param component_name:
            The value to assign to the component_name property of this ExternalAsmInstance.
        :type component_name: str

        :param compartment_id:
            The value to assign to the compartment_id property of this ExternalAsmInstance.
        :type compartment_id: str

        :param external_asm_id:
            The value to assign to the external_asm_id property of this ExternalAsmInstance.
        :type external_asm_id: str

        :param external_db_system_id:
            The value to assign to the external_db_system_id property of this ExternalAsmInstance.
        :type external_db_system_id: str

        :param external_db_node_id:
            The value to assign to the external_db_node_id property of this ExternalAsmInstance.
        :type external_db_node_id: str

        :param adr_home_directory:
            The value to assign to the adr_home_directory property of this ExternalAsmInstance.
        :type adr_home_directory: str

        :param host_name:
            The value to assign to the host_name property of this ExternalAsmInstance.
        :type host_name: str

        :param lifecycle_state:
            The value to assign to the lifecycle_state property of this ExternalAsmInstance.
            Allowed values for this property are: "CREATING", "ACTIVE", "INACTIVE", "UPDATING", "DELETING", "DELETED", 'UNKNOWN_ENUM_VALUE'.
            Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.
        :type lifecycle_state: str

        :param lifecycle_details:
            The value to assign to the lifecycle_details property of this ExternalAsmInstance.
        :type lifecycle_details: str

        :param time_created:
            The value to assign to the time_created property of this ExternalAsmInstance.
        :type time_created: datetime

        :param time_updated:
            The value to assign to the time_updated property of this ExternalAsmInstance.
        :type time_updated: datetime

        """
        self.swagger_types = {
            'id': 'str',
            'display_name': 'str',
            'component_name': 'str',
            'compartment_id': 'str',
            'external_asm_id': 'str',
            'external_db_system_id': 'str',
            'external_db_node_id': 'str',
            'adr_home_directory': 'str',
            'host_name': 'str',
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
            'external_asm_id': 'externalAsmId',
            'external_db_system_id': 'externalDbSystemId',
            'external_db_node_id': 'externalDbNodeId',
            'adr_home_directory': 'adrHomeDirectory',
            'host_name': 'hostName',
            'lifecycle_state': 'lifecycleState',
            'lifecycle_details': 'lifecycleDetails',
            'time_created': 'timeCreated',
            'time_updated': 'timeUpdated'
        }

        self._id = None
        self._display_name = None
        self._component_name = None
        self._compartment_id = None
        self._external_asm_id = None
        self._external_db_system_id = None
        self._external_db_node_id = None
        self._adr_home_directory = None
        self._host_name = None
        self._lifecycle_state = None
        self._lifecycle_details = None
        self._time_created = None
        self._time_updated = None

    @property
    def id(self):
        """
        **[Required]** Gets the id of this ExternalAsmInstance.
        The `OCID`__ of the external ASM instance.

        __ https://docs.cloud.oracle.com/Content/General/Concepts/identifiers.htm


        :return: The id of this ExternalAsmInstance.
        :rtype: str
        """
        return self._id

    @id.setter
    def id(self, id):
        """
        Sets the id of this ExternalAsmInstance.
        The `OCID`__ of the external ASM instance.

        __ https://docs.cloud.oracle.com/Content/General/Concepts/identifiers.htm


        :param id: The id of this ExternalAsmInstance.
        :type: str
        """
        self._id = id

    @property
    def display_name(self):
        """
        **[Required]** Gets the display_name of this ExternalAsmInstance.
        The user-friendly name for the ASM instance. The name does not have to be unique.


        :return: The display_name of this ExternalAsmInstance.
        :rtype: str
        """
        return self._display_name

    @display_name.setter
    def display_name(self, display_name):
        """
        Sets the display_name of this ExternalAsmInstance.
        The user-friendly name for the ASM instance. The name does not have to be unique.


        :param display_name: The display_name of this ExternalAsmInstance.
        :type: str
        """
        self._display_name = display_name

    @property
    def component_name(self):
        """
        **[Required]** Gets the component_name of this ExternalAsmInstance.
        The name of the external ASM instance.


        :return: The component_name of this ExternalAsmInstance.
        :rtype: str
        """
        return self._component_name

    @component_name.setter
    def component_name(self, component_name):
        """
        Sets the component_name of this ExternalAsmInstance.
        The name of the external ASM instance.


        :param component_name: The component_name of this ExternalAsmInstance.
        :type: str
        """
        self._component_name = component_name

    @property
    def compartment_id(self):
        """
        **[Required]** Gets the compartment_id of this ExternalAsmInstance.
        The `OCID`__ of the compartment.

        __ https://docs.cloud.oracle.com/Content/General/Concepts/identifiers.htm


        :return: The compartment_id of this ExternalAsmInstance.
        :rtype: str
        """
        return self._compartment_id

    @compartment_id.setter
    def compartment_id(self, compartment_id):
        """
        Sets the compartment_id of this ExternalAsmInstance.
        The `OCID`__ of the compartment.

        __ https://docs.cloud.oracle.com/Content/General/Concepts/identifiers.htm


        :param compartment_id: The compartment_id of this ExternalAsmInstance.
        :type: str
        """
        self._compartment_id = compartment_id

    @property
    def external_asm_id(self):
        """
        **[Required]** Gets the external_asm_id of this ExternalAsmInstance.
        The `OCID`__ of the external ASM that the ASM instance belongs to.

        __ https://docs.cloud.oracle.com/Content/General/Concepts/identifiers.htm


        :return: The external_asm_id of this ExternalAsmInstance.
        :rtype: str
        """
        return self._external_asm_id

    @external_asm_id.setter
    def external_asm_id(self, external_asm_id):
        """
        Sets the external_asm_id of this ExternalAsmInstance.
        The `OCID`__ of the external ASM that the ASM instance belongs to.

        __ https://docs.cloud.oracle.com/Content/General/Concepts/identifiers.htm


        :param external_asm_id: The external_asm_id of this ExternalAsmInstance.
        :type: str
        """
        self._external_asm_id = external_asm_id

    @property
    def external_db_system_id(self):
        """
        **[Required]** Gets the external_db_system_id of this ExternalAsmInstance.
        The `OCID`__ of the external DB system that the ASM instance is a part of.

        __ https://docs.cloud.oracle.com/Content/General/Concepts/identifiers.htm


        :return: The external_db_system_id of this ExternalAsmInstance.
        :rtype: str
        """
        return self._external_db_system_id

    @external_db_system_id.setter
    def external_db_system_id(self, external_db_system_id):
        """
        Sets the external_db_system_id of this ExternalAsmInstance.
        The `OCID`__ of the external DB system that the ASM instance is a part of.

        __ https://docs.cloud.oracle.com/Content/General/Concepts/identifiers.htm


        :param external_db_system_id: The external_db_system_id of this ExternalAsmInstance.
        :type: str
        """
        self._external_db_system_id = external_db_system_id

    @property
    def external_db_node_id(self):
        """
        Gets the external_db_node_id of this ExternalAsmInstance.
        The `OCID`__ of the external DB node on which the ASM instance is running.

        __ https://docs.cloud.oracle.com/Content/General/Concepts/identifiers.htm


        :return: The external_db_node_id of this ExternalAsmInstance.
        :rtype: str
        """
        return self._external_db_node_id

    @external_db_node_id.setter
    def external_db_node_id(self, external_db_node_id):
        """
        Sets the external_db_node_id of this ExternalAsmInstance.
        The `OCID`__ of the external DB node on which the ASM instance is running.

        __ https://docs.cloud.oracle.com/Content/General/Concepts/identifiers.htm


        :param external_db_node_id: The external_db_node_id of this ExternalAsmInstance.
        :type: str
        """
        self._external_db_node_id = external_db_node_id

    @property
    def adr_home_directory(self):
        """
        Gets the adr_home_directory of this ExternalAsmInstance.
        The Automatic Diagnostic Repository (ADR) home directory for the ASM instance.


        :return: The adr_home_directory of this ExternalAsmInstance.
        :rtype: str
        """
        return self._adr_home_directory

    @adr_home_directory.setter
    def adr_home_directory(self, adr_home_directory):
        """
        Sets the adr_home_directory of this ExternalAsmInstance.
        The Automatic Diagnostic Repository (ADR) home directory for the ASM instance.


        :param adr_home_directory: The adr_home_directory of this ExternalAsmInstance.
        :type: str
        """
        self._adr_home_directory = adr_home_directory

    @property
    def host_name(self):
        """
        Gets the host_name of this ExternalAsmInstance.
        The name of the host on which the ASM instance is running.


        :return: The host_name of this ExternalAsmInstance.
        :rtype: str
        """
        return self._host_name

    @host_name.setter
    def host_name(self, host_name):
        """
        Sets the host_name of this ExternalAsmInstance.
        The name of the host on which the ASM instance is running.


        :param host_name: The host_name of this ExternalAsmInstance.
        :type: str
        """
        self._host_name = host_name

    @property
    def lifecycle_state(self):
        """
        **[Required]** Gets the lifecycle_state of this ExternalAsmInstance.
        The current lifecycle state of the external ASM instance.

        Allowed values for this property are: "CREATING", "ACTIVE", "INACTIVE", "UPDATING", "DELETING", "DELETED", 'UNKNOWN_ENUM_VALUE'.
        Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.


        :return: The lifecycle_state of this ExternalAsmInstance.
        :rtype: str
        """
        return self._lifecycle_state

    @lifecycle_state.setter
    def lifecycle_state(self, lifecycle_state):
        """
        Sets the lifecycle_state of this ExternalAsmInstance.
        The current lifecycle state of the external ASM instance.


        :param lifecycle_state: The lifecycle_state of this ExternalAsmInstance.
        :type: str
        """
        allowed_values = ["CREATING", "ACTIVE", "INACTIVE", "UPDATING", "DELETING", "DELETED"]
        if not value_allowed_none_or_none_sentinel(lifecycle_state, allowed_values):
            lifecycle_state = 'UNKNOWN_ENUM_VALUE'
        self._lifecycle_state = lifecycle_state

    @property
    def lifecycle_details(self):
        """
        Gets the lifecycle_details of this ExternalAsmInstance.
        Additional information about the current lifecycle state.


        :return: The lifecycle_details of this ExternalAsmInstance.
        :rtype: str
        """
        return self._lifecycle_details

    @lifecycle_details.setter
    def lifecycle_details(self, lifecycle_details):
        """
        Sets the lifecycle_details of this ExternalAsmInstance.
        Additional information about the current lifecycle state.


        :param lifecycle_details: The lifecycle_details of this ExternalAsmInstance.
        :type: str
        """
        self._lifecycle_details = lifecycle_details

    @property
    def time_created(self):
        """
        Gets the time_created of this ExternalAsmInstance.
        The date and time the external ASM instance was created.


        :return: The time_created of this ExternalAsmInstance.
        :rtype: datetime
        """
        return self._time_created

    @time_created.setter
    def time_created(self, time_created):
        """
        Sets the time_created of this ExternalAsmInstance.
        The date and time the external ASM instance was created.


        :param time_created: The time_created of this ExternalAsmInstance.
        :type: datetime
        """
        self._time_created = time_created

    @property
    def time_updated(self):
        """
        Gets the time_updated of this ExternalAsmInstance.
        The date and time the external ASM instance was last updated.


        :return: The time_updated of this ExternalAsmInstance.
        :rtype: datetime
        """
        return self._time_updated

    @time_updated.setter
    def time_updated(self, time_updated):
        """
        Sets the time_updated of this ExternalAsmInstance.
        The date and time the external ASM instance was last updated.


        :param time_updated: The time_updated of this ExternalAsmInstance.
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