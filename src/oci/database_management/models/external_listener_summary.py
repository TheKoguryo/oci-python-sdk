# coding: utf-8
# Copyright (c) 2016, 2023, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.


from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class ExternalListenerSummary(object):
    """
    The summary of an external listener.
    """

    def __init__(self, **kwargs):
        """
        Initializes a new ExternalListenerSummary object with values from keyword arguments.
        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param id:
            The value to assign to the id property of this ExternalListenerSummary.
        :type id: str

        :param display_name:
            The value to assign to the display_name property of this ExternalListenerSummary.
        :type display_name: str

        :param component_name:
            The value to assign to the component_name property of this ExternalListenerSummary.
        :type component_name: str

        :param compartment_id:
            The value to assign to the compartment_id property of this ExternalListenerSummary.
        :type compartment_id: str

        :param external_db_system_id:
            The value to assign to the external_db_system_id property of this ExternalListenerSummary.
        :type external_db_system_id: str

        :param external_connector_id:
            The value to assign to the external_connector_id property of this ExternalListenerSummary.
        :type external_connector_id: str

        :param external_db_node_id:
            The value to assign to the external_db_node_id property of this ExternalListenerSummary.
        :type external_db_node_id: str

        :param listener_type:
            The value to assign to the listener_type property of this ExternalListenerSummary.
        :type listener_type: str

        :param lifecycle_state:
            The value to assign to the lifecycle_state property of this ExternalListenerSummary.
        :type lifecycle_state: str

        :param lifecycle_details:
            The value to assign to the lifecycle_details property of this ExternalListenerSummary.
        :type lifecycle_details: str

        :param time_created:
            The value to assign to the time_created property of this ExternalListenerSummary.
        :type time_created: datetime

        :param time_updated:
            The value to assign to the time_updated property of this ExternalListenerSummary.
        :type time_updated: datetime

        """
        self.swagger_types = {
            'id': 'str',
            'display_name': 'str',
            'component_name': 'str',
            'compartment_id': 'str',
            'external_db_system_id': 'str',
            'external_connector_id': 'str',
            'external_db_node_id': 'str',
            'listener_type': 'str',
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
            'external_db_node_id': 'externalDbNodeId',
            'listener_type': 'listenerType',
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
        self._external_db_node_id = None
        self._listener_type = None
        self._lifecycle_state = None
        self._lifecycle_details = None
        self._time_created = None
        self._time_updated = None

    @property
    def id(self):
        """
        **[Required]** Gets the id of this ExternalListenerSummary.
        The `OCID`__ of the external listener.

        __ https://docs.cloud.oracle.com/Content/General/Concepts/identifiers.htm


        :return: The id of this ExternalListenerSummary.
        :rtype: str
        """
        return self._id

    @id.setter
    def id(self, id):
        """
        Sets the id of this ExternalListenerSummary.
        The `OCID`__ of the external listener.

        __ https://docs.cloud.oracle.com/Content/General/Concepts/identifiers.htm


        :param id: The id of this ExternalListenerSummary.
        :type: str
        """
        self._id = id

    @property
    def display_name(self):
        """
        **[Required]** Gets the display_name of this ExternalListenerSummary.
        The user-friendly name for the external listener. The name does not have to be unique.


        :return: The display_name of this ExternalListenerSummary.
        :rtype: str
        """
        return self._display_name

    @display_name.setter
    def display_name(self, display_name):
        """
        Sets the display_name of this ExternalListenerSummary.
        The user-friendly name for the external listener. The name does not have to be unique.


        :param display_name: The display_name of this ExternalListenerSummary.
        :type: str
        """
        self._display_name = display_name

    @property
    def component_name(self):
        """
        **[Required]** Gets the component_name of this ExternalListenerSummary.
        The name of the external listener.


        :return: The component_name of this ExternalListenerSummary.
        :rtype: str
        """
        return self._component_name

    @component_name.setter
    def component_name(self, component_name):
        """
        Sets the component_name of this ExternalListenerSummary.
        The name of the external listener.


        :param component_name: The component_name of this ExternalListenerSummary.
        :type: str
        """
        self._component_name = component_name

    @property
    def compartment_id(self):
        """
        **[Required]** Gets the compartment_id of this ExternalListenerSummary.
        The `OCID`__ of the compartment.

        __ https://docs.cloud.oracle.com/Content/General/Concepts/identifiers.htm


        :return: The compartment_id of this ExternalListenerSummary.
        :rtype: str
        """
        return self._compartment_id

    @compartment_id.setter
    def compartment_id(self, compartment_id):
        """
        Sets the compartment_id of this ExternalListenerSummary.
        The `OCID`__ of the compartment.

        __ https://docs.cloud.oracle.com/Content/General/Concepts/identifiers.htm


        :param compartment_id: The compartment_id of this ExternalListenerSummary.
        :type: str
        """
        self._compartment_id = compartment_id

    @property
    def external_db_system_id(self):
        """
        **[Required]** Gets the external_db_system_id of this ExternalListenerSummary.
        The `OCID`__ of the external DB system that the listener is a member of.

        __ https://docs.cloud.oracle.com/Content/General/Concepts/identifiers.htm


        :return: The external_db_system_id of this ExternalListenerSummary.
        :rtype: str
        """
        return self._external_db_system_id

    @external_db_system_id.setter
    def external_db_system_id(self, external_db_system_id):
        """
        Sets the external_db_system_id of this ExternalListenerSummary.
        The `OCID`__ of the external DB system that the listener is a member of.

        __ https://docs.cloud.oracle.com/Content/General/Concepts/identifiers.htm


        :param external_db_system_id: The external_db_system_id of this ExternalListenerSummary.
        :type: str
        """
        self._external_db_system_id = external_db_system_id

    @property
    def external_connector_id(self):
        """
        Gets the external_connector_id of this ExternalListenerSummary.
        The `OCID`__ of the external connector.

        __ https://docs.cloud.oracle.com/Content/General/Concepts/identifiers.htm


        :return: The external_connector_id of this ExternalListenerSummary.
        :rtype: str
        """
        return self._external_connector_id

    @external_connector_id.setter
    def external_connector_id(self, external_connector_id):
        """
        Sets the external_connector_id of this ExternalListenerSummary.
        The `OCID`__ of the external connector.

        __ https://docs.cloud.oracle.com/Content/General/Concepts/identifiers.htm


        :param external_connector_id: The external_connector_id of this ExternalListenerSummary.
        :type: str
        """
        self._external_connector_id = external_connector_id

    @property
    def external_db_node_id(self):
        """
        Gets the external_db_node_id of this ExternalListenerSummary.
        The `OCID`__ of the external DB node on which the listener is running.

        __ https://docs.cloud.oracle.com/Content/General/Concepts/identifiers.htm


        :return: The external_db_node_id of this ExternalListenerSummary.
        :rtype: str
        """
        return self._external_db_node_id

    @external_db_node_id.setter
    def external_db_node_id(self, external_db_node_id):
        """
        Sets the external_db_node_id of this ExternalListenerSummary.
        The `OCID`__ of the external DB node on which the listener is running.

        __ https://docs.cloud.oracle.com/Content/General/Concepts/identifiers.htm


        :param external_db_node_id: The external_db_node_id of this ExternalListenerSummary.
        :type: str
        """
        self._external_db_node_id = external_db_node_id

    @property
    def listener_type(self):
        """
        Gets the listener_type of this ExternalListenerSummary.
        The type of listener.


        :return: The listener_type of this ExternalListenerSummary.
        :rtype: str
        """
        return self._listener_type

    @listener_type.setter
    def listener_type(self, listener_type):
        """
        Sets the listener_type of this ExternalListenerSummary.
        The type of listener.


        :param listener_type: The listener_type of this ExternalListenerSummary.
        :type: str
        """
        self._listener_type = listener_type

    @property
    def lifecycle_state(self):
        """
        **[Required]** Gets the lifecycle_state of this ExternalListenerSummary.
        The current lifecycle state of the external listener.


        :return: The lifecycle_state of this ExternalListenerSummary.
        :rtype: str
        """
        return self._lifecycle_state

    @lifecycle_state.setter
    def lifecycle_state(self, lifecycle_state):
        """
        Sets the lifecycle_state of this ExternalListenerSummary.
        The current lifecycle state of the external listener.


        :param lifecycle_state: The lifecycle_state of this ExternalListenerSummary.
        :type: str
        """
        self._lifecycle_state = lifecycle_state

    @property
    def lifecycle_details(self):
        """
        Gets the lifecycle_details of this ExternalListenerSummary.
        Additional information about the current lifecycle state.


        :return: The lifecycle_details of this ExternalListenerSummary.
        :rtype: str
        """
        return self._lifecycle_details

    @lifecycle_details.setter
    def lifecycle_details(self, lifecycle_details):
        """
        Sets the lifecycle_details of this ExternalListenerSummary.
        Additional information about the current lifecycle state.


        :param lifecycle_details: The lifecycle_details of this ExternalListenerSummary.
        :type: str
        """
        self._lifecycle_details = lifecycle_details

    @property
    def time_created(self):
        """
        **[Required]** Gets the time_created of this ExternalListenerSummary.
        The date and time the external listener was created.


        :return: The time_created of this ExternalListenerSummary.
        :rtype: datetime
        """
        return self._time_created

    @time_created.setter
    def time_created(self, time_created):
        """
        Sets the time_created of this ExternalListenerSummary.
        The date and time the external listener was created.


        :param time_created: The time_created of this ExternalListenerSummary.
        :type: datetime
        """
        self._time_created = time_created

    @property
    def time_updated(self):
        """
        **[Required]** Gets the time_updated of this ExternalListenerSummary.
        The date and time the external listener was last updated.


        :return: The time_updated of this ExternalListenerSummary.
        :rtype: datetime
        """
        return self._time_updated

    @time_updated.setter
    def time_updated(self, time_updated):
        """
        Sets the time_updated of this ExternalListenerSummary.
        The date and time the external listener was last updated.


        :param time_updated: The time_updated of this ExternalListenerSummary.
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
