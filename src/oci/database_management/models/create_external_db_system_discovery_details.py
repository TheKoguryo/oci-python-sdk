# coding: utf-8
# Copyright (c) 2016, 2023, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.


from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class CreateExternalDbSystemDiscoveryDetails(object):
    """
    The details required to create an external DB system discovery resource.
    """

    def __init__(self, **kwargs):
        """
        Initializes a new CreateExternalDbSystemDiscoveryDetails object with values from keyword arguments.
        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param display_name:
            The value to assign to the display_name property of this CreateExternalDbSystemDiscoveryDetails.
        :type display_name: str

        :param agent_id:
            The value to assign to the agent_id property of this CreateExternalDbSystemDiscoveryDetails.
        :type agent_id: str

        :param compartment_id:
            The value to assign to the compartment_id property of this CreateExternalDbSystemDiscoveryDetails.
        :type compartment_id: str

        """
        self.swagger_types = {
            'display_name': 'str',
            'agent_id': 'str',
            'compartment_id': 'str'
        }

        self.attribute_map = {
            'display_name': 'displayName',
            'agent_id': 'agentId',
            'compartment_id': 'compartmentId'
        }

        self._display_name = None
        self._agent_id = None
        self._compartment_id = None

    @property
    def display_name(self):
        """
        Gets the display_name of this CreateExternalDbSystemDiscoveryDetails.
        The user-friendly name for the DB system. The name does not have to be unique.


        :return: The display_name of this CreateExternalDbSystemDiscoveryDetails.
        :rtype: str
        """
        return self._display_name

    @display_name.setter
    def display_name(self, display_name):
        """
        Sets the display_name of this CreateExternalDbSystemDiscoveryDetails.
        The user-friendly name for the DB system. The name does not have to be unique.


        :param display_name: The display_name of this CreateExternalDbSystemDiscoveryDetails.
        :type: str
        """
        self._display_name = display_name

    @property
    def agent_id(self):
        """
        **[Required]** Gets the agent_id of this CreateExternalDbSystemDiscoveryDetails.
        The `OCID`__ of the management agent
        used for the external DB system discovery.

        __ https://docs.cloud.oracle.com/Content/General/Concepts/identifiers.htm


        :return: The agent_id of this CreateExternalDbSystemDiscoveryDetails.
        :rtype: str
        """
        return self._agent_id

    @agent_id.setter
    def agent_id(self, agent_id):
        """
        Sets the agent_id of this CreateExternalDbSystemDiscoveryDetails.
        The `OCID`__ of the management agent
        used for the external DB system discovery.

        __ https://docs.cloud.oracle.com/Content/General/Concepts/identifiers.htm


        :param agent_id: The agent_id of this CreateExternalDbSystemDiscoveryDetails.
        :type: str
        """
        self._agent_id = agent_id

    @property
    def compartment_id(self):
        """
        **[Required]** Gets the compartment_id of this CreateExternalDbSystemDiscoveryDetails.
        The `OCID`__ of the compartment in which the external DB system resides.

        __ https://docs.cloud.oracle.com/Content/General/Concepts/identifiers.htm


        :return: The compartment_id of this CreateExternalDbSystemDiscoveryDetails.
        :rtype: str
        """
        return self._compartment_id

    @compartment_id.setter
    def compartment_id(self, compartment_id):
        """
        Sets the compartment_id of this CreateExternalDbSystemDiscoveryDetails.
        The `OCID`__ of the compartment in which the external DB system resides.

        __ https://docs.cloud.oracle.com/Content/General/Concepts/identifiers.htm


        :param compartment_id: The compartment_id of this CreateExternalDbSystemDiscoveryDetails.
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
