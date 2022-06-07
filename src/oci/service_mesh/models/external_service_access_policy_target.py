# coding: utf-8
# Copyright (c) 2016, 2022, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

from .access_policy_target import AccessPolicyTarget
from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class ExternalServiceAccessPolicyTarget(AccessPolicyTarget):
    """
    External service target that internal virtual services direct traffic to.
    """

    #: A constant which can be used with the protocol property of a ExternalServiceAccessPolicyTarget.
    #: This constant has a value of "HTTP"
    PROTOCOL_HTTP = "HTTP"

    #: A constant which can be used with the protocol property of a ExternalServiceAccessPolicyTarget.
    #: This constant has a value of "HTTPS"
    PROTOCOL_HTTPS = "HTTPS"

    #: A constant which can be used with the protocol property of a ExternalServiceAccessPolicyTarget.
    #: This constant has a value of "TCP"
    PROTOCOL_TCP = "TCP"

    def __init__(self, **kwargs):
        """
        Initializes a new ExternalServiceAccessPolicyTarget object with values from keyword arguments. The default value of the :py:attr:`~oci.service_mesh.models.ExternalServiceAccessPolicyTarget.type` attribute
        of this class is ``EXTERNAL_SERVICE`` and it should not be changed.
        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param type:
            The value to assign to the type property of this ExternalServiceAccessPolicyTarget.
            Allowed values for this property are: "ALL_VIRTUAL_SERVICES", "VIRTUAL_SERVICE", "EXTERNAL_SERVICE", "INGRESS_GATEWAY", 'UNKNOWN_ENUM_VALUE'.
            Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.
        :type type: str

        :param hostnames:
            The value to assign to the hostnames property of this ExternalServiceAccessPolicyTarget.
        :type hostnames: list[str]

        :param ip_addresses:
            The value to assign to the ip_addresses property of this ExternalServiceAccessPolicyTarget.
        :type ip_addresses: list[str]

        :param ports:
            The value to assign to the ports property of this ExternalServiceAccessPolicyTarget.
        :type ports: list[int]

        :param protocol:
            The value to assign to the protocol property of this ExternalServiceAccessPolicyTarget.
            Allowed values for this property are: "HTTP", "HTTPS", "TCP", 'UNKNOWN_ENUM_VALUE'.
            Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.
        :type protocol: str

        """
        self.swagger_types = {
            'type': 'str',
            'hostnames': 'list[str]',
            'ip_addresses': 'list[str]',
            'ports': 'list[int]',
            'protocol': 'str'
        }

        self.attribute_map = {
            'type': 'type',
            'hostnames': 'hostnames',
            'ip_addresses': 'ipAddresses',
            'ports': 'ports',
            'protocol': 'protocol'
        }

        self._type = None
        self._hostnames = None
        self._ip_addresses = None
        self._ports = None
        self._protocol = None
        self._type = 'EXTERNAL_SERVICE'

    @property
    def hostnames(self):
        """
        Gets the hostnames of this ExternalServiceAccessPolicyTarget.
        The hostnames of the external service. Only applicable for HTTP and HTTPS protocols.
        Wildcard hostnames are supported in the prefix form.
        Examples of valid hostnames are \"www.example.com\", \"*.example.com\", \"*.com\", \"*\".
        Hostname \"*\" can be used to allow all hosts.


        :return: The hostnames of this ExternalServiceAccessPolicyTarget.
        :rtype: list[str]
        """
        return self._hostnames

    @hostnames.setter
    def hostnames(self, hostnames):
        """
        Sets the hostnames of this ExternalServiceAccessPolicyTarget.
        The hostnames of the external service. Only applicable for HTTP and HTTPS protocols.
        Wildcard hostnames are supported in the prefix form.
        Examples of valid hostnames are \"www.example.com\", \"*.example.com\", \"*.com\", \"*\".
        Hostname \"*\" can be used to allow all hosts.


        :param hostnames: The hostnames of this ExternalServiceAccessPolicyTarget.
        :type: list[str]
        """
        self._hostnames = hostnames

    @property
    def ip_addresses(self):
        """
        Gets the ip_addresses of this ExternalServiceAccessPolicyTarget.
        The ipAddresses of the external service in CIDR notation. Only applicable for TCP protocol.
        All requests matching the given CIDR notation will pass through.
        In case a wildcard CIDR \"0.0.0.0/0\" is provided, the same port cannot be used for a virtual service communication.


        :return: The ip_addresses of this ExternalServiceAccessPolicyTarget.
        :rtype: list[str]
        """
        return self._ip_addresses

    @ip_addresses.setter
    def ip_addresses(self, ip_addresses):
        """
        Sets the ip_addresses of this ExternalServiceAccessPolicyTarget.
        The ipAddresses of the external service in CIDR notation. Only applicable for TCP protocol.
        All requests matching the given CIDR notation will pass through.
        In case a wildcard CIDR \"0.0.0.0/0\" is provided, the same port cannot be used for a virtual service communication.


        :param ip_addresses: The ip_addresses of this ExternalServiceAccessPolicyTarget.
        :type: list[str]
        """
        self._ip_addresses = ip_addresses

    @property
    def ports(self):
        """
        Gets the ports of this ExternalServiceAccessPolicyTarget.
        Ports exposed by an external service. If left empty all ports will be allowed.


        :return: The ports of this ExternalServiceAccessPolicyTarget.
        :rtype: list[int]
        """
        return self._ports

    @ports.setter
    def ports(self, ports):
        """
        Sets the ports of this ExternalServiceAccessPolicyTarget.
        Ports exposed by an external service. If left empty all ports will be allowed.


        :param ports: The ports of this ExternalServiceAccessPolicyTarget.
        :type: list[int]
        """
        self._ports = ports

    @property
    def protocol(self):
        """
        Gets the protocol of this ExternalServiceAccessPolicyTarget.
        Protocol of the external service

        Allowed values for this property are: "HTTP", "HTTPS", "TCP", 'UNKNOWN_ENUM_VALUE'.
        Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.


        :return: The protocol of this ExternalServiceAccessPolicyTarget.
        :rtype: str
        """
        return self._protocol

    @protocol.setter
    def protocol(self, protocol):
        """
        Sets the protocol of this ExternalServiceAccessPolicyTarget.
        Protocol of the external service


        :param protocol: The protocol of this ExternalServiceAccessPolicyTarget.
        :type: str
        """
        allowed_values = ["HTTP", "HTTPS", "TCP"]
        if not value_allowed_none_or_none_sentinel(protocol, allowed_values):
            protocol = 'UNKNOWN_ENUM_VALUE'
        self._protocol = protocol

    def __repr__(self):
        return formatted_flat_dict(self)

    def __eq__(self, other):
        if other is None:
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not self == other