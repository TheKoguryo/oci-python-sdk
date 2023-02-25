# coding: utf-8
# Copyright (c) 2016, 2023, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.


from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class ExternalClusterScanListenerConfiguration(object):
    """
    The details of a SCAN listener in an external cluster.
    """

    #: A constant which can be used with the scan_protocol property of a ExternalClusterScanListenerConfiguration.
    #: This constant has a value of "TCP"
    SCAN_PROTOCOL_TCP = "TCP"

    #: A constant which can be used with the scan_protocol property of a ExternalClusterScanListenerConfiguration.
    #: This constant has a value of "TCPS"
    SCAN_PROTOCOL_TCPS = "TCPS"

    def __init__(self, **kwargs):
        """
        Initializes a new ExternalClusterScanListenerConfiguration object with values from keyword arguments.
        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param scan_name:
            The value to assign to the scan_name property of this ExternalClusterScanListenerConfiguration.
        :type scan_name: str

        :param network_number:
            The value to assign to the network_number property of this ExternalClusterScanListenerConfiguration.
        :type network_number: int

        :param scan_port:
            The value to assign to the scan_port property of this ExternalClusterScanListenerConfiguration.
        :type scan_port: int

        :param scan_protocol:
            The value to assign to the scan_protocol property of this ExternalClusterScanListenerConfiguration.
            Allowed values for this property are: "TCP", "TCPS", 'UNKNOWN_ENUM_VALUE'.
            Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.
        :type scan_protocol: str

        """
        self.swagger_types = {
            'scan_name': 'str',
            'network_number': 'int',
            'scan_port': 'int',
            'scan_protocol': 'str'
        }

        self.attribute_map = {
            'scan_name': 'scanName',
            'network_number': 'networkNumber',
            'scan_port': 'scanPort',
            'scan_protocol': 'scanProtocol'
        }

        self._scan_name = None
        self._network_number = None
        self._scan_port = None
        self._scan_protocol = None

    @property
    def scan_name(self):
        """
        Gets the scan_name of this ExternalClusterScanListenerConfiguration.
        The name of the SCAN listener.


        :return: The scan_name of this ExternalClusterScanListenerConfiguration.
        :rtype: str
        """
        return self._scan_name

    @scan_name.setter
    def scan_name(self, scan_name):
        """
        Sets the scan_name of this ExternalClusterScanListenerConfiguration.
        The name of the SCAN listener.


        :param scan_name: The scan_name of this ExternalClusterScanListenerConfiguration.
        :type: str
        """
        self._scan_name = scan_name

    @property
    def network_number(self):
        """
        Gets the network_number of this ExternalClusterScanListenerConfiguration.
        The network number from which SCAN VIPs are obtained.


        :return: The network_number of this ExternalClusterScanListenerConfiguration.
        :rtype: int
        """
        return self._network_number

    @network_number.setter
    def network_number(self, network_number):
        """
        Sets the network_number of this ExternalClusterScanListenerConfiguration.
        The network number from which SCAN VIPs are obtained.


        :param network_number: The network_number of this ExternalClusterScanListenerConfiguration.
        :type: int
        """
        self._network_number = network_number

    @property
    def scan_port(self):
        """
        Gets the scan_port of this ExternalClusterScanListenerConfiguration.
        The port number of the SCAN listener.


        :return: The scan_port of this ExternalClusterScanListenerConfiguration.
        :rtype: int
        """
        return self._scan_port

    @scan_port.setter
    def scan_port(self, scan_port):
        """
        Sets the scan_port of this ExternalClusterScanListenerConfiguration.
        The port number of the SCAN listener.


        :param scan_port: The scan_port of this ExternalClusterScanListenerConfiguration.
        :type: int
        """
        self._scan_port = scan_port

    @property
    def scan_protocol(self):
        """
        Gets the scan_protocol of this ExternalClusterScanListenerConfiguration.
        The protocol of the SCAN listener.

        Allowed values for this property are: "TCP", "TCPS", 'UNKNOWN_ENUM_VALUE'.
        Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.


        :return: The scan_protocol of this ExternalClusterScanListenerConfiguration.
        :rtype: str
        """
        return self._scan_protocol

    @scan_protocol.setter
    def scan_protocol(self, scan_protocol):
        """
        Sets the scan_protocol of this ExternalClusterScanListenerConfiguration.
        The protocol of the SCAN listener.


        :param scan_protocol: The scan_protocol of this ExternalClusterScanListenerConfiguration.
        :type: str
        """
        allowed_values = ["TCP", "TCPS"]
        if not value_allowed_none_or_none_sentinel(scan_protocol, allowed_values):
            scan_protocol = 'UNKNOWN_ENUM_VALUE'
        self._scan_protocol = scan_protocol

    def __repr__(self):
        return formatted_flat_dict(self)

    def __eq__(self, other):
        if other is None:
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not self == other
