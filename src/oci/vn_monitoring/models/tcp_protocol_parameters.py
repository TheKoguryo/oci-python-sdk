# coding: utf-8
# Copyright (c) 2016, 2022, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

from .protocol_parameters import ProtocolParameters
from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class TcpProtocolParameters(ProtocolParameters):
    """
    Defines the configuration for TCP protocol parameters.
    """

    def __init__(self, **kwargs):
        """
        Initializes a new TcpProtocolParameters object with values from keyword arguments. The default value of the :py:attr:`~oci.vn_monitoring.models.TcpProtocolParameters.type` attribute
        of this class is ``TCP`` and it should not be changed.
        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param type:
            The value to assign to the type property of this TcpProtocolParameters.
            Allowed values for this property are: "TCP", "UDP", "ICMP"
        :type type: str

        :param source_port:
            The value to assign to the source_port property of this TcpProtocolParameters.
        :type source_port: int

        :param destination_port:
            The value to assign to the destination_port property of this TcpProtocolParameters.
        :type destination_port: int

        """
        self.swagger_types = {
            'type': 'str',
            'source_port': 'int',
            'destination_port': 'int'
        }

        self.attribute_map = {
            'type': 'type',
            'source_port': 'sourcePort',
            'destination_port': 'destinationPort'
        }

        self._type = None
        self._source_port = None
        self._destination_port = None
        self._type = 'TCP'

    @property
    def source_port(self):
        """
        Gets the source_port of this TcpProtocolParameters.
        The source port to use in a `PathAnalyzerTest` resource.


        :return: The source_port of this TcpProtocolParameters.
        :rtype: int
        """
        return self._source_port

    @source_port.setter
    def source_port(self, source_port):
        """
        Sets the source_port of this TcpProtocolParameters.
        The source port to use in a `PathAnalyzerTest` resource.


        :param source_port: The source_port of this TcpProtocolParameters.
        :type: int
        """
        self._source_port = source_port

    @property
    def destination_port(self):
        """
        **[Required]** Gets the destination_port of this TcpProtocolParameters.
        The destination port to use in a `PathAnalyzerTest` resource.


        :return: The destination_port of this TcpProtocolParameters.
        :rtype: int
        """
        return self._destination_port

    @destination_port.setter
    def destination_port(self, destination_port):
        """
        Sets the destination_port of this TcpProtocolParameters.
        The destination port to use in a `PathAnalyzerTest` resource.


        :param destination_port: The destination_port of this TcpProtocolParameters.
        :type: int
        """
        self._destination_port = destination_port

    def __repr__(self):
        return formatted_flat_dict(self)

    def __eq__(self, other):
        if other is None:
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not self == other