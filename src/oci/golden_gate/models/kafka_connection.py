# coding: utf-8
# Copyright (c) 2016, 2023, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

from .connection import Connection
from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class KafkaConnection(Connection):
    """
    Represents the metadata of a Kafka Connection.
    """

    #: A constant which can be used with the technology_type property of a KafkaConnection.
    #: This constant has a value of "APACHE_KAFKA"
    TECHNOLOGY_TYPE_APACHE_KAFKA = "APACHE_KAFKA"

    #: A constant which can be used with the technology_type property of a KafkaConnection.
    #: This constant has a value of "AZURE_EVENT_HUBS"
    TECHNOLOGY_TYPE_AZURE_EVENT_HUBS = "AZURE_EVENT_HUBS"

    #: A constant which can be used with the technology_type property of a KafkaConnection.
    #: This constant has a value of "CONFLUENT_KAFKA"
    TECHNOLOGY_TYPE_CONFLUENT_KAFKA = "CONFLUENT_KAFKA"

    #: A constant which can be used with the technology_type property of a KafkaConnection.
    #: This constant has a value of "OCI_STREAMING"
    TECHNOLOGY_TYPE_OCI_STREAMING = "OCI_STREAMING"

    #: A constant which can be used with the security_protocol property of a KafkaConnection.
    #: This constant has a value of "SSL"
    SECURITY_PROTOCOL_SSL = "SSL"

    #: A constant which can be used with the security_protocol property of a KafkaConnection.
    #: This constant has a value of "SASL_SSL"
    SECURITY_PROTOCOL_SASL_SSL = "SASL_SSL"

    #: A constant which can be used with the security_protocol property of a KafkaConnection.
    #: This constant has a value of "PLAINTEXT"
    SECURITY_PROTOCOL_PLAINTEXT = "PLAINTEXT"

    #: A constant which can be used with the security_protocol property of a KafkaConnection.
    #: This constant has a value of "SASL_PLAINTEXT"
    SECURITY_PROTOCOL_SASL_PLAINTEXT = "SASL_PLAINTEXT"

    def __init__(self, **kwargs):
        """
        Initializes a new KafkaConnection object with values from keyword arguments. The default value of the :py:attr:`~oci.golden_gate.models.KafkaConnection.connection_type` attribute
        of this class is ``KAFKA`` and it should not be changed.
        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param connection_type:
            The value to assign to the connection_type property of this KafkaConnection.
            Allowed values for this property are: "GOLDENGATE", "KAFKA", "KAFKA_SCHEMA_REGISTRY", "MYSQL", "OCI_OBJECT_STORAGE", "ORACLE", "AZURE_DATA_LAKE_STORAGE", "POSTGRESQL", "AZURE_SYNAPSE_ANALYTICS", 'UNKNOWN_ENUM_VALUE'.
            Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.
        :type connection_type: str

        :param id:
            The value to assign to the id property of this KafkaConnection.
        :type id: str

        :param display_name:
            The value to assign to the display_name property of this KafkaConnection.
        :type display_name: str

        :param description:
            The value to assign to the description property of this KafkaConnection.
        :type description: str

        :param compartment_id:
            The value to assign to the compartment_id property of this KafkaConnection.
        :type compartment_id: str

        :param freeform_tags:
            The value to assign to the freeform_tags property of this KafkaConnection.
        :type freeform_tags: dict(str, str)

        :param defined_tags:
            The value to assign to the defined_tags property of this KafkaConnection.
        :type defined_tags: dict(str, dict(str, object))

        :param system_tags:
            The value to assign to the system_tags property of this KafkaConnection.
        :type system_tags: dict(str, dict(str, object))

        :param lifecycle_state:
            The value to assign to the lifecycle_state property of this KafkaConnection.
            Allowed values for this property are: "CREATING", "UPDATING", "ACTIVE", "DELETING", "DELETED", "FAILED", 'UNKNOWN_ENUM_VALUE'.
            Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.
        :type lifecycle_state: str

        :param lifecycle_details:
            The value to assign to the lifecycle_details property of this KafkaConnection.
        :type lifecycle_details: str

        :param time_created:
            The value to assign to the time_created property of this KafkaConnection.
        :type time_created: datetime

        :param time_updated:
            The value to assign to the time_updated property of this KafkaConnection.
        :type time_updated: datetime

        :param vault_id:
            The value to assign to the vault_id property of this KafkaConnection.
        :type vault_id: str

        :param key_id:
            The value to assign to the key_id property of this KafkaConnection.
        :type key_id: str

        :param subnet_id:
            The value to assign to the subnet_id property of this KafkaConnection.
        :type subnet_id: str

        :param ingress_ips:
            The value to assign to the ingress_ips property of this KafkaConnection.
        :type ingress_ips: list[oci.golden_gate.models.IngressIpDetails]

        :param nsg_ids:
            The value to assign to the nsg_ids property of this KafkaConnection.
        :type nsg_ids: list[str]

        :param technology_type:
            The value to assign to the technology_type property of this KafkaConnection.
            Allowed values for this property are: "APACHE_KAFKA", "AZURE_EVENT_HUBS", "CONFLUENT_KAFKA", "OCI_STREAMING", 'UNKNOWN_ENUM_VALUE'.
            Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.
        :type technology_type: str

        :param stream_pool_id:
            The value to assign to the stream_pool_id property of this KafkaConnection.
        :type stream_pool_id: str

        :param bootstrap_servers:
            The value to assign to the bootstrap_servers property of this KafkaConnection.
        :type bootstrap_servers: list[oci.golden_gate.models.KafkaBootstrapServer]

        :param security_protocol:
            The value to assign to the security_protocol property of this KafkaConnection.
            Allowed values for this property are: "SSL", "SASL_SSL", "PLAINTEXT", "SASL_PLAINTEXT", 'UNKNOWN_ENUM_VALUE'.
            Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.
        :type security_protocol: str

        :param username:
            The value to assign to the username property of this KafkaConnection.
        :type username: str

        """
        self.swagger_types = {
            'connection_type': 'str',
            'id': 'str',
            'display_name': 'str',
            'description': 'str',
            'compartment_id': 'str',
            'freeform_tags': 'dict(str, str)',
            'defined_tags': 'dict(str, dict(str, object))',
            'system_tags': 'dict(str, dict(str, object))',
            'lifecycle_state': 'str',
            'lifecycle_details': 'str',
            'time_created': 'datetime',
            'time_updated': 'datetime',
            'vault_id': 'str',
            'key_id': 'str',
            'subnet_id': 'str',
            'ingress_ips': 'list[IngressIpDetails]',
            'nsg_ids': 'list[str]',
            'technology_type': 'str',
            'stream_pool_id': 'str',
            'bootstrap_servers': 'list[KafkaBootstrapServer]',
            'security_protocol': 'str',
            'username': 'str'
        }

        self.attribute_map = {
            'connection_type': 'connectionType',
            'id': 'id',
            'display_name': 'displayName',
            'description': 'description',
            'compartment_id': 'compartmentId',
            'freeform_tags': 'freeformTags',
            'defined_tags': 'definedTags',
            'system_tags': 'systemTags',
            'lifecycle_state': 'lifecycleState',
            'lifecycle_details': 'lifecycleDetails',
            'time_created': 'timeCreated',
            'time_updated': 'timeUpdated',
            'vault_id': 'vaultId',
            'key_id': 'keyId',
            'subnet_id': 'subnetId',
            'ingress_ips': 'ingressIps',
            'nsg_ids': 'nsgIds',
            'technology_type': 'technologyType',
            'stream_pool_id': 'streamPoolId',
            'bootstrap_servers': 'bootstrapServers',
            'security_protocol': 'securityProtocol',
            'username': 'username'
        }

        self._connection_type = None
        self._id = None
        self._display_name = None
        self._description = None
        self._compartment_id = None
        self._freeform_tags = None
        self._defined_tags = None
        self._system_tags = None
        self._lifecycle_state = None
        self._lifecycle_details = None
        self._time_created = None
        self._time_updated = None
        self._vault_id = None
        self._key_id = None
        self._subnet_id = None
        self._ingress_ips = None
        self._nsg_ids = None
        self._technology_type = None
        self._stream_pool_id = None
        self._bootstrap_servers = None
        self._security_protocol = None
        self._username = None
        self._connection_type = 'KAFKA'

    @property
    def technology_type(self):
        """
        **[Required]** Gets the technology_type of this KafkaConnection.
        The Kafka technology type.

        Allowed values for this property are: "APACHE_KAFKA", "AZURE_EVENT_HUBS", "CONFLUENT_KAFKA", "OCI_STREAMING", 'UNKNOWN_ENUM_VALUE'.
        Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.


        :return: The technology_type of this KafkaConnection.
        :rtype: str
        """
        return self._technology_type

    @technology_type.setter
    def technology_type(self, technology_type):
        """
        Sets the technology_type of this KafkaConnection.
        The Kafka technology type.


        :param technology_type: The technology_type of this KafkaConnection.
        :type: str
        """
        allowed_values = ["APACHE_KAFKA", "AZURE_EVENT_HUBS", "CONFLUENT_KAFKA", "OCI_STREAMING"]
        if not value_allowed_none_or_none_sentinel(technology_type, allowed_values):
            technology_type = 'UNKNOWN_ENUM_VALUE'
        self._technology_type = technology_type

    @property
    def stream_pool_id(self):
        """
        Gets the stream_pool_id of this KafkaConnection.
        The `OCID`__ of the stream pool being referenced.

        __ https://docs.cloud.oracle.com/Content/General/Concepts/identifiers.htm


        :return: The stream_pool_id of this KafkaConnection.
        :rtype: str
        """
        return self._stream_pool_id

    @stream_pool_id.setter
    def stream_pool_id(self, stream_pool_id):
        """
        Sets the stream_pool_id of this KafkaConnection.
        The `OCID`__ of the stream pool being referenced.

        __ https://docs.cloud.oracle.com/Content/General/Concepts/identifiers.htm


        :param stream_pool_id: The stream_pool_id of this KafkaConnection.
        :type: str
        """
        self._stream_pool_id = stream_pool_id

    @property
    def bootstrap_servers(self):
        """
        Gets the bootstrap_servers of this KafkaConnection.
        Kafka bootstrap. Equivalent of bootstrap.servers configuration property in Kafka:
        list of KafkaBootstrapServer objects specified by host/port.
        Used for establishing the initial connection to the Kafka cluster.
        Example: `\"server1.example.com:9092,server2.example.com:9092\"`


        :return: The bootstrap_servers of this KafkaConnection.
        :rtype: list[oci.golden_gate.models.KafkaBootstrapServer]
        """
        return self._bootstrap_servers

    @bootstrap_servers.setter
    def bootstrap_servers(self, bootstrap_servers):
        """
        Sets the bootstrap_servers of this KafkaConnection.
        Kafka bootstrap. Equivalent of bootstrap.servers configuration property in Kafka:
        list of KafkaBootstrapServer objects specified by host/port.
        Used for establishing the initial connection to the Kafka cluster.
        Example: `\"server1.example.com:9092,server2.example.com:9092\"`


        :param bootstrap_servers: The bootstrap_servers of this KafkaConnection.
        :type: list[oci.golden_gate.models.KafkaBootstrapServer]
        """
        self._bootstrap_servers = bootstrap_servers

    @property
    def security_protocol(self):
        """
        Gets the security_protocol of this KafkaConnection.
        Kafka security protocol.

        Allowed values for this property are: "SSL", "SASL_SSL", "PLAINTEXT", "SASL_PLAINTEXT", 'UNKNOWN_ENUM_VALUE'.
        Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.


        :return: The security_protocol of this KafkaConnection.
        :rtype: str
        """
        return self._security_protocol

    @security_protocol.setter
    def security_protocol(self, security_protocol):
        """
        Sets the security_protocol of this KafkaConnection.
        Kafka security protocol.


        :param security_protocol: The security_protocol of this KafkaConnection.
        :type: str
        """
        allowed_values = ["SSL", "SASL_SSL", "PLAINTEXT", "SASL_PLAINTEXT"]
        if not value_allowed_none_or_none_sentinel(security_protocol, allowed_values):
            security_protocol = 'UNKNOWN_ENUM_VALUE'
        self._security_protocol = security_protocol

    @property
    def username(self):
        """
        Gets the username of this KafkaConnection.
        The username Oracle GoldenGate uses to connect the associated RDBMS.  This username must
        already exist and be available for use by the database.  It must conform to the security
        requirements implemented by the database including length, case sensitivity, and so on.


        :return: The username of this KafkaConnection.
        :rtype: str
        """
        return self._username

    @username.setter
    def username(self, username):
        """
        Sets the username of this KafkaConnection.
        The username Oracle GoldenGate uses to connect the associated RDBMS.  This username must
        already exist and be available for use by the database.  It must conform to the security
        requirements implemented by the database including length, case sensitivity, and so on.


        :param username: The username of this KafkaConnection.
        :type: str
        """
        self._username = username

    def __repr__(self):
        return formatted_flat_dict(self)

    def __eq__(self, other):
        if other is None:
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not self == other
