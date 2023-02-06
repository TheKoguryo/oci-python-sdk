# coding: utf-8
# Copyright (c) 2016, 2023, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.


from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class HttpMonitor(object):
    """
    This model contains all of the mutable and immutable properties for an HTTP monitor.
    """

    #: A constant which can be used with the protocol property of a HttpMonitor.
    #: This constant has a value of "HTTP"
    PROTOCOL_HTTP = "HTTP"

    #: A constant which can be used with the protocol property of a HttpMonitor.
    #: This constant has a value of "HTTPS"
    PROTOCOL_HTTPS = "HTTPS"

    #: A constant which can be used with the method property of a HttpMonitor.
    #: This constant has a value of "GET"
    METHOD_GET = "GET"

    #: A constant which can be used with the method property of a HttpMonitor.
    #: This constant has a value of "HEAD"
    METHOD_HEAD = "HEAD"

    def __init__(self, **kwargs):
        """
        Initializes a new HttpMonitor object with values from keyword arguments.
        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param id:
            The value to assign to the id property of this HttpMonitor.
        :type id: str

        :param results_url:
            The value to assign to the results_url property of this HttpMonitor.
        :type results_url: str

        :param home_region:
            The value to assign to the home_region property of this HttpMonitor.
        :type home_region: str

        :param time_created:
            The value to assign to the time_created property of this HttpMonitor.
        :type time_created: datetime

        :param compartment_id:
            The value to assign to the compartment_id property of this HttpMonitor.
        :type compartment_id: str

        :param targets:
            The value to assign to the targets property of this HttpMonitor.
        :type targets: list[str]

        :param vantage_point_names:
            The value to assign to the vantage_point_names property of this HttpMonitor.
        :type vantage_point_names: list[str]

        :param port:
            The value to assign to the port property of this HttpMonitor.
        :type port: int

        :param timeout_in_seconds:
            The value to assign to the timeout_in_seconds property of this HttpMonitor.
        :type timeout_in_seconds: int

        :param protocol:
            The value to assign to the protocol property of this HttpMonitor.
            Allowed values for this property are: "HTTP", "HTTPS", 'UNKNOWN_ENUM_VALUE'.
            Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.
        :type protocol: str

        :param method:
            The value to assign to the method property of this HttpMonitor.
            Allowed values for this property are: "GET", "HEAD", 'UNKNOWN_ENUM_VALUE'.
            Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.
        :type method: str

        :param path:
            The value to assign to the path property of this HttpMonitor.
        :type path: str

        :param headers:
            The value to assign to the headers property of this HttpMonitor.
        :type headers: dict(str, str)

        :param display_name:
            The value to assign to the display_name property of this HttpMonitor.
        :type display_name: str

        :param interval_in_seconds:
            The value to assign to the interval_in_seconds property of this HttpMonitor.
        :type interval_in_seconds: int

        :param is_enabled:
            The value to assign to the is_enabled property of this HttpMonitor.
        :type is_enabled: bool

        :param freeform_tags:
            The value to assign to the freeform_tags property of this HttpMonitor.
        :type freeform_tags: dict(str, str)

        :param defined_tags:
            The value to assign to the defined_tags property of this HttpMonitor.
        :type defined_tags: dict(str, dict(str, object))

        """
        self.swagger_types = {
            'id': 'str',
            'results_url': 'str',
            'home_region': 'str',
            'time_created': 'datetime',
            'compartment_id': 'str',
            'targets': 'list[str]',
            'vantage_point_names': 'list[str]',
            'port': 'int',
            'timeout_in_seconds': 'int',
            'protocol': 'str',
            'method': 'str',
            'path': 'str',
            'headers': 'dict(str, str)',
            'display_name': 'str',
            'interval_in_seconds': 'int',
            'is_enabled': 'bool',
            'freeform_tags': 'dict(str, str)',
            'defined_tags': 'dict(str, dict(str, object))'
        }

        self.attribute_map = {
            'id': 'id',
            'results_url': 'resultsUrl',
            'home_region': 'homeRegion',
            'time_created': 'timeCreated',
            'compartment_id': 'compartmentId',
            'targets': 'targets',
            'vantage_point_names': 'vantagePointNames',
            'port': 'port',
            'timeout_in_seconds': 'timeoutInSeconds',
            'protocol': 'protocol',
            'method': 'method',
            'path': 'path',
            'headers': 'headers',
            'display_name': 'displayName',
            'interval_in_seconds': 'intervalInSeconds',
            'is_enabled': 'isEnabled',
            'freeform_tags': 'freeformTags',
            'defined_tags': 'definedTags'
        }

        self._id = None
        self._results_url = None
        self._home_region = None
        self._time_created = None
        self._compartment_id = None
        self._targets = None
        self._vantage_point_names = None
        self._port = None
        self._timeout_in_seconds = None
        self._protocol = None
        self._method = None
        self._path = None
        self._headers = None
        self._display_name = None
        self._interval_in_seconds = None
        self._is_enabled = None
        self._freeform_tags = None
        self._defined_tags = None

    @property
    def id(self):
        """
        Gets the id of this HttpMonitor.
        The OCID of the resource.


        :return: The id of this HttpMonitor.
        :rtype: str
        """
        return self._id

    @id.setter
    def id(self, id):
        """
        Sets the id of this HttpMonitor.
        The OCID of the resource.


        :param id: The id of this HttpMonitor.
        :type: str
        """
        self._id = id

    @property
    def results_url(self):
        """
        Gets the results_url of this HttpMonitor.
        A URL for fetching the probe results.


        :return: The results_url of this HttpMonitor.
        :rtype: str
        """
        return self._results_url

    @results_url.setter
    def results_url(self, results_url):
        """
        Sets the results_url of this HttpMonitor.
        A URL for fetching the probe results.


        :param results_url: The results_url of this HttpMonitor.
        :type: str
        """
        self._results_url = results_url

    @property
    def home_region(self):
        """
        Gets the home_region of this HttpMonitor.
        The region where updates must be made and where results must be fetched from.


        :return: The home_region of this HttpMonitor.
        :rtype: str
        """
        return self._home_region

    @home_region.setter
    def home_region(self, home_region):
        """
        Sets the home_region of this HttpMonitor.
        The region where updates must be made and where results must be fetched from.


        :param home_region: The home_region of this HttpMonitor.
        :type: str
        """
        self._home_region = home_region

    @property
    def time_created(self):
        """
        Gets the time_created of this HttpMonitor.
        The RFC 3339-formatted creation date and time of the probe.


        :return: The time_created of this HttpMonitor.
        :rtype: datetime
        """
        return self._time_created

    @time_created.setter
    def time_created(self, time_created):
        """
        Sets the time_created of this HttpMonitor.
        The RFC 3339-formatted creation date and time of the probe.


        :param time_created: The time_created of this HttpMonitor.
        :type: datetime
        """
        self._time_created = time_created

    @property
    def compartment_id(self):
        """
        Gets the compartment_id of this HttpMonitor.
        The OCID of the compartment.


        :return: The compartment_id of this HttpMonitor.
        :rtype: str
        """
        return self._compartment_id

    @compartment_id.setter
    def compartment_id(self, compartment_id):
        """
        Sets the compartment_id of this HttpMonitor.
        The OCID of the compartment.


        :param compartment_id: The compartment_id of this HttpMonitor.
        :type: str
        """
        self._compartment_id = compartment_id

    @property
    def targets(self):
        """
        Gets the targets of this HttpMonitor.
        A list of targets (hostnames or IP addresses) of the probe.


        :return: The targets of this HttpMonitor.
        :rtype: list[str]
        """
        return self._targets

    @targets.setter
    def targets(self, targets):
        """
        Sets the targets of this HttpMonitor.
        A list of targets (hostnames or IP addresses) of the probe.


        :param targets: The targets of this HttpMonitor.
        :type: list[str]
        """
        self._targets = targets

    @property
    def vantage_point_names(self):
        """
        Gets the vantage_point_names of this HttpMonitor.
        A list of names of vantage points from which to execute the probe.


        :return: The vantage_point_names of this HttpMonitor.
        :rtype: list[str]
        """
        return self._vantage_point_names

    @vantage_point_names.setter
    def vantage_point_names(self, vantage_point_names):
        """
        Sets the vantage_point_names of this HttpMonitor.
        A list of names of vantage points from which to execute the probe.


        :param vantage_point_names: The vantage_point_names of this HttpMonitor.
        :type: list[str]
        """
        self._vantage_point_names = vantage_point_names

    @property
    def port(self):
        """
        Gets the port of this HttpMonitor.
        The port on which to probe endpoints. If unspecified, probes will use the
        default port of their protocol.


        :return: The port of this HttpMonitor.
        :rtype: int
        """
        return self._port

    @port.setter
    def port(self, port):
        """
        Sets the port of this HttpMonitor.
        The port on which to probe endpoints. If unspecified, probes will use the
        default port of their protocol.


        :param port: The port of this HttpMonitor.
        :type: int
        """
        self._port = port

    @property
    def timeout_in_seconds(self):
        """
        Gets the timeout_in_seconds of this HttpMonitor.
        The probe timeout in seconds. Valid values: 10, 20, 30, and 60.
        The probe timeout must be less than or equal to `intervalInSeconds` for monitors.


        :return: The timeout_in_seconds of this HttpMonitor.
        :rtype: int
        """
        return self._timeout_in_seconds

    @timeout_in_seconds.setter
    def timeout_in_seconds(self, timeout_in_seconds):
        """
        Sets the timeout_in_seconds of this HttpMonitor.
        The probe timeout in seconds. Valid values: 10, 20, 30, and 60.
        The probe timeout must be less than or equal to `intervalInSeconds` for monitors.


        :param timeout_in_seconds: The timeout_in_seconds of this HttpMonitor.
        :type: int
        """
        self._timeout_in_seconds = timeout_in_seconds

    @property
    def protocol(self):
        """
        Gets the protocol of this HttpMonitor.
        Allowed values for this property are: "HTTP", "HTTPS", 'UNKNOWN_ENUM_VALUE'.
        Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.


        :return: The protocol of this HttpMonitor.
        :rtype: str
        """
        return self._protocol

    @protocol.setter
    def protocol(self, protocol):
        """
        Sets the protocol of this HttpMonitor.

        :param protocol: The protocol of this HttpMonitor.
        :type: str
        """
        allowed_values = ["HTTP", "HTTPS"]
        if not value_allowed_none_or_none_sentinel(protocol, allowed_values):
            protocol = 'UNKNOWN_ENUM_VALUE'
        self._protocol = protocol

    @property
    def method(self):
        """
        Gets the method of this HttpMonitor.
        Allowed values for this property are: "GET", "HEAD", 'UNKNOWN_ENUM_VALUE'.
        Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.


        :return: The method of this HttpMonitor.
        :rtype: str
        """
        return self._method

    @method.setter
    def method(self, method):
        """
        Sets the method of this HttpMonitor.

        :param method: The method of this HttpMonitor.
        :type: str
        """
        allowed_values = ["GET", "HEAD"]
        if not value_allowed_none_or_none_sentinel(method, allowed_values):
            method = 'UNKNOWN_ENUM_VALUE'
        self._method = method

    @property
    def path(self):
        """
        Gets the path of this HttpMonitor.
        The optional URL path to probe, including query parameters.


        :return: The path of this HttpMonitor.
        :rtype: str
        """
        return self._path

    @path.setter
    def path(self, path):
        """
        Sets the path of this HttpMonitor.
        The optional URL path to probe, including query parameters.


        :param path: The path of this HttpMonitor.
        :type: str
        """
        self._path = path

    @property
    def headers(self):
        """
        Gets the headers of this HttpMonitor.
        A dictionary of HTTP request headers.

        *Note:* Monitors and probes do not support the use of the `Authorization` HTTP header.


        :return: The headers of this HttpMonitor.
        :rtype: dict(str, str)
        """
        return self._headers

    @headers.setter
    def headers(self, headers):
        """
        Sets the headers of this HttpMonitor.
        A dictionary of HTTP request headers.

        *Note:* Monitors and probes do not support the use of the `Authorization` HTTP header.


        :param headers: The headers of this HttpMonitor.
        :type: dict(str, str)
        """
        self._headers = headers

    @property
    def display_name(self):
        """
        Gets the display_name of this HttpMonitor.
        A user-friendly and mutable name suitable for display in a user interface.


        :return: The display_name of this HttpMonitor.
        :rtype: str
        """
        return self._display_name

    @display_name.setter
    def display_name(self, display_name):
        """
        Sets the display_name of this HttpMonitor.
        A user-friendly and mutable name suitable for display in a user interface.


        :param display_name: The display_name of this HttpMonitor.
        :type: str
        """
        self._display_name = display_name

    @property
    def interval_in_seconds(self):
        """
        Gets the interval_in_seconds of this HttpMonitor.
        The monitor interval in seconds. Valid values: 10, 30, and 60.


        :return: The interval_in_seconds of this HttpMonitor.
        :rtype: int
        """
        return self._interval_in_seconds

    @interval_in_seconds.setter
    def interval_in_seconds(self, interval_in_seconds):
        """
        Sets the interval_in_seconds of this HttpMonitor.
        The monitor interval in seconds. Valid values: 10, 30, and 60.


        :param interval_in_seconds: The interval_in_seconds of this HttpMonitor.
        :type: int
        """
        self._interval_in_seconds = interval_in_seconds

    @property
    def is_enabled(self):
        """
        Gets the is_enabled of this HttpMonitor.
        Enables or disables the monitor. Set to 'true' to launch monitoring.


        :return: The is_enabled of this HttpMonitor.
        :rtype: bool
        """
        return self._is_enabled

    @is_enabled.setter
    def is_enabled(self, is_enabled):
        """
        Sets the is_enabled of this HttpMonitor.
        Enables or disables the monitor. Set to 'true' to launch monitoring.


        :param is_enabled: The is_enabled of this HttpMonitor.
        :type: bool
        """
        self._is_enabled = is_enabled

    @property
    def freeform_tags(self):
        """
        Gets the freeform_tags of this HttpMonitor.
        Free-form tags for this resource. Each tag is a simple key-value pair with no
        predefined name, type, or namespace.  For more information,
        see `Resource Tags`__.
        Example: `{\"Department\": \"Finance\"}`

        __ https://docs.cloud.oracle.com/Content/General/Concepts/resourcetags.htm


        :return: The freeform_tags of this HttpMonitor.
        :rtype: dict(str, str)
        """
        return self._freeform_tags

    @freeform_tags.setter
    def freeform_tags(self, freeform_tags):
        """
        Sets the freeform_tags of this HttpMonitor.
        Free-form tags for this resource. Each tag is a simple key-value pair with no
        predefined name, type, or namespace.  For more information,
        see `Resource Tags`__.
        Example: `{\"Department\": \"Finance\"}`

        __ https://docs.cloud.oracle.com/Content/General/Concepts/resourcetags.htm


        :param freeform_tags: The freeform_tags of this HttpMonitor.
        :type: dict(str, str)
        """
        self._freeform_tags = freeform_tags

    @property
    def defined_tags(self):
        """
        Gets the defined_tags of this HttpMonitor.
        Defined tags for this resource. Each key is predefined and scoped to a namespace.
        For more information, see `Resource Tags`__.
        Example: `{\"Operations\": {\"CostCenter\": \"42\"}}`

        __ https://docs.cloud.oracle.com/Content/General/Concepts/resourcetags.htm


        :return: The defined_tags of this HttpMonitor.
        :rtype: dict(str, dict(str, object))
        """
        return self._defined_tags

    @defined_tags.setter
    def defined_tags(self, defined_tags):
        """
        Sets the defined_tags of this HttpMonitor.
        Defined tags for this resource. Each key is predefined and scoped to a namespace.
        For more information, see `Resource Tags`__.
        Example: `{\"Operations\": {\"CostCenter\": \"42\"}}`

        __ https://docs.cloud.oracle.com/Content/General/Concepts/resourcetags.htm


        :param defined_tags: The defined_tags of this HttpMonitor.
        :type: dict(str, dict(str, object))
        """
        self._defined_tags = defined_tags

    def __repr__(self):
        return formatted_flat_dict(self)

    def __eq__(self, other):
        if other is None:
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not self == other
