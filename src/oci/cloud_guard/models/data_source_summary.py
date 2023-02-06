# coding: utf-8
# Copyright (c) 2016, 2023, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.


from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class DataSourceSummary(object):
    """
    Summary of Data Source
    """

    #: A constant which can be used with the data_source_feed_provider property of a DataSourceSummary.
    #: This constant has a value of "LOGGINGQUERY"
    DATA_SOURCE_FEED_PROVIDER_LOGGINGQUERY = "LOGGINGQUERY"

    #: A constant which can be used with the status property of a DataSourceSummary.
    #: This constant has a value of "ENABLED"
    STATUS_ENABLED = "ENABLED"

    #: A constant which can be used with the status property of a DataSourceSummary.
    #: This constant has a value of "DISABLED"
    STATUS_DISABLED = "DISABLED"

    #: A constant which can be used with the lifecycle_state property of a DataSourceSummary.
    #: This constant has a value of "CREATING"
    LIFECYCLE_STATE_CREATING = "CREATING"

    #: A constant which can be used with the lifecycle_state property of a DataSourceSummary.
    #: This constant has a value of "UPDATING"
    LIFECYCLE_STATE_UPDATING = "UPDATING"

    #: A constant which can be used with the lifecycle_state property of a DataSourceSummary.
    #: This constant has a value of "ACTIVE"
    LIFECYCLE_STATE_ACTIVE = "ACTIVE"

    #: A constant which can be used with the lifecycle_state property of a DataSourceSummary.
    #: This constant has a value of "INACTIVE"
    LIFECYCLE_STATE_INACTIVE = "INACTIVE"

    #: A constant which can be used with the lifecycle_state property of a DataSourceSummary.
    #: This constant has a value of "DELETING"
    LIFECYCLE_STATE_DELETING = "DELETING"

    #: A constant which can be used with the lifecycle_state property of a DataSourceSummary.
    #: This constant has a value of "DELETED"
    LIFECYCLE_STATE_DELETED = "DELETED"

    #: A constant which can be used with the lifecycle_state property of a DataSourceSummary.
    #: This constant has a value of "FAILED"
    LIFECYCLE_STATE_FAILED = "FAILED"

    def __init__(self, **kwargs):
        """
        Initializes a new DataSourceSummary object with values from keyword arguments.
        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param id:
            The value to assign to the id property of this DataSourceSummary.
        :type id: str

        :param display_name:
            The value to assign to the display_name property of this DataSourceSummary.
        :type display_name: str

        :param data_source_feed_provider:
            The value to assign to the data_source_feed_provider property of this DataSourceSummary.
            Allowed values for this property are: "LOGGINGQUERY", 'UNKNOWN_ENUM_VALUE'.
            Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.
        :type data_source_feed_provider: str

        :param compartment_id:
            The value to assign to the compartment_id property of this DataSourceSummary.
        :type compartment_id: str

        :param data_source_summary_details:
            The value to assign to the data_source_summary_details property of this DataSourceSummary.
        :type data_source_summary_details: oci.cloud_guard.models.DataSourceSummaryDetails

        :param time_created:
            The value to assign to the time_created property of this DataSourceSummary.
        :type time_created: datetime

        :param time_updated:
            The value to assign to the time_updated property of this DataSourceSummary.
        :type time_updated: datetime

        :param status:
            The value to assign to the status property of this DataSourceSummary.
            Allowed values for this property are: "ENABLED", "DISABLED", 'UNKNOWN_ENUM_VALUE'.
            Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.
        :type status: str

        :param logging_query_details:
            The value to assign to the logging_query_details property of this DataSourceSummary.
        :type logging_query_details: oci.cloud_guard.models.LoggingQueryDetails

        :param lifecycle_state:
            The value to assign to the lifecycle_state property of this DataSourceSummary.
            Allowed values for this property are: "CREATING", "UPDATING", "ACTIVE", "INACTIVE", "DELETING", "DELETED", "FAILED", 'UNKNOWN_ENUM_VALUE'.
            Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.
        :type lifecycle_state: str

        :param lifecycle_details:
            The value to assign to the lifecycle_details property of this DataSourceSummary.
        :type lifecycle_details: str

        :param freeform_tags:
            The value to assign to the freeform_tags property of this DataSourceSummary.
        :type freeform_tags: dict(str, str)

        :param defined_tags:
            The value to assign to the defined_tags property of this DataSourceSummary.
        :type defined_tags: dict(str, dict(str, object))

        :param system_tags:
            The value to assign to the system_tags property of this DataSourceSummary.
        :type system_tags: dict(str, dict(str, object))

        """
        self.swagger_types = {
            'id': 'str',
            'display_name': 'str',
            'data_source_feed_provider': 'str',
            'compartment_id': 'str',
            'data_source_summary_details': 'DataSourceSummaryDetails',
            'time_created': 'datetime',
            'time_updated': 'datetime',
            'status': 'str',
            'logging_query_details': 'LoggingQueryDetails',
            'lifecycle_state': 'str',
            'lifecycle_details': 'str',
            'freeform_tags': 'dict(str, str)',
            'defined_tags': 'dict(str, dict(str, object))',
            'system_tags': 'dict(str, dict(str, object))'
        }

        self.attribute_map = {
            'id': 'id',
            'display_name': 'displayName',
            'data_source_feed_provider': 'dataSourceFeedProvider',
            'compartment_id': 'compartmentId',
            'data_source_summary_details': 'dataSourceSummaryDetails',
            'time_created': 'timeCreated',
            'time_updated': 'timeUpdated',
            'status': 'status',
            'logging_query_details': 'loggingQueryDetails',
            'lifecycle_state': 'lifecycleState',
            'lifecycle_details': 'lifecycleDetails',
            'freeform_tags': 'freeformTags',
            'defined_tags': 'definedTags',
            'system_tags': 'systemTags'
        }

        self._id = None
        self._display_name = None
        self._data_source_feed_provider = None
        self._compartment_id = None
        self._data_source_summary_details = None
        self._time_created = None
        self._time_updated = None
        self._status = None
        self._logging_query_details = None
        self._lifecycle_state = None
        self._lifecycle_details = None
        self._freeform_tags = None
        self._defined_tags = None
        self._system_tags = None

    @property
    def id(self):
        """
        **[Required]** Gets the id of this DataSourceSummary.
        Ocid for Data Source


        :return: The id of this DataSourceSummary.
        :rtype: str
        """
        return self._id

    @id.setter
    def id(self, id):
        """
        Sets the id of this DataSourceSummary.
        Ocid for Data Source


        :param id: The id of this DataSourceSummary.
        :type: str
        """
        self._id = id

    @property
    def display_name(self):
        """
        **[Required]** Gets the display_name of this DataSourceSummary.
        DisplayName of Data Source


        :return: The display_name of this DataSourceSummary.
        :rtype: str
        """
        return self._display_name

    @display_name.setter
    def display_name(self, display_name):
        """
        Sets the display_name of this DataSourceSummary.
        DisplayName of Data Source


        :param display_name: The display_name of this DataSourceSummary.
        :type: str
        """
        self._display_name = display_name

    @property
    def data_source_feed_provider(self):
        """
        **[Required]** Gets the data_source_feed_provider of this DataSourceSummary.
        Possible type of dataSourceFeed Provider(LoggingQuery)

        Allowed values for this property are: "LOGGINGQUERY", 'UNKNOWN_ENUM_VALUE'.
        Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.


        :return: The data_source_feed_provider of this DataSourceSummary.
        :rtype: str
        """
        return self._data_source_feed_provider

    @data_source_feed_provider.setter
    def data_source_feed_provider(self, data_source_feed_provider):
        """
        Sets the data_source_feed_provider of this DataSourceSummary.
        Possible type of dataSourceFeed Provider(LoggingQuery)


        :param data_source_feed_provider: The data_source_feed_provider of this DataSourceSummary.
        :type: str
        """
        allowed_values = ["LOGGINGQUERY"]
        if not value_allowed_none_or_none_sentinel(data_source_feed_provider, allowed_values):
            data_source_feed_provider = 'UNKNOWN_ENUM_VALUE'
        self._data_source_feed_provider = data_source_feed_provider

    @property
    def compartment_id(self):
        """
        **[Required]** Gets the compartment_id of this DataSourceSummary.
        CompartmentId of Data Source.


        :return: The compartment_id of this DataSourceSummary.
        :rtype: str
        """
        return self._compartment_id

    @compartment_id.setter
    def compartment_id(self, compartment_id):
        """
        Sets the compartment_id of this DataSourceSummary.
        CompartmentId of Data Source.


        :param compartment_id: The compartment_id of this DataSourceSummary.
        :type: str
        """
        self._compartment_id = compartment_id

    @property
    def data_source_summary_details(self):
        """
        Gets the data_source_summary_details of this DataSourceSummary.

        :return: The data_source_summary_details of this DataSourceSummary.
        :rtype: oci.cloud_guard.models.DataSourceSummaryDetails
        """
        return self._data_source_summary_details

    @data_source_summary_details.setter
    def data_source_summary_details(self, data_source_summary_details):
        """
        Sets the data_source_summary_details of this DataSourceSummary.

        :param data_source_summary_details: The data_source_summary_details of this DataSourceSummary.
        :type: oci.cloud_guard.models.DataSourceSummaryDetails
        """
        self._data_source_summary_details = data_source_summary_details

    @property
    def time_created(self):
        """
        Gets the time_created of this DataSourceSummary.
        The date and time the data source was created. Format defined by RFC3339.


        :return: The time_created of this DataSourceSummary.
        :rtype: datetime
        """
        return self._time_created

    @time_created.setter
    def time_created(self, time_created):
        """
        Sets the time_created of this DataSourceSummary.
        The date and time the data source was created. Format defined by RFC3339.


        :param time_created: The time_created of this DataSourceSummary.
        :type: datetime
        """
        self._time_created = time_created

    @property
    def time_updated(self):
        """
        Gets the time_updated of this DataSourceSummary.
        The date and time the data source was updated. Format defined by RFC3339.


        :return: The time_updated of this DataSourceSummary.
        :rtype: datetime
        """
        return self._time_updated

    @time_updated.setter
    def time_updated(self, time_updated):
        """
        Sets the time_updated of this DataSourceSummary.
        The date and time the data source was updated. Format defined by RFC3339.


        :param time_updated: The time_updated of this DataSourceSummary.
        :type: datetime
        """
        self._time_updated = time_updated

    @property
    def status(self):
        """
        Gets the status of this DataSourceSummary.
        Status of data Source

        Allowed values for this property are: "ENABLED", "DISABLED", 'UNKNOWN_ENUM_VALUE'.
        Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.


        :return: The status of this DataSourceSummary.
        :rtype: str
        """
        return self._status

    @status.setter
    def status(self, status):
        """
        Sets the status of this DataSourceSummary.
        Status of data Source


        :param status: The status of this DataSourceSummary.
        :type: str
        """
        allowed_values = ["ENABLED", "DISABLED"]
        if not value_allowed_none_or_none_sentinel(status, allowed_values):
            status = 'UNKNOWN_ENUM_VALUE'
        self._status = status

    @property
    def logging_query_details(self):
        """
        Gets the logging_query_details of this DataSourceSummary.

        :return: The logging_query_details of this DataSourceSummary.
        :rtype: oci.cloud_guard.models.LoggingQueryDetails
        """
        return self._logging_query_details

    @logging_query_details.setter
    def logging_query_details(self, logging_query_details):
        """
        Sets the logging_query_details of this DataSourceSummary.

        :param logging_query_details: The logging_query_details of this DataSourceSummary.
        :type: oci.cloud_guard.models.LoggingQueryDetails
        """
        self._logging_query_details = logging_query_details

    @property
    def lifecycle_state(self):
        """
        Gets the lifecycle_state of this DataSourceSummary.
        The current state of the resource.

        Allowed values for this property are: "CREATING", "UPDATING", "ACTIVE", "INACTIVE", "DELETING", "DELETED", "FAILED", 'UNKNOWN_ENUM_VALUE'.
        Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.


        :return: The lifecycle_state of this DataSourceSummary.
        :rtype: str
        """
        return self._lifecycle_state

    @lifecycle_state.setter
    def lifecycle_state(self, lifecycle_state):
        """
        Sets the lifecycle_state of this DataSourceSummary.
        The current state of the resource.


        :param lifecycle_state: The lifecycle_state of this DataSourceSummary.
        :type: str
        """
        allowed_values = ["CREATING", "UPDATING", "ACTIVE", "INACTIVE", "DELETING", "DELETED", "FAILED"]
        if not value_allowed_none_or_none_sentinel(lifecycle_state, allowed_values):
            lifecycle_state = 'UNKNOWN_ENUM_VALUE'
        self._lifecycle_state = lifecycle_state

    @property
    def lifecycle_details(self):
        """
        Gets the lifecycle_details of this DataSourceSummary.
        A message describing the current state in more detail. For example, this can be used to provide actionable information for a zone in the `Failed` state.


        :return: The lifecycle_details of this DataSourceSummary.
        :rtype: str
        """
        return self._lifecycle_details

    @lifecycle_details.setter
    def lifecycle_details(self, lifecycle_details):
        """
        Sets the lifecycle_details of this DataSourceSummary.
        A message describing the current state in more detail. For example, this can be used to provide actionable information for a zone in the `Failed` state.


        :param lifecycle_details: The lifecycle_details of this DataSourceSummary.
        :type: str
        """
        self._lifecycle_details = lifecycle_details

    @property
    def freeform_tags(self):
        """
        Gets the freeform_tags of this DataSourceSummary.
        Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only.
        Example: `{\"bar-key\": \"value\"}`

        Avoid entering confidential information.


        :return: The freeform_tags of this DataSourceSummary.
        :rtype: dict(str, str)
        """
        return self._freeform_tags

    @freeform_tags.setter
    def freeform_tags(self, freeform_tags):
        """
        Sets the freeform_tags of this DataSourceSummary.
        Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only.
        Example: `{\"bar-key\": \"value\"}`

        Avoid entering confidential information.


        :param freeform_tags: The freeform_tags of this DataSourceSummary.
        :type: dict(str, str)
        """
        self._freeform_tags = freeform_tags

    @property
    def defined_tags(self):
        """
        Gets the defined_tags of this DataSourceSummary.
        Defined tags for this resource. Each key is predefined and scoped to a namespace.
        Example: `{\"foo-namespace\": {\"bar-key\": \"value\"}}`


        :return: The defined_tags of this DataSourceSummary.
        :rtype: dict(str, dict(str, object))
        """
        return self._defined_tags

    @defined_tags.setter
    def defined_tags(self, defined_tags):
        """
        Sets the defined_tags of this DataSourceSummary.
        Defined tags for this resource. Each key is predefined and scoped to a namespace.
        Example: `{\"foo-namespace\": {\"bar-key\": \"value\"}}`


        :param defined_tags: The defined_tags of this DataSourceSummary.
        :type: dict(str, dict(str, object))
        """
        self._defined_tags = defined_tags

    @property
    def system_tags(self):
        """
        Gets the system_tags of this DataSourceSummary.
        System tags for this resource. Each key is predefined and scoped to a namespace.
        For more information, see `Resource Tags`__.
        System tags can be viewed by users, but can only be created by the system.

        Example: `{\"orcl-cloud\": {\"free-tier-retained\": \"true\"}}`

        __ https://docs.cloud.oracle.com/Content/General/Concepts/resourcetags.htm


        :return: The system_tags of this DataSourceSummary.
        :rtype: dict(str, dict(str, object))
        """
        return self._system_tags

    @system_tags.setter
    def system_tags(self, system_tags):
        """
        Sets the system_tags of this DataSourceSummary.
        System tags for this resource. Each key is predefined and scoped to a namespace.
        For more information, see `Resource Tags`__.
        System tags can be viewed by users, but can only be created by the system.

        Example: `{\"orcl-cloud\": {\"free-tier-retained\": \"true\"}}`

        __ https://docs.cloud.oracle.com/Content/General/Concepts/resourcetags.htm


        :param system_tags: The system_tags of this DataSourceSummary.
        :type: dict(str, dict(str, object))
        """
        self._system_tags = system_tags

    def __repr__(self):
        return formatted_flat_dict(self)

    def __eq__(self, other):
        if other is None:
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not self == other
