# coding: utf-8
# Copyright (c) 2016, 2023, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.


from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class ReportSummary(object):
    """
    Description of report.
    """

    #: A constant which can be used with the mime_type property of a ReportSummary.
    #: This constant has a value of "PDF"
    MIME_TYPE_PDF = "PDF"

    #: A constant which can be used with the mime_type property of a ReportSummary.
    #: This constant has a value of "XLS"
    MIME_TYPE_XLS = "XLS"

    #: A constant which can be used with the lifecycle_state property of a ReportSummary.
    #: This constant has a value of "UPDATING"
    LIFECYCLE_STATE_UPDATING = "UPDATING"

    #: A constant which can be used with the lifecycle_state property of a ReportSummary.
    #: This constant has a value of "ACTIVE"
    LIFECYCLE_STATE_ACTIVE = "ACTIVE"

    #: A constant which can be used with the type property of a ReportSummary.
    #: This constant has a value of "GENERATED"
    TYPE_GENERATED = "GENERATED"

    #: A constant which can be used with the type property of a ReportSummary.
    #: This constant has a value of "SCHEDULED"
    TYPE_SCHEDULED = "SCHEDULED"

    def __init__(self, **kwargs):
        """
        Initializes a new ReportSummary object with values from keyword arguments.
        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param display_name:
            The value to assign to the display_name property of this ReportSummary.
        :type display_name: str

        :param id:
            The value to assign to the id property of this ReportSummary.
        :type id: str

        :param report_definition_id:
            The value to assign to the report_definition_id property of this ReportSummary.
        :type report_definition_id: str

        :param description:
            The value to assign to the description property of this ReportSummary.
        :type description: str

        :param mime_type:
            The value to assign to the mime_type property of this ReportSummary.
            Allowed values for this property are: "PDF", "XLS", 'UNKNOWN_ENUM_VALUE'.
            Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.
        :type mime_type: str

        :param time_generated:
            The value to assign to the time_generated property of this ReportSummary.
        :type time_generated: datetime

        :param compartment_id:
            The value to assign to the compartment_id property of this ReportSummary.
        :type compartment_id: str

        :param lifecycle_state:
            The value to assign to the lifecycle_state property of this ReportSummary.
            Allowed values for this property are: "UPDATING", "ACTIVE", 'UNKNOWN_ENUM_VALUE'.
            Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.
        :type lifecycle_state: str

        :param type:
            The value to assign to the type property of this ReportSummary.
            Allowed values for this property are: "GENERATED", "SCHEDULED", 'UNKNOWN_ENUM_VALUE'.
            Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.
        :type type: str

        :param freeform_tags:
            The value to assign to the freeform_tags property of this ReportSummary.
        :type freeform_tags: dict(str, str)

        :param defined_tags:
            The value to assign to the defined_tags property of this ReportSummary.
        :type defined_tags: dict(str, dict(str, object))

        """
        self.swagger_types = {
            'display_name': 'str',
            'id': 'str',
            'report_definition_id': 'str',
            'description': 'str',
            'mime_type': 'str',
            'time_generated': 'datetime',
            'compartment_id': 'str',
            'lifecycle_state': 'str',
            'type': 'str',
            'freeform_tags': 'dict(str, str)',
            'defined_tags': 'dict(str, dict(str, object))'
        }

        self.attribute_map = {
            'display_name': 'displayName',
            'id': 'id',
            'report_definition_id': 'reportDefinitionId',
            'description': 'description',
            'mime_type': 'mimeType',
            'time_generated': 'timeGenerated',
            'compartment_id': 'compartmentId',
            'lifecycle_state': 'lifecycleState',
            'type': 'type',
            'freeform_tags': 'freeformTags',
            'defined_tags': 'definedTags'
        }

        self._display_name = None
        self._id = None
        self._report_definition_id = None
        self._description = None
        self._mime_type = None
        self._time_generated = None
        self._compartment_id = None
        self._lifecycle_state = None
        self._type = None
        self._freeform_tags = None
        self._defined_tags = None

    @property
    def display_name(self):
        """
        **[Required]** Gets the display_name of this ReportSummary.
        Name of the report.


        :return: The display_name of this ReportSummary.
        :rtype: str
        """
        return self._display_name

    @display_name.setter
    def display_name(self, display_name):
        """
        Sets the display_name of this ReportSummary.
        Name of the report.


        :param display_name: The display_name of this ReportSummary.
        :type: str
        """
        self._display_name = display_name

    @property
    def id(self):
        """
        **[Required]** Gets the id of this ReportSummary.
        The OCID of the report.


        :return: The id of this ReportSummary.
        :rtype: str
        """
        return self._id

    @id.setter
    def id(self, id):
        """
        Sets the id of this ReportSummary.
        The OCID of the report.


        :param id: The id of this ReportSummary.
        :type: str
        """
        self._id = id

    @property
    def report_definition_id(self):
        """
        Gets the report_definition_id of this ReportSummary.
        The OCID of the report definition.


        :return: The report_definition_id of this ReportSummary.
        :rtype: str
        """
        return self._report_definition_id

    @report_definition_id.setter
    def report_definition_id(self, report_definition_id):
        """
        Sets the report_definition_id of this ReportSummary.
        The OCID of the report definition.


        :param report_definition_id: The report_definition_id of this ReportSummary.
        :type: str
        """
        self._report_definition_id = report_definition_id

    @property
    def description(self):
        """
        Gets the description of this ReportSummary.
        Description of the report.


        :return: The description of this ReportSummary.
        :rtype: str
        """
        return self._description

    @description.setter
    def description(self, description):
        """
        Sets the description of this ReportSummary.
        Description of the report.


        :param description: The description of this ReportSummary.
        :type: str
        """
        self._description = description

    @property
    def mime_type(self):
        """
        Gets the mime_type of this ReportSummary.
        Specifies the format of report to be excel or pdf.

        Allowed values for this property are: "PDF", "XLS", 'UNKNOWN_ENUM_VALUE'.
        Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.


        :return: The mime_type of this ReportSummary.
        :rtype: str
        """
        return self._mime_type

    @mime_type.setter
    def mime_type(self, mime_type):
        """
        Sets the mime_type of this ReportSummary.
        Specifies the format of report to be excel or pdf.


        :param mime_type: The mime_type of this ReportSummary.
        :type: str
        """
        allowed_values = ["PDF", "XLS"]
        if not value_allowed_none_or_none_sentinel(mime_type, allowed_values):
            mime_type = 'UNKNOWN_ENUM_VALUE'
        self._mime_type = mime_type

    @property
    def time_generated(self):
        """
        **[Required]** Gets the time_generated of this ReportSummary.
        Specifies the time at which the report was generated.


        :return: The time_generated of this ReportSummary.
        :rtype: datetime
        """
        return self._time_generated

    @time_generated.setter
    def time_generated(self, time_generated):
        """
        Sets the time_generated of this ReportSummary.
        Specifies the time at which the report was generated.


        :param time_generated: The time_generated of this ReportSummary.
        :type: datetime
        """
        self._time_generated = time_generated

    @property
    def compartment_id(self):
        """
        **[Required]** Gets the compartment_id of this ReportSummary.
        The OCID of the compartment containing the report.


        :return: The compartment_id of this ReportSummary.
        :rtype: str
        """
        return self._compartment_id

    @compartment_id.setter
    def compartment_id(self, compartment_id):
        """
        Sets the compartment_id of this ReportSummary.
        The OCID of the compartment containing the report.


        :param compartment_id: The compartment_id of this ReportSummary.
        :type: str
        """
        self._compartment_id = compartment_id

    @property
    def lifecycle_state(self):
        """
        **[Required]** Gets the lifecycle_state of this ReportSummary.
        The current state of the report.

        Allowed values for this property are: "UPDATING", "ACTIVE", 'UNKNOWN_ENUM_VALUE'.
        Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.


        :return: The lifecycle_state of this ReportSummary.
        :rtype: str
        """
        return self._lifecycle_state

    @lifecycle_state.setter
    def lifecycle_state(self, lifecycle_state):
        """
        Sets the lifecycle_state of this ReportSummary.
        The current state of the report.


        :param lifecycle_state: The lifecycle_state of this ReportSummary.
        :type: str
        """
        allowed_values = ["UPDATING", "ACTIVE"]
        if not value_allowed_none_or_none_sentinel(lifecycle_state, allowed_values):
            lifecycle_state = 'UNKNOWN_ENUM_VALUE'
        self._lifecycle_state = lifecycle_state

    @property
    def type(self):
        """
        Gets the type of this ReportSummary.
        The type of the report.

        Allowed values for this property are: "GENERATED", "SCHEDULED", 'UNKNOWN_ENUM_VALUE'.
        Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.


        :return: The type of this ReportSummary.
        :rtype: str
        """
        return self._type

    @type.setter
    def type(self, type):
        """
        Sets the type of this ReportSummary.
        The type of the report.


        :param type: The type of this ReportSummary.
        :type: str
        """
        allowed_values = ["GENERATED", "SCHEDULED"]
        if not value_allowed_none_or_none_sentinel(type, allowed_values):
            type = 'UNKNOWN_ENUM_VALUE'
        self._type = type

    @property
    def freeform_tags(self):
        """
        Gets the freeform_tags of this ReportSummary.
        Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see `Resource Tags`__

        Example: `{\"Department\": \"Finance\"}`

        __ https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm


        :return: The freeform_tags of this ReportSummary.
        :rtype: dict(str, str)
        """
        return self._freeform_tags

    @freeform_tags.setter
    def freeform_tags(self, freeform_tags):
        """
        Sets the freeform_tags of this ReportSummary.
        Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see `Resource Tags`__

        Example: `{\"Department\": \"Finance\"}`

        __ https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm


        :param freeform_tags: The freeform_tags of this ReportSummary.
        :type: dict(str, str)
        """
        self._freeform_tags = freeform_tags

    @property
    def defined_tags(self):
        """
        Gets the defined_tags of this ReportSummary.
        Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see `Resource Tags`__

        Example: `{\"Operations\": {\"CostCenter\": \"42\"}}`

        __ https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm


        :return: The defined_tags of this ReportSummary.
        :rtype: dict(str, dict(str, object))
        """
        return self._defined_tags

    @defined_tags.setter
    def defined_tags(self, defined_tags):
        """
        Sets the defined_tags of this ReportSummary.
        Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see `Resource Tags`__

        Example: `{\"Operations\": {\"CostCenter\": \"42\"}}`

        __ https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm


        :param defined_tags: The defined_tags of this ReportSummary.
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
