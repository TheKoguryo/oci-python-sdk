# coding: utf-8
# Copyright (c) 2016, 2023, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.


from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class UpdateMaskingPolicyDetails(object):
    """
    Details to update a masking policy.
    """

    def __init__(self, **kwargs):
        """
        Initializes a new UpdateMaskingPolicyDetails object with values from keyword arguments.
        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param display_name:
            The value to assign to the display_name property of this UpdateMaskingPolicyDetails.
        :type display_name: str

        :param description:
            The value to assign to the description property of this UpdateMaskingPolicyDetails.
        :type description: str

        :param is_drop_temp_tables_enabled:
            The value to assign to the is_drop_temp_tables_enabled property of this UpdateMaskingPolicyDetails.
        :type is_drop_temp_tables_enabled: bool

        :param is_redo_logging_enabled:
            The value to assign to the is_redo_logging_enabled property of this UpdateMaskingPolicyDetails.
        :type is_redo_logging_enabled: bool

        :param is_refresh_stats_enabled:
            The value to assign to the is_refresh_stats_enabled property of this UpdateMaskingPolicyDetails.
        :type is_refresh_stats_enabled: bool

        :param parallel_degree:
            The value to assign to the parallel_degree property of this UpdateMaskingPolicyDetails.
        :type parallel_degree: str

        :param recompile:
            The value to assign to the recompile property of this UpdateMaskingPolicyDetails.
        :type recompile: str

        :param pre_masking_script:
            The value to assign to the pre_masking_script property of this UpdateMaskingPolicyDetails.
        :type pre_masking_script: str

        :param post_masking_script:
            The value to assign to the post_masking_script property of this UpdateMaskingPolicyDetails.
        :type post_masking_script: str

        :param column_source:
            The value to assign to the column_source property of this UpdateMaskingPolicyDetails.
        :type column_source: oci.data_safe.models.UpdateColumnSourceDetails

        :param freeform_tags:
            The value to assign to the freeform_tags property of this UpdateMaskingPolicyDetails.
        :type freeform_tags: dict(str, str)

        :param defined_tags:
            The value to assign to the defined_tags property of this UpdateMaskingPolicyDetails.
        :type defined_tags: dict(str, dict(str, object))

        """
        self.swagger_types = {
            'display_name': 'str',
            'description': 'str',
            'is_drop_temp_tables_enabled': 'bool',
            'is_redo_logging_enabled': 'bool',
            'is_refresh_stats_enabled': 'bool',
            'parallel_degree': 'str',
            'recompile': 'str',
            'pre_masking_script': 'str',
            'post_masking_script': 'str',
            'column_source': 'UpdateColumnSourceDetails',
            'freeform_tags': 'dict(str, str)',
            'defined_tags': 'dict(str, dict(str, object))'
        }

        self.attribute_map = {
            'display_name': 'displayName',
            'description': 'description',
            'is_drop_temp_tables_enabled': 'isDropTempTablesEnabled',
            'is_redo_logging_enabled': 'isRedoLoggingEnabled',
            'is_refresh_stats_enabled': 'isRefreshStatsEnabled',
            'parallel_degree': 'parallelDegree',
            'recompile': 'recompile',
            'pre_masking_script': 'preMaskingScript',
            'post_masking_script': 'postMaskingScript',
            'column_source': 'columnSource',
            'freeform_tags': 'freeformTags',
            'defined_tags': 'definedTags'
        }

        self._display_name = None
        self._description = None
        self._is_drop_temp_tables_enabled = None
        self._is_redo_logging_enabled = None
        self._is_refresh_stats_enabled = None
        self._parallel_degree = None
        self._recompile = None
        self._pre_masking_script = None
        self._post_masking_script = None
        self._column_source = None
        self._freeform_tags = None
        self._defined_tags = None

    @property
    def display_name(self):
        """
        Gets the display_name of this UpdateMaskingPolicyDetails.
        The display name of the masking policy. The name does not have to be unique, and it's changeable.


        :return: The display_name of this UpdateMaskingPolicyDetails.
        :rtype: str
        """
        return self._display_name

    @display_name.setter
    def display_name(self, display_name):
        """
        Sets the display_name of this UpdateMaskingPolicyDetails.
        The display name of the masking policy. The name does not have to be unique, and it's changeable.


        :param display_name: The display_name of this UpdateMaskingPolicyDetails.
        :type: str
        """
        self._display_name = display_name

    @property
    def description(self):
        """
        Gets the description of this UpdateMaskingPolicyDetails.
        The description of the masking policy.


        :return: The description of this UpdateMaskingPolicyDetails.
        :rtype: str
        """
        return self._description

    @description.setter
    def description(self, description):
        """
        Sets the description of this UpdateMaskingPolicyDetails.
        The description of the masking policy.


        :param description: The description of this UpdateMaskingPolicyDetails.
        :type: str
        """
        self._description = description

    @property
    def is_drop_temp_tables_enabled(self):
        """
        Gets the is_drop_temp_tables_enabled of this UpdateMaskingPolicyDetails.
        Indicates if the temporary tables created during a masking operation should be dropped after masking. It's enabled by default.
        Set this attribute to false to preserve the temporary tables. Masking creates temporary tables that map the original sensitive
        data values to mask values. By default, these temporary tables are dropped after masking. But, in some cases, you may want
        to preserve this information to track how masking changed your data. Note that doing so compromises security. These tables
        must be dropped before the database is available for unprivileged users.


        :return: The is_drop_temp_tables_enabled of this UpdateMaskingPolicyDetails.
        :rtype: bool
        """
        return self._is_drop_temp_tables_enabled

    @is_drop_temp_tables_enabled.setter
    def is_drop_temp_tables_enabled(self, is_drop_temp_tables_enabled):
        """
        Sets the is_drop_temp_tables_enabled of this UpdateMaskingPolicyDetails.
        Indicates if the temporary tables created during a masking operation should be dropped after masking. It's enabled by default.
        Set this attribute to false to preserve the temporary tables. Masking creates temporary tables that map the original sensitive
        data values to mask values. By default, these temporary tables are dropped after masking. But, in some cases, you may want
        to preserve this information to track how masking changed your data. Note that doing so compromises security. These tables
        must be dropped before the database is available for unprivileged users.


        :param is_drop_temp_tables_enabled: The is_drop_temp_tables_enabled of this UpdateMaskingPolicyDetails.
        :type: bool
        """
        self._is_drop_temp_tables_enabled = is_drop_temp_tables_enabled

    @property
    def is_redo_logging_enabled(self):
        """
        Gets the is_redo_logging_enabled of this UpdateMaskingPolicyDetails.
        Indicates if redo logging is enabled during a masking operation. It's disabled by default. Set this attribute to true to
        enable redo logging. By default, masking disables redo logging and flashback logging to purge any original unmasked
        data from logs. However, in certain circumstances when you only want to test masking, rollback changes, and retry masking,
        you could enable logging and use a flashback database to retrieve the original unmasked data after it has been masked.


        :return: The is_redo_logging_enabled of this UpdateMaskingPolicyDetails.
        :rtype: bool
        """
        return self._is_redo_logging_enabled

    @is_redo_logging_enabled.setter
    def is_redo_logging_enabled(self, is_redo_logging_enabled):
        """
        Sets the is_redo_logging_enabled of this UpdateMaskingPolicyDetails.
        Indicates if redo logging is enabled during a masking operation. It's disabled by default. Set this attribute to true to
        enable redo logging. By default, masking disables redo logging and flashback logging to purge any original unmasked
        data from logs. However, in certain circumstances when you only want to test masking, rollback changes, and retry masking,
        you could enable logging and use a flashback database to retrieve the original unmasked data after it has been masked.


        :param is_redo_logging_enabled: The is_redo_logging_enabled of this UpdateMaskingPolicyDetails.
        :type: bool
        """
        self._is_redo_logging_enabled = is_redo_logging_enabled

    @property
    def is_refresh_stats_enabled(self):
        """
        Gets the is_refresh_stats_enabled of this UpdateMaskingPolicyDetails.
        Indicates if statistics gathering is enabled. It's enabled by default. Set this attribute to false to disable statistics
        gathering. The masking process gathers statistics on masked database tables after masking completes.


        :return: The is_refresh_stats_enabled of this UpdateMaskingPolicyDetails.
        :rtype: bool
        """
        return self._is_refresh_stats_enabled

    @is_refresh_stats_enabled.setter
    def is_refresh_stats_enabled(self, is_refresh_stats_enabled):
        """
        Sets the is_refresh_stats_enabled of this UpdateMaskingPolicyDetails.
        Indicates if statistics gathering is enabled. It's enabled by default. Set this attribute to false to disable statistics
        gathering. The masking process gathers statistics on masked database tables after masking completes.


        :param is_refresh_stats_enabled: The is_refresh_stats_enabled of this UpdateMaskingPolicyDetails.
        :type: bool
        """
        self._is_refresh_stats_enabled = is_refresh_stats_enabled

    @property
    def parallel_degree(self):
        """
        Gets the parallel_degree of this UpdateMaskingPolicyDetails.
        Specifies options to enable parallel execution when running data masking. Allowed values are 'NONE' (no parallelism),
        'DEFAULT' (the Oracle Database computes the optimum degree of parallelism) or an integer value to be used as the degree
        of parallelism. Parallel execution helps effectively use multiple CPUsi and improve masking performance. Refer to the
        Oracle Database parallel execution framework when choosing an explicit degree of parallelism.


        :return: The parallel_degree of this UpdateMaskingPolicyDetails.
        :rtype: str
        """
        return self._parallel_degree

    @parallel_degree.setter
    def parallel_degree(self, parallel_degree):
        """
        Sets the parallel_degree of this UpdateMaskingPolicyDetails.
        Specifies options to enable parallel execution when running data masking. Allowed values are 'NONE' (no parallelism),
        'DEFAULT' (the Oracle Database computes the optimum degree of parallelism) or an integer value to be used as the degree
        of parallelism. Parallel execution helps effectively use multiple CPUsi and improve masking performance. Refer to the
        Oracle Database parallel execution framework when choosing an explicit degree of parallelism.


        :param parallel_degree: The parallel_degree of this UpdateMaskingPolicyDetails.
        :type: str
        """
        self._parallel_degree = parallel_degree

    @property
    def recompile(self):
        """
        Gets the recompile of this UpdateMaskingPolicyDetails.
        Specifies how to recompile invalid objects post data masking. Allowed values are 'SERIAL' (recompile in serial),
        'PARALLEL' (recompile in parallel), 'NONE' (do not recompile). If it's set to PARALLEL, the value of parallelDegree
        attribute is used.


        :return: The recompile of this UpdateMaskingPolicyDetails.
        :rtype: str
        """
        return self._recompile

    @recompile.setter
    def recompile(self, recompile):
        """
        Sets the recompile of this UpdateMaskingPolicyDetails.
        Specifies how to recompile invalid objects post data masking. Allowed values are 'SERIAL' (recompile in serial),
        'PARALLEL' (recompile in parallel), 'NONE' (do not recompile). If it's set to PARALLEL, the value of parallelDegree
        attribute is used.


        :param recompile: The recompile of this UpdateMaskingPolicyDetails.
        :type: str
        """
        self._recompile = recompile

    @property
    def pre_masking_script(self):
        """
        Gets the pre_masking_script of this UpdateMaskingPolicyDetails.
        A pre-masking script, which can contain SQL and PL/SQL statements. It's executed before
        the core masking script generated using the masking policy. It's usually used to perform
        any preparation or prerequisite work before masking data.


        :return: The pre_masking_script of this UpdateMaskingPolicyDetails.
        :rtype: str
        """
        return self._pre_masking_script

    @pre_masking_script.setter
    def pre_masking_script(self, pre_masking_script):
        """
        Sets the pre_masking_script of this UpdateMaskingPolicyDetails.
        A pre-masking script, which can contain SQL and PL/SQL statements. It's executed before
        the core masking script generated using the masking policy. It's usually used to perform
        any preparation or prerequisite work before masking data.


        :param pre_masking_script: The pre_masking_script of this UpdateMaskingPolicyDetails.
        :type: str
        """
        self._pre_masking_script = pre_masking_script

    @property
    def post_masking_script(self):
        """
        Gets the post_masking_script of this UpdateMaskingPolicyDetails.
        A post-masking script, which can contain SQL and PL/SQL statements. It's executed after
        the core masking script generated using the masking policy. It's usually used to perform
        additional transformation or cleanup work after masking.


        :return: The post_masking_script of this UpdateMaskingPolicyDetails.
        :rtype: str
        """
        return self._post_masking_script

    @post_masking_script.setter
    def post_masking_script(self, post_masking_script):
        """
        Sets the post_masking_script of this UpdateMaskingPolicyDetails.
        A post-masking script, which can contain SQL and PL/SQL statements. It's executed after
        the core masking script generated using the masking policy. It's usually used to perform
        additional transformation or cleanup work after masking.


        :param post_masking_script: The post_masking_script of this UpdateMaskingPolicyDetails.
        :type: str
        """
        self._post_masking_script = post_masking_script

    @property
    def column_source(self):
        """
        Gets the column_source of this UpdateMaskingPolicyDetails.

        :return: The column_source of this UpdateMaskingPolicyDetails.
        :rtype: oci.data_safe.models.UpdateColumnSourceDetails
        """
        return self._column_source

    @column_source.setter
    def column_source(self, column_source):
        """
        Sets the column_source of this UpdateMaskingPolicyDetails.

        :param column_source: The column_source of this UpdateMaskingPolicyDetails.
        :type: oci.data_safe.models.UpdateColumnSourceDetails
        """
        self._column_source = column_source

    @property
    def freeform_tags(self):
        """
        Gets the freeform_tags of this UpdateMaskingPolicyDetails.
        Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see `Resource Tags`__

        Example: `{\"Department\": \"Finance\"}`

        __ https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm


        :return: The freeform_tags of this UpdateMaskingPolicyDetails.
        :rtype: dict(str, str)
        """
        return self._freeform_tags

    @freeform_tags.setter
    def freeform_tags(self, freeform_tags):
        """
        Sets the freeform_tags of this UpdateMaskingPolicyDetails.
        Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see `Resource Tags`__

        Example: `{\"Department\": \"Finance\"}`

        __ https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm


        :param freeform_tags: The freeform_tags of this UpdateMaskingPolicyDetails.
        :type: dict(str, str)
        """
        self._freeform_tags = freeform_tags

    @property
    def defined_tags(self):
        """
        Gets the defined_tags of this UpdateMaskingPolicyDetails.
        Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see `Resource Tags`__

        Example: `{\"Operations\": {\"CostCenter\": \"42\"}}`

        __ https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm


        :return: The defined_tags of this UpdateMaskingPolicyDetails.
        :rtype: dict(str, dict(str, object))
        """
        return self._defined_tags

    @defined_tags.setter
    def defined_tags(self, defined_tags):
        """
        Sets the defined_tags of this UpdateMaskingPolicyDetails.
        Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see `Resource Tags`__

        Example: `{\"Operations\": {\"CostCenter\": \"42\"}}`

        __ https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm


        :param defined_tags: The defined_tags of this UpdateMaskingPolicyDetails.
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
