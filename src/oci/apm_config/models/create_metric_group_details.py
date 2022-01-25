# coding: utf-8
# Copyright (c) 2016, 2022, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

from .create_config_details import CreateConfigDetails
from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class CreateMetricGroupDetails(CreateConfigDetails):
    """
    A Metric Group.
    """

    def __init__(self, **kwargs):
        """
        Initializes a new CreateMetricGroupDetails object with values from keyword arguments. The default value of the :py:attr:`~oci.apm_config.models.CreateMetricGroupDetails.config_type` attribute
        of this class is ``METRIC_GROUP`` and it should not be changed.
        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param config_type:
            The value to assign to the config_type property of this CreateMetricGroupDetails.
            Allowed values for this property are: "SPAN_FILTER", "METRIC_GROUP", "APDEX"
        :type config_type: str

        :param freeform_tags:
            The value to assign to the freeform_tags property of this CreateMetricGroupDetails.
        :type freeform_tags: dict(str, str)

        :param defined_tags:
            The value to assign to the defined_tags property of this CreateMetricGroupDetails.
        :type defined_tags: dict(str, dict(str, object))

        :param display_name:
            The value to assign to the display_name property of this CreateMetricGroupDetails.
        :type display_name: str

        :param filter_id:
            The value to assign to the filter_id property of this CreateMetricGroupDetails.
        :type filter_id: str

        :param namespace:
            The value to assign to the namespace property of this CreateMetricGroupDetails.
        :type namespace: str

        :param dimensions:
            The value to assign to the dimensions property of this CreateMetricGroupDetails.
        :type dimensions: list[oci.apm_config.models.Dimension]

        :param metrics:
            The value to assign to the metrics property of this CreateMetricGroupDetails.
        :type metrics: list[oci.apm_config.models.Metric]

        """
        self.swagger_types = {
            'config_type': 'str',
            'freeform_tags': 'dict(str, str)',
            'defined_tags': 'dict(str, dict(str, object))',
            'display_name': 'str',
            'filter_id': 'str',
            'namespace': 'str',
            'dimensions': 'list[Dimension]',
            'metrics': 'list[Metric]'
        }

        self.attribute_map = {
            'config_type': 'configType',
            'freeform_tags': 'freeformTags',
            'defined_tags': 'definedTags',
            'display_name': 'displayName',
            'filter_id': 'filterId',
            'namespace': 'namespace',
            'dimensions': 'dimensions',
            'metrics': 'metrics'
        }

        self._config_type = None
        self._freeform_tags = None
        self._defined_tags = None
        self._display_name = None
        self._filter_id = None
        self._namespace = None
        self._dimensions = None
        self._metrics = None
        self._config_type = 'METRIC_GROUP'

    @property
    def display_name(self):
        """
        **[Required]** Gets the display_name of this CreateMetricGroupDetails.
        The name of this metric group


        :return: The display_name of this CreateMetricGroupDetails.
        :rtype: str
        """
        return self._display_name

    @display_name.setter
    def display_name(self, display_name):
        """
        Sets the display_name of this CreateMetricGroupDetails.
        The name of this metric group


        :param display_name: The display_name of this CreateMetricGroupDetails.
        :type: str
        """
        self._display_name = display_name

    @property
    def filter_id(self):
        """
        **[Required]** Gets the filter_id of this CreateMetricGroupDetails.
        The `OCID`__ of a Span Filter. The filterId is mandatory for the creation
        of MetricGroups. A filterId will be generated when a Span Filter is created.

        __ https://docs.cloud.oracle.com/Content/General/Concepts/identifiers.htm


        :return: The filter_id of this CreateMetricGroupDetails.
        :rtype: str
        """
        return self._filter_id

    @filter_id.setter
    def filter_id(self, filter_id):
        """
        Sets the filter_id of this CreateMetricGroupDetails.
        The `OCID`__ of a Span Filter. The filterId is mandatory for the creation
        of MetricGroups. A filterId will be generated when a Span Filter is created.

        __ https://docs.cloud.oracle.com/Content/General/Concepts/identifiers.htm


        :param filter_id: The filter_id of this CreateMetricGroupDetails.
        :type: str
        """
        self._filter_id = filter_id

    @property
    def namespace(self):
        """
        Gets the namespace of this CreateMetricGroupDetails.
        The namespace to write the metrics to


        :return: The namespace of this CreateMetricGroupDetails.
        :rtype: str
        """
        return self._namespace

    @namespace.setter
    def namespace(self, namespace):
        """
        Sets the namespace of this CreateMetricGroupDetails.
        The namespace to write the metrics to


        :param namespace: The namespace of this CreateMetricGroupDetails.
        :type: str
        """
        self._namespace = namespace

    @property
    def dimensions(self):
        """
        Gets the dimensions of this CreateMetricGroupDetails.
        A list of dimensions for this metric


        :return: The dimensions of this CreateMetricGroupDetails.
        :rtype: list[oci.apm_config.models.Dimension]
        """
        return self._dimensions

    @dimensions.setter
    def dimensions(self, dimensions):
        """
        Sets the dimensions of this CreateMetricGroupDetails.
        A list of dimensions for this metric


        :param dimensions: The dimensions of this CreateMetricGroupDetails.
        :type: list[oci.apm_config.models.Dimension]
        """
        self._dimensions = dimensions

    @property
    def metrics(self):
        """
        **[Required]** Gets the metrics of this CreateMetricGroupDetails.

        :return: The metrics of this CreateMetricGroupDetails.
        :rtype: list[oci.apm_config.models.Metric]
        """
        return self._metrics

    @metrics.setter
    def metrics(self, metrics):
        """
        Sets the metrics of this CreateMetricGroupDetails.

        :param metrics: The metrics of this CreateMetricGroupDetails.
        :type: list[oci.apm_config.models.Metric]
        """
        self._metrics = metrics

    def __repr__(self):
        return formatted_flat_dict(self)

    def __eq__(self, other):
        if other is None:
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not self == other