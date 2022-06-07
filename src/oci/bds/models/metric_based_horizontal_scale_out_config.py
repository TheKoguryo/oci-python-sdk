# coding: utf-8
# Copyright (c) 2016, 2022, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.


from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class MetricBasedHorizontalScaleOutConfig(object):
    """
    Configration for a metric based horizontal scale-out policy.
    """

    def __init__(self, **kwargs):
        """
        Initializes a new MetricBasedHorizontalScaleOutConfig object with values from keyword arguments.
        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param metric:
            The value to assign to the metric property of this MetricBasedHorizontalScaleOutConfig.
        :type metric: oci.bds.models.AutoScalePolicyMetricRule

        :param max_node_count:
            The value to assign to the max_node_count property of this MetricBasedHorizontalScaleOutConfig.
        :type max_node_count: int

        :param step_size:
            The value to assign to the step_size property of this MetricBasedHorizontalScaleOutConfig.
        :type step_size: int

        """
        self.swagger_types = {
            'metric': 'AutoScalePolicyMetricRule',
            'max_node_count': 'int',
            'step_size': 'int'
        }

        self.attribute_map = {
            'metric': 'metric',
            'max_node_count': 'maxNodeCount',
            'step_size': 'stepSize'
        }

        self._metric = None
        self._max_node_count = None
        self._step_size = None

    @property
    def metric(self):
        """
        Gets the metric of this MetricBasedHorizontalScaleOutConfig.

        :return: The metric of this MetricBasedHorizontalScaleOutConfig.
        :rtype: oci.bds.models.AutoScalePolicyMetricRule
        """
        return self._metric

    @metric.setter
    def metric(self, metric):
        """
        Sets the metric of this MetricBasedHorizontalScaleOutConfig.

        :param metric: The metric of this MetricBasedHorizontalScaleOutConfig.
        :type: oci.bds.models.AutoScalePolicyMetricRule
        """
        self._metric = metric

    @property
    def max_node_count(self):
        """
        Gets the max_node_count of this MetricBasedHorizontalScaleOutConfig.
        This value is the maximum number of nodes the cluster can be scaled-out to.


        :return: The max_node_count of this MetricBasedHorizontalScaleOutConfig.
        :rtype: int
        """
        return self._max_node_count

    @max_node_count.setter
    def max_node_count(self, max_node_count):
        """
        Sets the max_node_count of this MetricBasedHorizontalScaleOutConfig.
        This value is the maximum number of nodes the cluster can be scaled-out to.


        :param max_node_count: The max_node_count of this MetricBasedHorizontalScaleOutConfig.
        :type: int
        """
        self._max_node_count = max_node_count

    @property
    def step_size(self):
        """
        Gets the step_size of this MetricBasedHorizontalScaleOutConfig.
        This value is the number of nodes to add during a scale-out event.


        :return: The step_size of this MetricBasedHorizontalScaleOutConfig.
        :rtype: int
        """
        return self._step_size

    @step_size.setter
    def step_size(self, step_size):
        """
        Sets the step_size of this MetricBasedHorizontalScaleOutConfig.
        This value is the number of nodes to add during a scale-out event.


        :param step_size: The step_size of this MetricBasedHorizontalScaleOutConfig.
        :type: int
        """
        self._step_size = step_size

    def __repr__(self):
        return formatted_flat_dict(self)

    def __eq__(self, other):
        if other is None:
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not self == other