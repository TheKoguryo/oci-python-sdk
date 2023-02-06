# coding: utf-8
# Copyright (c) 2016, 2023, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.


from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class TimeAndVerticalScalingConfig(object):
    """
    Time of day and vertical scaling configuration.
    """

    def __init__(self, **kwargs):
        """
        Initializes a new TimeAndVerticalScalingConfig object with values from keyword arguments.
        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param time_recurrence:
            The value to assign to the time_recurrence property of this TimeAndVerticalScalingConfig.
        :type time_recurrence: str

        :param target_shape:
            The value to assign to the target_shape property of this TimeAndVerticalScalingConfig.
        :type target_shape: str

        :param target_ocpus_per_node:
            The value to assign to the target_ocpus_per_node property of this TimeAndVerticalScalingConfig.
        :type target_ocpus_per_node: int

        :param target_memory_per_node:
            The value to assign to the target_memory_per_node property of this TimeAndVerticalScalingConfig.
        :type target_memory_per_node: int

        """
        self.swagger_types = {
            'time_recurrence': 'str',
            'target_shape': 'str',
            'target_ocpus_per_node': 'int',
            'target_memory_per_node': 'int'
        }

        self.attribute_map = {
            'time_recurrence': 'timeRecurrence',
            'target_shape': 'targetShape',
            'target_ocpus_per_node': 'targetOcpusPerNode',
            'target_memory_per_node': 'targetMemoryPerNode'
        }

        self._time_recurrence = None
        self._target_shape = None
        self._target_ocpus_per_node = None
        self._target_memory_per_node = None

    @property
    def time_recurrence(self):
        """
        Gets the time_recurrence of this TimeAndVerticalScalingConfig.
        Day/time recurrence (specified following RFC 5545) at which to trigger autoscaling action. Currently only WEEKLY frequency is supported. Days of the week are specified using BYDAY field. Time of the day is specified using BYHOUR and BYMINUTE fields. Other fields are not supported.


        :return: The time_recurrence of this TimeAndVerticalScalingConfig.
        :rtype: str
        """
        return self._time_recurrence

    @time_recurrence.setter
    def time_recurrence(self, time_recurrence):
        """
        Sets the time_recurrence of this TimeAndVerticalScalingConfig.
        Day/time recurrence (specified following RFC 5545) at which to trigger autoscaling action. Currently only WEEKLY frequency is supported. Days of the week are specified using BYDAY field. Time of the day is specified using BYHOUR and BYMINUTE fields. Other fields are not supported.


        :param time_recurrence: The time_recurrence of this TimeAndVerticalScalingConfig.
        :type: str
        """
        self._time_recurrence = time_recurrence

    @property
    def target_shape(self):
        """
        Gets the target_shape of this TimeAndVerticalScalingConfig.
        For nodes with `fixed compute shapes`__, this value is the desired shape of each node. This value is not used for nodes with flexible compute shapes.

        __ https://docs.cloud.oracle.com/iaas/Content/bigdata/create-cluster.htm#cluster-plan-shape


        :return: The target_shape of this TimeAndVerticalScalingConfig.
        :rtype: str
        """
        return self._target_shape

    @target_shape.setter
    def target_shape(self, target_shape):
        """
        Sets the target_shape of this TimeAndVerticalScalingConfig.
        For nodes with `fixed compute shapes`__, this value is the desired shape of each node. This value is not used for nodes with flexible compute shapes.

        __ https://docs.cloud.oracle.com/iaas/Content/bigdata/create-cluster.htm#cluster-plan-shape


        :param target_shape: The target_shape of this TimeAndVerticalScalingConfig.
        :type: str
        """
        self._target_shape = target_shape

    @property
    def target_ocpus_per_node(self):
        """
        Gets the target_ocpus_per_node of this TimeAndVerticalScalingConfig.
        For nodes with `flexible compute shapes`__, this value is the desired OCPUs count on each node. This value is not used for nodes with fixed compute shapes.

        __ https://docs.cloud.oracle.com/iaas/Content/bigdata/create-cluster.htm#cluster-plan-shape


        :return: The target_ocpus_per_node of this TimeAndVerticalScalingConfig.
        :rtype: int
        """
        return self._target_ocpus_per_node

    @target_ocpus_per_node.setter
    def target_ocpus_per_node(self, target_ocpus_per_node):
        """
        Sets the target_ocpus_per_node of this TimeAndVerticalScalingConfig.
        For nodes with `flexible compute shapes`__, this value is the desired OCPUs count on each node. This value is not used for nodes with fixed compute shapes.

        __ https://docs.cloud.oracle.com/iaas/Content/bigdata/create-cluster.htm#cluster-plan-shape


        :param target_ocpus_per_node: The target_ocpus_per_node of this TimeAndVerticalScalingConfig.
        :type: int
        """
        self._target_ocpus_per_node = target_ocpus_per_node

    @property
    def target_memory_per_node(self):
        """
        Gets the target_memory_per_node of this TimeAndVerticalScalingConfig.
        For nodes with `flexible compute shapes`__, this value is the desired memory in GBs on each node. This value is not used for nodes with fixed compute shapes.

        __ https://docs.cloud.oracle.com/iaas/Content/bigdata/create-cluster.htm#cluster-plan-shape


        :return: The target_memory_per_node of this TimeAndVerticalScalingConfig.
        :rtype: int
        """
        return self._target_memory_per_node

    @target_memory_per_node.setter
    def target_memory_per_node(self, target_memory_per_node):
        """
        Sets the target_memory_per_node of this TimeAndVerticalScalingConfig.
        For nodes with `flexible compute shapes`__, this value is the desired memory in GBs on each node. This value is not used for nodes with fixed compute shapes.

        __ https://docs.cloud.oracle.com/iaas/Content/bigdata/create-cluster.htm#cluster-plan-shape


        :param target_memory_per_node: The target_memory_per_node of this TimeAndVerticalScalingConfig.
        :type: int
        """
        self._target_memory_per_node = target_memory_per_node

    def __repr__(self):
        return formatted_flat_dict(self)

    def __eq__(self, other):
        if other is None:
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not self == other
