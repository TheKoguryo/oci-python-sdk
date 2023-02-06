# coding: utf-8
# Copyright (c) 2016, 2023, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.


from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class SqlInsightThresholds(object):
    """
    Inventory details.
    """

    def __init__(self, **kwargs):
        """
        Initializes a new SqlInsightThresholds object with values from keyword arguments.
        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param degradation_in_pct:
            The value to assign to the degradation_in_pct property of this SqlInsightThresholds.
        :type degradation_in_pct: int

        :param variability:
            The value to assign to the variability property of this SqlInsightThresholds.
        :type variability: float

        :param inefficiency_in_pct:
            The value to assign to the inefficiency_in_pct property of this SqlInsightThresholds.
        :type inefficiency_in_pct: int

        :param increase_in_io_in_pct:
            The value to assign to the increase_in_io_in_pct property of this SqlInsightThresholds.
        :type increase_in_io_in_pct: int

        :param increase_in_cpu_in_pct:
            The value to assign to the increase_in_cpu_in_pct property of this SqlInsightThresholds.
        :type increase_in_cpu_in_pct: int

        :param increase_in_inefficient_wait_in_pct:
            The value to assign to the increase_in_inefficient_wait_in_pct property of this SqlInsightThresholds.
        :type increase_in_inefficient_wait_in_pct: int

        :param improved_in_pct:
            The value to assign to the improved_in_pct property of this SqlInsightThresholds.
        :type improved_in_pct: int

        """
        self.swagger_types = {
            'degradation_in_pct': 'int',
            'variability': 'float',
            'inefficiency_in_pct': 'int',
            'increase_in_io_in_pct': 'int',
            'increase_in_cpu_in_pct': 'int',
            'increase_in_inefficient_wait_in_pct': 'int',
            'improved_in_pct': 'int'
        }

        self.attribute_map = {
            'degradation_in_pct': 'degradationInPct',
            'variability': 'variability',
            'inefficiency_in_pct': 'inefficiencyInPct',
            'increase_in_io_in_pct': 'increaseInIOInPct',
            'increase_in_cpu_in_pct': 'increaseInCPUInPct',
            'increase_in_inefficient_wait_in_pct': 'increaseInInefficientWaitInPct',
            'improved_in_pct': 'improvedInPct'
        }

        self._degradation_in_pct = None
        self._variability = None
        self._inefficiency_in_pct = None
        self._increase_in_io_in_pct = None
        self._increase_in_cpu_in_pct = None
        self._increase_in_inefficient_wait_in_pct = None
        self._improved_in_pct = None

    @property
    def degradation_in_pct(self):
        """
        **[Required]** Gets the degradation_in_pct of this SqlInsightThresholds.
        Degradation Percent Threshold is used to derive degrading SQLs.


        :return: The degradation_in_pct of this SqlInsightThresholds.
        :rtype: int
        """
        return self._degradation_in_pct

    @degradation_in_pct.setter
    def degradation_in_pct(self, degradation_in_pct):
        """
        Sets the degradation_in_pct of this SqlInsightThresholds.
        Degradation Percent Threshold is used to derive degrading SQLs.


        :param degradation_in_pct: The degradation_in_pct of this SqlInsightThresholds.
        :type: int
        """
        self._degradation_in_pct = degradation_in_pct

    @property
    def variability(self):
        """
        **[Required]** Gets the variability of this SqlInsightThresholds.
        Variability Percent Threshold is used to derive variant SQLs.


        :return: The variability of this SqlInsightThresholds.
        :rtype: float
        """
        return self._variability

    @variability.setter
    def variability(self, variability):
        """
        Sets the variability of this SqlInsightThresholds.
        Variability Percent Threshold is used to derive variant SQLs.


        :param variability: The variability of this SqlInsightThresholds.
        :type: float
        """
        self._variability = variability

    @property
    def inefficiency_in_pct(self):
        """
        **[Required]** Gets the inefficiency_in_pct of this SqlInsightThresholds.
        Inefficiency Percent Threshold is used to derive inefficient SQLs.


        :return: The inefficiency_in_pct of this SqlInsightThresholds.
        :rtype: int
        """
        return self._inefficiency_in_pct

    @inefficiency_in_pct.setter
    def inefficiency_in_pct(self, inefficiency_in_pct):
        """
        Sets the inefficiency_in_pct of this SqlInsightThresholds.
        Inefficiency Percent Threshold is used to derive inefficient SQLs.


        :param inefficiency_in_pct: The inefficiency_in_pct of this SqlInsightThresholds.
        :type: int
        """
        self._inefficiency_in_pct = inefficiency_in_pct

    @property
    def increase_in_io_in_pct(self):
        """
        **[Required]** Gets the increase_in_io_in_pct of this SqlInsightThresholds.
        PctIncreaseInIO is used for deriving insights for SQLs which are degrading or
        variant or inefficient. And these SQLs should also have increasing change in IO Time
        beyond threshold. Insights are derived using linear regression.


        :return: The increase_in_io_in_pct of this SqlInsightThresholds.
        :rtype: int
        """
        return self._increase_in_io_in_pct

    @increase_in_io_in_pct.setter
    def increase_in_io_in_pct(self, increase_in_io_in_pct):
        """
        Sets the increase_in_io_in_pct of this SqlInsightThresholds.
        PctIncreaseInIO is used for deriving insights for SQLs which are degrading or
        variant or inefficient. And these SQLs should also have increasing change in IO Time
        beyond threshold. Insights are derived using linear regression.


        :param increase_in_io_in_pct: The increase_in_io_in_pct of this SqlInsightThresholds.
        :type: int
        """
        self._increase_in_io_in_pct = increase_in_io_in_pct

    @property
    def increase_in_cpu_in_pct(self):
        """
        **[Required]** Gets the increase_in_cpu_in_pct of this SqlInsightThresholds.
        PctIncreaseInCPU is used for deriving insights for SQLs which are degrading or
        variant or inefficient. And these SQLs should also have increasing change in CPU Time
        beyond threshold. Insights are derived using linear regression.


        :return: The increase_in_cpu_in_pct of this SqlInsightThresholds.
        :rtype: int
        """
        return self._increase_in_cpu_in_pct

    @increase_in_cpu_in_pct.setter
    def increase_in_cpu_in_pct(self, increase_in_cpu_in_pct):
        """
        Sets the increase_in_cpu_in_pct of this SqlInsightThresholds.
        PctIncreaseInCPU is used for deriving insights for SQLs which are degrading or
        variant or inefficient. And these SQLs should also have increasing change in CPU Time
        beyond threshold. Insights are derived using linear regression.


        :param increase_in_cpu_in_pct: The increase_in_cpu_in_pct of this SqlInsightThresholds.
        :type: int
        """
        self._increase_in_cpu_in_pct = increase_in_cpu_in_pct

    @property
    def increase_in_inefficient_wait_in_pct(self):
        """
        **[Required]** Gets the increase_in_inefficient_wait_in_pct of this SqlInsightThresholds.
        PctIncreaseInIO is used for deriving insights for SQLs which are degrading or
        variant or inefficient. And these SQLs should also have increasing change in
        Other Wait Time beyond threshold. Insights are derived using linear regression.


        :return: The increase_in_inefficient_wait_in_pct of this SqlInsightThresholds.
        :rtype: int
        """
        return self._increase_in_inefficient_wait_in_pct

    @increase_in_inefficient_wait_in_pct.setter
    def increase_in_inefficient_wait_in_pct(self, increase_in_inefficient_wait_in_pct):
        """
        Sets the increase_in_inefficient_wait_in_pct of this SqlInsightThresholds.
        PctIncreaseInIO is used for deriving insights for SQLs which are degrading or
        variant or inefficient. And these SQLs should also have increasing change in
        Other Wait Time beyond threshold. Insights are derived using linear regression.


        :param increase_in_inefficient_wait_in_pct: The increase_in_inefficient_wait_in_pct of this SqlInsightThresholds.
        :type: int
        """
        self._increase_in_inefficient_wait_in_pct = increase_in_inefficient_wait_in_pct

    @property
    def improved_in_pct(self):
        """
        **[Required]** Gets the improved_in_pct of this SqlInsightThresholds.
        Improved Percent Threshold is used to derive improving SQLs.


        :return: The improved_in_pct of this SqlInsightThresholds.
        :rtype: int
        """
        return self._improved_in_pct

    @improved_in_pct.setter
    def improved_in_pct(self, improved_in_pct):
        """
        Sets the improved_in_pct of this SqlInsightThresholds.
        Improved Percent Threshold is used to derive improving SQLs.


        :param improved_in_pct: The improved_in_pct of this SqlInsightThresholds.
        :type: int
        """
        self._improved_in_pct = improved_in_pct

    def __repr__(self):
        return formatted_flat_dict(self)

    def __eq__(self, other):
        if other is None:
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not self == other
