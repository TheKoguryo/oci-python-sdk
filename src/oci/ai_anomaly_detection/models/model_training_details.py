# coding: utf-8
# Copyright (c) 2016, 2023, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.


from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class ModelTrainingDetails(object):
    """
    Specifies the details of the MSET model during the create call.
    """

    #: A constant which can be used with the algorithm_hint property of a ModelTrainingDetails.
    #: This constant has a value of "MULTIVARIATE_MSET"
    ALGORITHM_HINT_MULTIVARIATE_MSET = "MULTIVARIATE_MSET"

    #: A constant which can be used with the algorithm_hint property of a ModelTrainingDetails.
    #: This constant has a value of "UNIVARIATE_OCSVM"
    ALGORITHM_HINT_UNIVARIATE_OCSVM = "UNIVARIATE_OCSVM"

    def __init__(self, **kwargs):
        """
        Initializes a new ModelTrainingDetails object with values from keyword arguments.
        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param algorithm_hint:
            The value to assign to the algorithm_hint property of this ModelTrainingDetails.
            Allowed values for this property are: "MULTIVARIATE_MSET", "UNIVARIATE_OCSVM", 'UNKNOWN_ENUM_VALUE'.
            Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.
        :type algorithm_hint: str

        :param target_fap:
            The value to assign to the target_fap property of this ModelTrainingDetails.
        :type target_fap: float

        :param training_fraction:
            The value to assign to the training_fraction property of this ModelTrainingDetails.
        :type training_fraction: float

        :param window_size:
            The value to assign to the window_size property of this ModelTrainingDetails.
        :type window_size: int

        :param data_asset_ids:
            The value to assign to the data_asset_ids property of this ModelTrainingDetails.
        :type data_asset_ids: list[str]

        """
        self.swagger_types = {
            'algorithm_hint': 'str',
            'target_fap': 'float',
            'training_fraction': 'float',
            'window_size': 'int',
            'data_asset_ids': 'list[str]'
        }

        self.attribute_map = {
            'algorithm_hint': 'algorithmHint',
            'target_fap': 'targetFap',
            'training_fraction': 'trainingFraction',
            'window_size': 'windowSize',
            'data_asset_ids': 'dataAssetIds'
        }

        self._algorithm_hint = None
        self._target_fap = None
        self._training_fraction = None
        self._window_size = None
        self._data_asset_ids = None

    @property
    def algorithm_hint(self):
        """
        Gets the algorithm_hint of this ModelTrainingDetails.
        User can choose specific algorithm for training.

        Allowed values for this property are: "MULTIVARIATE_MSET", "UNIVARIATE_OCSVM", 'UNKNOWN_ENUM_VALUE'.
        Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.


        :return: The algorithm_hint of this ModelTrainingDetails.
        :rtype: str
        """
        return self._algorithm_hint

    @algorithm_hint.setter
    def algorithm_hint(self, algorithm_hint):
        """
        Sets the algorithm_hint of this ModelTrainingDetails.
        User can choose specific algorithm for training.


        :param algorithm_hint: The algorithm_hint of this ModelTrainingDetails.
        :type: str
        """
        allowed_values = ["MULTIVARIATE_MSET", "UNIVARIATE_OCSVM"]
        if not value_allowed_none_or_none_sentinel(algorithm_hint, allowed_values):
            algorithm_hint = 'UNKNOWN_ENUM_VALUE'
        self._algorithm_hint = algorithm_hint

    @property
    def target_fap(self):
        """
        Gets the target_fap of this ModelTrainingDetails.
        A target model accuracy metric user provides as their requirement


        :return: The target_fap of this ModelTrainingDetails.
        :rtype: float
        """
        return self._target_fap

    @target_fap.setter
    def target_fap(self, target_fap):
        """
        Sets the target_fap of this ModelTrainingDetails.
        A target model accuracy metric user provides as their requirement


        :param target_fap: The target_fap of this ModelTrainingDetails.
        :type: float
        """
        self._target_fap = target_fap

    @property
    def training_fraction(self):
        """
        Gets the training_fraction of this ModelTrainingDetails.
        Fraction of total data that is used for training the model. The remaining is used for validation of the model.


        :return: The training_fraction of this ModelTrainingDetails.
        :rtype: float
        """
        return self._training_fraction

    @training_fraction.setter
    def training_fraction(self, training_fraction):
        """
        Sets the training_fraction of this ModelTrainingDetails.
        Fraction of total data that is used for training the model. The remaining is used for validation of the model.


        :param training_fraction: The training_fraction of this ModelTrainingDetails.
        :type: float
        """
        self._training_fraction = training_fraction

    @property
    def window_size(self):
        """
        Gets the window_size of this ModelTrainingDetails.
        This value would determine the window size of the training algorithm.


        :return: The window_size of this ModelTrainingDetails.
        :rtype: int
        """
        return self._window_size

    @window_size.setter
    def window_size(self, window_size):
        """
        Sets the window_size of this ModelTrainingDetails.
        This value would determine the window size of the training algorithm.


        :param window_size: The window_size of this ModelTrainingDetails.
        :type: int
        """
        self._window_size = window_size

    @property
    def data_asset_ids(self):
        """
        **[Required]** Gets the data_asset_ids of this ModelTrainingDetails.
        The list of OCIDs of the data assets to train the model. The dataAssets have to be in the same project where the ai model would reside.


        :return: The data_asset_ids of this ModelTrainingDetails.
        :rtype: list[str]
        """
        return self._data_asset_ids

    @data_asset_ids.setter
    def data_asset_ids(self, data_asset_ids):
        """
        Sets the data_asset_ids of this ModelTrainingDetails.
        The list of OCIDs of the data assets to train the model. The dataAssets have to be in the same project where the ai model would reside.


        :param data_asset_ids: The data_asset_ids of this ModelTrainingDetails.
        :type: list[str]
        """
        self._data_asset_ids = data_asset_ids

    def __repr__(self):
        return formatted_flat_dict(self)

    def __eq__(self, other):
        if other is None:
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not self == other
