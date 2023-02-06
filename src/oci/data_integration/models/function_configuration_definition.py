# coding: utf-8
# Copyright (c) 2016, 2023, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.


from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class FunctionConfigurationDefinition(object):
    """
    The configuration details of a configurable object. This contains one or more config param definitions.
    """

    #: A constant which can be used with the model_type property of a FunctionConfigurationDefinition.
    #: This constant has a value of "CONFIG_DEFINITION"
    MODEL_TYPE_CONFIG_DEFINITION = "CONFIG_DEFINITION"

    def __init__(self, **kwargs):
        """
        Initializes a new FunctionConfigurationDefinition object with values from keyword arguments.
        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param key:
            The value to assign to the key property of this FunctionConfigurationDefinition.
        :type key: str

        :param model_type:
            The value to assign to the model_type property of this FunctionConfigurationDefinition.
            Allowed values for this property are: "CONFIG_DEFINITION", 'UNKNOWN_ENUM_VALUE'.
            Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.
        :type model_type: str

        :param model_version:
            The value to assign to the model_version property of this FunctionConfigurationDefinition.
        :type model_version: str

        :param parent_ref:
            The value to assign to the parent_ref property of this FunctionConfigurationDefinition.
        :type parent_ref: oci.data_integration.models.ParentReference

        :param is_contained:
            The value to assign to the is_contained property of this FunctionConfigurationDefinition.
        :type is_contained: bool

        :param config_param_defs:
            The value to assign to the config_param_defs property of this FunctionConfigurationDefinition.
        :type config_param_defs: dict(str, ConfigParameterDefinition)

        """
        self.swagger_types = {
            'key': 'str',
            'model_type': 'str',
            'model_version': 'str',
            'parent_ref': 'ParentReference',
            'is_contained': 'bool',
            'config_param_defs': 'dict(str, ConfigParameterDefinition)'
        }

        self.attribute_map = {
            'key': 'key',
            'model_type': 'modelType',
            'model_version': 'modelVersion',
            'parent_ref': 'parentRef',
            'is_contained': 'isContained',
            'config_param_defs': 'configParamDefs'
        }

        self._key = None
        self._model_type = None
        self._model_version = None
        self._parent_ref = None
        self._is_contained = None
        self._config_param_defs = None

    @property
    def key(self):
        """
        Gets the key of this FunctionConfigurationDefinition.
        The key of the object.


        :return: The key of this FunctionConfigurationDefinition.
        :rtype: str
        """
        return self._key

    @key.setter
    def key(self, key):
        """
        Sets the key of this FunctionConfigurationDefinition.
        The key of the object.


        :param key: The key of this FunctionConfigurationDefinition.
        :type: str
        """
        self._key = key

    @property
    def model_type(self):
        """
        Gets the model_type of this FunctionConfigurationDefinition.
        The type of the object.

        Allowed values for this property are: "CONFIG_DEFINITION", 'UNKNOWN_ENUM_VALUE'.
        Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.


        :return: The model_type of this FunctionConfigurationDefinition.
        :rtype: str
        """
        return self._model_type

    @model_type.setter
    def model_type(self, model_type):
        """
        Sets the model_type of this FunctionConfigurationDefinition.
        The type of the object.


        :param model_type: The model_type of this FunctionConfigurationDefinition.
        :type: str
        """
        allowed_values = ["CONFIG_DEFINITION"]
        if not value_allowed_none_or_none_sentinel(model_type, allowed_values):
            model_type = 'UNKNOWN_ENUM_VALUE'
        self._model_type = model_type

    @property
    def model_version(self):
        """
        Gets the model_version of this FunctionConfigurationDefinition.
        The model version of an object.


        :return: The model_version of this FunctionConfigurationDefinition.
        :rtype: str
        """
        return self._model_version

    @model_version.setter
    def model_version(self, model_version):
        """
        Sets the model_version of this FunctionConfigurationDefinition.
        The model version of an object.


        :param model_version: The model_version of this FunctionConfigurationDefinition.
        :type: str
        """
        self._model_version = model_version

    @property
    def parent_ref(self):
        """
        Gets the parent_ref of this FunctionConfigurationDefinition.

        :return: The parent_ref of this FunctionConfigurationDefinition.
        :rtype: oci.data_integration.models.ParentReference
        """
        return self._parent_ref

    @parent_ref.setter
    def parent_ref(self, parent_ref):
        """
        Sets the parent_ref of this FunctionConfigurationDefinition.

        :param parent_ref: The parent_ref of this FunctionConfigurationDefinition.
        :type: oci.data_integration.models.ParentReference
        """
        self._parent_ref = parent_ref

    @property
    def is_contained(self):
        """
        Gets the is_contained of this FunctionConfigurationDefinition.
        Specifies whether the configuration is contained or not.


        :return: The is_contained of this FunctionConfigurationDefinition.
        :rtype: bool
        """
        return self._is_contained

    @is_contained.setter
    def is_contained(self, is_contained):
        """
        Sets the is_contained of this FunctionConfigurationDefinition.
        Specifies whether the configuration is contained or not.


        :param is_contained: The is_contained of this FunctionConfigurationDefinition.
        :type: bool
        """
        self._is_contained = is_contained

    @property
    def config_param_defs(self):
        """
        Gets the config_param_defs of this FunctionConfigurationDefinition.
        The parameter configuration details.


        :return: The config_param_defs of this FunctionConfigurationDefinition.
        :rtype: dict(str, ConfigParameterDefinition)
        """
        return self._config_param_defs

    @config_param_defs.setter
    def config_param_defs(self, config_param_defs):
        """
        Sets the config_param_defs of this FunctionConfigurationDefinition.
        The parameter configuration details.


        :param config_param_defs: The config_param_defs of this FunctionConfigurationDefinition.
        :type: dict(str, ConfigParameterDefinition)
        """
        self._config_param_defs = config_param_defs

    def __repr__(self):
        return formatted_flat_dict(self)

    def __eq__(self, other):
        if other is None:
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not self == other
