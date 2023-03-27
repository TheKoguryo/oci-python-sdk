# coding: utf-8
# Copyright (c) 2016, 2023, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.


from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class AuthenticationFactorSettingsCompliancePolicy(object):
    """
    Compliance Policy that defines actions to be taken when a condition is violated
    """

    #: A constant which can be used with the action property of a AuthenticationFactorSettingsCompliancePolicy.
    #: This constant has a value of "Allow"
    ACTION_ALLOW = "Allow"

    #: A constant which can be used with the action property of a AuthenticationFactorSettingsCompliancePolicy.
    #: This constant has a value of "Block"
    ACTION_BLOCK = "Block"

    #: A constant which can be used with the action property of a AuthenticationFactorSettingsCompliancePolicy.
    #: This constant has a value of "Notify"
    ACTION_NOTIFY = "Notify"

    #: A constant which can be used with the action property of a AuthenticationFactorSettingsCompliancePolicy.
    #: This constant has a value of "None"
    ACTION_NONE = "None"

    def __init__(self, **kwargs):
        """
        Initializes a new AuthenticationFactorSettingsCompliancePolicy object with values from keyword arguments.
        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param name:
            The value to assign to the name property of this AuthenticationFactorSettingsCompliancePolicy.
        :type name: str

        :param action:
            The value to assign to the action property of this AuthenticationFactorSettingsCompliancePolicy.
            Allowed values for this property are: "Allow", "Block", "Notify", "None", 'UNKNOWN_ENUM_VALUE'.
            Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.
        :type action: str

        :param value:
            The value to assign to the value property of this AuthenticationFactorSettingsCompliancePolicy.
        :type value: str

        """
        self.swagger_types = {
            'name': 'str',
            'action': 'str',
            'value': 'str'
        }

        self.attribute_map = {
            'name': 'name',
            'action': 'action',
            'value': 'value'
        }

        self._name = None
        self._action = None
        self._value = None

    @property
    def name(self):
        """
        **[Required]** Gets the name of this AuthenticationFactorSettingsCompliancePolicy.
        The name of the attribute being evaluated

        **SCIM++ Properties:**
         - idcsSearchable: false
         - multiValued: false
         - mutability: readWrite
         - required: true
         - returned: default
         - type: string
         - uniqueness: none


        :return: The name of this AuthenticationFactorSettingsCompliancePolicy.
        :rtype: str
        """
        return self._name

    @name.setter
    def name(self, name):
        """
        Sets the name of this AuthenticationFactorSettingsCompliancePolicy.
        The name of the attribute being evaluated

        **SCIM++ Properties:**
         - idcsSearchable: false
         - multiValued: false
         - mutability: readWrite
         - required: true
         - returned: default
         - type: string
         - uniqueness: none


        :param name: The name of this AuthenticationFactorSettingsCompliancePolicy.
        :type: str
        """
        self._name = name

    @property
    def action(self):
        """
        **[Required]** Gets the action of this AuthenticationFactorSettingsCompliancePolicy.
        The action to be taken if the value of the attribute is not as expected

        **SCIM++ Properties:**
         - idcsSearchable: false
         - multiValued: false
         - mutability: readWrite
         - required: true
         - returned: default
         - type: string
         - uniqueness: none

        Allowed values for this property are: "Allow", "Block", "Notify", "None", 'UNKNOWN_ENUM_VALUE'.
        Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.


        :return: The action of this AuthenticationFactorSettingsCompliancePolicy.
        :rtype: str
        """
        return self._action

    @action.setter
    def action(self, action):
        """
        Sets the action of this AuthenticationFactorSettingsCompliancePolicy.
        The action to be taken if the value of the attribute is not as expected

        **SCIM++ Properties:**
         - idcsSearchable: false
         - multiValued: false
         - mutability: readWrite
         - required: true
         - returned: default
         - type: string
         - uniqueness: none


        :param action: The action of this AuthenticationFactorSettingsCompliancePolicy.
        :type: str
        """
        allowed_values = ["Allow", "Block", "Notify", "None"]
        if not value_allowed_none_or_none_sentinel(action, allowed_values):
            action = 'UNKNOWN_ENUM_VALUE'
        self._action = action

    @property
    def value(self):
        """
        **[Required]** Gets the value of this AuthenticationFactorSettingsCompliancePolicy.
        The value of the attribute to be evaluated

        **SCIM++ Properties:**
         - idcsSearchable: false
         - multiValued: false
         - mutability: readWrite
         - required: true
         - returned: default
         - type: string
         - uniqueness: none


        :return: The value of this AuthenticationFactorSettingsCompliancePolicy.
        :rtype: str
        """
        return self._value

    @value.setter
    def value(self, value):
        """
        Sets the value of this AuthenticationFactorSettingsCompliancePolicy.
        The value of the attribute to be evaluated

        **SCIM++ Properties:**
         - idcsSearchable: false
         - multiValued: false
         - mutability: readWrite
         - required: true
         - returned: default
         - type: string
         - uniqueness: none


        :param value: The value of this AuthenticationFactorSettingsCompliancePolicy.
        :type: str
        """
        self._value = value

    def __repr__(self):
        return formatted_flat_dict(self)

    def __eq__(self, other):
        if other is None:
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not self == other
