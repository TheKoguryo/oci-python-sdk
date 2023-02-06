# coding: utf-8
# Copyright (c) 2016, 2023, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.


from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class LimitDefinitionSummary(object):
    """
    The metadata specific to a resource limit definition.
    """

    #: A constant which can be used with the scope_type property of a LimitDefinitionSummary.
    #: This constant has a value of "GLOBAL"
    SCOPE_TYPE_GLOBAL = "GLOBAL"

    #: A constant which can be used with the scope_type property of a LimitDefinitionSummary.
    #: This constant has a value of "REGION"
    SCOPE_TYPE_REGION = "REGION"

    #: A constant which can be used with the scope_type property of a LimitDefinitionSummary.
    #: This constant has a value of "AD"
    SCOPE_TYPE_AD = "AD"

    def __init__(self, **kwargs):
        """
        Initializes a new LimitDefinitionSummary object with values from keyword arguments.
        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param name:
            The value to assign to the name property of this LimitDefinitionSummary.
        :type name: str

        :param service_name:
            The value to assign to the service_name property of this LimitDefinitionSummary.
        :type service_name: str

        :param description:
            The value to assign to the description property of this LimitDefinitionSummary.
        :type description: str

        :param scope_type:
            The value to assign to the scope_type property of this LimitDefinitionSummary.
            Allowed values for this property are: "GLOBAL", "REGION", "AD", 'UNKNOWN_ENUM_VALUE'.
            Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.
        :type scope_type: str

        :param are_quotas_supported:
            The value to assign to the are_quotas_supported property of this LimitDefinitionSummary.
        :type are_quotas_supported: bool

        :param is_resource_availability_supported:
            The value to assign to the is_resource_availability_supported property of this LimitDefinitionSummary.
        :type is_resource_availability_supported: bool

        :param is_deprecated:
            The value to assign to the is_deprecated property of this LimitDefinitionSummary.
        :type is_deprecated: bool

        :param is_eligible_for_limit_increase:
            The value to assign to the is_eligible_for_limit_increase property of this LimitDefinitionSummary.
        :type is_eligible_for_limit_increase: bool

        :param is_dynamic:
            The value to assign to the is_dynamic property of this LimitDefinitionSummary.
        :type is_dynamic: bool

        """
        self.swagger_types = {
            'name': 'str',
            'service_name': 'str',
            'description': 'str',
            'scope_type': 'str',
            'are_quotas_supported': 'bool',
            'is_resource_availability_supported': 'bool',
            'is_deprecated': 'bool',
            'is_eligible_for_limit_increase': 'bool',
            'is_dynamic': 'bool'
        }

        self.attribute_map = {
            'name': 'name',
            'service_name': 'serviceName',
            'description': 'description',
            'scope_type': 'scopeType',
            'are_quotas_supported': 'areQuotasSupported',
            'is_resource_availability_supported': 'isResourceAvailabilitySupported',
            'is_deprecated': 'isDeprecated',
            'is_eligible_for_limit_increase': 'isEligibleForLimitIncrease',
            'is_dynamic': 'isDynamic'
        }

        self._name = None
        self._service_name = None
        self._description = None
        self._scope_type = None
        self._are_quotas_supported = None
        self._is_resource_availability_supported = None
        self._is_deprecated = None
        self._is_eligible_for_limit_increase = None
        self._is_dynamic = None

    @property
    def name(self):
        """
        Gets the name of this LimitDefinitionSummary.
        The resource limit name. To be used for writing policies (in case of quotas) or other programmatic calls.


        :return: The name of this LimitDefinitionSummary.
        :rtype: str
        """
        return self._name

    @name.setter
    def name(self, name):
        """
        Sets the name of this LimitDefinitionSummary.
        The resource limit name. To be used for writing policies (in case of quotas) or other programmatic calls.


        :param name: The name of this LimitDefinitionSummary.
        :type: str
        """
        self._name = name

    @property
    def service_name(self):
        """
        Gets the service_name of this LimitDefinitionSummary.
        The service name of the limit.


        :return: The service_name of this LimitDefinitionSummary.
        :rtype: str
        """
        return self._service_name

    @service_name.setter
    def service_name(self, service_name):
        """
        Sets the service_name of this LimitDefinitionSummary.
        The service name of the limit.


        :param service_name: The service_name of this LimitDefinitionSummary.
        :type: str
        """
        self._service_name = service_name

    @property
    def description(self):
        """
        Gets the description of this LimitDefinitionSummary.
        The limit description.


        :return: The description of this LimitDefinitionSummary.
        :rtype: str
        """
        return self._description

    @description.setter
    def description(self, description):
        """
        Sets the description of this LimitDefinitionSummary.
        The limit description.


        :param description: The description of this LimitDefinitionSummary.
        :type: str
        """
        self._description = description

    @property
    def scope_type(self):
        """
        Gets the scope_type of this LimitDefinitionSummary.
        Reflects the scope of the resource limit, whether Global (across all regions), regional, or availability domain-specific.

        Allowed values for this property are: "GLOBAL", "REGION", "AD", 'UNKNOWN_ENUM_VALUE'.
        Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.


        :return: The scope_type of this LimitDefinitionSummary.
        :rtype: str
        """
        return self._scope_type

    @scope_type.setter
    def scope_type(self, scope_type):
        """
        Sets the scope_type of this LimitDefinitionSummary.
        Reflects the scope of the resource limit, whether Global (across all regions), regional, or availability domain-specific.


        :param scope_type: The scope_type of this LimitDefinitionSummary.
        :type: str
        """
        allowed_values = ["GLOBAL", "REGION", "AD"]
        if not value_allowed_none_or_none_sentinel(scope_type, allowed_values):
            scope_type = 'UNKNOWN_ENUM_VALUE'
        self._scope_type = scope_type

    @property
    def are_quotas_supported(self):
        """
        Gets the are_quotas_supported of this LimitDefinitionSummary.
        If true, quota policies can be created on top of this resource limit.


        :return: The are_quotas_supported of this LimitDefinitionSummary.
        :rtype: bool
        """
        return self._are_quotas_supported

    @are_quotas_supported.setter
    def are_quotas_supported(self, are_quotas_supported):
        """
        Sets the are_quotas_supported of this LimitDefinitionSummary.
        If true, quota policies can be created on top of this resource limit.


        :param are_quotas_supported: The are_quotas_supported of this LimitDefinitionSummary.
        :type: bool
        """
        self._are_quotas_supported = are_quotas_supported

    @property
    def is_resource_availability_supported(self):
        """
        Gets the is_resource_availability_supported of this LimitDefinitionSummary.
        Reflects whether or not the GetResourceAvailability API is supported for this limit.
        If not, the API returns an empty JSON response.


        :return: The is_resource_availability_supported of this LimitDefinitionSummary.
        :rtype: bool
        """
        return self._is_resource_availability_supported

    @is_resource_availability_supported.setter
    def is_resource_availability_supported(self, is_resource_availability_supported):
        """
        Sets the is_resource_availability_supported of this LimitDefinitionSummary.
        Reflects whether or not the GetResourceAvailability API is supported for this limit.
        If not, the API returns an empty JSON response.


        :param is_resource_availability_supported: The is_resource_availability_supported of this LimitDefinitionSummary.
        :type: bool
        """
        self._is_resource_availability_supported = is_resource_availability_supported

    @property
    def is_deprecated(self):
        """
        Gets the is_deprecated of this LimitDefinitionSummary.
        Indicates if the limit has been deprecated.


        :return: The is_deprecated of this LimitDefinitionSummary.
        :rtype: bool
        """
        return self._is_deprecated

    @is_deprecated.setter
    def is_deprecated(self, is_deprecated):
        """
        Sets the is_deprecated of this LimitDefinitionSummary.
        Indicates if the limit has been deprecated.


        :param is_deprecated: The is_deprecated of this LimitDefinitionSummary.
        :type: bool
        """
        self._is_deprecated = is_deprecated

    @property
    def is_eligible_for_limit_increase(self):
        """
        Gets the is_eligible_for_limit_increase of this LimitDefinitionSummary.
        Indicates if the customer can request a limit increase for this resource.


        :return: The is_eligible_for_limit_increase of this LimitDefinitionSummary.
        :rtype: bool
        """
        return self._is_eligible_for_limit_increase

    @is_eligible_for_limit_increase.setter
    def is_eligible_for_limit_increase(self, is_eligible_for_limit_increase):
        """
        Sets the is_eligible_for_limit_increase of this LimitDefinitionSummary.
        Indicates if the customer can request a limit increase for this resource.


        :param is_eligible_for_limit_increase: The is_eligible_for_limit_increase of this LimitDefinitionSummary.
        :type: bool
        """
        self._is_eligible_for_limit_increase = is_eligible_for_limit_increase

    @property
    def is_dynamic(self):
        """
        Gets the is_dynamic of this LimitDefinitionSummary.
        The limit for this resource has a dynamic value that is based on consumption across all OCI services.


        :return: The is_dynamic of this LimitDefinitionSummary.
        :rtype: bool
        """
        return self._is_dynamic

    @is_dynamic.setter
    def is_dynamic(self, is_dynamic):
        """
        Sets the is_dynamic of this LimitDefinitionSummary.
        The limit for this resource has a dynamic value that is based on consumption across all OCI services.


        :param is_dynamic: The is_dynamic of this LimitDefinitionSummary.
        :type: bool
        """
        self._is_dynamic = is_dynamic

    def __repr__(self):
        return formatted_flat_dict(self)

    def __eq__(self, other):
        if other is None:
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not self == other
