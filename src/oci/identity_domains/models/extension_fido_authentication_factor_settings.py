# coding: utf-8
# Copyright (c) 2016, 2023, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.


from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class ExtensionFidoAuthenticationFactorSettings(object):
    """
    This extension defines attributes used to manage Multi-Factor Authentication settings of fido authentication
    """

    #: A constant which can be used with the attestation property of a ExtensionFidoAuthenticationFactorSettings.
    #: This constant has a value of "NONE"
    ATTESTATION_NONE = "NONE"

    #: A constant which can be used with the attestation property of a ExtensionFidoAuthenticationFactorSettings.
    #: This constant has a value of "DIRECT"
    ATTESTATION_DIRECT = "DIRECT"

    #: A constant which can be used with the attestation property of a ExtensionFidoAuthenticationFactorSettings.
    #: This constant has a value of "INDIRECT"
    ATTESTATION_INDIRECT = "INDIRECT"

    #: A constant which can be used with the authenticator_selection_attachment property of a ExtensionFidoAuthenticationFactorSettings.
    #: This constant has a value of "PLATFORM"
    AUTHENTICATOR_SELECTION_ATTACHMENT_PLATFORM = "PLATFORM"

    #: A constant which can be used with the authenticator_selection_attachment property of a ExtensionFidoAuthenticationFactorSettings.
    #: This constant has a value of "CROSS-PLATFORM"
    AUTHENTICATOR_SELECTION_ATTACHMENT_CROSS_PLATFORM = "CROSS-PLATFORM"

    #: A constant which can be used with the authenticator_selection_attachment property of a ExtensionFidoAuthenticationFactorSettings.
    #: This constant has a value of "BOTH"
    AUTHENTICATOR_SELECTION_ATTACHMENT_BOTH = "BOTH"

    #: A constant which can be used with the authenticator_selection_user_verification property of a ExtensionFidoAuthenticationFactorSettings.
    #: This constant has a value of "REQUIRED"
    AUTHENTICATOR_SELECTION_USER_VERIFICATION_REQUIRED = "REQUIRED"

    #: A constant which can be used with the authenticator_selection_user_verification property of a ExtensionFidoAuthenticationFactorSettings.
    #: This constant has a value of "PREFERRED"
    AUTHENTICATOR_SELECTION_USER_VERIFICATION_PREFERRED = "PREFERRED"

    #: A constant which can be used with the authenticator_selection_user_verification property of a ExtensionFidoAuthenticationFactorSettings.
    #: This constant has a value of "DISCOURAGED"
    AUTHENTICATOR_SELECTION_USER_VERIFICATION_DISCOURAGED = "DISCOURAGED"

    #: A constant which can be used with the authenticator_selection_resident_key property of a ExtensionFidoAuthenticationFactorSettings.
    #: This constant has a value of "REQUIRED"
    AUTHENTICATOR_SELECTION_RESIDENT_KEY_REQUIRED = "REQUIRED"

    #: A constant which can be used with the authenticator_selection_resident_key property of a ExtensionFidoAuthenticationFactorSettings.
    #: This constant has a value of "PREFERRED"
    AUTHENTICATOR_SELECTION_RESIDENT_KEY_PREFERRED = "PREFERRED"

    #: A constant which can be used with the authenticator_selection_resident_key property of a ExtensionFidoAuthenticationFactorSettings.
    #: This constant has a value of "DISCOURAGED"
    AUTHENTICATOR_SELECTION_RESIDENT_KEY_DISCOURAGED = "DISCOURAGED"

    #: A constant which can be used with the authenticator_selection_resident_key property of a ExtensionFidoAuthenticationFactorSettings.
    #: This constant has a value of "NONE"
    AUTHENTICATOR_SELECTION_RESIDENT_KEY_NONE = "NONE"

    #: A constant which can be used with the public_key_types property of a ExtensionFidoAuthenticationFactorSettings.
    #: This constant has a value of "RS1"
    PUBLIC_KEY_TYPES_RS1 = "RS1"

    #: A constant which can be used with the public_key_types property of a ExtensionFidoAuthenticationFactorSettings.
    #: This constant has a value of "RS256"
    PUBLIC_KEY_TYPES_RS256 = "RS256"

    #: A constant which can be used with the public_key_types property of a ExtensionFidoAuthenticationFactorSettings.
    #: This constant has a value of "ES256"
    PUBLIC_KEY_TYPES_ES256 = "ES256"

    def __init__(self, **kwargs):
        """
        Initializes a new ExtensionFidoAuthenticationFactorSettings object with values from keyword arguments.
        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param attestation:
            The value to assign to the attestation property of this ExtensionFidoAuthenticationFactorSettings.
            Allowed values for this property are: "NONE", "DIRECT", "INDIRECT", 'UNKNOWN_ENUM_VALUE'.
            Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.
        :type attestation: str

        :param authenticator_selection_attachment:
            The value to assign to the authenticator_selection_attachment property of this ExtensionFidoAuthenticationFactorSettings.
            Allowed values for this property are: "PLATFORM", "CROSS-PLATFORM", "BOTH", 'UNKNOWN_ENUM_VALUE'.
            Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.
        :type authenticator_selection_attachment: str

        :param authenticator_selection_user_verification:
            The value to assign to the authenticator_selection_user_verification property of this ExtensionFidoAuthenticationFactorSettings.
            Allowed values for this property are: "REQUIRED", "PREFERRED", "DISCOURAGED", 'UNKNOWN_ENUM_VALUE'.
            Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.
        :type authenticator_selection_user_verification: str

        :param authenticator_selection_resident_key:
            The value to assign to the authenticator_selection_resident_key property of this ExtensionFidoAuthenticationFactorSettings.
            Allowed values for this property are: "REQUIRED", "PREFERRED", "DISCOURAGED", "NONE", 'UNKNOWN_ENUM_VALUE'.
            Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.
        :type authenticator_selection_resident_key: str

        :param timeout:
            The value to assign to the timeout property of this ExtensionFidoAuthenticationFactorSettings.
        :type timeout: int

        :param authenticator_selection_require_resident_key:
            The value to assign to the authenticator_selection_require_resident_key property of this ExtensionFidoAuthenticationFactorSettings.
        :type authenticator_selection_require_resident_key: bool

        :param public_key_types:
            The value to assign to the public_key_types property of this ExtensionFidoAuthenticationFactorSettings.
            Allowed values for items in this list are: "RS1", "RS256", "ES256", 'UNKNOWN_ENUM_VALUE'.
            Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.
        :type public_key_types: list[str]

        :param exclude_credentials:
            The value to assign to the exclude_credentials property of this ExtensionFidoAuthenticationFactorSettings.
        :type exclude_credentials: bool

        :param domain_validation_level:
            The value to assign to the domain_validation_level property of this ExtensionFidoAuthenticationFactorSettings.
        :type domain_validation_level: int

        """
        self.swagger_types = {
            'attestation': 'str',
            'authenticator_selection_attachment': 'str',
            'authenticator_selection_user_verification': 'str',
            'authenticator_selection_resident_key': 'str',
            'timeout': 'int',
            'authenticator_selection_require_resident_key': 'bool',
            'public_key_types': 'list[str]',
            'exclude_credentials': 'bool',
            'domain_validation_level': 'int'
        }

        self.attribute_map = {
            'attestation': 'attestation',
            'authenticator_selection_attachment': 'authenticatorSelectionAttachment',
            'authenticator_selection_user_verification': 'authenticatorSelectionUserVerification',
            'authenticator_selection_resident_key': 'authenticatorSelectionResidentKey',
            'timeout': 'timeout',
            'authenticator_selection_require_resident_key': 'authenticatorSelectionRequireResidentKey',
            'public_key_types': 'publicKeyTypes',
            'exclude_credentials': 'excludeCredentials',
            'domain_validation_level': 'domainValidationLevel'
        }

        self._attestation = None
        self._authenticator_selection_attachment = None
        self._authenticator_selection_user_verification = None
        self._authenticator_selection_resident_key = None
        self._timeout = None
        self._authenticator_selection_require_resident_key = None
        self._public_key_types = None
        self._exclude_credentials = None
        self._domain_validation_level = None

    @property
    def attestation(self):
        """
        **[Required]** Gets the attestation of this ExtensionFidoAuthenticationFactorSettings.
        Attribute used to define the type of attestation required.

        **Added In:** 2009232244

        **SCIM++ Properties:**
         - idcsSearchable: false
         - multiValued: false
         - mutability: readWrite
         - required: true
         - returned: default
         - type: string
         - uniqueness: none

        Allowed values for this property are: "NONE", "DIRECT", "INDIRECT", 'UNKNOWN_ENUM_VALUE'.
        Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.


        :return: The attestation of this ExtensionFidoAuthenticationFactorSettings.
        :rtype: str
        """
        return self._attestation

    @attestation.setter
    def attestation(self, attestation):
        """
        Sets the attestation of this ExtensionFidoAuthenticationFactorSettings.
        Attribute used to define the type of attestation required.

        **Added In:** 2009232244

        **SCIM++ Properties:**
         - idcsSearchable: false
         - multiValued: false
         - mutability: readWrite
         - required: true
         - returned: default
         - type: string
         - uniqueness: none


        :param attestation: The attestation of this ExtensionFidoAuthenticationFactorSettings.
        :type: str
        """
        allowed_values = ["NONE", "DIRECT", "INDIRECT"]
        if not value_allowed_none_or_none_sentinel(attestation, allowed_values):
            attestation = 'UNKNOWN_ENUM_VALUE'
        self._attestation = attestation

    @property
    def authenticator_selection_attachment(self):
        """
        **[Required]** Gets the authenticator_selection_attachment of this ExtensionFidoAuthenticationFactorSettings.
        Attribute used to define authenticator selection attachment.

        **Added In:** 2009232244

        **SCIM++ Properties:**
         - idcsSearchable: false
         - multiValued: false
         - mutability: readWrite
         - required: true
         - returned: default
         - type: string
         - uniqueness: none

        Allowed values for this property are: "PLATFORM", "CROSS-PLATFORM", "BOTH", 'UNKNOWN_ENUM_VALUE'.
        Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.


        :return: The authenticator_selection_attachment of this ExtensionFidoAuthenticationFactorSettings.
        :rtype: str
        """
        return self._authenticator_selection_attachment

    @authenticator_selection_attachment.setter
    def authenticator_selection_attachment(self, authenticator_selection_attachment):
        """
        Sets the authenticator_selection_attachment of this ExtensionFidoAuthenticationFactorSettings.
        Attribute used to define authenticator selection attachment.

        **Added In:** 2009232244

        **SCIM++ Properties:**
         - idcsSearchable: false
         - multiValued: false
         - mutability: readWrite
         - required: true
         - returned: default
         - type: string
         - uniqueness: none


        :param authenticator_selection_attachment: The authenticator_selection_attachment of this ExtensionFidoAuthenticationFactorSettings.
        :type: str
        """
        allowed_values = ["PLATFORM", "CROSS-PLATFORM", "BOTH"]
        if not value_allowed_none_or_none_sentinel(authenticator_selection_attachment, allowed_values):
            authenticator_selection_attachment = 'UNKNOWN_ENUM_VALUE'
        self._authenticator_selection_attachment = authenticator_selection_attachment

    @property
    def authenticator_selection_user_verification(self):
        """
        **[Required]** Gets the authenticator_selection_user_verification of this ExtensionFidoAuthenticationFactorSettings.
        Attribute used to define authenticator selection verification.

        **Added In:** 2009232244

        **SCIM++ Properties:**
         - idcsSearchable: false
         - multiValued: false
         - mutability: readWrite
         - required: true
         - returned: default
         - type: string
         - uniqueness: none

        Allowed values for this property are: "REQUIRED", "PREFERRED", "DISCOURAGED", 'UNKNOWN_ENUM_VALUE'.
        Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.


        :return: The authenticator_selection_user_verification of this ExtensionFidoAuthenticationFactorSettings.
        :rtype: str
        """
        return self._authenticator_selection_user_verification

    @authenticator_selection_user_verification.setter
    def authenticator_selection_user_verification(self, authenticator_selection_user_verification):
        """
        Sets the authenticator_selection_user_verification of this ExtensionFidoAuthenticationFactorSettings.
        Attribute used to define authenticator selection verification.

        **Added In:** 2009232244

        **SCIM++ Properties:**
         - idcsSearchable: false
         - multiValued: false
         - mutability: readWrite
         - required: true
         - returned: default
         - type: string
         - uniqueness: none


        :param authenticator_selection_user_verification: The authenticator_selection_user_verification of this ExtensionFidoAuthenticationFactorSettings.
        :type: str
        """
        allowed_values = ["REQUIRED", "PREFERRED", "DISCOURAGED"]
        if not value_allowed_none_or_none_sentinel(authenticator_selection_user_verification, allowed_values):
            authenticator_selection_user_verification = 'UNKNOWN_ENUM_VALUE'
        self._authenticator_selection_user_verification = authenticator_selection_user_verification

    @property
    def authenticator_selection_resident_key(self):
        """
        **[Required]** Gets the authenticator_selection_resident_key of this ExtensionFidoAuthenticationFactorSettings.
        Attribute used to define authenticator selection resident key requirement.

        **Added In:** 2009232244

        **SCIM++ Properties:**
         - idcsSearchable: false
         - multiValued: false
         - mutability: readWrite
         - required: true
         - returned: default
         - type: string
         - uniqueness: none

        Allowed values for this property are: "REQUIRED", "PREFERRED", "DISCOURAGED", "NONE", 'UNKNOWN_ENUM_VALUE'.
        Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.


        :return: The authenticator_selection_resident_key of this ExtensionFidoAuthenticationFactorSettings.
        :rtype: str
        """
        return self._authenticator_selection_resident_key

    @authenticator_selection_resident_key.setter
    def authenticator_selection_resident_key(self, authenticator_selection_resident_key):
        """
        Sets the authenticator_selection_resident_key of this ExtensionFidoAuthenticationFactorSettings.
        Attribute used to define authenticator selection resident key requirement.

        **Added In:** 2009232244

        **SCIM++ Properties:**
         - idcsSearchable: false
         - multiValued: false
         - mutability: readWrite
         - required: true
         - returned: default
         - type: string
         - uniqueness: none


        :param authenticator_selection_resident_key: The authenticator_selection_resident_key of this ExtensionFidoAuthenticationFactorSettings.
        :type: str
        """
        allowed_values = ["REQUIRED", "PREFERRED", "DISCOURAGED", "NONE"]
        if not value_allowed_none_or_none_sentinel(authenticator_selection_resident_key, allowed_values):
            authenticator_selection_resident_key = 'UNKNOWN_ENUM_VALUE'
        self._authenticator_selection_resident_key = authenticator_selection_resident_key

    @property
    def timeout(self):
        """
        **[Required]** Gets the timeout of this ExtensionFidoAuthenticationFactorSettings.
        Timeout for the fido authentication to complete

        **Added In:** 2009232244

        **SCIM++ Properties:**
         - idcsSearchable: false
         - multiValued: false
         - mutability: readWrite
         - idcsMaxValue: 600000
         - idcsMinValue: 10000
         - required: true
         - returned: default
         - type: integer
         - uniqueness: none


        :return: The timeout of this ExtensionFidoAuthenticationFactorSettings.
        :rtype: int
        """
        return self._timeout

    @timeout.setter
    def timeout(self, timeout):
        """
        Sets the timeout of this ExtensionFidoAuthenticationFactorSettings.
        Timeout for the fido authentication to complete

        **Added In:** 2009232244

        **SCIM++ Properties:**
         - idcsSearchable: false
         - multiValued: false
         - mutability: readWrite
         - idcsMaxValue: 600000
         - idcsMinValue: 10000
         - required: true
         - returned: default
         - type: integer
         - uniqueness: none


        :param timeout: The timeout of this ExtensionFidoAuthenticationFactorSettings.
        :type: int
        """
        self._timeout = timeout

    @property
    def authenticator_selection_require_resident_key(self):
        """
        **[Required]** Gets the authenticator_selection_require_resident_key of this ExtensionFidoAuthenticationFactorSettings.
        Flag used to indicate authenticator selection is required or not

        **Added In:** 2009232244

        **SCIM++ Properties:**
         - idcsSearchable: false
         - multiValued: false
         - mutability: readWrite
         - required: true
         - returned: default
         - type: boolean
         - uniqueness: none


        :return: The authenticator_selection_require_resident_key of this ExtensionFidoAuthenticationFactorSettings.
        :rtype: bool
        """
        return self._authenticator_selection_require_resident_key

    @authenticator_selection_require_resident_key.setter
    def authenticator_selection_require_resident_key(self, authenticator_selection_require_resident_key):
        """
        Sets the authenticator_selection_require_resident_key of this ExtensionFidoAuthenticationFactorSettings.
        Flag used to indicate authenticator selection is required or not

        **Added In:** 2009232244

        **SCIM++ Properties:**
         - idcsSearchable: false
         - multiValued: false
         - mutability: readWrite
         - required: true
         - returned: default
         - type: boolean
         - uniqueness: none


        :param authenticator_selection_require_resident_key: The authenticator_selection_require_resident_key of this ExtensionFidoAuthenticationFactorSettings.
        :type: bool
        """
        self._authenticator_selection_require_resident_key = authenticator_selection_require_resident_key

    @property
    def public_key_types(self):
        """
        **[Required]** Gets the public_key_types of this ExtensionFidoAuthenticationFactorSettings.
        List of server supported public key algorithms

        **Added In:** 2009232244

        **SCIM++ Properties:**
         - idcsSearchable: false
         - multiValued: true
         - mutability: readWrite
         - required: true
         - returned: default
         - type: string
         - uniqueness: none

        Allowed values for items in this list are: "RS1", "RS256", "ES256", 'UNKNOWN_ENUM_VALUE'.
        Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.


        :return: The public_key_types of this ExtensionFidoAuthenticationFactorSettings.
        :rtype: list[str]
        """
        return self._public_key_types

    @public_key_types.setter
    def public_key_types(self, public_key_types):
        """
        Sets the public_key_types of this ExtensionFidoAuthenticationFactorSettings.
        List of server supported public key algorithms

        **Added In:** 2009232244

        **SCIM++ Properties:**
         - idcsSearchable: false
         - multiValued: true
         - mutability: readWrite
         - required: true
         - returned: default
         - type: string
         - uniqueness: none


        :param public_key_types: The public_key_types of this ExtensionFidoAuthenticationFactorSettings.
        :type: list[str]
        """
        allowed_values = ["RS1", "RS256", "ES256"]
        if public_key_types:
            public_key_types[:] = ['UNKNOWN_ENUM_VALUE' if not value_allowed_none_or_none_sentinel(x, allowed_values) else x for x in public_key_types]
        self._public_key_types = public_key_types

    @property
    def exclude_credentials(self):
        """
        **[Required]** Gets the exclude_credentials of this ExtensionFidoAuthenticationFactorSettings.
        Flag used to indicate whether we need to restrict creation of multiple credentials in same authenticator

        **Added In:** 2009232244

        **SCIM++ Properties:**
         - idcsSearchable: false
         - multiValued: false
         - mutability: readWrite
         - required: true
         - returned: default
         - type: boolean
         - uniqueness: none


        :return: The exclude_credentials of this ExtensionFidoAuthenticationFactorSettings.
        :rtype: bool
        """
        return self._exclude_credentials

    @exclude_credentials.setter
    def exclude_credentials(self, exclude_credentials):
        """
        Sets the exclude_credentials of this ExtensionFidoAuthenticationFactorSettings.
        Flag used to indicate whether we need to restrict creation of multiple credentials in same authenticator

        **Added In:** 2009232244

        **SCIM++ Properties:**
         - idcsSearchable: false
         - multiValued: false
         - mutability: readWrite
         - required: true
         - returned: default
         - type: boolean
         - uniqueness: none


        :param exclude_credentials: The exclude_credentials of this ExtensionFidoAuthenticationFactorSettings.
        :type: bool
        """
        self._exclude_credentials = exclude_credentials

    @property
    def domain_validation_level(self):
        """
        Gets the domain_validation_level of this ExtensionFidoAuthenticationFactorSettings.
        Number of domain levels IDCS should use for origin comparision

        **Added In:** 2109020413

        **SCIM++ Properties:**
         - idcsSearchable: false
         - multiValued: false
         - mutability: readWrite
         - idcsMaxValue: 2
         - idcsMinValue: 0
         - required: false
         - returned: default
         - type: integer
         - uniqueness: none


        :return: The domain_validation_level of this ExtensionFidoAuthenticationFactorSettings.
        :rtype: int
        """
        return self._domain_validation_level

    @domain_validation_level.setter
    def domain_validation_level(self, domain_validation_level):
        """
        Sets the domain_validation_level of this ExtensionFidoAuthenticationFactorSettings.
        Number of domain levels IDCS should use for origin comparision

        **Added In:** 2109020413

        **SCIM++ Properties:**
         - idcsSearchable: false
         - multiValued: false
         - mutability: readWrite
         - idcsMaxValue: 2
         - idcsMinValue: 0
         - required: false
         - returned: default
         - type: integer
         - uniqueness: none


        :param domain_validation_level: The domain_validation_level of this ExtensionFidoAuthenticationFactorSettings.
        :type: int
        """
        self._domain_validation_level = domain_validation_level

    def __repr__(self):
        return formatted_flat_dict(self)

    def __eq__(self, other):
        if other is None:
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not self == other
