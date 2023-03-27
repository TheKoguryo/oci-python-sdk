# coding: utf-8
# Copyright (c) 2016, 2023, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.


from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class ExtensionX509IdentityProvider(object):
    """
    X509 Identity Provider Extension Schema
    """

    def __init__(self, **kwargs):
        """
        Initializes a new ExtensionX509IdentityProvider object with values from keyword arguments.
        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param cert_match_attribute:
            The value to assign to the cert_match_attribute property of this ExtensionX509IdentityProvider.
        :type cert_match_attribute: str

        :param user_match_attribute:
            The value to assign to the user_match_attribute property of this ExtensionX509IdentityProvider.
        :type user_match_attribute: str

        :param other_cert_match_attribute:
            The value to assign to the other_cert_match_attribute property of this ExtensionX509IdentityProvider.
        :type other_cert_match_attribute: str

        :param signing_certificate_chain:
            The value to assign to the signing_certificate_chain property of this ExtensionX509IdentityProvider.
        :type signing_certificate_chain: list[str]

        :param ocsp_enabled:
            The value to assign to the ocsp_enabled property of this ExtensionX509IdentityProvider.
        :type ocsp_enabled: bool

        :param ocsp_server_name:
            The value to assign to the ocsp_server_name property of this ExtensionX509IdentityProvider.
        :type ocsp_server_name: str

        :param ocsp_responder_url:
            The value to assign to the ocsp_responder_url property of this ExtensionX509IdentityProvider.
        :type ocsp_responder_url: str

        :param ocsp_allow_unknown_response_status:
            The value to assign to the ocsp_allow_unknown_response_status property of this ExtensionX509IdentityProvider.
        :type ocsp_allow_unknown_response_status: bool

        :param ocsp_revalidate_time:
            The value to assign to the ocsp_revalidate_time property of this ExtensionX509IdentityProvider.
        :type ocsp_revalidate_time: int

        :param ocsp_enable_signed_response:
            The value to assign to the ocsp_enable_signed_response property of this ExtensionX509IdentityProvider.
        :type ocsp_enable_signed_response: bool

        :param ocsp_trust_cert_chain:
            The value to assign to the ocsp_trust_cert_chain property of this ExtensionX509IdentityProvider.
        :type ocsp_trust_cert_chain: list[str]

        :param crl_enabled:
            The value to assign to the crl_enabled property of this ExtensionX509IdentityProvider.
        :type crl_enabled: bool

        :param crl_check_on_ocsp_failure_enabled:
            The value to assign to the crl_check_on_ocsp_failure_enabled property of this ExtensionX509IdentityProvider.
        :type crl_check_on_ocsp_failure_enabled: bool

        :param crl_location:
            The value to assign to the crl_location property of this ExtensionX509IdentityProvider.
        :type crl_location: str

        :param crl_reload_duration:
            The value to assign to the crl_reload_duration property of this ExtensionX509IdentityProvider.
        :type crl_reload_duration: int

        """
        self.swagger_types = {
            'cert_match_attribute': 'str',
            'user_match_attribute': 'str',
            'other_cert_match_attribute': 'str',
            'signing_certificate_chain': 'list[str]',
            'ocsp_enabled': 'bool',
            'ocsp_server_name': 'str',
            'ocsp_responder_url': 'str',
            'ocsp_allow_unknown_response_status': 'bool',
            'ocsp_revalidate_time': 'int',
            'ocsp_enable_signed_response': 'bool',
            'ocsp_trust_cert_chain': 'list[str]',
            'crl_enabled': 'bool',
            'crl_check_on_ocsp_failure_enabled': 'bool',
            'crl_location': 'str',
            'crl_reload_duration': 'int'
        }

        self.attribute_map = {
            'cert_match_attribute': 'certMatchAttribute',
            'user_match_attribute': 'userMatchAttribute',
            'other_cert_match_attribute': 'otherCertMatchAttribute',
            'signing_certificate_chain': 'signingCertificateChain',
            'ocsp_enabled': 'ocspEnabled',
            'ocsp_server_name': 'ocspServerName',
            'ocsp_responder_url': 'ocspResponderURL',
            'ocsp_allow_unknown_response_status': 'ocspAllowUnknownResponseStatus',
            'ocsp_revalidate_time': 'ocspRevalidateTime',
            'ocsp_enable_signed_response': 'ocspEnableSignedResponse',
            'ocsp_trust_cert_chain': 'ocspTrustCertChain',
            'crl_enabled': 'crlEnabled',
            'crl_check_on_ocsp_failure_enabled': 'crlCheckOnOCSPFailureEnabled',
            'crl_location': 'crlLocation',
            'crl_reload_duration': 'crlReloadDuration'
        }

        self._cert_match_attribute = None
        self._user_match_attribute = None
        self._other_cert_match_attribute = None
        self._signing_certificate_chain = None
        self._ocsp_enabled = None
        self._ocsp_server_name = None
        self._ocsp_responder_url = None
        self._ocsp_allow_unknown_response_status = None
        self._ocsp_revalidate_time = None
        self._ocsp_enable_signed_response = None
        self._ocsp_trust_cert_chain = None
        self._crl_enabled = None
        self._crl_check_on_ocsp_failure_enabled = None
        self._crl_location = None
        self._crl_reload_duration = None

    @property
    def cert_match_attribute(self):
        """
        **[Required]** Gets the cert_match_attribute of this ExtensionX509IdentityProvider.
        X509 Certificate Matching Attribute

        **Added In:** 2010242156

        **SCIM++ Properties:**
         - caseExact: false
         - idcsSearchable: false
         - multiValued: false
         - mutability: readWrite
         - required: true
         - returned: default
         - type: string
         - uniqueness: none


        :return: The cert_match_attribute of this ExtensionX509IdentityProvider.
        :rtype: str
        """
        return self._cert_match_attribute

    @cert_match_attribute.setter
    def cert_match_attribute(self, cert_match_attribute):
        """
        Sets the cert_match_attribute of this ExtensionX509IdentityProvider.
        X509 Certificate Matching Attribute

        **Added In:** 2010242156

        **SCIM++ Properties:**
         - caseExact: false
         - idcsSearchable: false
         - multiValued: false
         - mutability: readWrite
         - required: true
         - returned: default
         - type: string
         - uniqueness: none


        :param cert_match_attribute: The cert_match_attribute of this ExtensionX509IdentityProvider.
        :type: str
        """
        self._cert_match_attribute = cert_match_attribute

    @property
    def user_match_attribute(self):
        """
        **[Required]** Gets the user_match_attribute of this ExtensionX509IdentityProvider.
        This property specifies the userstore attribute value that must match the incoming certificate attribute.

        **Added In:** 2010242156

        **SCIM++ Properties:**
         - caseExact: false
         - idcsSearchable: false
         - multiValued: false
         - mutability: readWrite
         - required: true
         - returned: default
         - type: string
         - uniqueness: none


        :return: The user_match_attribute of this ExtensionX509IdentityProvider.
        :rtype: str
        """
        return self._user_match_attribute

    @user_match_attribute.setter
    def user_match_attribute(self, user_match_attribute):
        """
        Sets the user_match_attribute of this ExtensionX509IdentityProvider.
        This property specifies the userstore attribute value that must match the incoming certificate attribute.

        **Added In:** 2010242156

        **SCIM++ Properties:**
         - caseExact: false
         - idcsSearchable: false
         - multiValued: false
         - mutability: readWrite
         - required: true
         - returned: default
         - type: string
         - uniqueness: none


        :param user_match_attribute: The user_match_attribute of this ExtensionX509IdentityProvider.
        :type: str
        """
        self._user_match_attribute = user_match_attribute

    @property
    def other_cert_match_attribute(self):
        """
        Gets the other_cert_match_attribute of this ExtensionX509IdentityProvider.
        Check for specific conditions of other certificate attributes

        **Added In:** 2010242156

        **SCIM++ Properties:**
         - caseExact: false
         - idcsSearchable: false
         - multiValued: false
         - mutability: readWrite
         - required: false
         - returned: default
         - type: string
         - uniqueness: none


        :return: The other_cert_match_attribute of this ExtensionX509IdentityProvider.
        :rtype: str
        """
        return self._other_cert_match_attribute

    @other_cert_match_attribute.setter
    def other_cert_match_attribute(self, other_cert_match_attribute):
        """
        Sets the other_cert_match_attribute of this ExtensionX509IdentityProvider.
        Check for specific conditions of other certificate attributes

        **Added In:** 2010242156

        **SCIM++ Properties:**
         - caseExact: false
         - idcsSearchable: false
         - multiValued: false
         - mutability: readWrite
         - required: false
         - returned: default
         - type: string
         - uniqueness: none


        :param other_cert_match_attribute: The other_cert_match_attribute of this ExtensionX509IdentityProvider.
        :type: str
        """
        self._other_cert_match_attribute = other_cert_match_attribute

    @property
    def signing_certificate_chain(self):
        """
        **[Required]** Gets the signing_certificate_chain of this ExtensionX509IdentityProvider.
        Certificate alias list to create a chain for the incoming client certificate

        **Added In:** 2010242156

        **SCIM++ Properties:**
         - caseExact: false
         - idcsSearchable: false
         - multiValued: true
         - mutability: readWrite
         - required: true
         - returned: default
         - type: string
         - uniqueness: none


        :return: The signing_certificate_chain of this ExtensionX509IdentityProvider.
        :rtype: list[str]
        """
        return self._signing_certificate_chain

    @signing_certificate_chain.setter
    def signing_certificate_chain(self, signing_certificate_chain):
        """
        Sets the signing_certificate_chain of this ExtensionX509IdentityProvider.
        Certificate alias list to create a chain for the incoming client certificate

        **Added In:** 2010242156

        **SCIM++ Properties:**
         - caseExact: false
         - idcsSearchable: false
         - multiValued: true
         - mutability: readWrite
         - required: true
         - returned: default
         - type: string
         - uniqueness: none


        :param signing_certificate_chain: The signing_certificate_chain of this ExtensionX509IdentityProvider.
        :type: list[str]
        """
        self._signing_certificate_chain = signing_certificate_chain

    @property
    def ocsp_enabled(self):
        """
        Gets the ocsp_enabled of this ExtensionX509IdentityProvider.
        Set to true to enable OCSP Validation

        **Added In:** 2010242156

        **SCIM++ Properties:**
         - caseExact: false
         - idcsSearchable: false
         - multiValued: false
         - mutability: readWrite
         - required: false
         - returned: default
         - type: boolean
         - uniqueness: none


        :return: The ocsp_enabled of this ExtensionX509IdentityProvider.
        :rtype: bool
        """
        return self._ocsp_enabled

    @ocsp_enabled.setter
    def ocsp_enabled(self, ocsp_enabled):
        """
        Sets the ocsp_enabled of this ExtensionX509IdentityProvider.
        Set to true to enable OCSP Validation

        **Added In:** 2010242156

        **SCIM++ Properties:**
         - caseExact: false
         - idcsSearchable: false
         - multiValued: false
         - mutability: readWrite
         - required: false
         - returned: default
         - type: boolean
         - uniqueness: none


        :param ocsp_enabled: The ocsp_enabled of this ExtensionX509IdentityProvider.
        :type: bool
        """
        self._ocsp_enabled = ocsp_enabled

    @property
    def ocsp_server_name(self):
        """
        Gets the ocsp_server_name of this ExtensionX509IdentityProvider.
        This property specifies the OCSP Server alias name

        **Added In:** 2010242156

        **SCIM++ Properties:**
         - caseExact: false
         - idcsSearchable: false
         - multiValued: false
         - mutability: readWrite
         - required: false
         - returned: default
         - type: string
         - uniqueness: none


        :return: The ocsp_server_name of this ExtensionX509IdentityProvider.
        :rtype: str
        """
        return self._ocsp_server_name

    @ocsp_server_name.setter
    def ocsp_server_name(self, ocsp_server_name):
        """
        Sets the ocsp_server_name of this ExtensionX509IdentityProvider.
        This property specifies the OCSP Server alias name

        **Added In:** 2010242156

        **SCIM++ Properties:**
         - caseExact: false
         - idcsSearchable: false
         - multiValued: false
         - mutability: readWrite
         - required: false
         - returned: default
         - type: string
         - uniqueness: none


        :param ocsp_server_name: The ocsp_server_name of this ExtensionX509IdentityProvider.
        :type: str
        """
        self._ocsp_server_name = ocsp_server_name

    @property
    def ocsp_responder_url(self):
        """
        Gets the ocsp_responder_url of this ExtensionX509IdentityProvider.
        This property specifies OCSP Responder URL.

        **Added In:** 2010242156

        **SCIM++ Properties:**
         - caseExact: false
         - idcsSearchable: false
         - multiValued: false
         - mutability: readWrite
         - required: false
         - returned: default
         - type: string
         - uniqueness: none


        :return: The ocsp_responder_url of this ExtensionX509IdentityProvider.
        :rtype: str
        """
        return self._ocsp_responder_url

    @ocsp_responder_url.setter
    def ocsp_responder_url(self, ocsp_responder_url):
        """
        Sets the ocsp_responder_url of this ExtensionX509IdentityProvider.
        This property specifies OCSP Responder URL.

        **Added In:** 2010242156

        **SCIM++ Properties:**
         - caseExact: false
         - idcsSearchable: false
         - multiValued: false
         - mutability: readWrite
         - required: false
         - returned: default
         - type: string
         - uniqueness: none


        :param ocsp_responder_url: The ocsp_responder_url of this ExtensionX509IdentityProvider.
        :type: str
        """
        self._ocsp_responder_url = ocsp_responder_url

    @property
    def ocsp_allow_unknown_response_status(self):
        """
        Gets the ocsp_allow_unknown_response_status of this ExtensionX509IdentityProvider.
        Allow access if OCSP response is UNKNOWN or OCSP Responder does not respond within the timeout duration

        **Added In:** 2010242156

        **SCIM++ Properties:**
         - caseExact: false
         - idcsSearchable: false
         - multiValued: false
         - mutability: readWrite
         - required: false
         - returned: default
         - type: boolean
         - uniqueness: none


        :return: The ocsp_allow_unknown_response_status of this ExtensionX509IdentityProvider.
        :rtype: bool
        """
        return self._ocsp_allow_unknown_response_status

    @ocsp_allow_unknown_response_status.setter
    def ocsp_allow_unknown_response_status(self, ocsp_allow_unknown_response_status):
        """
        Sets the ocsp_allow_unknown_response_status of this ExtensionX509IdentityProvider.
        Allow access if OCSP response is UNKNOWN or OCSP Responder does not respond within the timeout duration

        **Added In:** 2010242156

        **SCIM++ Properties:**
         - caseExact: false
         - idcsSearchable: false
         - multiValued: false
         - mutability: readWrite
         - required: false
         - returned: default
         - type: boolean
         - uniqueness: none


        :param ocsp_allow_unknown_response_status: The ocsp_allow_unknown_response_status of this ExtensionX509IdentityProvider.
        :type: bool
        """
        self._ocsp_allow_unknown_response_status = ocsp_allow_unknown_response_status

    @property
    def ocsp_revalidate_time(self):
        """
        Gets the ocsp_revalidate_time of this ExtensionX509IdentityProvider.
        Revalidate OCSP status for user after X hours

        **Added In:** 2010242156

        **SCIM++ Properties:**
         - idcsMaxValue: 24
         - idcsMinValue: 0
         - idcsSearchable: false
         - multiValued: false
         - mutability: readWrite
         - required: false
         - returned: default
         - type: integer
         - uniqueness: none


        :return: The ocsp_revalidate_time of this ExtensionX509IdentityProvider.
        :rtype: int
        """
        return self._ocsp_revalidate_time

    @ocsp_revalidate_time.setter
    def ocsp_revalidate_time(self, ocsp_revalidate_time):
        """
        Sets the ocsp_revalidate_time of this ExtensionX509IdentityProvider.
        Revalidate OCSP status for user after X hours

        **Added In:** 2010242156

        **SCIM++ Properties:**
         - idcsMaxValue: 24
         - idcsMinValue: 0
         - idcsSearchable: false
         - multiValued: false
         - mutability: readWrite
         - required: false
         - returned: default
         - type: integer
         - uniqueness: none


        :param ocsp_revalidate_time: The ocsp_revalidate_time of this ExtensionX509IdentityProvider.
        :type: int
        """
        self._ocsp_revalidate_time = ocsp_revalidate_time

    @property
    def ocsp_enable_signed_response(self):
        """
        Gets the ocsp_enable_signed_response of this ExtensionX509IdentityProvider.
        Describes if the OCSP response is signed

        **Added In:** 2010242156

        **SCIM++ Properties:**
         - caseExact: false
         - idcsSearchable: false
         - multiValued: false
         - mutability: readWrite
         - required: false
         - returned: default
         - type: boolean
         - uniqueness: none


        :return: The ocsp_enable_signed_response of this ExtensionX509IdentityProvider.
        :rtype: bool
        """
        return self._ocsp_enable_signed_response

    @ocsp_enable_signed_response.setter
    def ocsp_enable_signed_response(self, ocsp_enable_signed_response):
        """
        Sets the ocsp_enable_signed_response of this ExtensionX509IdentityProvider.
        Describes if the OCSP response is signed

        **Added In:** 2010242156

        **SCIM++ Properties:**
         - caseExact: false
         - idcsSearchable: false
         - multiValued: false
         - mutability: readWrite
         - required: false
         - returned: default
         - type: boolean
         - uniqueness: none


        :param ocsp_enable_signed_response: The ocsp_enable_signed_response of this ExtensionX509IdentityProvider.
        :type: bool
        """
        self._ocsp_enable_signed_response = ocsp_enable_signed_response

    @property
    def ocsp_trust_cert_chain(self):
        """
        Gets the ocsp_trust_cert_chain of this ExtensionX509IdentityProvider.
        OCSP Trusted Certificate Chain

        **Added In:** 2010242156

        **SCIM++ Properties:**
         - caseExact: false
         - idcsSearchable: false
         - multiValued: true
         - mutability: readWrite
         - required: false
         - returned: default
         - type: string
         - uniqueness: none


        :return: The ocsp_trust_cert_chain of this ExtensionX509IdentityProvider.
        :rtype: list[str]
        """
        return self._ocsp_trust_cert_chain

    @ocsp_trust_cert_chain.setter
    def ocsp_trust_cert_chain(self, ocsp_trust_cert_chain):
        """
        Sets the ocsp_trust_cert_chain of this ExtensionX509IdentityProvider.
        OCSP Trusted Certificate Chain

        **Added In:** 2010242156

        **SCIM++ Properties:**
         - caseExact: false
         - idcsSearchable: false
         - multiValued: true
         - mutability: readWrite
         - required: false
         - returned: default
         - type: string
         - uniqueness: none


        :param ocsp_trust_cert_chain: The ocsp_trust_cert_chain of this ExtensionX509IdentityProvider.
        :type: list[str]
        """
        self._ocsp_trust_cert_chain = ocsp_trust_cert_chain

    @property
    def crl_enabled(self):
        """
        Gets the crl_enabled of this ExtensionX509IdentityProvider.
        Set to true to enable CRL Validation

        **Added In:** 2010242156

        **SCIM++ Properties:**
         - caseExact: false
         - idcsSearchable: false
         - multiValued: false
         - mutability: readWrite
         - required: false
         - returned: default
         - type: boolean
         - uniqueness: none


        :return: The crl_enabled of this ExtensionX509IdentityProvider.
        :rtype: bool
        """
        return self._crl_enabled

    @crl_enabled.setter
    def crl_enabled(self, crl_enabled):
        """
        Sets the crl_enabled of this ExtensionX509IdentityProvider.
        Set to true to enable CRL Validation

        **Added In:** 2010242156

        **SCIM++ Properties:**
         - caseExact: false
         - idcsSearchable: false
         - multiValued: false
         - mutability: readWrite
         - required: false
         - returned: default
         - type: boolean
         - uniqueness: none


        :param crl_enabled: The crl_enabled of this ExtensionX509IdentityProvider.
        :type: bool
        """
        self._crl_enabled = crl_enabled

    @property
    def crl_check_on_ocsp_failure_enabled(self):
        """
        Gets the crl_check_on_ocsp_failure_enabled of this ExtensionX509IdentityProvider.
        Fallback on CRL Validation if OCSP fails.

        **Added In:** 2010242156

        **SCIM++ Properties:**
         - caseExact: false
         - idcsSearchable: false
         - multiValued: false
         - mutability: readWrite
         - required: false
         - returned: default
         - type: boolean
         - uniqueness: none


        :return: The crl_check_on_ocsp_failure_enabled of this ExtensionX509IdentityProvider.
        :rtype: bool
        """
        return self._crl_check_on_ocsp_failure_enabled

    @crl_check_on_ocsp_failure_enabled.setter
    def crl_check_on_ocsp_failure_enabled(self, crl_check_on_ocsp_failure_enabled):
        """
        Sets the crl_check_on_ocsp_failure_enabled of this ExtensionX509IdentityProvider.
        Fallback on CRL Validation if OCSP fails.

        **Added In:** 2010242156

        **SCIM++ Properties:**
         - caseExact: false
         - idcsSearchable: false
         - multiValued: false
         - mutability: readWrite
         - required: false
         - returned: default
         - type: boolean
         - uniqueness: none


        :param crl_check_on_ocsp_failure_enabled: The crl_check_on_ocsp_failure_enabled of this ExtensionX509IdentityProvider.
        :type: bool
        """
        self._crl_check_on_ocsp_failure_enabled = crl_check_on_ocsp_failure_enabled

    @property
    def crl_location(self):
        """
        Gets the crl_location of this ExtensionX509IdentityProvider.
        CRL Location URL

        **Added In:** 2010242156

        **SCIM++ Properties:**
         - caseExact: false
         - idcsSearchable: false
         - multiValued: false
         - mutability: readWrite
         - required: false
         - returned: default
         - type: string
         - uniqueness: none


        :return: The crl_location of this ExtensionX509IdentityProvider.
        :rtype: str
        """
        return self._crl_location

    @crl_location.setter
    def crl_location(self, crl_location):
        """
        Sets the crl_location of this ExtensionX509IdentityProvider.
        CRL Location URL

        **Added In:** 2010242156

        **SCIM++ Properties:**
         - caseExact: false
         - idcsSearchable: false
         - multiValued: false
         - mutability: readWrite
         - required: false
         - returned: default
         - type: string
         - uniqueness: none


        :param crl_location: The crl_location of this ExtensionX509IdentityProvider.
        :type: str
        """
        self._crl_location = crl_location

    @property
    def crl_reload_duration(self):
        """
        Gets the crl_reload_duration of this ExtensionX509IdentityProvider.
        Fetch the CRL contents every X minutes

        **Added In:** 2010242156

        **SCIM++ Properties:**
         - idcsSearchable: false
         - multiValued: false
         - mutability: readWrite
         - required: false
         - returned: default
         - type: integer
         - uniqueness: none


        :return: The crl_reload_duration of this ExtensionX509IdentityProvider.
        :rtype: int
        """
        return self._crl_reload_duration

    @crl_reload_duration.setter
    def crl_reload_duration(self, crl_reload_duration):
        """
        Sets the crl_reload_duration of this ExtensionX509IdentityProvider.
        Fetch the CRL contents every X minutes

        **Added In:** 2010242156

        **SCIM++ Properties:**
         - idcsSearchable: false
         - multiValued: false
         - mutability: readWrite
         - required: false
         - returned: default
         - type: integer
         - uniqueness: none


        :param crl_reload_duration: The crl_reload_duration of this ExtensionX509IdentityProvider.
        :type: int
        """
        self._crl_reload_duration = crl_reload_duration

    def __repr__(self):
        return formatted_flat_dict(self)

    def __eq__(self, other):
        if other is None:
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not self == other
