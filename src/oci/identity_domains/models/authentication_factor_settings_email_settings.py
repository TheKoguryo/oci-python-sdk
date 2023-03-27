# coding: utf-8
# Copyright (c) 2016, 2023, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.


from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class AuthenticationFactorSettingsEmailSettings(object):
    """
    Settings related to Email Factor, such as enabled email magic link factor, custom url for Email Link

    **Added In:** 20.1.3

    **SCIM++ Properties:**
    - idcsSearchable: false
    - multiValued: false
    - mutability: readWrite
    - required: false
    - returned: default
    - type: complex
    - uniqueness: none
    """

    def __init__(self, **kwargs):
        """
        Initializes a new AuthenticationFactorSettingsEmailSettings object with values from keyword arguments.
        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param email_link_enabled:
            The value to assign to the email_link_enabled property of this AuthenticationFactorSettingsEmailSettings.
        :type email_link_enabled: bool

        :param email_link_custom_url:
            The value to assign to the email_link_custom_url property of this AuthenticationFactorSettingsEmailSettings.
        :type email_link_custom_url: str

        """
        self.swagger_types = {
            'email_link_enabled': 'bool',
            'email_link_custom_url': 'str'
        }

        self.attribute_map = {
            'email_link_enabled': 'emailLinkEnabled',
            'email_link_custom_url': 'emailLinkCustomUrl'
        }

        self._email_link_enabled = None
        self._email_link_custom_url = None

    @property
    def email_link_enabled(self):
        """
        **[Required]** Gets the email_link_enabled of this AuthenticationFactorSettingsEmailSettings.
        Specifies whether Email link is enabled or not.

        **Added In:** 20.1.3

        **SCIM++ Properties:**
         - idcsSearchable: false
         - multiValued: false
         - mutability: readWrite
         - required: true
         - returned: default
         - type: boolean
         - uniqueness: none


        :return: The email_link_enabled of this AuthenticationFactorSettingsEmailSettings.
        :rtype: bool
        """
        return self._email_link_enabled

    @email_link_enabled.setter
    def email_link_enabled(self, email_link_enabled):
        """
        Sets the email_link_enabled of this AuthenticationFactorSettingsEmailSettings.
        Specifies whether Email link is enabled or not.

        **Added In:** 20.1.3

        **SCIM++ Properties:**
         - idcsSearchable: false
         - multiValued: false
         - mutability: readWrite
         - required: true
         - returned: default
         - type: boolean
         - uniqueness: none


        :param email_link_enabled: The email_link_enabled of this AuthenticationFactorSettingsEmailSettings.
        :type: bool
        """
        self._email_link_enabled = email_link_enabled

    @property
    def email_link_custom_url(self):
        """
        Gets the email_link_custom_url of this AuthenticationFactorSettingsEmailSettings.
        Custom redirect Url which will be used in email link

        **Added In:** 20.1.3

        **SCIM++ Properties:**
         - idcsSearchable: false
         - multiValued: false
         - mutability: readWrite
         - required: false
         - returned: default
         - type: string
         - uniqueness: none


        :return: The email_link_custom_url of this AuthenticationFactorSettingsEmailSettings.
        :rtype: str
        """
        return self._email_link_custom_url

    @email_link_custom_url.setter
    def email_link_custom_url(self, email_link_custom_url):
        """
        Sets the email_link_custom_url of this AuthenticationFactorSettingsEmailSettings.
        Custom redirect Url which will be used in email link

        **Added In:** 20.1.3

        **SCIM++ Properties:**
         - idcsSearchable: false
         - multiValued: false
         - mutability: readWrite
         - required: false
         - returned: default
         - type: string
         - uniqueness: none


        :param email_link_custom_url: The email_link_custom_url of this AuthenticationFactorSettingsEmailSettings.
        :type: str
        """
        self._email_link_custom_url = email_link_custom_url

    def __repr__(self):
        return formatted_flat_dict(self)

    def __eq__(self, other):
        if other is None:
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not self == other
