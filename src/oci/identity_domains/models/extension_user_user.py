# coding: utf-8
# Copyright (c) 2016, 2023, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.


from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class ExtensionUserUser(object):
    """
    OCI IAM User
    """

    #: A constant which can be used with the status property of a ExtensionUserUser.
    #: This constant has a value of "pendingVerification"
    STATUS_PENDING_VERIFICATION = "pendingVerification"

    #: A constant which can be used with the status property of a ExtensionUserUser.
    #: This constant has a value of "verified"
    STATUS_VERIFIED = "verified"

    #: A constant which can be used with the provider property of a ExtensionUserUser.
    #: This constant has a value of "facebook"
    PROVIDER_FACEBOOK = "facebook"

    #: A constant which can be used with the provider property of a ExtensionUserUser.
    #: This constant has a value of "google"
    PROVIDER_GOOGLE = "google"

    #: A constant which can be used with the provider property of a ExtensionUserUser.
    #: This constant has a value of "IDCS"
    PROVIDER_IDCS = "IDCS"

    #: A constant which can be used with the provider property of a ExtensionUserUser.
    #: This constant has a value of "twitter"
    PROVIDER_TWITTER = "twitter"

    #: A constant which can be used with the creation_mechanism property of a ExtensionUserUser.
    #: This constant has a value of "bulk"
    CREATION_MECHANISM_BULK = "bulk"

    #: A constant which can be used with the creation_mechanism property of a ExtensionUserUser.
    #: This constant has a value of "api"
    CREATION_MECHANISM_API = "api"

    #: A constant which can be used with the creation_mechanism property of a ExtensionUserUser.
    #: This constant has a value of "adsync"
    CREATION_MECHANISM_ADSYNC = "adsync"

    #: A constant which can be used with the creation_mechanism property of a ExtensionUserUser.
    #: This constant has a value of "idcsui"
    CREATION_MECHANISM_IDCSUI = "idcsui"

    #: A constant which can be used with the creation_mechanism property of a ExtensionUserUser.
    #: This constant has a value of "import"
    CREATION_MECHANISM_IMPORT = "import"

    #: A constant which can be used with the creation_mechanism property of a ExtensionUserUser.
    #: This constant has a value of "authsync"
    CREATION_MECHANISM_AUTHSYNC = "authsync"

    #: A constant which can be used with the creation_mechanism property of a ExtensionUserUser.
    #: This constant has a value of "selfreg"
    CREATION_MECHANISM_SELFREG = "selfreg"

    #: A constant which can be used with the creation_mechanism property of a ExtensionUserUser.
    #: This constant has a value of "samljit"
    CREATION_MECHANISM_SAMLJIT = "samljit"

    def __init__(self, **kwargs):
        """
        Initializes a new ExtensionUserUser object with values from keyword arguments.
        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param is_federated_user:
            The value to assign to the is_federated_user property of this ExtensionUserUser.
        :type is_federated_user: bool

        :param is_authentication_delegated:
            The value to assign to the is_authentication_delegated property of this ExtensionUserUser.
        :type is_authentication_delegated: bool

        :param status:
            The value to assign to the status property of this ExtensionUserUser.
            Allowed values for this property are: "pendingVerification", "verified", 'UNKNOWN_ENUM_VALUE'.
            Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.
        :type status: str

        :param provider:
            The value to assign to the provider property of this ExtensionUserUser.
            Allowed values for this property are: "facebook", "google", "IDCS", "twitter", 'UNKNOWN_ENUM_VALUE'.
            Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.
        :type provider: str

        :param creation_mechanism:
            The value to assign to the creation_mechanism property of this ExtensionUserUser.
            Allowed values for this property are: "bulk", "api", "adsync", "idcsui", "import", "authsync", "selfreg", "samljit", 'UNKNOWN_ENUM_VALUE'.
            Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.
        :type creation_mechanism: str

        :param do_not_show_getting_started:
            The value to assign to the do_not_show_getting_started property of this ExtensionUserUser.
        :type do_not_show_getting_started: bool

        :param bypass_notification:
            The value to assign to the bypass_notification property of this ExtensionUserUser.
        :type bypass_notification: bool

        :param is_account_recovery_enrolled:
            The value to assign to the is_account_recovery_enrolled property of this ExtensionUserUser.
        :type is_account_recovery_enrolled: bool

        :param account_recovery_required:
            The value to assign to the account_recovery_required property of this ExtensionUserUser.
        :type account_recovery_required: bool

        :param user_flow_controlled_by_external_client:
            The value to assign to the user_flow_controlled_by_external_client property of this ExtensionUserUser.
        :type user_flow_controlled_by_external_client: bool

        :param is_group_membership_normalized:
            The value to assign to the is_group_membership_normalized property of this ExtensionUserUser.
        :type is_group_membership_normalized: bool

        :param is_group_membership_synced_to_users_groups:
            The value to assign to the is_group_membership_synced_to_users_groups property of this ExtensionUserUser.
        :type is_group_membership_synced_to_users_groups: bool

        :param notification_email_template_id:
            The value to assign to the notification_email_template_id property of this ExtensionUserUser.
        :type notification_email_template_id: str

        :param support_accounts:
            The value to assign to the support_accounts property of this ExtensionUserUser.
        :type support_accounts: list[oci.identity_domains.models.UserExtSupportAccounts]

        :param idcs_app_roles_limited_to_groups:
            The value to assign to the idcs_app_roles_limited_to_groups property of this ExtensionUserUser.
        :type idcs_app_roles_limited_to_groups: list[oci.identity_domains.models.UserExtIdcsAppRolesLimitedToGroups]

        :param user_token:
            The value to assign to the user_token property of this ExtensionUserUser.
        :type user_token: oci.identity_domains.models.UserExtUserToken

        :param synced_from_app:
            The value to assign to the synced_from_app property of this ExtensionUserUser.
        :type synced_from_app: oci.identity_domains.models.UserExtSyncedFromApp

        :param applicable_authentication_target_app:
            The value to assign to the applicable_authentication_target_app property of this ExtensionUserUser.
        :type applicable_authentication_target_app: oci.identity_domains.models.UserExtApplicableAuthenticationTargetApp

        :param delegated_authentication_target_app:
            The value to assign to the delegated_authentication_target_app property of this ExtensionUserUser.
        :type delegated_authentication_target_app: oci.identity_domains.models.UserExtDelegatedAuthenticationTargetApp

        :param accounts:
            The value to assign to the accounts property of this ExtensionUserUser.
        :type accounts: list[oci.identity_domains.models.UserExtAccounts]

        :param grants:
            The value to assign to the grants property of this ExtensionUserUser.
        :type grants: list[oci.identity_domains.models.UserExtGrants]

        :param app_roles:
            The value to assign to the app_roles property of this ExtensionUserUser.
        :type app_roles: list[oci.identity_domains.models.UserExtAppRoles]

        """
        self.swagger_types = {
            'is_federated_user': 'bool',
            'is_authentication_delegated': 'bool',
            'status': 'str',
            'provider': 'str',
            'creation_mechanism': 'str',
            'do_not_show_getting_started': 'bool',
            'bypass_notification': 'bool',
            'is_account_recovery_enrolled': 'bool',
            'account_recovery_required': 'bool',
            'user_flow_controlled_by_external_client': 'bool',
            'is_group_membership_normalized': 'bool',
            'is_group_membership_synced_to_users_groups': 'bool',
            'notification_email_template_id': 'str',
            'support_accounts': 'list[UserExtSupportAccounts]',
            'idcs_app_roles_limited_to_groups': 'list[UserExtIdcsAppRolesLimitedToGroups]',
            'user_token': 'UserExtUserToken',
            'synced_from_app': 'UserExtSyncedFromApp',
            'applicable_authentication_target_app': 'UserExtApplicableAuthenticationTargetApp',
            'delegated_authentication_target_app': 'UserExtDelegatedAuthenticationTargetApp',
            'accounts': 'list[UserExtAccounts]',
            'grants': 'list[UserExtGrants]',
            'app_roles': 'list[UserExtAppRoles]'
        }

        self.attribute_map = {
            'is_federated_user': 'isFederatedUser',
            'is_authentication_delegated': 'isAuthenticationDelegated',
            'status': 'status',
            'provider': 'provider',
            'creation_mechanism': 'creationMechanism',
            'do_not_show_getting_started': 'doNotShowGettingStarted',
            'bypass_notification': 'bypassNotification',
            'is_account_recovery_enrolled': 'isAccountRecoveryEnrolled',
            'account_recovery_required': 'accountRecoveryRequired',
            'user_flow_controlled_by_external_client': 'userFlowControlledByExternalClient',
            'is_group_membership_normalized': 'isGroupMembershipNormalized',
            'is_group_membership_synced_to_users_groups': 'isGroupMembershipSyncedToUsersGroups',
            'notification_email_template_id': 'notificationEmailTemplateId',
            'support_accounts': 'supportAccounts',
            'idcs_app_roles_limited_to_groups': 'idcsAppRolesLimitedToGroups',
            'user_token': 'userToken',
            'synced_from_app': 'syncedFromApp',
            'applicable_authentication_target_app': 'applicableAuthenticationTargetApp',
            'delegated_authentication_target_app': 'delegatedAuthenticationTargetApp',
            'accounts': 'accounts',
            'grants': 'grants',
            'app_roles': 'appRoles'
        }

        self._is_federated_user = None
        self._is_authentication_delegated = None
        self._status = None
        self._provider = None
        self._creation_mechanism = None
        self._do_not_show_getting_started = None
        self._bypass_notification = None
        self._is_account_recovery_enrolled = None
        self._account_recovery_required = None
        self._user_flow_controlled_by_external_client = None
        self._is_group_membership_normalized = None
        self._is_group_membership_synced_to_users_groups = None
        self._notification_email_template_id = None
        self._support_accounts = None
        self._idcs_app_roles_limited_to_groups = None
        self._user_token = None
        self._synced_from_app = None
        self._applicable_authentication_target_app = None
        self._delegated_authentication_target_app = None
        self._accounts = None
        self._grants = None
        self._app_roles = None

    @property
    def is_federated_user(self):
        """
        Gets the is_federated_user of this ExtensionUserUser.
        A Boolean value indicating whether or not the user is federated.

        **SCIM++ Properties:**
         - caseExact: false
         - idcsCsvAttributeName: Federated
         - idcsCsvAttributeNameMappings: [[columnHeaderName:Federated]]
         - idcsSearchable: true
         - multiValued: false
         - mutability: readWrite
         - required: false
         - returned: default
         - type: boolean
         - uniqueness: none


        :return: The is_federated_user of this ExtensionUserUser.
        :rtype: bool
        """
        return self._is_federated_user

    @is_federated_user.setter
    def is_federated_user(self, is_federated_user):
        """
        Sets the is_federated_user of this ExtensionUserUser.
        A Boolean value indicating whether or not the user is federated.

        **SCIM++ Properties:**
         - caseExact: false
         - idcsCsvAttributeName: Federated
         - idcsCsvAttributeNameMappings: [[columnHeaderName:Federated]]
         - idcsSearchable: true
         - multiValued: false
         - mutability: readWrite
         - required: false
         - returned: default
         - type: boolean
         - uniqueness: none


        :param is_federated_user: The is_federated_user of this ExtensionUserUser.
        :type: bool
        """
        self._is_federated_user = is_federated_user

    @property
    def is_authentication_delegated(self):
        """
        Gets the is_authentication_delegated of this ExtensionUserUser.
        A Boolean value indicating whether or not authentication request by this user should be delegated to a remote app. This value should be true only when the User was originally synced from an app which is enabled for delegated authentication

        **Added In:** 17.4.6

        **SCIM++ Properties:**
         - caseExact: false
         - idcsSearchable: false
         - multiValued: false
         - mutability: immutable
         - required: false
         - returned: never
         - type: boolean
         - uniqueness: none


        :return: The is_authentication_delegated of this ExtensionUserUser.
        :rtype: bool
        """
        return self._is_authentication_delegated

    @is_authentication_delegated.setter
    def is_authentication_delegated(self, is_authentication_delegated):
        """
        Sets the is_authentication_delegated of this ExtensionUserUser.
        A Boolean value indicating whether or not authentication request by this user should be delegated to a remote app. This value should be true only when the User was originally synced from an app which is enabled for delegated authentication

        **Added In:** 17.4.6

        **SCIM++ Properties:**
         - caseExact: false
         - idcsSearchable: false
         - multiValued: false
         - mutability: immutable
         - required: false
         - returned: never
         - type: boolean
         - uniqueness: none


        :param is_authentication_delegated: The is_authentication_delegated of this ExtensionUserUser.
        :type: bool
        """
        self._is_authentication_delegated = is_authentication_delegated

    @property
    def status(self):
        """
        Gets the status of this ExtensionUserUser.
        A supplemental status indicating the reason why a user is disabled

        **SCIM++ Properties:**
         - caseExact: false
         - idcsSearchable: true
         - multiValued: false
         - mutability: readOnly
         - required: false
         - returned: request
         - type: string
         - uniqueness: none

        Allowed values for this property are: "pendingVerification", "verified", 'UNKNOWN_ENUM_VALUE'.
        Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.


        :return: The status of this ExtensionUserUser.
        :rtype: str
        """
        return self._status

    @status.setter
    def status(self, status):
        """
        Sets the status of this ExtensionUserUser.
        A supplemental status indicating the reason why a user is disabled

        **SCIM++ Properties:**
         - caseExact: false
         - idcsSearchable: true
         - multiValued: false
         - mutability: readOnly
         - required: false
         - returned: request
         - type: string
         - uniqueness: none


        :param status: The status of this ExtensionUserUser.
        :type: str
        """
        allowed_values = ["pendingVerification", "verified"]
        if not value_allowed_none_or_none_sentinel(status, allowed_values):
            status = 'UNKNOWN_ENUM_VALUE'
        self._status = status

    @property
    def provider(self):
        """
        Gets the provider of this ExtensionUserUser.
        Registration provider

        **SCIM++ Properties:**
         - caseExact: false
         - idcsSearchable: true
         - multiValued: false
         - mutability: immutable
         - required: false
         - returned: default
         - type: string
         - uniqueness: none

        Allowed values for this property are: "facebook", "google", "IDCS", "twitter", 'UNKNOWN_ENUM_VALUE'.
        Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.


        :return: The provider of this ExtensionUserUser.
        :rtype: str
        """
        return self._provider

    @provider.setter
    def provider(self, provider):
        """
        Sets the provider of this ExtensionUserUser.
        Registration provider

        **SCIM++ Properties:**
         - caseExact: false
         - idcsSearchable: true
         - multiValued: false
         - mutability: immutable
         - required: false
         - returned: default
         - type: string
         - uniqueness: none


        :param provider: The provider of this ExtensionUserUser.
        :type: str
        """
        allowed_values = ["facebook", "google", "IDCS", "twitter"]
        if not value_allowed_none_or_none_sentinel(provider, allowed_values):
            provider = 'UNKNOWN_ENUM_VALUE'
        self._provider = provider

    @property
    def creation_mechanism(self):
        """
        Gets the creation_mechanism of this ExtensionUserUser.
        User creation mechanism

        **SCIM++ Properties:**
         - caseExact: false
         - idcsCsvAttributeNameMappings: [[defaultValue:import]]
         - idcsSearchable: true
         - multiValued: false
         - mutability: immutable
         - required: false
         - returned: request
         - type: string
         - uniqueness: none

        Allowed values for this property are: "bulk", "api", "adsync", "idcsui", "import", "authsync", "selfreg", "samljit", 'UNKNOWN_ENUM_VALUE'.
        Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.


        :return: The creation_mechanism of this ExtensionUserUser.
        :rtype: str
        """
        return self._creation_mechanism

    @creation_mechanism.setter
    def creation_mechanism(self, creation_mechanism):
        """
        Sets the creation_mechanism of this ExtensionUserUser.
        User creation mechanism

        **SCIM++ Properties:**
         - caseExact: false
         - idcsCsvAttributeNameMappings: [[defaultValue:import]]
         - idcsSearchable: true
         - multiValued: false
         - mutability: immutable
         - required: false
         - returned: request
         - type: string
         - uniqueness: none


        :param creation_mechanism: The creation_mechanism of this ExtensionUserUser.
        :type: str
        """
        allowed_values = ["bulk", "api", "adsync", "idcsui", "import", "authsync", "selfreg", "samljit"]
        if not value_allowed_none_or_none_sentinel(creation_mechanism, allowed_values):
            creation_mechanism = 'UNKNOWN_ENUM_VALUE'
        self._creation_mechanism = creation_mechanism

    @property
    def do_not_show_getting_started(self):
        """
        Gets the do_not_show_getting_started of this ExtensionUserUser.
        A Boolean value indicating whether or not to hide the getting started page

        **SCIM++ Properties:**
         - caseExact: false
         - idcsSearchable: true
         - multiValued: false
         - mutability: readWrite
         - required: false
         - returned: default
         - type: boolean
         - uniqueness: none


        :return: The do_not_show_getting_started of this ExtensionUserUser.
        :rtype: bool
        """
        return self._do_not_show_getting_started

    @do_not_show_getting_started.setter
    def do_not_show_getting_started(self, do_not_show_getting_started):
        """
        Sets the do_not_show_getting_started of this ExtensionUserUser.
        A Boolean value indicating whether or not to hide the getting started page

        **SCIM++ Properties:**
         - caseExact: false
         - idcsSearchable: true
         - multiValued: false
         - mutability: readWrite
         - required: false
         - returned: default
         - type: boolean
         - uniqueness: none


        :param do_not_show_getting_started: The do_not_show_getting_started of this ExtensionUserUser.
        :type: bool
        """
        self._do_not_show_getting_started = do_not_show_getting_started

    @property
    def bypass_notification(self):
        """
        Gets the bypass_notification of this ExtensionUserUser.
        A Boolean value indicating whether or not to send email notification after creating the user. This attribute is not used in update/replace operations.

        **SCIM++ Properties:**
         - caseExact: false
         - idcsCsvAttributeNameMappings: [[columnHeaderName:ByPass Notification]]
         - idcsSearchable: false
         - multiValued: false
         - mutability: immutable
         - required: false
         - returned: never
         - type: boolean
         - uniqueness: none


        :return: The bypass_notification of this ExtensionUserUser.
        :rtype: bool
        """
        return self._bypass_notification

    @bypass_notification.setter
    def bypass_notification(self, bypass_notification):
        """
        Sets the bypass_notification of this ExtensionUserUser.
        A Boolean value indicating whether or not to send email notification after creating the user. This attribute is not used in update/replace operations.

        **SCIM++ Properties:**
         - caseExact: false
         - idcsCsvAttributeNameMappings: [[columnHeaderName:ByPass Notification]]
         - idcsSearchable: false
         - multiValued: false
         - mutability: immutable
         - required: false
         - returned: never
         - type: boolean
         - uniqueness: none


        :param bypass_notification: The bypass_notification of this ExtensionUserUser.
        :type: bool
        """
        self._bypass_notification = bypass_notification

    @property
    def is_account_recovery_enrolled(self):
        """
        Gets the is_account_recovery_enrolled of this ExtensionUserUser.
        A Boolean value indicating whether or not a user is enrolled for account recovery

        **Added In:** 19.1.4

        **SCIM++ Properties:**
         - caseExact: false
         - idcsSearchable: false
         - multiValued: false
         - mutability: readOnly
         - required: false
         - returned: request
         - type: boolean
         - uniqueness: none


        :return: The is_account_recovery_enrolled of this ExtensionUserUser.
        :rtype: bool
        """
        return self._is_account_recovery_enrolled

    @is_account_recovery_enrolled.setter
    def is_account_recovery_enrolled(self, is_account_recovery_enrolled):
        """
        Sets the is_account_recovery_enrolled of this ExtensionUserUser.
        A Boolean value indicating whether or not a user is enrolled for account recovery

        **Added In:** 19.1.4

        **SCIM++ Properties:**
         - caseExact: false
         - idcsSearchable: false
         - multiValued: false
         - mutability: readOnly
         - required: false
         - returned: request
         - type: boolean
         - uniqueness: none


        :param is_account_recovery_enrolled: The is_account_recovery_enrolled of this ExtensionUserUser.
        :type: bool
        """
        self._is_account_recovery_enrolled = is_account_recovery_enrolled

    @property
    def account_recovery_required(self):
        """
        Gets the account_recovery_required of this ExtensionUserUser.
        Boolean value to prompt user to setup account recovery during login.

        **Added In:** 19.1.4

        **SCIM++ Properties:**
         - idcsSearchable: false
         - multiValued: false
         - mutability: readWrite
         - required: false
         - returned: request
         - type: boolean
         - uniqueness: none


        :return: The account_recovery_required of this ExtensionUserUser.
        :rtype: bool
        """
        return self._account_recovery_required

    @account_recovery_required.setter
    def account_recovery_required(self, account_recovery_required):
        """
        Sets the account_recovery_required of this ExtensionUserUser.
        Boolean value to prompt user to setup account recovery during login.

        **Added In:** 19.1.4

        **SCIM++ Properties:**
         - idcsSearchable: false
         - multiValued: false
         - mutability: readWrite
         - required: false
         - returned: request
         - type: boolean
         - uniqueness: none


        :param account_recovery_required: The account_recovery_required of this ExtensionUserUser.
        :type: bool
        """
        self._account_recovery_required = account_recovery_required

    @property
    def user_flow_controlled_by_external_client(self):
        """
        Gets the user_flow_controlled_by_external_client of this ExtensionUserUser.
        A Boolean value indicating whether to bypass notification and return user token to be used by an external client to control the user flow.

        **Added In:** 18.4.2

        **SCIM++ Properties:**
         - caseExact: false
         - idcsSearchable: false
         - multiValued: false
         - mutability: immutable
         - required: false
         - returned: never
         - type: boolean
         - uniqueness: none


        :return: The user_flow_controlled_by_external_client of this ExtensionUserUser.
        :rtype: bool
        """
        return self._user_flow_controlled_by_external_client

    @user_flow_controlled_by_external_client.setter
    def user_flow_controlled_by_external_client(self, user_flow_controlled_by_external_client):
        """
        Sets the user_flow_controlled_by_external_client of this ExtensionUserUser.
        A Boolean value indicating whether to bypass notification and return user token to be used by an external client to control the user flow.

        **Added In:** 18.4.2

        **SCIM++ Properties:**
         - caseExact: false
         - idcsSearchable: false
         - multiValued: false
         - mutability: immutable
         - required: false
         - returned: never
         - type: boolean
         - uniqueness: none


        :param user_flow_controlled_by_external_client: The user_flow_controlled_by_external_client of this ExtensionUserUser.
        :type: bool
        """
        self._user_flow_controlled_by_external_client = user_flow_controlled_by_external_client

    @property
    def is_group_membership_normalized(self):
        """
        Gets the is_group_membership_normalized of this ExtensionUserUser.
        A Boolean value indicating whether or not group membership is normalized for this user.

        **Deprecated Since: 19.3.3**

        **SCIM++ Properties:**
         - caseExact: false
         - idcsSearchable: false
         - multiValued: false
         - mutability: immutable
         - required: false
         - returned: never
         - type: boolean
         - uniqueness: none


        :return: The is_group_membership_normalized of this ExtensionUserUser.
        :rtype: bool
        """
        return self._is_group_membership_normalized

    @is_group_membership_normalized.setter
    def is_group_membership_normalized(self, is_group_membership_normalized):
        """
        Sets the is_group_membership_normalized of this ExtensionUserUser.
        A Boolean value indicating whether or not group membership is normalized for this user.

        **Deprecated Since: 19.3.3**

        **SCIM++ Properties:**
         - caseExact: false
         - idcsSearchable: false
         - multiValued: false
         - mutability: immutable
         - required: false
         - returned: never
         - type: boolean
         - uniqueness: none


        :param is_group_membership_normalized: The is_group_membership_normalized of this ExtensionUserUser.
        :type: bool
        """
        self._is_group_membership_normalized = is_group_membership_normalized

    @property
    def is_group_membership_synced_to_users_groups(self):
        """
        Gets the is_group_membership_synced_to_users_groups of this ExtensionUserUser.
        A Boolean value Indicates whether this User's group membership has been sync'ed from Group.members to UsersGroups.

        **Added In:** 19.3.3

        **SCIM++ Properties:**
         - caseExact: false
         - idcsSearchable: false
         - multiValued: false
         - mutability: immutable
         - required: false
         - returned: never
         - type: boolean
         - uniqueness: none


        :return: The is_group_membership_synced_to_users_groups of this ExtensionUserUser.
        :rtype: bool
        """
        return self._is_group_membership_synced_to_users_groups

    @is_group_membership_synced_to_users_groups.setter
    def is_group_membership_synced_to_users_groups(self, is_group_membership_synced_to_users_groups):
        """
        Sets the is_group_membership_synced_to_users_groups of this ExtensionUserUser.
        A Boolean value Indicates whether this User's group membership has been sync'ed from Group.members to UsersGroups.

        **Added In:** 19.3.3

        **SCIM++ Properties:**
         - caseExact: false
         - idcsSearchable: false
         - multiValued: false
         - mutability: immutable
         - required: false
         - returned: never
         - type: boolean
         - uniqueness: none


        :param is_group_membership_synced_to_users_groups: The is_group_membership_synced_to_users_groups of this ExtensionUserUser.
        :type: bool
        """
        self._is_group_membership_synced_to_users_groups = is_group_membership_synced_to_users_groups

    @property
    def notification_email_template_id(self):
        """
        Gets the notification_email_template_id of this ExtensionUserUser.
        Specifies the EmailTemplate to be used when sending notification to the user this request is for. If specified, it overrides the default EmailTemplate for this event.

        **SCIM++ Properties:**
         - caseExact: false
         - idcsSearchable: false
         - multiValued: false
         - mutability: writeOnly
         - required: false
         - returned: never
         - type: string
         - uniqueness: none


        :return: The notification_email_template_id of this ExtensionUserUser.
        :rtype: str
        """
        return self._notification_email_template_id

    @notification_email_template_id.setter
    def notification_email_template_id(self, notification_email_template_id):
        """
        Sets the notification_email_template_id of this ExtensionUserUser.
        Specifies the EmailTemplate to be used when sending notification to the user this request is for. If specified, it overrides the default EmailTemplate for this event.

        **SCIM++ Properties:**
         - caseExact: false
         - idcsSearchable: false
         - multiValued: false
         - mutability: writeOnly
         - required: false
         - returned: never
         - type: string
         - uniqueness: none


        :param notification_email_template_id: The notification_email_template_id of this ExtensionUserUser.
        :type: str
        """
        self._notification_email_template_id = notification_email_template_id

    @property
    def support_accounts(self):
        """
        Gets the support_accounts of this ExtensionUserUser.
        A list of Support Accounts corresponding to user.

        **Added In:** 2103141444

        **SCIM++ Properties:**
         - idcsCompositeKey: [value]
         - idcsSearchable: true
         - multiValued: true
         - mutability: readOnly
         - required: false
         - returned: request
         - type: complex
         - uniqueness: none


        :return: The support_accounts of this ExtensionUserUser.
        :rtype: list[oci.identity_domains.models.UserExtSupportAccounts]
        """
        return self._support_accounts

    @support_accounts.setter
    def support_accounts(self, support_accounts):
        """
        Sets the support_accounts of this ExtensionUserUser.
        A list of Support Accounts corresponding to user.

        **Added In:** 2103141444

        **SCIM++ Properties:**
         - idcsCompositeKey: [value]
         - idcsSearchable: true
         - multiValued: true
         - mutability: readOnly
         - required: false
         - returned: request
         - type: complex
         - uniqueness: none


        :param support_accounts: The support_accounts of this ExtensionUserUser.
        :type: list[oci.identity_domains.models.UserExtSupportAccounts]
        """
        self._support_accounts = support_accounts

    @property
    def idcs_app_roles_limited_to_groups(self):
        """
        Gets the idcs_app_roles_limited_to_groups of this ExtensionUserUser.
        Description:

        **Added In:** 19.2.1

        **SCIM++ Properties:**
         - idcsCompositeKey: [value, idcsAppRoleId]
         - idcsSearchable: true
         - multiValued: true
         - mutability: readOnly
         - required: false
         - returned: request
         - type: complex


        :return: The idcs_app_roles_limited_to_groups of this ExtensionUserUser.
        :rtype: list[oci.identity_domains.models.UserExtIdcsAppRolesLimitedToGroups]
        """
        return self._idcs_app_roles_limited_to_groups

    @idcs_app_roles_limited_to_groups.setter
    def idcs_app_roles_limited_to_groups(self, idcs_app_roles_limited_to_groups):
        """
        Sets the idcs_app_roles_limited_to_groups of this ExtensionUserUser.
        Description:

        **Added In:** 19.2.1

        **SCIM++ Properties:**
         - idcsCompositeKey: [value, idcsAppRoleId]
         - idcsSearchable: true
         - multiValued: true
         - mutability: readOnly
         - required: false
         - returned: request
         - type: complex


        :param idcs_app_roles_limited_to_groups: The idcs_app_roles_limited_to_groups of this ExtensionUserUser.
        :type: list[oci.identity_domains.models.UserExtIdcsAppRolesLimitedToGroups]
        """
        self._idcs_app_roles_limited_to_groups = idcs_app_roles_limited_to_groups

    @property
    def user_token(self):
        """
        Gets the user_token of this ExtensionUserUser.

        :return: The user_token of this ExtensionUserUser.
        :rtype: oci.identity_domains.models.UserExtUserToken
        """
        return self._user_token

    @user_token.setter
    def user_token(self, user_token):
        """
        Sets the user_token of this ExtensionUserUser.

        :param user_token: The user_token of this ExtensionUserUser.
        :type: oci.identity_domains.models.UserExtUserToken
        """
        self._user_token = user_token

    @property
    def synced_from_app(self):
        """
        Gets the synced_from_app of this ExtensionUserUser.

        :return: The synced_from_app of this ExtensionUserUser.
        :rtype: oci.identity_domains.models.UserExtSyncedFromApp
        """
        return self._synced_from_app

    @synced_from_app.setter
    def synced_from_app(self, synced_from_app):
        """
        Sets the synced_from_app of this ExtensionUserUser.

        :param synced_from_app: The synced_from_app of this ExtensionUserUser.
        :type: oci.identity_domains.models.UserExtSyncedFromApp
        """
        self._synced_from_app = synced_from_app

    @property
    def applicable_authentication_target_app(self):
        """
        Gets the applicable_authentication_target_app of this ExtensionUserUser.

        :return: The applicable_authentication_target_app of this ExtensionUserUser.
        :rtype: oci.identity_domains.models.UserExtApplicableAuthenticationTargetApp
        """
        return self._applicable_authentication_target_app

    @applicable_authentication_target_app.setter
    def applicable_authentication_target_app(self, applicable_authentication_target_app):
        """
        Sets the applicable_authentication_target_app of this ExtensionUserUser.

        :param applicable_authentication_target_app: The applicable_authentication_target_app of this ExtensionUserUser.
        :type: oci.identity_domains.models.UserExtApplicableAuthenticationTargetApp
        """
        self._applicable_authentication_target_app = applicable_authentication_target_app

    @property
    def delegated_authentication_target_app(self):
        """
        Gets the delegated_authentication_target_app of this ExtensionUserUser.

        :return: The delegated_authentication_target_app of this ExtensionUserUser.
        :rtype: oci.identity_domains.models.UserExtDelegatedAuthenticationTargetApp
        """
        return self._delegated_authentication_target_app

    @delegated_authentication_target_app.setter
    def delegated_authentication_target_app(self, delegated_authentication_target_app):
        """
        Sets the delegated_authentication_target_app of this ExtensionUserUser.

        :param delegated_authentication_target_app: The delegated_authentication_target_app of this ExtensionUserUser.
        :type: oci.identity_domains.models.UserExtDelegatedAuthenticationTargetApp
        """
        self._delegated_authentication_target_app = delegated_authentication_target_app

    @property
    def accounts(self):
        """
        Gets the accounts of this ExtensionUserUser.
        Accounts assigned to this User. Each value of this attribute refers to an app-specific identity that is owned by this User. Therefore, this attribute is a convenience that allows one to see on each User the Apps to which that User has access.

        **SCIM++ Properties:**
         - idcsPii: true
         - idcsSearchable: true
         - multiValued: true
         - mutability: readOnly
         - required: false
         - returned: request
         - type: complex
         - uniqueness: none


        :return: The accounts of this ExtensionUserUser.
        :rtype: list[oci.identity_domains.models.UserExtAccounts]
        """
        return self._accounts

    @accounts.setter
    def accounts(self, accounts):
        """
        Sets the accounts of this ExtensionUserUser.
        Accounts assigned to this User. Each value of this attribute refers to an app-specific identity that is owned by this User. Therefore, this attribute is a convenience that allows one to see on each User the Apps to which that User has access.

        **SCIM++ Properties:**
         - idcsPii: true
         - idcsSearchable: true
         - multiValued: true
         - mutability: readOnly
         - required: false
         - returned: request
         - type: complex
         - uniqueness: none


        :param accounts: The accounts of this ExtensionUserUser.
        :type: list[oci.identity_domains.models.UserExtAccounts]
        """
        self._accounts = accounts

    @property
    def grants(self):
        """
        Gets the grants of this ExtensionUserUser.
        Grants to this User. Each value of this attribute refers to a Grant to this User of some App (and optionally of some entitlement). Therefore, this attribute is a convenience that allows one to see on each User all of the Grants to that User.

        **SCIM++ Properties:**
         - idcsSearchable: true
         - multiValued: true
         - mutability: readOnly
         - required: false
         - returned: request
         - type: complex
         - uniqueness: none


        :return: The grants of this ExtensionUserUser.
        :rtype: list[oci.identity_domains.models.UserExtGrants]
        """
        return self._grants

    @grants.setter
    def grants(self, grants):
        """
        Sets the grants of this ExtensionUserUser.
        Grants to this User. Each value of this attribute refers to a Grant to this User of some App (and optionally of some entitlement). Therefore, this attribute is a convenience that allows one to see on each User all of the Grants to that User.

        **SCIM++ Properties:**
         - idcsSearchable: true
         - multiValued: true
         - mutability: readOnly
         - required: false
         - returned: request
         - type: complex
         - uniqueness: none


        :param grants: The grants of this ExtensionUserUser.
        :type: list[oci.identity_domains.models.UserExtGrants]
        """
        self._grants = grants

    @property
    def app_roles(self):
        """
        Gets the app_roles of this ExtensionUserUser.
        A list of all AppRoles to which this User belongs directly, indirectly or implicitly. The User could belong directly because the User is a member of the AppRole, could belong indirectly because the User is a member of a Group that is a member of the AppRole, or could belong implicitly because the AppRole is public.

        **SCIM++ Properties:**
         - idcsCompositeKey: [value]
         - multiValued: true
         - mutability: readOnly
         - required: false
         - returned: request
         - type: complex
         - uniqueness: none


        :return: The app_roles of this ExtensionUserUser.
        :rtype: list[oci.identity_domains.models.UserExtAppRoles]
        """
        return self._app_roles

    @app_roles.setter
    def app_roles(self, app_roles):
        """
        Sets the app_roles of this ExtensionUserUser.
        A list of all AppRoles to which this User belongs directly, indirectly or implicitly. The User could belong directly because the User is a member of the AppRole, could belong indirectly because the User is a member of a Group that is a member of the AppRole, or could belong implicitly because the AppRole is public.

        **SCIM++ Properties:**
         - idcsCompositeKey: [value]
         - multiValued: true
         - mutability: readOnly
         - required: false
         - returned: request
         - type: complex
         - uniqueness: none


        :param app_roles: The app_roles of this ExtensionUserUser.
        :type: list[oci.identity_domains.models.UserExtAppRoles]
        """
        self._app_roles = app_roles

    def __repr__(self):
        return formatted_flat_dict(self)

    def __eq__(self, other):
        if other is None:
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not self == other
