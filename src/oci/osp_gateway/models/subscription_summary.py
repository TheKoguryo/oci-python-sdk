# coding: utf-8
# Copyright (c) 2016, 2022, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.


from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class SubscriptionSummary(object):
    """
    Subscription object which contains the common subscription data.
    """

    #: A constant which can be used with the plan_type property of a SubscriptionSummary.
    #: This constant has a value of "FREE_TIER"
    PLAN_TYPE_FREE_TIER = "FREE_TIER"

    #: A constant which can be used with the plan_type property of a SubscriptionSummary.
    #: This constant has a value of "PAYG"
    PLAN_TYPE_PAYG = "PAYG"

    #: A constant which can be used with the upgrade_state property of a SubscriptionSummary.
    #: This constant has a value of "PROMO"
    UPGRADE_STATE_PROMO = "PROMO"

    #: A constant which can be used with the upgrade_state property of a SubscriptionSummary.
    #: This constant has a value of "SUBMITTED"
    UPGRADE_STATE_SUBMITTED = "SUBMITTED"

    #: A constant which can be used with the upgrade_state property of a SubscriptionSummary.
    #: This constant has a value of "ERROR"
    UPGRADE_STATE_ERROR = "ERROR"

    #: A constant which can be used with the upgrade_state property of a SubscriptionSummary.
    #: This constant has a value of "UPGRADED"
    UPGRADE_STATE_UPGRADED = "UPGRADED"

    #: A constant which can be used with the upgrade_state_details property of a SubscriptionSummary.
    #: This constant has a value of "TAX_ERROR"
    UPGRADE_STATE_DETAILS_TAX_ERROR = "TAX_ERROR"

    #: A constant which can be used with the upgrade_state_details property of a SubscriptionSummary.
    #: This constant has a value of "UPGRADE_ERROR"
    UPGRADE_STATE_DETAILS_UPGRADE_ERROR = "UPGRADE_ERROR"

    def __init__(self, **kwargs):
        """
        Initializes a new SubscriptionSummary object with values from keyword arguments.
        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param id:
            The value to assign to the id property of this SubscriptionSummary.
        :type id: str

        :param subscription_plan_number:
            The value to assign to the subscription_plan_number property of this SubscriptionSummary.
        :type subscription_plan_number: str

        :param plan_type:
            The value to assign to the plan_type property of this SubscriptionSummary.
            Allowed values for this property are: "FREE_TIER", "PAYG", 'UNKNOWN_ENUM_VALUE'.
            Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.
        :type plan_type: str

        :param time_start:
            The value to assign to the time_start property of this SubscriptionSummary.
        :type time_start: datetime

        :param ship_to_cust_acct_site_id:
            The value to assign to the ship_to_cust_acct_site_id property of this SubscriptionSummary.
        :type ship_to_cust_acct_site_id: str

        :param ship_to_cust_acct_role_id:
            The value to assign to the ship_to_cust_acct_role_id property of this SubscriptionSummary.
        :type ship_to_cust_acct_role_id: str

        :param bill_to_cust_account_id:
            The value to assign to the bill_to_cust_account_id property of this SubscriptionSummary.
        :type bill_to_cust_account_id: str

        :param is_intent_to_pay:
            The value to assign to the is_intent_to_pay property of this SubscriptionSummary.
        :type is_intent_to_pay: bool

        :param currency_code:
            The value to assign to the currency_code property of this SubscriptionSummary.
        :type currency_code: str

        :param gsi_org_code:
            The value to assign to the gsi_org_code property of this SubscriptionSummary.
        :type gsi_org_code: str

        :param language_code:
            The value to assign to the language_code property of this SubscriptionSummary.
        :type language_code: str

        :param organization_id:
            The value to assign to the organization_id property of this SubscriptionSummary.
        :type organization_id: str

        :param upgrade_state:
            The value to assign to the upgrade_state property of this SubscriptionSummary.
            Allowed values for this property are: "PROMO", "SUBMITTED", "ERROR", "UPGRADED", 'UNKNOWN_ENUM_VALUE'.
            Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.
        :type upgrade_state: str

        :param upgrade_state_details:
            The value to assign to the upgrade_state_details property of this SubscriptionSummary.
            Allowed values for this property are: "TAX_ERROR", "UPGRADE_ERROR", 'UNKNOWN_ENUM_VALUE'.
            Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.
        :type upgrade_state_details: str

        :param tax_info:
            The value to assign to the tax_info property of this SubscriptionSummary.
        :type tax_info: oci.osp_gateway.models.TaxInfo

        :param payment_options:
            The value to assign to the payment_options property of this SubscriptionSummary.
        :type payment_options: list[oci.osp_gateway.models.PaymentOption]

        :param payment_gateway:
            The value to assign to the payment_gateway property of this SubscriptionSummary.
        :type payment_gateway: oci.osp_gateway.models.PaymentGateway

        :param billing_address:
            The value to assign to the billing_address property of this SubscriptionSummary.
        :type billing_address: oci.osp_gateway.models.BillingAddress

        :param time_plan_upgrade:
            The value to assign to the time_plan_upgrade property of this SubscriptionSummary.
        :type time_plan_upgrade: datetime

        """
        self.swagger_types = {
            'id': 'str',
            'subscription_plan_number': 'str',
            'plan_type': 'str',
            'time_start': 'datetime',
            'ship_to_cust_acct_site_id': 'str',
            'ship_to_cust_acct_role_id': 'str',
            'bill_to_cust_account_id': 'str',
            'is_intent_to_pay': 'bool',
            'currency_code': 'str',
            'gsi_org_code': 'str',
            'language_code': 'str',
            'organization_id': 'str',
            'upgrade_state': 'str',
            'upgrade_state_details': 'str',
            'tax_info': 'TaxInfo',
            'payment_options': 'list[PaymentOption]',
            'payment_gateway': 'PaymentGateway',
            'billing_address': 'BillingAddress',
            'time_plan_upgrade': 'datetime'
        }

        self.attribute_map = {
            'id': 'id',
            'subscription_plan_number': 'subscriptionPlanNumber',
            'plan_type': 'planType',
            'time_start': 'timeStart',
            'ship_to_cust_acct_site_id': 'shipToCustAcctSiteId',
            'ship_to_cust_acct_role_id': 'shipToCustAcctRoleId',
            'bill_to_cust_account_id': 'billToCustAccountId',
            'is_intent_to_pay': 'isIntentToPay',
            'currency_code': 'currencyCode',
            'gsi_org_code': 'gsiOrgCode',
            'language_code': 'languageCode',
            'organization_id': 'organizationId',
            'upgrade_state': 'upgradeState',
            'upgrade_state_details': 'upgradeStateDetails',
            'tax_info': 'taxInfo',
            'payment_options': 'paymentOptions',
            'payment_gateway': 'paymentGateway',
            'billing_address': 'billingAddress',
            'time_plan_upgrade': 'timePlanUpgrade'
        }

        self._id = None
        self._subscription_plan_number = None
        self._plan_type = None
        self._time_start = None
        self._ship_to_cust_acct_site_id = None
        self._ship_to_cust_acct_role_id = None
        self._bill_to_cust_account_id = None
        self._is_intent_to_pay = None
        self._currency_code = None
        self._gsi_org_code = None
        self._language_code = None
        self._organization_id = None
        self._upgrade_state = None
        self._upgrade_state_details = None
        self._tax_info = None
        self._payment_options = None
        self._payment_gateway = None
        self._billing_address = None
        self._time_plan_upgrade = None

    @property
    def id(self):
        """
        Gets the id of this SubscriptionSummary.
        Subscription id identifier (OCID).


        :return: The id of this SubscriptionSummary.
        :rtype: str
        """
        return self._id

    @id.setter
    def id(self, id):
        """
        Sets the id of this SubscriptionSummary.
        Subscription id identifier (OCID).


        :param id: The id of this SubscriptionSummary.
        :type: str
        """
        self._id = id

    @property
    def subscription_plan_number(self):
        """
        **[Required]** Gets the subscription_plan_number of this SubscriptionSummary.
        Subscription plan number.


        :return: The subscription_plan_number of this SubscriptionSummary.
        :rtype: str
        """
        return self._subscription_plan_number

    @subscription_plan_number.setter
    def subscription_plan_number(self, subscription_plan_number):
        """
        Sets the subscription_plan_number of this SubscriptionSummary.
        Subscription plan number.


        :param subscription_plan_number: The subscription_plan_number of this SubscriptionSummary.
        :type: str
        """
        self._subscription_plan_number = subscription_plan_number

    @property
    def plan_type(self):
        """
        Gets the plan_type of this SubscriptionSummary.
        Subscription plan type.

        Allowed values for this property are: "FREE_TIER", "PAYG", 'UNKNOWN_ENUM_VALUE'.
        Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.


        :return: The plan_type of this SubscriptionSummary.
        :rtype: str
        """
        return self._plan_type

    @plan_type.setter
    def plan_type(self, plan_type):
        """
        Sets the plan_type of this SubscriptionSummary.
        Subscription plan type.


        :param plan_type: The plan_type of this SubscriptionSummary.
        :type: str
        """
        allowed_values = ["FREE_TIER", "PAYG"]
        if not value_allowed_none_or_none_sentinel(plan_type, allowed_values):
            plan_type = 'UNKNOWN_ENUM_VALUE'
        self._plan_type = plan_type

    @property
    def time_start(self):
        """
        Gets the time_start of this SubscriptionSummary.
        Start date of the subscription.


        :return: The time_start of this SubscriptionSummary.
        :rtype: datetime
        """
        return self._time_start

    @time_start.setter
    def time_start(self, time_start):
        """
        Sets the time_start of this SubscriptionSummary.
        Start date of the subscription.


        :param time_start: The time_start of this SubscriptionSummary.
        :type: datetime
        """
        self._time_start = time_start

    @property
    def ship_to_cust_acct_site_id(self):
        """
        Gets the ship_to_cust_acct_site_id of this SubscriptionSummary.
        Ship to customer account site address id.


        :return: The ship_to_cust_acct_site_id of this SubscriptionSummary.
        :rtype: str
        """
        return self._ship_to_cust_acct_site_id

    @ship_to_cust_acct_site_id.setter
    def ship_to_cust_acct_site_id(self, ship_to_cust_acct_site_id):
        """
        Sets the ship_to_cust_acct_site_id of this SubscriptionSummary.
        Ship to customer account site address id.


        :param ship_to_cust_acct_site_id: The ship_to_cust_acct_site_id of this SubscriptionSummary.
        :type: str
        """
        self._ship_to_cust_acct_site_id = ship_to_cust_acct_site_id

    @property
    def ship_to_cust_acct_role_id(self):
        """
        Gets the ship_to_cust_acct_role_id of this SubscriptionSummary.
        Ship to customer account role.


        :return: The ship_to_cust_acct_role_id of this SubscriptionSummary.
        :rtype: str
        """
        return self._ship_to_cust_acct_role_id

    @ship_to_cust_acct_role_id.setter
    def ship_to_cust_acct_role_id(self, ship_to_cust_acct_role_id):
        """
        Sets the ship_to_cust_acct_role_id of this SubscriptionSummary.
        Ship to customer account role.


        :param ship_to_cust_acct_role_id: The ship_to_cust_acct_role_id of this SubscriptionSummary.
        :type: str
        """
        self._ship_to_cust_acct_role_id = ship_to_cust_acct_role_id

    @property
    def bill_to_cust_account_id(self):
        """
        Gets the bill_to_cust_account_id of this SubscriptionSummary.
        Bill to customer Account id.


        :return: The bill_to_cust_account_id of this SubscriptionSummary.
        :rtype: str
        """
        return self._bill_to_cust_account_id

    @bill_to_cust_account_id.setter
    def bill_to_cust_account_id(self, bill_to_cust_account_id):
        """
        Sets the bill_to_cust_account_id of this SubscriptionSummary.
        Bill to customer Account id.


        :param bill_to_cust_account_id: The bill_to_cust_account_id of this SubscriptionSummary.
        :type: str
        """
        self._bill_to_cust_account_id = bill_to_cust_account_id

    @property
    def is_intent_to_pay(self):
        """
        Gets the is_intent_to_pay of this SubscriptionSummary.
        Payment intension.


        :return: The is_intent_to_pay of this SubscriptionSummary.
        :rtype: bool
        """
        return self._is_intent_to_pay

    @is_intent_to_pay.setter
    def is_intent_to_pay(self, is_intent_to_pay):
        """
        Sets the is_intent_to_pay of this SubscriptionSummary.
        Payment intension.


        :param is_intent_to_pay: The is_intent_to_pay of this SubscriptionSummary.
        :type: bool
        """
        self._is_intent_to_pay = is_intent_to_pay

    @property
    def currency_code(self):
        """
        Gets the currency_code of this SubscriptionSummary.
        Currency code


        :return: The currency_code of this SubscriptionSummary.
        :rtype: str
        """
        return self._currency_code

    @currency_code.setter
    def currency_code(self, currency_code):
        """
        Sets the currency_code of this SubscriptionSummary.
        Currency code


        :param currency_code: The currency_code of this SubscriptionSummary.
        :type: str
        """
        self._currency_code = currency_code

    @property
    def gsi_org_code(self):
        """
        Gets the gsi_org_code of this SubscriptionSummary.
        GSI Subscription external code.


        :return: The gsi_org_code of this SubscriptionSummary.
        :rtype: str
        """
        return self._gsi_org_code

    @gsi_org_code.setter
    def gsi_org_code(self, gsi_org_code):
        """
        Sets the gsi_org_code of this SubscriptionSummary.
        GSI Subscription external code.


        :param gsi_org_code: The gsi_org_code of this SubscriptionSummary.
        :type: str
        """
        self._gsi_org_code = gsi_org_code

    @property
    def language_code(self):
        """
        Gets the language_code of this SubscriptionSummary.
        Language short code (en, de, hu, etc)


        :return: The language_code of this SubscriptionSummary.
        :rtype: str
        """
        return self._language_code

    @language_code.setter
    def language_code(self, language_code):
        """
        Sets the language_code of this SubscriptionSummary.
        Language short code (en, de, hu, etc)


        :param language_code: The language_code of this SubscriptionSummary.
        :type: str
        """
        self._language_code = language_code

    @property
    def organization_id(self):
        """
        Gets the organization_id of this SubscriptionSummary.
        GSI organization external identifier.


        :return: The organization_id of this SubscriptionSummary.
        :rtype: str
        """
        return self._organization_id

    @organization_id.setter
    def organization_id(self, organization_id):
        """
        Sets the organization_id of this SubscriptionSummary.
        GSI organization external identifier.


        :param organization_id: The organization_id of this SubscriptionSummary.
        :type: str
        """
        self._organization_id = organization_id

    @property
    def upgrade_state(self):
        """
        Gets the upgrade_state of this SubscriptionSummary.
        Status of the upgrade.

        Allowed values for this property are: "PROMO", "SUBMITTED", "ERROR", "UPGRADED", 'UNKNOWN_ENUM_VALUE'.
        Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.


        :return: The upgrade_state of this SubscriptionSummary.
        :rtype: str
        """
        return self._upgrade_state

    @upgrade_state.setter
    def upgrade_state(self, upgrade_state):
        """
        Sets the upgrade_state of this SubscriptionSummary.
        Status of the upgrade.


        :param upgrade_state: The upgrade_state of this SubscriptionSummary.
        :type: str
        """
        allowed_values = ["PROMO", "SUBMITTED", "ERROR", "UPGRADED"]
        if not value_allowed_none_or_none_sentinel(upgrade_state, allowed_values):
            upgrade_state = 'UNKNOWN_ENUM_VALUE'
        self._upgrade_state = upgrade_state

    @property
    def upgrade_state_details(self):
        """
        Gets the upgrade_state_details of this SubscriptionSummary.
        This field is used to describe the Upgrade State in case of error (E.g. Upgrade failure caused by interfacing Tax details- TaxError)

        Allowed values for this property are: "TAX_ERROR", "UPGRADE_ERROR", 'UNKNOWN_ENUM_VALUE'.
        Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.


        :return: The upgrade_state_details of this SubscriptionSummary.
        :rtype: str
        """
        return self._upgrade_state_details

    @upgrade_state_details.setter
    def upgrade_state_details(self, upgrade_state_details):
        """
        Sets the upgrade_state_details of this SubscriptionSummary.
        This field is used to describe the Upgrade State in case of error (E.g. Upgrade failure caused by interfacing Tax details- TaxError)


        :param upgrade_state_details: The upgrade_state_details of this SubscriptionSummary.
        :type: str
        """
        allowed_values = ["TAX_ERROR", "UPGRADE_ERROR"]
        if not value_allowed_none_or_none_sentinel(upgrade_state_details, allowed_values):
            upgrade_state_details = 'UNKNOWN_ENUM_VALUE'
        self._upgrade_state_details = upgrade_state_details

    @property
    def tax_info(self):
        """
        Gets the tax_info of this SubscriptionSummary.

        :return: The tax_info of this SubscriptionSummary.
        :rtype: oci.osp_gateway.models.TaxInfo
        """
        return self._tax_info

    @tax_info.setter
    def tax_info(self, tax_info):
        """
        Sets the tax_info of this SubscriptionSummary.

        :param tax_info: The tax_info of this SubscriptionSummary.
        :type: oci.osp_gateway.models.TaxInfo
        """
        self._tax_info = tax_info

    @property
    def payment_options(self):
        """
        Gets the payment_options of this SubscriptionSummary.
        Payment option list of a subscription.


        :return: The payment_options of this SubscriptionSummary.
        :rtype: list[oci.osp_gateway.models.PaymentOption]
        """
        return self._payment_options

    @payment_options.setter
    def payment_options(self, payment_options):
        """
        Sets the payment_options of this SubscriptionSummary.
        Payment option list of a subscription.


        :param payment_options: The payment_options of this SubscriptionSummary.
        :type: list[oci.osp_gateway.models.PaymentOption]
        """
        self._payment_options = payment_options

    @property
    def payment_gateway(self):
        """
        Gets the payment_gateway of this SubscriptionSummary.

        :return: The payment_gateway of this SubscriptionSummary.
        :rtype: oci.osp_gateway.models.PaymentGateway
        """
        return self._payment_gateway

    @payment_gateway.setter
    def payment_gateway(self, payment_gateway):
        """
        Sets the payment_gateway of this SubscriptionSummary.

        :param payment_gateway: The payment_gateway of this SubscriptionSummary.
        :type: oci.osp_gateway.models.PaymentGateway
        """
        self._payment_gateway = payment_gateway

    @property
    def billing_address(self):
        """
        Gets the billing_address of this SubscriptionSummary.

        :return: The billing_address of this SubscriptionSummary.
        :rtype: oci.osp_gateway.models.BillingAddress
        """
        return self._billing_address

    @billing_address.setter
    def billing_address(self, billing_address):
        """
        Sets the billing_address of this SubscriptionSummary.

        :param billing_address: The billing_address of this SubscriptionSummary.
        :type: oci.osp_gateway.models.BillingAddress
        """
        self._billing_address = billing_address

    @property
    def time_plan_upgrade(self):
        """
        Gets the time_plan_upgrade of this SubscriptionSummary.
        Date of upgrade/conversion when planType changed from FREE_TIER to PAYG


        :return: The time_plan_upgrade of this SubscriptionSummary.
        :rtype: datetime
        """
        return self._time_plan_upgrade

    @time_plan_upgrade.setter
    def time_plan_upgrade(self, time_plan_upgrade):
        """
        Sets the time_plan_upgrade of this SubscriptionSummary.
        Date of upgrade/conversion when planType changed from FREE_TIER to PAYG


        :param time_plan_upgrade: The time_plan_upgrade of this SubscriptionSummary.
        :type: datetime
        """
        self._time_plan_upgrade = time_plan_upgrade

    def __repr__(self):
        return formatted_flat_dict(self)

    def __eq__(self, other):
        if other is None:
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not self == other