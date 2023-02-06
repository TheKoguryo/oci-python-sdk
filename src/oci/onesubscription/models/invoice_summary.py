# coding: utf-8
# Copyright (c) 2016, 2023, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.


from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class InvoiceSummary(object):
    """
    Invoice details
    """

    def __init__(self, **kwargs):
        """
        Initializes a new InvoiceSummary object with values from keyword arguments.
        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param spm_invoice_number:
            The value to assign to the spm_invoice_number property of this InvoiceSummary.
        :type spm_invoice_number: str

        :param ar_invoices:
            The value to assign to the ar_invoices property of this InvoiceSummary.
        :type ar_invoices: str

        :param bill_to_customer:
            The value to assign to the bill_to_customer property of this InvoiceSummary.
        :type bill_to_customer: oci.onesubscription.models.InvoicingBusinessPartner

        :param bill_to_contact:
            The value to assign to the bill_to_contact property of this InvoiceSummary.
        :type bill_to_contact: oci.onesubscription.models.InvoicingUser

        :param bill_to_address:
            The value to assign to the bill_to_address property of this InvoiceSummary.
        :type bill_to_address: oci.onesubscription.models.InvoicingAddress

        :param payment_method:
            The value to assign to the payment_method property of this InvoiceSummary.
        :type payment_method: str

        :param payment_term:
            The value to assign to the payment_term property of this InvoiceSummary.
        :type payment_term: oci.onesubscription.models.InvoicingPaymentTerm

        :param receipt_method:
            The value to assign to the receipt_method property of this InvoiceSummary.
        :type receipt_method: str

        :param currency:
            The value to assign to the currency property of this InvoiceSummary.
        :type currency: oci.onesubscription.models.InvoicingCurrency

        :param organization:
            The value to assign to the organization property of this InvoiceSummary.
        :type organization: oci.onesubscription.models.InvoicingOrganization

        :param type:
            The value to assign to the type property of this InvoiceSummary.
        :type type: str

        :param status:
            The value to assign to the status property of this InvoiceSummary.
        :type status: str

        :param subscription_number:
            The value to assign to the subscription_number property of this InvoiceSummary.
        :type subscription_number: str

        :param time_invoice_date:
            The value to assign to the time_invoice_date property of this InvoiceSummary.
        :type time_invoice_date: datetime

        :param time_created:
            The value to assign to the time_created property of this InvoiceSummary.
        :type time_created: datetime

        :param created_by:
            The value to assign to the created_by property of this InvoiceSummary.
        :type created_by: str

        :param time_updated:
            The value to assign to the time_updated property of this InvoiceSummary.
        :type time_updated: datetime

        :param updated_by:
            The value to assign to the updated_by property of this InvoiceSummary.
        :type updated_by: str

        :param invoice_lines:
            The value to assign to the invoice_lines property of this InvoiceSummary.
        :type invoice_lines: list[oci.onesubscription.models.InvoiceLineSummary]

        """
        self.swagger_types = {
            'spm_invoice_number': 'str',
            'ar_invoices': 'str',
            'bill_to_customer': 'InvoicingBusinessPartner',
            'bill_to_contact': 'InvoicingUser',
            'bill_to_address': 'InvoicingAddress',
            'payment_method': 'str',
            'payment_term': 'InvoicingPaymentTerm',
            'receipt_method': 'str',
            'currency': 'InvoicingCurrency',
            'organization': 'InvoicingOrganization',
            'type': 'str',
            'status': 'str',
            'subscription_number': 'str',
            'time_invoice_date': 'datetime',
            'time_created': 'datetime',
            'created_by': 'str',
            'time_updated': 'datetime',
            'updated_by': 'str',
            'invoice_lines': 'list[InvoiceLineSummary]'
        }

        self.attribute_map = {
            'spm_invoice_number': 'spmInvoiceNumber',
            'ar_invoices': 'arInvoices',
            'bill_to_customer': 'billToCustomer',
            'bill_to_contact': 'billToContact',
            'bill_to_address': 'billToAddress',
            'payment_method': 'paymentMethod',
            'payment_term': 'paymentTerm',
            'receipt_method': 'receiptMethod',
            'currency': 'currency',
            'organization': 'organization',
            'type': 'type',
            'status': 'status',
            'subscription_number': 'subscriptionNumber',
            'time_invoice_date': 'timeInvoiceDate',
            'time_created': 'timeCreated',
            'created_by': 'createdBy',
            'time_updated': 'timeUpdated',
            'updated_by': 'updatedBy',
            'invoice_lines': 'invoiceLines'
        }

        self._spm_invoice_number = None
        self._ar_invoices = None
        self._bill_to_customer = None
        self._bill_to_contact = None
        self._bill_to_address = None
        self._payment_method = None
        self._payment_term = None
        self._receipt_method = None
        self._currency = None
        self._organization = None
        self._type = None
        self._status = None
        self._subscription_number = None
        self._time_invoice_date = None
        self._time_created = None
        self._created_by = None
        self._time_updated = None
        self._updated_by = None
        self._invoice_lines = None

    @property
    def spm_invoice_number(self):
        """
        **[Required]** Gets the spm_invoice_number of this InvoiceSummary.
        SPM Document Number is an functional identifier for invoice in SPM


        :return: The spm_invoice_number of this InvoiceSummary.
        :rtype: str
        """
        return self._spm_invoice_number

    @spm_invoice_number.setter
    def spm_invoice_number(self, spm_invoice_number):
        """
        Sets the spm_invoice_number of this InvoiceSummary.
        SPM Document Number is an functional identifier for invoice in SPM


        :param spm_invoice_number: The spm_invoice_number of this InvoiceSummary.
        :type: str
        """
        self._spm_invoice_number = spm_invoice_number

    @property
    def ar_invoices(self):
        """
        Gets the ar_invoices of this InvoiceSummary.
        AR Invoice Numbers comma separated under one invoice


        :return: The ar_invoices of this InvoiceSummary.
        :rtype: str
        """
        return self._ar_invoices

    @ar_invoices.setter
    def ar_invoices(self, ar_invoices):
        """
        Sets the ar_invoices of this InvoiceSummary.
        AR Invoice Numbers comma separated under one invoice


        :param ar_invoices: The ar_invoices of this InvoiceSummary.
        :type: str
        """
        self._ar_invoices = ar_invoices

    @property
    def bill_to_customer(self):
        """
        **[Required]** Gets the bill_to_customer of this InvoiceSummary.

        :return: The bill_to_customer of this InvoiceSummary.
        :rtype: oci.onesubscription.models.InvoicingBusinessPartner
        """
        return self._bill_to_customer

    @bill_to_customer.setter
    def bill_to_customer(self, bill_to_customer):
        """
        Sets the bill_to_customer of this InvoiceSummary.

        :param bill_to_customer: The bill_to_customer of this InvoiceSummary.
        :type: oci.onesubscription.models.InvoicingBusinessPartner
        """
        self._bill_to_customer = bill_to_customer

    @property
    def bill_to_contact(self):
        """
        **[Required]** Gets the bill_to_contact of this InvoiceSummary.

        :return: The bill_to_contact of this InvoiceSummary.
        :rtype: oci.onesubscription.models.InvoicingUser
        """
        return self._bill_to_contact

    @bill_to_contact.setter
    def bill_to_contact(self, bill_to_contact):
        """
        Sets the bill_to_contact of this InvoiceSummary.

        :param bill_to_contact: The bill_to_contact of this InvoiceSummary.
        :type: oci.onesubscription.models.InvoicingUser
        """
        self._bill_to_contact = bill_to_contact

    @property
    def bill_to_address(self):
        """
        **[Required]** Gets the bill_to_address of this InvoiceSummary.

        :return: The bill_to_address of this InvoiceSummary.
        :rtype: oci.onesubscription.models.InvoicingAddress
        """
        return self._bill_to_address

    @bill_to_address.setter
    def bill_to_address(self, bill_to_address):
        """
        Sets the bill_to_address of this InvoiceSummary.

        :param bill_to_address: The bill_to_address of this InvoiceSummary.
        :type: oci.onesubscription.models.InvoicingAddress
        """
        self._bill_to_address = bill_to_address

    @property
    def payment_method(self):
        """
        **[Required]** Gets the payment_method of this InvoiceSummary.
        Payment Method


        :return: The payment_method of this InvoiceSummary.
        :rtype: str
        """
        return self._payment_method

    @payment_method.setter
    def payment_method(self, payment_method):
        """
        Sets the payment_method of this InvoiceSummary.
        Payment Method


        :param payment_method: The payment_method of this InvoiceSummary.
        :type: str
        """
        self._payment_method = payment_method

    @property
    def payment_term(self):
        """
        **[Required]** Gets the payment_term of this InvoiceSummary.

        :return: The payment_term of this InvoiceSummary.
        :rtype: oci.onesubscription.models.InvoicingPaymentTerm
        """
        return self._payment_term

    @payment_term.setter
    def payment_term(self, payment_term):
        """
        Sets the payment_term of this InvoiceSummary.

        :param payment_term: The payment_term of this InvoiceSummary.
        :type: oci.onesubscription.models.InvoicingPaymentTerm
        """
        self._payment_term = payment_term

    @property
    def receipt_method(self):
        """
        Gets the receipt_method of this InvoiceSummary.
        Receipt Method of Payment Mode


        :return: The receipt_method of this InvoiceSummary.
        :rtype: str
        """
        return self._receipt_method

    @receipt_method.setter
    def receipt_method(self, receipt_method):
        """
        Sets the receipt_method of this InvoiceSummary.
        Receipt Method of Payment Mode


        :param receipt_method: The receipt_method of this InvoiceSummary.
        :type: str
        """
        self._receipt_method = receipt_method

    @property
    def currency(self):
        """
        **[Required]** Gets the currency of this InvoiceSummary.

        :return: The currency of this InvoiceSummary.
        :rtype: oci.onesubscription.models.InvoicingCurrency
        """
        return self._currency

    @currency.setter
    def currency(self, currency):
        """
        Sets the currency of this InvoiceSummary.

        :param currency: The currency of this InvoiceSummary.
        :type: oci.onesubscription.models.InvoicingCurrency
        """
        self._currency = currency

    @property
    def organization(self):
        """
        **[Required]** Gets the organization of this InvoiceSummary.

        :return: The organization of this InvoiceSummary.
        :rtype: oci.onesubscription.models.InvoicingOrganization
        """
        return self._organization

    @organization.setter
    def organization(self, organization):
        """
        Sets the organization of this InvoiceSummary.

        :param organization: The organization of this InvoiceSummary.
        :type: oci.onesubscription.models.InvoicingOrganization
        """
        self._organization = organization

    @property
    def type(self):
        """
        **[Required]** Gets the type of this InvoiceSummary.
        Document Type in SPM like SPM Invoice,SPM Credit Memo etc.,


        :return: The type of this InvoiceSummary.
        :rtype: str
        """
        return self._type

    @type.setter
    def type(self, type):
        """
        Sets the type of this InvoiceSummary.
        Document Type in SPM like SPM Invoice,SPM Credit Memo etc.,


        :param type: The type of this InvoiceSummary.
        :type: str
        """
        self._type = type

    @property
    def status(self):
        """
        **[Required]** Gets the status of this InvoiceSummary.
        Document Status in SPM which depicts current state of invoice


        :return: The status of this InvoiceSummary.
        :rtype: str
        """
        return self._status

    @status.setter
    def status(self, status):
        """
        Sets the status of this InvoiceSummary.
        Document Status in SPM which depicts current state of invoice


        :param status: The status of this InvoiceSummary.
        :type: str
        """
        self._status = status

    @property
    def subscription_number(self):
        """
        **[Required]** Gets the subscription_number of this InvoiceSummary.
        Invoice associated subscription plan number.


        :return: The subscription_number of this InvoiceSummary.
        :rtype: str
        """
        return self._subscription_number

    @subscription_number.setter
    def subscription_number(self, subscription_number):
        """
        Sets the subscription_number of this InvoiceSummary.
        Invoice associated subscription plan number.


        :param subscription_number: The subscription_number of this InvoiceSummary.
        :type: str
        """
        self._subscription_number = subscription_number

    @property
    def time_invoice_date(self):
        """
        **[Required]** Gets the time_invoice_date of this InvoiceSummary.
        Invoice Date


        :return: The time_invoice_date of this InvoiceSummary.
        :rtype: datetime
        """
        return self._time_invoice_date

    @time_invoice_date.setter
    def time_invoice_date(self, time_invoice_date):
        """
        Sets the time_invoice_date of this InvoiceSummary.
        Invoice Date


        :param time_invoice_date: The time_invoice_date of this InvoiceSummary.
        :type: datetime
        """
        self._time_invoice_date = time_invoice_date

    @property
    def time_created(self):
        """
        Gets the time_created of this InvoiceSummary.
        SPM Invocie creation date


        :return: The time_created of this InvoiceSummary.
        :rtype: datetime
        """
        return self._time_created

    @time_created.setter
    def time_created(self, time_created):
        """
        Sets the time_created of this InvoiceSummary.
        SPM Invocie creation date


        :param time_created: The time_created of this InvoiceSummary.
        :type: datetime
        """
        self._time_created = time_created

    @property
    def created_by(self):
        """
        Gets the created_by of this InvoiceSummary.
        User that executed SPM Invoice process


        :return: The created_by of this InvoiceSummary.
        :rtype: str
        """
        return self._created_by

    @created_by.setter
    def created_by(self, created_by):
        """
        Sets the created_by of this InvoiceSummary.
        User that executed SPM Invoice process


        :param created_by: The created_by of this InvoiceSummary.
        :type: str
        """
        self._created_by = created_by

    @property
    def time_updated(self):
        """
        Gets the time_updated of this InvoiceSummary.
        SPM Invoice updated date


        :return: The time_updated of this InvoiceSummary.
        :rtype: datetime
        """
        return self._time_updated

    @time_updated.setter
    def time_updated(self, time_updated):
        """
        Sets the time_updated of this InvoiceSummary.
        SPM Invoice updated date


        :param time_updated: The time_updated of this InvoiceSummary.
        :type: datetime
        """
        self._time_updated = time_updated

    @property
    def updated_by(self):
        """
        Gets the updated_by of this InvoiceSummary.
        User that updated SPM Invoice


        :return: The updated_by of this InvoiceSummary.
        :rtype: str
        """
        return self._updated_by

    @updated_by.setter
    def updated_by(self, updated_by):
        """
        Sets the updated_by of this InvoiceSummary.
        User that updated SPM Invoice


        :param updated_by: The updated_by of this InvoiceSummary.
        :type: str
        """
        self._updated_by = updated_by

    @property
    def invoice_lines(self):
        """
        Gets the invoice_lines of this InvoiceSummary.
        Invoice Lines under particular invoice.


        :return: The invoice_lines of this InvoiceSummary.
        :rtype: list[oci.onesubscription.models.InvoiceLineSummary]
        """
        return self._invoice_lines

    @invoice_lines.setter
    def invoice_lines(self, invoice_lines):
        """
        Sets the invoice_lines of this InvoiceSummary.
        Invoice Lines under particular invoice.


        :param invoice_lines: The invoice_lines of this InvoiceSummary.
        :type: list[oci.onesubscription.models.InvoiceLineSummary]
        """
        self._invoice_lines = invoice_lines

    def __repr__(self):
        return formatted_flat_dict(self)

    def __eq__(self, other):
        if other is None:
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not self == other
