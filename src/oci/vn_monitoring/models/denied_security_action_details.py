# coding: utf-8
# Copyright (c) 2016, 2022, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.


from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class DeniedSecurityActionDetails(object):
    """
    Defines details for the security action taken on denied traffic.
    """

    def __init__(self, **kwargs):
        """
        Initializes a new DeniedSecurityActionDetails object with values from keyword arguments.
        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param is_restricted_or_partial:
            The value to assign to the is_restricted_or_partial property of this DeniedSecurityActionDetails.
        :type is_restricted_or_partial: bool

        :param evaluated_security_list_ids:
            The value to assign to the evaluated_security_list_ids property of this DeniedSecurityActionDetails.
        :type evaluated_security_list_ids: list[str]

        :param evaluated_nsg_ids:
            The value to assign to the evaluated_nsg_ids property of this DeniedSecurityActionDetails.
        :type evaluated_nsg_ids: list[str]

        """
        self.swagger_types = {
            'is_restricted_or_partial': 'bool',
            'evaluated_security_list_ids': 'list[str]',
            'evaluated_nsg_ids': 'list[str]'
        }

        self.attribute_map = {
            'is_restricted_or_partial': 'isRestrictedOrPartial',
            'evaluated_security_list_ids': 'evaluatedSecurityListIds',
            'evaluated_nsg_ids': 'evaluatedNsgIds'
        }

        self._is_restricted_or_partial = None
        self._evaluated_security_list_ids = None
        self._evaluated_nsg_ids = None

    @property
    def is_restricted_or_partial(self):
        """
        **[Required]** Gets the is_restricted_or_partial of this DeniedSecurityActionDetails.
        If true, the evaluated security list and network security group ID details are incomplete.


        :return: The is_restricted_or_partial of this DeniedSecurityActionDetails.
        :rtype: bool
        """
        return self._is_restricted_or_partial

    @is_restricted_or_partial.setter
    def is_restricted_or_partial(self, is_restricted_or_partial):
        """
        Sets the is_restricted_or_partial of this DeniedSecurityActionDetails.
        If true, the evaluated security list and network security group ID details are incomplete.


        :param is_restricted_or_partial: The is_restricted_or_partial of this DeniedSecurityActionDetails.
        :type: bool
        """
        self._is_restricted_or_partial = is_restricted_or_partial

    @property
    def evaluated_security_list_ids(self):
        """
        Gets the evaluated_security_list_ids of this DeniedSecurityActionDetails.
        The list of `OCIDs`__ of evaluated security lists associcated
        with the OCI resource's subnet.

        __ https://docs.cloud.oracle.com/Content/General/Concepts/identifiers.htm


        :return: The evaluated_security_list_ids of this DeniedSecurityActionDetails.
        :rtype: list[str]
        """
        return self._evaluated_security_list_ids

    @evaluated_security_list_ids.setter
    def evaluated_security_list_ids(self, evaluated_security_list_ids):
        """
        Sets the evaluated_security_list_ids of this DeniedSecurityActionDetails.
        The list of `OCIDs`__ of evaluated security lists associcated
        with the OCI resource's subnet.

        __ https://docs.cloud.oracle.com/Content/General/Concepts/identifiers.htm


        :param evaluated_security_list_ids: The evaluated_security_list_ids of this DeniedSecurityActionDetails.
        :type: list[str]
        """
        self._evaluated_security_list_ids = evaluated_security_list_ids

    @property
    def evaluated_nsg_ids(self):
        """
        Gets the evaluated_nsg_ids of this DeniedSecurityActionDetails.
        List of `OCIDs`__ of evaluated network security groups
        associated with the OCI resource's VNIC.

        __ https://docs.cloud.oracle.com/Content/General/Concepts/identifiers.htm


        :return: The evaluated_nsg_ids of this DeniedSecurityActionDetails.
        :rtype: list[str]
        """
        return self._evaluated_nsg_ids

    @evaluated_nsg_ids.setter
    def evaluated_nsg_ids(self, evaluated_nsg_ids):
        """
        Sets the evaluated_nsg_ids of this DeniedSecurityActionDetails.
        List of `OCIDs`__ of evaluated network security groups
        associated with the OCI resource's VNIC.

        __ https://docs.cloud.oracle.com/Content/General/Concepts/identifiers.htm


        :param evaluated_nsg_ids: The evaluated_nsg_ids of this DeniedSecurityActionDetails.
        :type: list[str]
        """
        self._evaluated_nsg_ids = evaluated_nsg_ids

    def __repr__(self):
        return formatted_flat_dict(self)

    def __eq__(self, other):
        if other is None:
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not self == other