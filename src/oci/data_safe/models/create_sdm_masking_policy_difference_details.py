# coding: utf-8
# Copyright (c) 2016, 2023, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.


from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class CreateSdmMaskingPolicyDifferenceDetails(object):
    """
    Details to create a new SDM masking policy difference.
    """

    def __init__(self, **kwargs):
        """
        Initializes a new CreateSdmMaskingPolicyDifferenceDetails object with values from keyword arguments.
        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param difference_type:
            The value to assign to the difference_type property of this CreateSdmMaskingPolicyDifferenceDetails.
        :type difference_type: str

        :param masking_policy_id:
            The value to assign to the masking_policy_id property of this CreateSdmMaskingPolicyDifferenceDetails.
        :type masking_policy_id: str

        :param compartment_id:
            The value to assign to the compartment_id property of this CreateSdmMaskingPolicyDifferenceDetails.
        :type compartment_id: str

        :param display_name:
            The value to assign to the display_name property of this CreateSdmMaskingPolicyDifferenceDetails.
        :type display_name: str

        :param freeform_tags:
            The value to assign to the freeform_tags property of this CreateSdmMaskingPolicyDifferenceDetails.
        :type freeform_tags: dict(str, str)

        :param defined_tags:
            The value to assign to the defined_tags property of this CreateSdmMaskingPolicyDifferenceDetails.
        :type defined_tags: dict(str, dict(str, object))

        """
        self.swagger_types = {
            'difference_type': 'str',
            'masking_policy_id': 'str',
            'compartment_id': 'str',
            'display_name': 'str',
            'freeform_tags': 'dict(str, str)',
            'defined_tags': 'dict(str, dict(str, object))'
        }

        self.attribute_map = {
            'difference_type': 'differenceType',
            'masking_policy_id': 'maskingPolicyId',
            'compartment_id': 'compartmentId',
            'display_name': 'displayName',
            'freeform_tags': 'freeformTags',
            'defined_tags': 'definedTags'
        }

        self._difference_type = None
        self._masking_policy_id = None
        self._compartment_id = None
        self._display_name = None
        self._freeform_tags = None
        self._defined_tags = None

    @property
    def difference_type(self):
        """
        Gets the difference_type of this CreateSdmMaskingPolicyDifferenceDetails.
        The type of the SDM masking policy difference. It defines the difference scope.
        NEW identifies new sensitive columns in the sensitive data model that are not in the masking policy.
        DELETED identifies columns that are present in the masking policy but have been deleted from the sensitive data model.
        MODIFIED identifies columns that are present in the sensitive data model as well as the masking policy but some of their attributes have been modified.
        ALL covers all the above three scenarios and reports new, deleted and modified columns.


        :return: The difference_type of this CreateSdmMaskingPolicyDifferenceDetails.
        :rtype: str
        """
        return self._difference_type

    @difference_type.setter
    def difference_type(self, difference_type):
        """
        Sets the difference_type of this CreateSdmMaskingPolicyDifferenceDetails.
        The type of the SDM masking policy difference. It defines the difference scope.
        NEW identifies new sensitive columns in the sensitive data model that are not in the masking policy.
        DELETED identifies columns that are present in the masking policy but have been deleted from the sensitive data model.
        MODIFIED identifies columns that are present in the sensitive data model as well as the masking policy but some of their attributes have been modified.
        ALL covers all the above three scenarios and reports new, deleted and modified columns.


        :param difference_type: The difference_type of this CreateSdmMaskingPolicyDifferenceDetails.
        :type: str
        """
        self._difference_type = difference_type

    @property
    def masking_policy_id(self):
        """
        **[Required]** Gets the masking_policy_id of this CreateSdmMaskingPolicyDifferenceDetails.
        The OCID of the masking policy. Note that if the masking policy is not associated with an SDM, CreateSdmMaskingPolicyDifference
        operation won't be allowed.


        :return: The masking_policy_id of this CreateSdmMaskingPolicyDifferenceDetails.
        :rtype: str
        """
        return self._masking_policy_id

    @masking_policy_id.setter
    def masking_policy_id(self, masking_policy_id):
        """
        Sets the masking_policy_id of this CreateSdmMaskingPolicyDifferenceDetails.
        The OCID of the masking policy. Note that if the masking policy is not associated with an SDM, CreateSdmMaskingPolicyDifference
        operation won't be allowed.


        :param masking_policy_id: The masking_policy_id of this CreateSdmMaskingPolicyDifferenceDetails.
        :type: str
        """
        self._masking_policy_id = masking_policy_id

    @property
    def compartment_id(self):
        """
        **[Required]** Gets the compartment_id of this CreateSdmMaskingPolicyDifferenceDetails.
        The OCID of the compartment where the SDM masking policy difference resource should be created.


        :return: The compartment_id of this CreateSdmMaskingPolicyDifferenceDetails.
        :rtype: str
        """
        return self._compartment_id

    @compartment_id.setter
    def compartment_id(self, compartment_id):
        """
        Sets the compartment_id of this CreateSdmMaskingPolicyDifferenceDetails.
        The OCID of the compartment where the SDM masking policy difference resource should be created.


        :param compartment_id: The compartment_id of this CreateSdmMaskingPolicyDifferenceDetails.
        :type: str
        """
        self._compartment_id = compartment_id

    @property
    def display_name(self):
        """
        Gets the display_name of this CreateSdmMaskingPolicyDifferenceDetails.
        A user-friendly name for the SDM masking policy difference. Does not have to be unique, and it is changeable. Avoid entering confidential information.


        :return: The display_name of this CreateSdmMaskingPolicyDifferenceDetails.
        :rtype: str
        """
        return self._display_name

    @display_name.setter
    def display_name(self, display_name):
        """
        Sets the display_name of this CreateSdmMaskingPolicyDifferenceDetails.
        A user-friendly name for the SDM masking policy difference. Does not have to be unique, and it is changeable. Avoid entering confidential information.


        :param display_name: The display_name of this CreateSdmMaskingPolicyDifferenceDetails.
        :type: str
        """
        self._display_name = display_name

    @property
    def freeform_tags(self):
        """
        Gets the freeform_tags of this CreateSdmMaskingPolicyDifferenceDetails.
        Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see `Resource Tags`__

        Example: `{\"Department\": \"Finance\"}`

        __ https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm


        :return: The freeform_tags of this CreateSdmMaskingPolicyDifferenceDetails.
        :rtype: dict(str, str)
        """
        return self._freeform_tags

    @freeform_tags.setter
    def freeform_tags(self, freeform_tags):
        """
        Sets the freeform_tags of this CreateSdmMaskingPolicyDifferenceDetails.
        Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see `Resource Tags`__

        Example: `{\"Department\": \"Finance\"}`

        __ https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm


        :param freeform_tags: The freeform_tags of this CreateSdmMaskingPolicyDifferenceDetails.
        :type: dict(str, str)
        """
        self._freeform_tags = freeform_tags

    @property
    def defined_tags(self):
        """
        Gets the defined_tags of this CreateSdmMaskingPolicyDifferenceDetails.
        Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see `Resource Tags`__

        Example: `{\"Operations\": {\"CostCenter\": \"42\"}}`

        __ https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm


        :return: The defined_tags of this CreateSdmMaskingPolicyDifferenceDetails.
        :rtype: dict(str, dict(str, object))
        """
        return self._defined_tags

    @defined_tags.setter
    def defined_tags(self, defined_tags):
        """
        Sets the defined_tags of this CreateSdmMaskingPolicyDifferenceDetails.
        Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see `Resource Tags`__

        Example: `{\"Operations\": {\"CostCenter\": \"42\"}}`

        __ https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm


        :param defined_tags: The defined_tags of this CreateSdmMaskingPolicyDifferenceDetails.
        :type: dict(str, dict(str, object))
        """
        self._defined_tags = defined_tags

    def __repr__(self):
        return formatted_flat_dict(self)

    def __eq__(self, other):
        if other is None:
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not self == other
