# coding: utf-8
# Copyright (c) 2016, 2020, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.


from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class CreateLogSavedSearchDetails(object):
    """
    A log saved search that can be used to save and share a given search result.
    """

    def __init__(self, **kwargs):
        """
        Initializes a new CreateLogSavedSearchDetails object with values from keyword arguments.
        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param compartment_id:
            The value to assign to the compartment_id property of this CreateLogSavedSearchDetails.
        :type compartment_id: str

        :param name:
            The value to assign to the name property of this CreateLogSavedSearchDetails.
        :type name: str

        :param description:
            The value to assign to the description property of this CreateLogSavedSearchDetails.
        :type description: str

        :param query:
            The value to assign to the query property of this CreateLogSavedSearchDetails.
        :type query: str

        :param is_quick_start:
            The value to assign to the is_quick_start property of this CreateLogSavedSearchDetails.
        :type is_quick_start: bool

        :param defined_tags:
            The value to assign to the defined_tags property of this CreateLogSavedSearchDetails.
        :type defined_tags: dict(str, dict(str, object))

        :param freeform_tags:
            The value to assign to the freeform_tags property of this CreateLogSavedSearchDetails.
        :type freeform_tags: dict(str, str)

        """
        self.swagger_types = {
            'compartment_id': 'str',
            'name': 'str',
            'description': 'str',
            'query': 'str',
            'is_quick_start': 'bool',
            'defined_tags': 'dict(str, dict(str, object))',
            'freeform_tags': 'dict(str, str)'
        }

        self.attribute_map = {
            'compartment_id': 'compartmentId',
            'name': 'name',
            'description': 'description',
            'query': 'query',
            'is_quick_start': 'isQuickStart',
            'defined_tags': 'definedTags',
            'freeform_tags': 'freeformTags'
        }

        self._compartment_id = None
        self._name = None
        self._description = None
        self._query = None
        self._is_quick_start = None
        self._defined_tags = None
        self._freeform_tags = None

    @property
    def compartment_id(self):
        """
        **[Required]** Gets the compartment_id of this CreateLogSavedSearchDetails.
        The OCID of the compartment that the resource belongs to.


        :return: The compartment_id of this CreateLogSavedSearchDetails.
        :rtype: str
        """
        return self._compartment_id

    @compartment_id.setter
    def compartment_id(self, compartment_id):
        """
        Sets the compartment_id of this CreateLogSavedSearchDetails.
        The OCID of the compartment that the resource belongs to.


        :param compartment_id: The compartment_id of this CreateLogSavedSearchDetails.
        :type: str
        """
        self._compartment_id = compartment_id

    @property
    def name(self):
        """
        **[Required]** Gets the name of this CreateLogSavedSearchDetails.
        The display name of a user-friendly name. It has to be unique within enclosing resource,
        and it's changeable. Avoid entering confidential information.


        :return: The name of this CreateLogSavedSearchDetails.
        :rtype: str
        """
        return self._name

    @name.setter
    def name(self, name):
        """
        Sets the name of this CreateLogSavedSearchDetails.
        The display name of a user-friendly name. It has to be unique within enclosing resource,
        and it's changeable. Avoid entering confidential information.


        :param name: The name of this CreateLogSavedSearchDetails.
        :type: str
        """
        self._name = name

    @property
    def description(self):
        """
        Gets the description of this CreateLogSavedSearchDetails.
        Description for this resource.


        :return: The description of this CreateLogSavedSearchDetails.
        :rtype: str
        """
        return self._description

    @description.setter
    def description(self, description):
        """
        Sets the description of this CreateLogSavedSearchDetails.
        Description for this resource.


        :param description: The description of this CreateLogSavedSearchDetails.
        :type: str
        """
        self._description = description

    @property
    def query(self):
        """
        **[Required]** Gets the query of this CreateLogSavedSearchDetails.
        The search query that is saved.


        :return: The query of this CreateLogSavedSearchDetails.
        :rtype: str
        """
        return self._query

    @query.setter
    def query(self, query):
        """
        Sets the query of this CreateLogSavedSearchDetails.
        The search query that is saved.


        :param query: The query of this CreateLogSavedSearchDetails.
        :type: str
        """
        self._query = query

    @property
    def is_quick_start(self):
        """
        **[Required]** Gets the is_quick_start of this CreateLogSavedSearchDetails.
        True if the LogSavedSearch should be show as quickstart in the UI


        :return: The is_quick_start of this CreateLogSavedSearchDetails.
        :rtype: bool
        """
        return self._is_quick_start

    @is_quick_start.setter
    def is_quick_start(self, is_quick_start):
        """
        Sets the is_quick_start of this CreateLogSavedSearchDetails.
        True if the LogSavedSearch should be show as quickstart in the UI


        :param is_quick_start: The is_quick_start of this CreateLogSavedSearchDetails.
        :type: bool
        """
        self._is_quick_start = is_quick_start

    @property
    def defined_tags(self):
        """
        Gets the defined_tags of this CreateLogSavedSearchDetails.
        Defined tags for this resource. Each key is predefined and scoped to a
        namespace. For more information, see `Resource Tags`__.

        Example: `{\"Operations\": {\"CostCenter\": \"42\"}}`

        __ https://docs.cloud.oracle.com/Content/General/Concepts/resourcetags.htm


        :return: The defined_tags of this CreateLogSavedSearchDetails.
        :rtype: dict(str, dict(str, object))
        """
        return self._defined_tags

    @defined_tags.setter
    def defined_tags(self, defined_tags):
        """
        Sets the defined_tags of this CreateLogSavedSearchDetails.
        Defined tags for this resource. Each key is predefined and scoped to a
        namespace. For more information, see `Resource Tags`__.

        Example: `{\"Operations\": {\"CostCenter\": \"42\"}}`

        __ https://docs.cloud.oracle.com/Content/General/Concepts/resourcetags.htm


        :param defined_tags: The defined_tags of this CreateLogSavedSearchDetails.
        :type: dict(str, dict(str, object))
        """
        self._defined_tags = defined_tags

    @property
    def freeform_tags(self):
        """
        Gets the freeform_tags of this CreateLogSavedSearchDetails.
        Free-form tags for this resource. Each tag is a simple key-value pair with no
        predefined name, type, or namespace. For more information, see `Resource Tags`__.
        Example: `{\"Department\": \"Finance\"}`

        __ https://docs.cloud.oracle.com/Content/General/Concepts/resourcetags.htm


        :return: The freeform_tags of this CreateLogSavedSearchDetails.
        :rtype: dict(str, str)
        """
        return self._freeform_tags

    @freeform_tags.setter
    def freeform_tags(self, freeform_tags):
        """
        Sets the freeform_tags of this CreateLogSavedSearchDetails.
        Free-form tags for this resource. Each tag is a simple key-value pair with no
        predefined name, type, or namespace. For more information, see `Resource Tags`__.
        Example: `{\"Department\": \"Finance\"}`

        __ https://docs.cloud.oracle.com/Content/General/Concepts/resourcetags.htm


        :param freeform_tags: The freeform_tags of this CreateLogSavedSearchDetails.
        :type: dict(str, str)
        """
        self._freeform_tags = freeform_tags

    def __repr__(self):
        return formatted_flat_dict(self)

    def __eq__(self, other):
        if other is None:
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not self == other
