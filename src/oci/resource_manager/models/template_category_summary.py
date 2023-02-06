# coding: utf-8
# Copyright (c) 2016, 2023, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.


from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class TemplateCategorySummary(object):
    """
    Summary information for the template category.
    """

    def __init__(self, **kwargs):
        """
        Initializes a new TemplateCategorySummary object with values from keyword arguments.
        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param id:
            The value to assign to the id property of this TemplateCategorySummary.
        :type id: str

        :param display_name:
            The value to assign to the display_name property of this TemplateCategorySummary.
        :type display_name: str

        """
        self.swagger_types = {
            'id': 'str',
            'display_name': 'str'
        }

        self.attribute_map = {
            'id': 'id',
            'display_name': 'displayName'
        }

        self._id = None
        self._display_name = None

    @property
    def id(self):
        """
        Gets the id of this TemplateCategorySummary.
        Unique identifier for the template category.
        Possible values are `0` (Quickstarts), `1` (Service), `2` (Architecture), and `3` (Private).
        Template category labels are displayed in the Console page listing templates.
        Quickstarts, Service, and Architecture templates (categories 0, 1, and 2) are available in all compartments.
        Each private template (category 3) is available in the compartment where it was created.


        :return: The id of this TemplateCategorySummary.
        :rtype: str
        """
        return self._id

    @id.setter
    def id(self, id):
        """
        Sets the id of this TemplateCategorySummary.
        Unique identifier for the template category.
        Possible values are `0` (Quickstarts), `1` (Service), `2` (Architecture), and `3` (Private).
        Template category labels are displayed in the Console page listing templates.
        Quickstarts, Service, and Architecture templates (categories 0, 1, and 2) are available in all compartments.
        Each private template (category 3) is available in the compartment where it was created.


        :param id: The id of this TemplateCategorySummary.
        :type: str
        """
        self._id = id

    @property
    def display_name(self):
        """
        Gets the display_name of this TemplateCategorySummary.
        The name of the template category.


        :return: The display_name of this TemplateCategorySummary.
        :rtype: str
        """
        return self._display_name

    @display_name.setter
    def display_name(self, display_name):
        """
        Sets the display_name of this TemplateCategorySummary.
        The name of the template category.


        :param display_name: The display_name of this TemplateCategorySummary.
        :type: str
        """
        self._display_name = display_name

    def __repr__(self):
        return formatted_flat_dict(self)

    def __eq__(self, other):
        if other is None:
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not self == other
