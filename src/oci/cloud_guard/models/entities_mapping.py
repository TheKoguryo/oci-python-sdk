# coding: utf-8
# Copyright (c) 2016, 2023, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.


from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class EntitiesMapping(object):
    """
    Data Source Entities mappings
    """

    #: A constant which can be used with the entity_type property of a EntitiesMapping.
    #: This constant has a value of "EXTERNAL_IP"
    ENTITY_TYPE_EXTERNAL_IP = "EXTERNAL_IP"

    #: A constant which can be used with the entity_type property of a EntitiesMapping.
    #: This constant has a value of "INTERNAL_IP"
    ENTITY_TYPE_INTERNAL_IP = "INTERNAL_IP"

    #: A constant which can be used with the entity_type property of a EntitiesMapping.
    #: This constant has a value of "TEXT"
    ENTITY_TYPE_TEXT = "TEXT"

    #: A constant which can be used with the entity_type property of a EntitiesMapping.
    #: This constant has a value of "JSON_LIST"
    ENTITY_TYPE_JSON_LIST = "JSON_LIST"

    def __init__(self, **kwargs):
        """
        Initializes a new EntitiesMapping object with values from keyword arguments.
        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param display_name:
            The value to assign to the display_name property of this EntitiesMapping.
        :type display_name: str

        :param query_field:
            The value to assign to the query_field property of this EntitiesMapping.
        :type query_field: str

        :param entity_type:
            The value to assign to the entity_type property of this EntitiesMapping.
            Allowed values for this property are: "EXTERNAL_IP", "INTERNAL_IP", "TEXT", "JSON_LIST", 'UNKNOWN_ENUM_VALUE'.
            Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.
        :type entity_type: str

        """
        self.swagger_types = {
            'display_name': 'str',
            'query_field': 'str',
            'entity_type': 'str'
        }

        self.attribute_map = {
            'display_name': 'displayName',
            'query_field': 'queryField',
            'entity_type': 'entityType'
        }

        self._display_name = None
        self._query_field = None
        self._entity_type = None

    @property
    def display_name(self):
        """
        Gets the display_name of this EntitiesMapping.
        The display name of entity


        :return: The display_name of this EntitiesMapping.
        :rtype: str
        """
        return self._display_name

    @display_name.setter
    def display_name(self, display_name):
        """
        Sets the display_name of this EntitiesMapping.
        The display name of entity


        :param display_name: The display_name of this EntitiesMapping.
        :type: str
        """
        self._display_name = display_name

    @property
    def query_field(self):
        """
        **[Required]** Gets the query_field of this EntitiesMapping.
        The entity value mapped to a data source query


        :return: The query_field of this EntitiesMapping.
        :rtype: str
        """
        return self._query_field

    @query_field.setter
    def query_field(self, query_field):
        """
        Sets the query_field of this EntitiesMapping.
        The entity value mapped to a data source query


        :param query_field: The query_field of this EntitiesMapping.
        :type: str
        """
        self._query_field = query_field

    @property
    def entity_type(self):
        """
        Gets the entity_type of this EntitiesMapping.
        Possible type of entity

        Allowed values for this property are: "EXTERNAL_IP", "INTERNAL_IP", "TEXT", "JSON_LIST", 'UNKNOWN_ENUM_VALUE'.
        Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.


        :return: The entity_type of this EntitiesMapping.
        :rtype: str
        """
        return self._entity_type

    @entity_type.setter
    def entity_type(self, entity_type):
        """
        Sets the entity_type of this EntitiesMapping.
        Possible type of entity


        :param entity_type: The entity_type of this EntitiesMapping.
        :type: str
        """
        allowed_values = ["EXTERNAL_IP", "INTERNAL_IP", "TEXT", "JSON_LIST"]
        if not value_allowed_none_or_none_sentinel(entity_type, allowed_values):
            entity_type = 'UNKNOWN_ENUM_VALUE'
        self._entity_type = entity_type

    def __repr__(self):
        return formatted_flat_dict(self)

    def __eq__(self, other):
        if other is None:
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not self == other
