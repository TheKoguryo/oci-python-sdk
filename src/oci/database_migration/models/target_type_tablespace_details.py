# coding: utf-8
# Copyright (c) 2016, 2023, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.


from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class TargetTypeTablespaceDetails(object):
    """
    Migration tablespace settings.
    """

    #: A constant which can be used with the target_type property of a TargetTypeTablespaceDetails.
    #: This constant has a value of "ADB_S_REMAP"
    TARGET_TYPE_ADB_S_REMAP = "ADB_S_REMAP"

    #: A constant which can be used with the target_type property of a TargetTypeTablespaceDetails.
    #: This constant has a value of "ADB_D_REMAP"
    TARGET_TYPE_ADB_D_REMAP = "ADB_D_REMAP"

    #: A constant which can be used with the target_type property of a TargetTypeTablespaceDetails.
    #: This constant has a value of "ADB_D_AUTOCREATE"
    TARGET_TYPE_ADB_D_AUTOCREATE = "ADB_D_AUTOCREATE"

    #: A constant which can be used with the target_type property of a TargetTypeTablespaceDetails.
    #: This constant has a value of "NON_ADB_REMAP"
    TARGET_TYPE_NON_ADB_REMAP = "NON_ADB_REMAP"

    #: A constant which can be used with the target_type property of a TargetTypeTablespaceDetails.
    #: This constant has a value of "NON_ADB_AUTOCREATE"
    TARGET_TYPE_NON_ADB_AUTOCREATE = "NON_ADB_AUTOCREATE"

    def __init__(self, **kwargs):
        """
        Initializes a new TargetTypeTablespaceDetails object with values from keyword arguments. This class has the following subclasses and if you are using this class as input
        to a service operations then you should favor using a subclass over the base class:

        * :class:`~oci.database_migration.models.ADBDedicatedAutoCreateTablespaceDetails`
        * :class:`~oci.database_migration.models.ADBServerlesTablespaceDetails`
        * :class:`~oci.database_migration.models.ADBDedicatedRemapTargetTablespaceDetails`
        * :class:`~oci.database_migration.models.NonADBRemapTablespaceDetails`
        * :class:`~oci.database_migration.models.NonADBAutoCreateTablespaceDetails`

        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param target_type:
            The value to assign to the target_type property of this TargetTypeTablespaceDetails.
            Allowed values for this property are: "ADB_S_REMAP", "ADB_D_REMAP", "ADB_D_AUTOCREATE", "NON_ADB_REMAP", "NON_ADB_AUTOCREATE", 'UNKNOWN_ENUM_VALUE'.
            Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.
        :type target_type: str

        """
        self.swagger_types = {
            'target_type': 'str'
        }

        self.attribute_map = {
            'target_type': 'targetType'
        }

        self._target_type = None

    @staticmethod
    def get_subtype(object_dictionary):
        """
        Given the hash representation of a subtype of this class,
        use the info in the hash to return the class of the subtype.
        """
        type = object_dictionary['targetType']

        if type == 'ADB_D_AUTOCREATE':
            return 'ADBDedicatedAutoCreateTablespaceDetails'

        if type == 'ADB_S_REMAP':
            return 'ADBServerlesTablespaceDetails'

        if type == 'ADB_D_REMAP':
            return 'ADBDedicatedRemapTargetTablespaceDetails'

        if type == 'NON_ADB_REMAP':
            return 'NonADBRemapTablespaceDetails'

        if type == 'NON_ADB_AUTOCREATE':
            return 'NonADBAutoCreateTablespaceDetails'
        else:
            return 'TargetTypeTablespaceDetails'

    @property
    def target_type(self):
        """
        **[Required]** Gets the target_type of this TargetTypeTablespaceDetails.
        Type of Database Base Migration Target.

        Allowed values for this property are: "ADB_S_REMAP", "ADB_D_REMAP", "ADB_D_AUTOCREATE", "NON_ADB_REMAP", "NON_ADB_AUTOCREATE", 'UNKNOWN_ENUM_VALUE'.
        Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.


        :return: The target_type of this TargetTypeTablespaceDetails.
        :rtype: str
        """
        return self._target_type

    @target_type.setter
    def target_type(self, target_type):
        """
        Sets the target_type of this TargetTypeTablespaceDetails.
        Type of Database Base Migration Target.


        :param target_type: The target_type of this TargetTypeTablespaceDetails.
        :type: str
        """
        allowed_values = ["ADB_S_REMAP", "ADB_D_REMAP", "ADB_D_AUTOCREATE", "NON_ADB_REMAP", "NON_ADB_AUTOCREATE"]
        if not value_allowed_none_or_none_sentinel(target_type, allowed_values):
            target_type = 'UNKNOWN_ENUM_VALUE'
        self._target_type = target_type

    def __repr__(self):
        return formatted_flat_dict(self)

    def __eq__(self, other):
        if other is None:
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not self == other
