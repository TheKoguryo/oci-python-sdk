# coding: utf-8
# Copyright (c) 2016, 2023, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.


from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class CreateReplicationDetails(object):
    """
    Details for creating the replication and replication target.
    """

    def __init__(self, **kwargs):
        """
        Initializes a new CreateReplicationDetails object with values from keyword arguments.
        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param compartment_id:
            The value to assign to the compartment_id property of this CreateReplicationDetails.
        :type compartment_id: str

        :param source_id:
            The value to assign to the source_id property of this CreateReplicationDetails.
        :type source_id: str

        :param target_id:
            The value to assign to the target_id property of this CreateReplicationDetails.
        :type target_id: str

        :param display_name:
            The value to assign to the display_name property of this CreateReplicationDetails.
        :type display_name: str

        :param replication_interval:
            The value to assign to the replication_interval property of this CreateReplicationDetails.
        :type replication_interval: int

        :param freeform_tags:
            The value to assign to the freeform_tags property of this CreateReplicationDetails.
        :type freeform_tags: dict(str, str)

        :param defined_tags:
            The value to assign to the defined_tags property of this CreateReplicationDetails.
        :type defined_tags: dict(str, dict(str, object))

        """
        self.swagger_types = {
            'compartment_id': 'str',
            'source_id': 'str',
            'target_id': 'str',
            'display_name': 'str',
            'replication_interval': 'int',
            'freeform_tags': 'dict(str, str)',
            'defined_tags': 'dict(str, dict(str, object))'
        }

        self.attribute_map = {
            'compartment_id': 'compartmentId',
            'source_id': 'sourceId',
            'target_id': 'targetId',
            'display_name': 'displayName',
            'replication_interval': 'replicationInterval',
            'freeform_tags': 'freeformTags',
            'defined_tags': 'definedTags'
        }

        self._compartment_id = None
        self._source_id = None
        self._target_id = None
        self._display_name = None
        self._replication_interval = None
        self._freeform_tags = None
        self._defined_tags = None

    @property
    def compartment_id(self):
        """
        **[Required]** Gets the compartment_id of this CreateReplicationDetails.
        The `OCID`__ of the compartment that contains the replication.

        __ https://docs.cloud.oracle.com/Content/General/Concepts/identifiers.htm


        :return: The compartment_id of this CreateReplicationDetails.
        :rtype: str
        """
        return self._compartment_id

    @compartment_id.setter
    def compartment_id(self, compartment_id):
        """
        Sets the compartment_id of this CreateReplicationDetails.
        The `OCID`__ of the compartment that contains the replication.

        __ https://docs.cloud.oracle.com/Content/General/Concepts/identifiers.htm


        :param compartment_id: The compartment_id of this CreateReplicationDetails.
        :type: str
        """
        self._compartment_id = compartment_id

    @property
    def source_id(self):
        """
        **[Required]** Gets the source_id of this CreateReplicationDetails.
        The `OCID`__ of the source file system.

        __ https://docs.cloud.oracle.com/Content/General/Concepts/identifiers.htm


        :return: The source_id of this CreateReplicationDetails.
        :rtype: str
        """
        return self._source_id

    @source_id.setter
    def source_id(self, source_id):
        """
        Sets the source_id of this CreateReplicationDetails.
        The `OCID`__ of the source file system.

        __ https://docs.cloud.oracle.com/Content/General/Concepts/identifiers.htm


        :param source_id: The source_id of this CreateReplicationDetails.
        :type: str
        """
        self._source_id = source_id

    @property
    def target_id(self):
        """
        **[Required]** Gets the target_id of this CreateReplicationDetails.
        The `OCID`__ of the target file system.

        __ https://docs.cloud.oracle.com/Content/General/Concepts/identifiers.htm


        :return: The target_id of this CreateReplicationDetails.
        :rtype: str
        """
        return self._target_id

    @target_id.setter
    def target_id(self, target_id):
        """
        Sets the target_id of this CreateReplicationDetails.
        The `OCID`__ of the target file system.

        __ https://docs.cloud.oracle.com/Content/General/Concepts/identifiers.htm


        :param target_id: The target_id of this CreateReplicationDetails.
        :type: str
        """
        self._target_id = target_id

    @property
    def display_name(self):
        """
        Gets the display_name of this CreateReplicationDetails.
        A user-friendly name. It does not have to be unique, and it is changeable.
        Avoid entering confidential information.
        An associated replication target will also created with the same `displayName`.
        Example: `My replication`


        :return: The display_name of this CreateReplicationDetails.
        :rtype: str
        """
        return self._display_name

    @display_name.setter
    def display_name(self, display_name):
        """
        Sets the display_name of this CreateReplicationDetails.
        A user-friendly name. It does not have to be unique, and it is changeable.
        Avoid entering confidential information.
        An associated replication target will also created with the same `displayName`.
        Example: `My replication`


        :param display_name: The display_name of this CreateReplicationDetails.
        :type: str
        """
        self._display_name = display_name

    @property
    def replication_interval(self):
        """
        Gets the replication_interval of this CreateReplicationDetails.
        Duration in minutes between replication snapshots.


        :return: The replication_interval of this CreateReplicationDetails.
        :rtype: int
        """
        return self._replication_interval

    @replication_interval.setter
    def replication_interval(self, replication_interval):
        """
        Sets the replication_interval of this CreateReplicationDetails.
        Duration in minutes between replication snapshots.


        :param replication_interval: The replication_interval of this CreateReplicationDetails.
        :type: int
        """
        self._replication_interval = replication_interval

    @property
    def freeform_tags(self):
        """
        Gets the freeform_tags of this CreateReplicationDetails.
        Free-form tags for this resource. Each tag is a simple key-value pair
         with no predefined name, type, or namespace.
        For more information, see `Resource Tags`__.
        Example: `{\"Department\": \"Finance\"}`

        __ https://docs.cloud.oracle.com/Content/General/Concepts/resourcetags.htm


        :return: The freeform_tags of this CreateReplicationDetails.
        :rtype: dict(str, str)
        """
        return self._freeform_tags

    @freeform_tags.setter
    def freeform_tags(self, freeform_tags):
        """
        Sets the freeform_tags of this CreateReplicationDetails.
        Free-form tags for this resource. Each tag is a simple key-value pair
         with no predefined name, type, or namespace.
        For more information, see `Resource Tags`__.
        Example: `{\"Department\": \"Finance\"}`

        __ https://docs.cloud.oracle.com/Content/General/Concepts/resourcetags.htm


        :param freeform_tags: The freeform_tags of this CreateReplicationDetails.
        :type: dict(str, str)
        """
        self._freeform_tags = freeform_tags

    @property
    def defined_tags(self):
        """
        Gets the defined_tags of this CreateReplicationDetails.
        Defined tags for this resource. Each key is predefined and scoped to a namespace.
        For more information, see `Resource Tags`__.
        Example: `{\"Operations\": {\"CostCenter\": \"42\"}}`

        __ https://docs.cloud.oracle.com/Content/General/Concepts/resourcetags.htm


        :return: The defined_tags of this CreateReplicationDetails.
        :rtype: dict(str, dict(str, object))
        """
        return self._defined_tags

    @defined_tags.setter
    def defined_tags(self, defined_tags):
        """
        Sets the defined_tags of this CreateReplicationDetails.
        Defined tags for this resource. Each key is predefined and scoped to a namespace.
        For more information, see `Resource Tags`__.
        Example: `{\"Operations\": {\"CostCenter\": \"42\"}}`

        __ https://docs.cloud.oracle.com/Content/General/Concepts/resourcetags.htm


        :param defined_tags: The defined_tags of this CreateReplicationDetails.
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
