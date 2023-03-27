# coding: utf-8
# Copyright (c) 2016, 2023, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.


from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class PbfListingSummary(object):
    """
    Summary of the PbfListing.
    """

    def __init__(self, **kwargs):
        """
        Initializes a new PbfListingSummary object with values from keyword arguments.
        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param id:
            The value to assign to the id property of this PbfListingSummary.
        :type id: str

        :param name:
            The value to assign to the name property of this PbfListingSummary.
        :type name: str

        :param description:
            The value to assign to the description property of this PbfListingSummary.
        :type description: str

        :param publisher_details:
            The value to assign to the publisher_details property of this PbfListingSummary.
        :type publisher_details: oci.functions.models.PublisherDetails

        :param triggers:
            The value to assign to the triggers property of this PbfListingSummary.
        :type triggers: list[oci.functions.models.Trigger]

        :param time_created:
            The value to assign to the time_created property of this PbfListingSummary.
        :type time_created: datetime

        :param time_updated:
            The value to assign to the time_updated property of this PbfListingSummary.
        :type time_updated: datetime

        :param lifecycle_state:
            The value to assign to the lifecycle_state property of this PbfListingSummary.
        :type lifecycle_state: str

        :param freeform_tags:
            The value to assign to the freeform_tags property of this PbfListingSummary.
        :type freeform_tags: dict(str, str)

        :param defined_tags:
            The value to assign to the defined_tags property of this PbfListingSummary.
        :type defined_tags: dict(str, dict(str, object))

        :param system_tags:
            The value to assign to the system_tags property of this PbfListingSummary.
        :type system_tags: dict(str, dict(str, object))

        """
        self.swagger_types = {
            'id': 'str',
            'name': 'str',
            'description': 'str',
            'publisher_details': 'PublisherDetails',
            'triggers': 'list[Trigger]',
            'time_created': 'datetime',
            'time_updated': 'datetime',
            'lifecycle_state': 'str',
            'freeform_tags': 'dict(str, str)',
            'defined_tags': 'dict(str, dict(str, object))',
            'system_tags': 'dict(str, dict(str, object))'
        }

        self.attribute_map = {
            'id': 'id',
            'name': 'name',
            'description': 'description',
            'publisher_details': 'publisherDetails',
            'triggers': 'triggers',
            'time_created': 'timeCreated',
            'time_updated': 'timeUpdated',
            'lifecycle_state': 'lifecycleState',
            'freeform_tags': 'freeformTags',
            'defined_tags': 'definedTags',
            'system_tags': 'systemTags'
        }

        self._id = None
        self._name = None
        self._description = None
        self._publisher_details = None
        self._triggers = None
        self._time_created = None
        self._time_updated = None
        self._lifecycle_state = None
        self._freeform_tags = None
        self._defined_tags = None
        self._system_tags = None

    @property
    def id(self):
        """
        **[Required]** Gets the id of this PbfListingSummary.
        Unique identifier that is immutable on creation.


        :return: The id of this PbfListingSummary.
        :rtype: str
        """
        return self._id

    @id.setter
    def id(self, id):
        """
        Sets the id of this PbfListingSummary.
        Unique identifier that is immutable on creation.


        :param id: The id of this PbfListingSummary.
        :type: str
        """
        self._id = id

    @property
    def name(self):
        """
        **[Required]** Gets the name of this PbfListingSummary.
        A brief descriptive name for the PBF listing. The PBF listing name must be unique, and not match and existing
        PBF.


        :return: The name of this PbfListingSummary.
        :rtype: str
        """
        return self._name

    @name.setter
    def name(self, name):
        """
        Sets the name of this PbfListingSummary.
        A brief descriptive name for the PBF listing. The PBF listing name must be unique, and not match and existing
        PBF.


        :param name: The name of this PbfListingSummary.
        :type: str
        """
        self._name = name

    @property
    def description(self):
        """
        **[Required]** Gets the description of this PbfListingSummary.
        A short overview of the PBF Listing: the purpose of the PBF and and associated information.


        :return: The description of this PbfListingSummary.
        :rtype: str
        """
        return self._description

    @description.setter
    def description(self, description):
        """
        Sets the description of this PbfListingSummary.
        A short overview of the PBF Listing: the purpose of the PBF and and associated information.


        :param description: The description of this PbfListingSummary.
        :type: str
        """
        self._description = description

    @property
    def publisher_details(self):
        """
        **[Required]** Gets the publisher_details of this PbfListingSummary.

        :return: The publisher_details of this PbfListingSummary.
        :rtype: oci.functions.models.PublisherDetails
        """
        return self._publisher_details

    @publisher_details.setter
    def publisher_details(self, publisher_details):
        """
        Sets the publisher_details of this PbfListingSummary.

        :param publisher_details: The publisher_details of this PbfListingSummary.
        :type: oci.functions.models.PublisherDetails
        """
        self._publisher_details = publisher_details

    @property
    def triggers(self):
        """
        Gets the triggers of this PbfListingSummary.
        An array of Trigger. A list of triggers that may activate the PBF.


        :return: The triggers of this PbfListingSummary.
        :rtype: list[oci.functions.models.Trigger]
        """
        return self._triggers

    @triggers.setter
    def triggers(self, triggers):
        """
        Sets the triggers of this PbfListingSummary.
        An array of Trigger. A list of triggers that may activate the PBF.


        :param triggers: The triggers of this PbfListingSummary.
        :type: list[oci.functions.models.Trigger]
        """
        self._triggers = triggers

    @property
    def time_created(self):
        """
        **[Required]** Gets the time_created of this PbfListingSummary.
        The time the PbfListing was created. An RFC3339 formatted datetime string.


        :return: The time_created of this PbfListingSummary.
        :rtype: datetime
        """
        return self._time_created

    @time_created.setter
    def time_created(self, time_created):
        """
        Sets the time_created of this PbfListingSummary.
        The time the PbfListing was created. An RFC3339 formatted datetime string.


        :param time_created: The time_created of this PbfListingSummary.
        :type: datetime
        """
        self._time_created = time_created

    @property
    def time_updated(self):
        """
        **[Required]** Gets the time_updated of this PbfListingSummary.
        The last time the PbfListing was updated. An RFC3339 formatted datetime string.


        :return: The time_updated of this PbfListingSummary.
        :rtype: datetime
        """
        return self._time_updated

    @time_updated.setter
    def time_updated(self, time_updated):
        """
        Sets the time_updated of this PbfListingSummary.
        The last time the PbfListing was updated. An RFC3339 formatted datetime string.


        :param time_updated: The time_updated of this PbfListingSummary.
        :type: datetime
        """
        self._time_updated = time_updated

    @property
    def lifecycle_state(self):
        """
        **[Required]** Gets the lifecycle_state of this PbfListingSummary.
        The current state of the PBF resource.


        :return: The lifecycle_state of this PbfListingSummary.
        :rtype: str
        """
        return self._lifecycle_state

    @lifecycle_state.setter
    def lifecycle_state(self, lifecycle_state):
        """
        Sets the lifecycle_state of this PbfListingSummary.
        The current state of the PBF resource.


        :param lifecycle_state: The lifecycle_state of this PbfListingSummary.
        :type: str
        """
        self._lifecycle_state = lifecycle_state

    @property
    def freeform_tags(self):
        """
        Gets the freeform_tags of this PbfListingSummary.
        Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only.
        Example: `{\"bar-key\": \"value\"}`


        :return: The freeform_tags of this PbfListingSummary.
        :rtype: dict(str, str)
        """
        return self._freeform_tags

    @freeform_tags.setter
    def freeform_tags(self, freeform_tags):
        """
        Sets the freeform_tags of this PbfListingSummary.
        Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only.
        Example: `{\"bar-key\": \"value\"}`


        :param freeform_tags: The freeform_tags of this PbfListingSummary.
        :type: dict(str, str)
        """
        self._freeform_tags = freeform_tags

    @property
    def defined_tags(self):
        """
        Gets the defined_tags of this PbfListingSummary.
        Defined tags for this resource. Each key is predefined and scoped to a namespace.
        Example: `{\"foo-namespace\": {\"bar-key\": \"value\"}}`


        :return: The defined_tags of this PbfListingSummary.
        :rtype: dict(str, dict(str, object))
        """
        return self._defined_tags

    @defined_tags.setter
    def defined_tags(self, defined_tags):
        """
        Sets the defined_tags of this PbfListingSummary.
        Defined tags for this resource. Each key is predefined and scoped to a namespace.
        Example: `{\"foo-namespace\": {\"bar-key\": \"value\"}}`


        :param defined_tags: The defined_tags of this PbfListingSummary.
        :type: dict(str, dict(str, object))
        """
        self._defined_tags = defined_tags

    @property
    def system_tags(self):
        """
        Gets the system_tags of this PbfListingSummary.
        System tags for this resource. Each key is predefined and scoped to a namespace.
        Example: `{\"orcl-cloud\": {\"free-tier-retained\": \"true\"}}`


        :return: The system_tags of this PbfListingSummary.
        :rtype: dict(str, dict(str, object))
        """
        return self._system_tags

    @system_tags.setter
    def system_tags(self, system_tags):
        """
        Sets the system_tags of this PbfListingSummary.
        System tags for this resource. Each key is predefined and scoped to a namespace.
        Example: `{\"orcl-cloud\": {\"free-tier-retained\": \"true\"}}`


        :param system_tags: The system_tags of this PbfListingSummary.
        :type: dict(str, dict(str, object))
        """
        self._system_tags = system_tags

    def __repr__(self):
        return formatted_flat_dict(self)

    def __eq__(self, other):
        if other is None:
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not self == other
