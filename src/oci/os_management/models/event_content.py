# coding: utf-8
# Copyright (c) 2016, 2022, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.


from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class EventContent(object):
    """
    Information about the data collected as a ZIP file when the event occurred.
    """

    #: A constant which can be used with the content_availability property of a EventContent.
    #: This constant has a value of "NOT_AVAILABLE"
    CONTENT_AVAILABILITY_NOT_AVAILABLE = "NOT_AVAILABLE"

    #: A constant which can be used with the content_availability property of a EventContent.
    #: This constant has a value of "AVAILABLE_ON_INSTANCE"
    CONTENT_AVAILABILITY_AVAILABLE_ON_INSTANCE = "AVAILABLE_ON_INSTANCE"

    #: A constant which can be used with the content_availability property of a EventContent.
    #: This constant has a value of "AVAILABLE_ON_SERVICE"
    CONTENT_AVAILABILITY_AVAILABLE_ON_SERVICE = "AVAILABLE_ON_SERVICE"

    #: A constant which can be used with the content_availability property of a EventContent.
    #: This constant has a value of "AVAILABLE_ON_INSTANCE_AND_SERVICE"
    CONTENT_AVAILABILITY_AVAILABLE_ON_INSTANCE_AND_SERVICE = "AVAILABLE_ON_INSTANCE_AND_SERVICE"

    #: A constant which can be used with the content_availability property of a EventContent.
    #: This constant has a value of "AVAILABLE_ON_INSTANCE_UPLOAD_IN_PROGRESS"
    CONTENT_AVAILABILITY_AVAILABLE_ON_INSTANCE_UPLOAD_IN_PROGRESS = "AVAILABLE_ON_INSTANCE_UPLOAD_IN_PROGRESS"

    def __init__(self, **kwargs):
        """
        Initializes a new EventContent object with values from keyword arguments.
        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param content_availability:
            The value to assign to the content_availability property of this EventContent.
            Allowed values for this property are: "NOT_AVAILABLE", "AVAILABLE_ON_INSTANCE", "AVAILABLE_ON_SERVICE", "AVAILABLE_ON_INSTANCE_AND_SERVICE", "AVAILABLE_ON_INSTANCE_UPLOAD_IN_PROGRESS", 'UNKNOWN_ENUM_VALUE'.
            Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.
        :type content_availability: str

        :param instance_path:
            The value to assign to the instance_path property of this EventContent.
        :type instance_path: str

        :param size:
            The value to assign to the size property of this EventContent.
        :type size: int

        """
        self.swagger_types = {
            'content_availability': 'str',
            'instance_path': 'str',
            'size': 'int'
        }

        self.attribute_map = {
            'content_availability': 'contentAvailability',
            'instance_path': 'instancePath',
            'size': 'size'
        }

        self._content_availability = None
        self._instance_path = None
        self._size = None

    @property
    def content_availability(self):
        """
        Gets the content_availability of this EventContent.
        Status of the event content

        Allowed values for this property are: "NOT_AVAILABLE", "AVAILABLE_ON_INSTANCE", "AVAILABLE_ON_SERVICE", "AVAILABLE_ON_INSTANCE_AND_SERVICE", "AVAILABLE_ON_INSTANCE_UPLOAD_IN_PROGRESS", 'UNKNOWN_ENUM_VALUE'.
        Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.


        :return: The content_availability of this EventContent.
        :rtype: str
        """
        return self._content_availability

    @content_availability.setter
    def content_availability(self, content_availability):
        """
        Sets the content_availability of this EventContent.
        Status of the event content


        :param content_availability: The content_availability of this EventContent.
        :type: str
        """
        allowed_values = ["NOT_AVAILABLE", "AVAILABLE_ON_INSTANCE", "AVAILABLE_ON_SERVICE", "AVAILABLE_ON_INSTANCE_AND_SERVICE", "AVAILABLE_ON_INSTANCE_UPLOAD_IN_PROGRESS"]
        if not value_allowed_none_or_none_sentinel(content_availability, allowed_values):
            content_availability = 'UNKNOWN_ENUM_VALUE'
        self._content_availability = content_availability

    @property
    def instance_path(self):
        """
        Gets the instance_path of this EventContent.
        Path to the event content on the instance


        :return: The instance_path of this EventContent.
        :rtype: str
        """
        return self._instance_path

    @instance_path.setter
    def instance_path(self, instance_path):
        """
        Sets the instance_path of this EventContent.
        Path to the event content on the instance


        :param instance_path: The instance_path of this EventContent.
        :type: str
        """
        self._instance_path = instance_path

    @property
    def size(self):
        """
        Gets the size of this EventContent.
        size in bytes of the event content (size of the zip file uploaded)


        :return: The size of this EventContent.
        :rtype: int
        """
        return self._size

    @size.setter
    def size(self, size):
        """
        Sets the size of this EventContent.
        size in bytes of the event content (size of the zip file uploaded)


        :param size: The size of this EventContent.
        :type: int
        """
        self._size = size

    def __repr__(self):
        return formatted_flat_dict(self)

    def __eq__(self, other):
        if other is None:
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not self == other