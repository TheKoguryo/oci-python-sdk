# coding: utf-8
# Copyright (c) 2016, 2023, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.


from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class JfrAttachmentTarget(object):
    """
    The target to collect JFR data. A target is a managed instance, with options to further limit to specific application and/or Java runtime.
    When the applicationKey isn't specified, then all applications are selected.
    When the jreKey isn't specified, then all supported Java runtime versions are selected.
    """

    def __init__(self, **kwargs):
        """
        Initializes a new JfrAttachmentTarget object with values from keyword arguments.
        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param managed_instance_id:
            The value to assign to the managed_instance_id property of this JfrAttachmentTarget.
        :type managed_instance_id: str

        :param application_key:
            The value to assign to the application_key property of this JfrAttachmentTarget.
        :type application_key: str

        :param jre_key:
            The value to assign to the jre_key property of this JfrAttachmentTarget.
        :type jre_key: str

        """
        self.swagger_types = {
            'managed_instance_id': 'str',
            'application_key': 'str',
            'jre_key': 'str'
        }

        self.attribute_map = {
            'managed_instance_id': 'managedInstanceId',
            'application_key': 'applicationKey',
            'jre_key': 'jreKey'
        }

        self._managed_instance_id = None
        self._application_key = None
        self._jre_key = None

    @property
    def managed_instance_id(self):
        """
        **[Required]** Gets the managed_instance_id of this JfrAttachmentTarget.
        OCID of the Managed Instance to collect JFR data.


        :return: The managed_instance_id of this JfrAttachmentTarget.
        :rtype: str
        """
        return self._managed_instance_id

    @managed_instance_id.setter
    def managed_instance_id(self, managed_instance_id):
        """
        Sets the managed_instance_id of this JfrAttachmentTarget.
        OCID of the Managed Instance to collect JFR data.


        :param managed_instance_id: The managed_instance_id of this JfrAttachmentTarget.
        :type: str
        """
        self._managed_instance_id = managed_instance_id

    @property
    def application_key(self):
        """
        Gets the application_key of this JfrAttachmentTarget.
        Unique key that identify the application for JFR data collection.


        :return: The application_key of this JfrAttachmentTarget.
        :rtype: str
        """
        return self._application_key

    @application_key.setter
    def application_key(self, application_key):
        """
        Sets the application_key of this JfrAttachmentTarget.
        Unique key that identify the application for JFR data collection.


        :param application_key: The application_key of this JfrAttachmentTarget.
        :type: str
        """
        self._application_key = application_key

    @property
    def jre_key(self):
        """
        Gets the jre_key of this JfrAttachmentTarget.
        Unique key that identify the JVM for JFR data collection.


        :return: The jre_key of this JfrAttachmentTarget.
        :rtype: str
        """
        return self._jre_key

    @jre_key.setter
    def jre_key(self, jre_key):
        """
        Sets the jre_key of this JfrAttachmentTarget.
        Unique key that identify the JVM for JFR data collection.


        :param jre_key: The jre_key of this JfrAttachmentTarget.
        :type: str
        """
        self._jre_key = jre_key

    def __repr__(self):
        return formatted_flat_dict(self)

    def __eq__(self, other):
        if other is None:
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not self == other
