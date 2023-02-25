# coding: utf-8
# Copyright (c) 2016, 2023, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.


from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class DatabaseManagementConfig(object):
    """
    The configuration of the Database Management service.
    """

    #: A constant which can be used with the database_management_status property of a DatabaseManagementConfig.
    #: This constant has a value of "ENABLING"
    DATABASE_MANAGEMENT_STATUS_ENABLING = "ENABLING"

    #: A constant which can be used with the database_management_status property of a DatabaseManagementConfig.
    #: This constant has a value of "ENABLED"
    DATABASE_MANAGEMENT_STATUS_ENABLED = "ENABLED"

    #: A constant which can be used with the database_management_status property of a DatabaseManagementConfig.
    #: This constant has a value of "DISABLING"
    DATABASE_MANAGEMENT_STATUS_DISABLING = "DISABLING"

    #: A constant which can be used with the database_management_status property of a DatabaseManagementConfig.
    #: This constant has a value of "NOT_ENABLED"
    DATABASE_MANAGEMENT_STATUS_NOT_ENABLED = "NOT_ENABLED"

    #: A constant which can be used with the database_management_status property of a DatabaseManagementConfig.
    #: This constant has a value of "FAILED_ENABLING"
    DATABASE_MANAGEMENT_STATUS_FAILED_ENABLING = "FAILED_ENABLING"

    #: A constant which can be used with the database_management_status property of a DatabaseManagementConfig.
    #: This constant has a value of "FAILED_DISABLING"
    DATABASE_MANAGEMENT_STATUS_FAILED_DISABLING = "FAILED_DISABLING"

    #: A constant which can be used with the license_model property of a DatabaseManagementConfig.
    #: This constant has a value of "LICENSE_INCLUDED"
    LICENSE_MODEL_LICENSE_INCLUDED = "LICENSE_INCLUDED"

    #: A constant which can be used with the license_model property of a DatabaseManagementConfig.
    #: This constant has a value of "BRING_YOUR_OWN_LICENSE"
    LICENSE_MODEL_BRING_YOUR_OWN_LICENSE = "BRING_YOUR_OWN_LICENSE"

    def __init__(self, **kwargs):
        """
        Initializes a new DatabaseManagementConfig object with values from keyword arguments.
        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param database_management_status:
            The value to assign to the database_management_status property of this DatabaseManagementConfig.
            Allowed values for this property are: "ENABLING", "ENABLED", "DISABLING", "NOT_ENABLED", "FAILED_ENABLING", "FAILED_DISABLING", 'UNKNOWN_ENUM_VALUE'.
            Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.
        :type database_management_status: str

        :param connector_id:
            The value to assign to the connector_id property of this DatabaseManagementConfig.
        :type connector_id: str

        :param license_model:
            The value to assign to the license_model property of this DatabaseManagementConfig.
            Allowed values for this property are: "LICENSE_INCLUDED", "BRING_YOUR_OWN_LICENSE", 'UNKNOWN_ENUM_VALUE'.
            Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.
        :type license_model: str

        """
        self.swagger_types = {
            'database_management_status': 'str',
            'connector_id': 'str',
            'license_model': 'str'
        }

        self.attribute_map = {
            'database_management_status': 'databaseManagementStatus',
            'connector_id': 'connectorId',
            'license_model': 'licenseModel'
        }

        self._database_management_status = None
        self._connector_id = None
        self._license_model = None

    @property
    def database_management_status(self):
        """
        **[Required]** Gets the database_management_status of this DatabaseManagementConfig.
        The status of the Database Management service.

        Allowed values for this property are: "ENABLING", "ENABLED", "DISABLING", "NOT_ENABLED", "FAILED_ENABLING", "FAILED_DISABLING", 'UNKNOWN_ENUM_VALUE'.
        Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.


        :return: The database_management_status of this DatabaseManagementConfig.
        :rtype: str
        """
        return self._database_management_status

    @database_management_status.setter
    def database_management_status(self, database_management_status):
        """
        Sets the database_management_status of this DatabaseManagementConfig.
        The status of the Database Management service.


        :param database_management_status: The database_management_status of this DatabaseManagementConfig.
        :type: str
        """
        allowed_values = ["ENABLING", "ENABLED", "DISABLING", "NOT_ENABLED", "FAILED_ENABLING", "FAILED_DISABLING"]
        if not value_allowed_none_or_none_sentinel(database_management_status, allowed_values):
            database_management_status = 'UNKNOWN_ENUM_VALUE'
        self._database_management_status = database_management_status

    @property
    def connector_id(self):
        """
        Gets the connector_id of this DatabaseManagementConfig.
        The `OCID`__ of the external database connector.

        __ https://docs.cloud.oracle.com/Content/General/Concepts/identifiers.htm


        :return: The connector_id of this DatabaseManagementConfig.
        :rtype: str
        """
        return self._connector_id

    @connector_id.setter
    def connector_id(self, connector_id):
        """
        Sets the connector_id of this DatabaseManagementConfig.
        The `OCID`__ of the external database connector.

        __ https://docs.cloud.oracle.com/Content/General/Concepts/identifiers.htm


        :param connector_id: The connector_id of this DatabaseManagementConfig.
        :type: str
        """
        self._connector_id = connector_id

    @property
    def license_model(self):
        """
        **[Required]** Gets the license_model of this DatabaseManagementConfig.
        The Oracle license model that applies to the external database.

        Allowed values for this property are: "LICENSE_INCLUDED", "BRING_YOUR_OWN_LICENSE", 'UNKNOWN_ENUM_VALUE'.
        Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.


        :return: The license_model of this DatabaseManagementConfig.
        :rtype: str
        """
        return self._license_model

    @license_model.setter
    def license_model(self, license_model):
        """
        Sets the license_model of this DatabaseManagementConfig.
        The Oracle license model that applies to the external database.


        :param license_model: The license_model of this DatabaseManagementConfig.
        :type: str
        """
        allowed_values = ["LICENSE_INCLUDED", "BRING_YOUR_OWN_LICENSE"]
        if not value_allowed_none_or_none_sentinel(license_model, allowed_values):
            license_model = 'UNKNOWN_ENUM_VALUE'
        self._license_model = license_model

    def __repr__(self):
        return formatted_flat_dict(self)

    def __eq__(self, other):
        if other is None:
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not self == other
