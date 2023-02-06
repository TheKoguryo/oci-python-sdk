# coding: utf-8
# Copyright (c) 2016, 2023, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

from .managed_database_credential import ManagedDatabaseCredential
from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class ManagedDatabaseSecretCredential(ManagedDatabaseCredential):
    """
    User provides a secret OCID, which will be used to retrieve the password to connect to the database.
    """

    def __init__(self, **kwargs):
        """
        Initializes a new ManagedDatabaseSecretCredential object with values from keyword arguments. The default value of the :py:attr:`~oci.database_management.models.ManagedDatabaseSecretCredential.credential_type` attribute
        of this class is ``SECRET`` and it should not be changed.
        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param credential_type:
            The value to assign to the credential_type property of this ManagedDatabaseSecretCredential.
            Allowed values for this property are: "SECRET", "PASSWORD"
        :type credential_type: str

        :param username:
            The value to assign to the username property of this ManagedDatabaseSecretCredential.
        :type username: str

        :param role:
            The value to assign to the role property of this ManagedDatabaseSecretCredential.
            Allowed values for this property are: "NORMAL", "SYSDBA"
        :type role: str

        :param password_secret_id:
            The value to assign to the password_secret_id property of this ManagedDatabaseSecretCredential.
        :type password_secret_id: str

        """
        self.swagger_types = {
            'credential_type': 'str',
            'username': 'str',
            'role': 'str',
            'password_secret_id': 'str'
        }

        self.attribute_map = {
            'credential_type': 'credentialType',
            'username': 'username',
            'role': 'role',
            'password_secret_id': 'passwordSecretId'
        }

        self._credential_type = None
        self._username = None
        self._role = None
        self._password_secret_id = None
        self._credential_type = 'SECRET'

    @property
    def password_secret_id(self):
        """
        **[Required]** Gets the password_secret_id of this ManagedDatabaseSecretCredential.
        The `OCID`__ of the Secret
        where the database password is stored.

        __ https://docs.cloud.oracle.com/Content/General/Concepts/identifiers.htm


        :return: The password_secret_id of this ManagedDatabaseSecretCredential.
        :rtype: str
        """
        return self._password_secret_id

    @password_secret_id.setter
    def password_secret_id(self, password_secret_id):
        """
        Sets the password_secret_id of this ManagedDatabaseSecretCredential.
        The `OCID`__ of the Secret
        where the database password is stored.

        __ https://docs.cloud.oracle.com/Content/General/Concepts/identifiers.htm


        :param password_secret_id: The password_secret_id of this ManagedDatabaseSecretCredential.
        :type: str
        """
        self._password_secret_id = password_secret_id

    def __repr__(self):
        return formatted_flat_dict(self)

    def __eq__(self, other):
        if other is None:
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not self == other
