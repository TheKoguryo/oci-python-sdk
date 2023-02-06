# coding: utf-8
# Copyright (c) 2016, 2023, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

from .validate_database_tools_connection_details import ValidateDatabaseToolsConnectionDetails
from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class ValidateDatabaseToolsConnectionMySqlDetails(ValidateDatabaseToolsConnectionDetails):
    """
    Connection validation details for the MySQL Server.
    """

    def __init__(self, **kwargs):
        """
        Initializes a new ValidateDatabaseToolsConnectionMySqlDetails object with values from keyword arguments. The default value of the :py:attr:`~oci.database_tools.models.ValidateDatabaseToolsConnectionMySqlDetails.type` attribute
        of this class is ``MYSQL`` and it should not be changed.
        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param type:
            The value to assign to the type property of this ValidateDatabaseToolsConnectionMySqlDetails.
            Allowed values for this property are: "ORACLE_DATABASE", "MYSQL"
        :type type: str

        """
        self.swagger_types = {
            'type': 'str'
        }

        self.attribute_map = {
            'type': 'type'
        }

        self._type = None
        self._type = 'MYSQL'

    def __repr__(self):
        return formatted_flat_dict(self)

    def __eq__(self, other):
        if other is None:
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not self == other
