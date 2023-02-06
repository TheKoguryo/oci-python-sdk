# coding: utf-8
# Copyright (c) 2016, 2023, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.


from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class CreateStatementDetails(object):
    """
    The details required to create a statement.
    """

    def __init__(self, **kwargs):
        """
        Initializes a new CreateStatementDetails object with values from keyword arguments.
        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param code:
            The value to assign to the code property of this CreateStatementDetails.
        :type code: str

        """
        self.swagger_types = {
            'code': 'str'
        }

        self.attribute_map = {
            'code': 'code'
        }

        self._code = None

    @property
    def code(self):
        """
        **[Required]** Gets the code of this CreateStatementDetails.
        The statement code to execute.
        Example: `println(sc.version)`


        :return: The code of this CreateStatementDetails.
        :rtype: str
        """
        return self._code

    @code.setter
    def code(self, code):
        """
        Sets the code of this CreateStatementDetails.
        The statement code to execute.
        Example: `println(sc.version)`


        :param code: The code of this CreateStatementDetails.
        :type: str
        """
        self._code = code

    def __repr__(self):
        return formatted_flat_dict(self)

    def __eq__(self, other):
        if other is None:
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not self == other
