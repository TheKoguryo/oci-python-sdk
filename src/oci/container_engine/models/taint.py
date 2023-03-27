# coding: utf-8
# Copyright (c) 2016, 2023, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.


from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class Taint(object):
    """
    taints
    """

    def __init__(self, **kwargs):
        """
        Initializes a new Taint object with values from keyword arguments.
        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param key:
            The value to assign to the key property of this Taint.
        :type key: str

        :param value:
            The value to assign to the value property of this Taint.
        :type value: str

        :param effect:
            The value to assign to the effect property of this Taint.
        :type effect: str

        """
        self.swagger_types = {
            'key': 'str',
            'value': 'str',
            'effect': 'str'
        }

        self.attribute_map = {
            'key': 'key',
            'value': 'value',
            'effect': 'effect'
        }

        self._key = None
        self._value = None
        self._effect = None

    @property
    def key(self):
        """
        Gets the key of this Taint.
        The key of the pair.


        :return: The key of this Taint.
        :rtype: str
        """
        return self._key

    @key.setter
    def key(self, key):
        """
        Sets the key of this Taint.
        The key of the pair.


        :param key: The key of this Taint.
        :type: str
        """
        self._key = key

    @property
    def value(self):
        """
        Gets the value of this Taint.
        The value of the pair.


        :return: The value of this Taint.
        :rtype: str
        """
        return self._value

    @value.setter
    def value(self, value):
        """
        Sets the value of this Taint.
        The value of the pair.


        :param value: The value of this Taint.
        :type: str
        """
        self._value = value

    @property
    def effect(self):
        """
        Gets the effect of this Taint.
        The effect of the pair.


        :return: The effect of this Taint.
        :rtype: str
        """
        return self._effect

    @effect.setter
    def effect(self, effect):
        """
        Sets the effect of this Taint.
        The effect of the pair.


        :param effect: The effect of this Taint.
        :type: str
        """
        self._effect = effect

    def __repr__(self):
        return formatted_flat_dict(self)

    def __eq__(self, other):
        if other is None:
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not self == other
