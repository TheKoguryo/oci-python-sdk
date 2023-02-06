# coding: utf-8
# Copyright (c) 2016, 2023, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.


from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class Nvdimm(object):
    """
    The asset's NVDIMM configuration.
    """

    def __init__(self, **kwargs):
        """
        Initializes a new Nvdimm object with values from keyword arguments.
        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param label:
            The value to assign to the label property of this Nvdimm.
        :type label: str

        :param unit_number:
            The value to assign to the unit_number property of this Nvdimm.
        :type unit_number: int

        :param controller_key:
            The value to assign to the controller_key property of this Nvdimm.
        :type controller_key: int

        """
        self.swagger_types = {
            'label': 'str',
            'unit_number': 'int',
            'controller_key': 'int'
        }

        self.attribute_map = {
            'label': 'label',
            'unit_number': 'unitNumber',
            'controller_key': 'controllerKey'
        }

        self._label = None
        self._unit_number = None
        self._controller_key = None

    @property
    def label(self):
        """
        Gets the label of this Nvdimm.
        Provides a label and summary information for the device.


        :return: The label of this Nvdimm.
        :rtype: str
        """
        return self._label

    @label.setter
    def label(self, label):
        """
        Sets the label of this Nvdimm.
        Provides a label and summary information for the device.


        :param label: The label of this Nvdimm.
        :type: str
        """
        self._label = label

    @property
    def unit_number(self):
        """
        Gets the unit_number of this Nvdimm.
        The unit number of NVDIMM.


        :return: The unit_number of this Nvdimm.
        :rtype: int
        """
        return self._unit_number

    @unit_number.setter
    def unit_number(self, unit_number):
        """
        Sets the unit_number of this Nvdimm.
        The unit number of NVDIMM.


        :param unit_number: The unit_number of this Nvdimm.
        :type: int
        """
        self._unit_number = unit_number

    @property
    def controller_key(self):
        """
        Gets the controller_key of this Nvdimm.
        Controller key.


        :return: The controller_key of this Nvdimm.
        :rtype: int
        """
        return self._controller_key

    @controller_key.setter
    def controller_key(self, controller_key):
        """
        Sets the controller_key of this Nvdimm.
        Controller key.


        :param controller_key: The controller_key of this Nvdimm.
        :type: int
        """
        self._controller_key = controller_key

    def __repr__(self):
        return formatted_flat_dict(self)

    def __eq__(self, other):
        if other is None:
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not self == other
