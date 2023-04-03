# coding: utf-8
# Copyright (c) 2016, 2023, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.


from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class ClusterConfigDetails(object):
    """
    The HPC cluster configuration requested when launching instances in a compute capacity reservation.

    If the parameter is provided, the reservation is created with the HPC island and a list of HPC blocks that you
    specify. If a list of HPC blocks are missing or not provided, the reservation is created with any HPC blocks in
    the HPC island that you specify. If the values of HPC island or HPC block that you provide are not valid, an error
    is returned.
    """

    def __init__(self, **kwargs):
        """
        Initializes a new ClusterConfigDetails object with values from keyword arguments.
        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param hpc_island_id:
            The value to assign to the hpc_island_id property of this ClusterConfigDetails.
        :type hpc_island_id: str

        :param network_block_ids:
            The value to assign to the network_block_ids property of this ClusterConfigDetails.
        :type network_block_ids: list[str]

        """
        self.swagger_types = {
            'hpc_island_id': 'str',
            'network_block_ids': 'list[str]'
        }

        self.attribute_map = {
            'hpc_island_id': 'hpcIslandId',
            'network_block_ids': 'networkBlockIds'
        }

        self._hpc_island_id = None
        self._network_block_ids = None

    @property
    def hpc_island_id(self):
        """
        **[Required]** Gets the hpc_island_id of this ClusterConfigDetails.
        The `OCID`__ of the HpcIsland.

        __ https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm


        :return: The hpc_island_id of this ClusterConfigDetails.
        :rtype: str
        """
        return self._hpc_island_id

    @hpc_island_id.setter
    def hpc_island_id(self, hpc_island_id):
        """
        Sets the hpc_island_id of this ClusterConfigDetails.
        The `OCID`__ of the HpcIsland.

        __ https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm


        :param hpc_island_id: The hpc_island_id of this ClusterConfigDetails.
        :type: str
        """
        self._hpc_island_id = hpc_island_id

    @property
    def network_block_ids(self):
        """
        Gets the network_block_ids of this ClusterConfigDetails.
        The list of OCID of the network blocks.


        :return: The network_block_ids of this ClusterConfigDetails.
        :rtype: list[str]
        """
        return self._network_block_ids

    @network_block_ids.setter
    def network_block_ids(self, network_block_ids):
        """
        Sets the network_block_ids of this ClusterConfigDetails.
        The list of OCID of the network blocks.


        :param network_block_ids: The network_block_ids of this ClusterConfigDetails.
        :type: list[str]
        """
        self._network_block_ids = network_block_ids

    def __repr__(self):
        return formatted_flat_dict(self)

    def __eq__(self, other):
        if other is None:
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not self == other
