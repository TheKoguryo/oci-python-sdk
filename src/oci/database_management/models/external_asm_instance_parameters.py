# coding: utf-8
# Copyright (c) 2016, 2023, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.


from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class ExternalAsmInstanceParameters(object):
    """
    The initialization parameters for an ASM instance.
    """

    def __init__(self, **kwargs):
        """
        Initializes a new ExternalAsmInstanceParameters object with values from keyword arguments.
        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param asm_instance_id:
            The value to assign to the asm_instance_id property of this ExternalAsmInstanceParameters.
        :type asm_instance_id: str

        :param asm_instance_display_name:
            The value to assign to the asm_instance_display_name property of this ExternalAsmInstanceParameters.
        :type asm_instance_display_name: str

        :param disk_discovery_path:
            The value to assign to the disk_discovery_path property of this ExternalAsmInstanceParameters.
        :type disk_discovery_path: str

        :param auto_mount_disk_groups:
            The value to assign to the auto_mount_disk_groups property of this ExternalAsmInstanceParameters.
        :type auto_mount_disk_groups: list[str]

        :param rebalance_power:
            The value to assign to the rebalance_power property of this ExternalAsmInstanceParameters.
        :type rebalance_power: int

        :param preferred_read_failure_groups:
            The value to assign to the preferred_read_failure_groups property of this ExternalAsmInstanceParameters.
        :type preferred_read_failure_groups: list[str]

        """
        self.swagger_types = {
            'asm_instance_id': 'str',
            'asm_instance_display_name': 'str',
            'disk_discovery_path': 'str',
            'auto_mount_disk_groups': 'list[str]',
            'rebalance_power': 'int',
            'preferred_read_failure_groups': 'list[str]'
        }

        self.attribute_map = {
            'asm_instance_id': 'asmInstanceId',
            'asm_instance_display_name': 'asmInstanceDisplayName',
            'disk_discovery_path': 'diskDiscoveryPath',
            'auto_mount_disk_groups': 'autoMountDiskGroups',
            'rebalance_power': 'rebalancePower',
            'preferred_read_failure_groups': 'preferredReadFailureGroups'
        }

        self._asm_instance_id = None
        self._asm_instance_display_name = None
        self._disk_discovery_path = None
        self._auto_mount_disk_groups = None
        self._rebalance_power = None
        self._preferred_read_failure_groups = None

    @property
    def asm_instance_id(self):
        """
        **[Required]** Gets the asm_instance_id of this ExternalAsmInstanceParameters.
        The `OCID`__ of the external ASM instance.

        __ https://docs.cloud.oracle.com/Content/General/Concepts/identifiers.htm


        :return: The asm_instance_id of this ExternalAsmInstanceParameters.
        :rtype: str
        """
        return self._asm_instance_id

    @asm_instance_id.setter
    def asm_instance_id(self, asm_instance_id):
        """
        Sets the asm_instance_id of this ExternalAsmInstanceParameters.
        The `OCID`__ of the external ASM instance.

        __ https://docs.cloud.oracle.com/Content/General/Concepts/identifiers.htm


        :param asm_instance_id: The asm_instance_id of this ExternalAsmInstanceParameters.
        :type: str
        """
        self._asm_instance_id = asm_instance_id

    @property
    def asm_instance_display_name(self):
        """
        **[Required]** Gets the asm_instance_display_name of this ExternalAsmInstanceParameters.
        The user-friendly name for the ASM instance. The name does not have to be unique.


        :return: The asm_instance_display_name of this ExternalAsmInstanceParameters.
        :rtype: str
        """
        return self._asm_instance_display_name

    @asm_instance_display_name.setter
    def asm_instance_display_name(self, asm_instance_display_name):
        """
        Sets the asm_instance_display_name of this ExternalAsmInstanceParameters.
        The user-friendly name for the ASM instance. The name does not have to be unique.


        :param asm_instance_display_name: The asm_instance_display_name of this ExternalAsmInstanceParameters.
        :type: str
        """
        self._asm_instance_display_name = asm_instance_display_name

    @property
    def disk_discovery_path(self):
        """
        **[Required]** Gets the disk_discovery_path of this ExternalAsmInstanceParameters.
        An operating system-dependent value used to limit the set of disks considered for discovery.


        :return: The disk_discovery_path of this ExternalAsmInstanceParameters.
        :rtype: str
        """
        return self._disk_discovery_path

    @disk_discovery_path.setter
    def disk_discovery_path(self, disk_discovery_path):
        """
        Sets the disk_discovery_path of this ExternalAsmInstanceParameters.
        An operating system-dependent value used to limit the set of disks considered for discovery.


        :param disk_discovery_path: The disk_discovery_path of this ExternalAsmInstanceParameters.
        :type: str
        """
        self._disk_discovery_path = disk_discovery_path

    @property
    def auto_mount_disk_groups(self):
        """
        **[Required]** Gets the auto_mount_disk_groups of this ExternalAsmInstanceParameters.
        The list of disk group names that an ASM instance mounts at startup or when the `ALTER DISKGROUP ALL MOUNT` statement is issued.


        :return: The auto_mount_disk_groups of this ExternalAsmInstanceParameters.
        :rtype: list[str]
        """
        return self._auto_mount_disk_groups

    @auto_mount_disk_groups.setter
    def auto_mount_disk_groups(self, auto_mount_disk_groups):
        """
        Sets the auto_mount_disk_groups of this ExternalAsmInstanceParameters.
        The list of disk group names that an ASM instance mounts at startup or when the `ALTER DISKGROUP ALL MOUNT` statement is issued.


        :param auto_mount_disk_groups: The auto_mount_disk_groups of this ExternalAsmInstanceParameters.
        :type: list[str]
        """
        self._auto_mount_disk_groups = auto_mount_disk_groups

    @property
    def rebalance_power(self):
        """
        **[Required]** Gets the rebalance_power of this ExternalAsmInstanceParameters.
        The maximum power on an ASM instance for disk rebalancing.


        :return: The rebalance_power of this ExternalAsmInstanceParameters.
        :rtype: int
        """
        return self._rebalance_power

    @rebalance_power.setter
    def rebalance_power(self, rebalance_power):
        """
        Sets the rebalance_power of this ExternalAsmInstanceParameters.
        The maximum power on an ASM instance for disk rebalancing.


        :param rebalance_power: The rebalance_power of this ExternalAsmInstanceParameters.
        :type: int
        """
        self._rebalance_power = rebalance_power

    @property
    def preferred_read_failure_groups(self):
        """
        **[Required]** Gets the preferred_read_failure_groups of this ExternalAsmInstanceParameters.
        The list of failure groups that contain preferred read disks.


        :return: The preferred_read_failure_groups of this ExternalAsmInstanceParameters.
        :rtype: list[str]
        """
        return self._preferred_read_failure_groups

    @preferred_read_failure_groups.setter
    def preferred_read_failure_groups(self, preferred_read_failure_groups):
        """
        Sets the preferred_read_failure_groups of this ExternalAsmInstanceParameters.
        The list of failure groups that contain preferred read disks.


        :param preferred_read_failure_groups: The preferred_read_failure_groups of this ExternalAsmInstanceParameters.
        :type: list[str]
        """
        self._preferred_read_failure_groups = preferred_read_failure_groups

    def __repr__(self):
        return formatted_flat_dict(self)

    def __eq__(self, other):
        if other is None:
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not self == other
