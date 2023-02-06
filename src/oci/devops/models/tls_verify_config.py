# coding: utf-8
# Copyright (c) 2016, 2023, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.


from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class TlsVerifyConfig(object):
    """
    TLS configuration used by build service to verify TLS connection.
    """

    #: A constant which can be used with the tls_verify_mode property of a TlsVerifyConfig.
    #: This constant has a value of "CA_CERTIFICATE_VERIFY"
    TLS_VERIFY_MODE_CA_CERTIFICATE_VERIFY = "CA_CERTIFICATE_VERIFY"

    def __init__(self, **kwargs):
        """
        Initializes a new TlsVerifyConfig object with values from keyword arguments. This class has the following subclasses and if you are using this class as input
        to a service operations then you should favor using a subclass over the base class:

        * :class:`~oci.devops.models.CaCertVerify`

        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param tls_verify_mode:
            The value to assign to the tls_verify_mode property of this TlsVerifyConfig.
            Allowed values for this property are: "CA_CERTIFICATE_VERIFY", 'UNKNOWN_ENUM_VALUE'.
            Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.
        :type tls_verify_mode: str

        """
        self.swagger_types = {
            'tls_verify_mode': 'str'
        }

        self.attribute_map = {
            'tls_verify_mode': 'tlsVerifyMode'
        }

        self._tls_verify_mode = None

    @staticmethod
    def get_subtype(object_dictionary):
        """
        Given the hash representation of a subtype of this class,
        use the info in the hash to return the class of the subtype.
        """
        type = object_dictionary['tlsVerifyMode']

        if type == 'CA_CERTIFICATE_VERIFY':
            return 'CaCertVerify'
        else:
            return 'TlsVerifyConfig'

    @property
    def tls_verify_mode(self):
        """
        **[Required]** Gets the tls_verify_mode of this TlsVerifyConfig.
        The type of TLS verification.

        Allowed values for this property are: "CA_CERTIFICATE_VERIFY", 'UNKNOWN_ENUM_VALUE'.
        Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.


        :return: The tls_verify_mode of this TlsVerifyConfig.
        :rtype: str
        """
        return self._tls_verify_mode

    @tls_verify_mode.setter
    def tls_verify_mode(self, tls_verify_mode):
        """
        Sets the tls_verify_mode of this TlsVerifyConfig.
        The type of TLS verification.


        :param tls_verify_mode: The tls_verify_mode of this TlsVerifyConfig.
        :type: str
        """
        allowed_values = ["CA_CERTIFICATE_VERIFY"]
        if not value_allowed_none_or_none_sentinel(tls_verify_mode, allowed_values):
            tls_verify_mode = 'UNKNOWN_ENUM_VALUE'
        self._tls_verify_mode = tls_verify_mode

    def __repr__(self):
        return formatted_flat_dict(self)

    def __eq__(self, other):
        if other is None:
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not self == other
