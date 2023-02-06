# coding: utf-8
# Copyright (c) 2016, 2023, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.


from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class ProblemEndpointSummary(object):
    """
    Problem endpoints summary.
    """

    def __init__(self, **kwargs):
        """
        Initializes a new ProblemEndpointSummary object with values from keyword arguments.
        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param id:
            The value to assign to the id property of this ProblemEndpointSummary.
        :type id: str

        :param sighting_id:
            The value to assign to the sighting_id property of this ProblemEndpointSummary.
        :type sighting_id: str

        :param problem_id:
            The value to assign to the problem_id property of this ProblemEndpointSummary.
        :type problem_id: str

        :param sighting_type:
            The value to assign to the sighting_type property of this ProblemEndpointSummary.
        :type sighting_type: str

        :param sighting_type_display_name:
            The value to assign to the sighting_type_display_name property of this ProblemEndpointSummary.
        :type sighting_type_display_name: str

        :param ip_address:
            The value to assign to the ip_address property of this ProblemEndpointSummary.
        :type ip_address: str

        :param ip_address_type:
            The value to assign to the ip_address_type property of this ProblemEndpointSummary.
        :type ip_address_type: str

        :param ip_classification_type:
            The value to assign to the ip_classification_type property of this ProblemEndpointSummary.
        :type ip_classification_type: str

        :param country:
            The value to assign to the country property of this ProblemEndpointSummary.
        :type country: str

        :param latitude:
            The value to assign to the latitude property of this ProblemEndpointSummary.
        :type latitude: float

        :param longitude:
            The value to assign to the longitude property of this ProblemEndpointSummary.
        :type longitude: float

        :param asn_number:
            The value to assign to the asn_number property of this ProblemEndpointSummary.
        :type asn_number: str

        :param regions:
            The value to assign to the regions property of this ProblemEndpointSummary.
        :type regions: list[str]

        :param services:
            The value to assign to the services property of this ProblemEndpointSummary.
        :type services: list[str]

        :param time_last_detected:
            The value to assign to the time_last_detected property of this ProblemEndpointSummary.
        :type time_last_detected: datetime

        """
        self.swagger_types = {
            'id': 'str',
            'sighting_id': 'str',
            'problem_id': 'str',
            'sighting_type': 'str',
            'sighting_type_display_name': 'str',
            'ip_address': 'str',
            'ip_address_type': 'str',
            'ip_classification_type': 'str',
            'country': 'str',
            'latitude': 'float',
            'longitude': 'float',
            'asn_number': 'str',
            'regions': 'list[str]',
            'services': 'list[str]',
            'time_last_detected': 'datetime'
        }

        self.attribute_map = {
            'id': 'id',
            'sighting_id': 'sightingId',
            'problem_id': 'problemId',
            'sighting_type': 'sightingType',
            'sighting_type_display_name': 'sightingTypeDisplayName',
            'ip_address': 'ipAddress',
            'ip_address_type': 'ipAddressType',
            'ip_classification_type': 'ipClassificationType',
            'country': 'country',
            'latitude': 'latitude',
            'longitude': 'longitude',
            'asn_number': 'asnNumber',
            'regions': 'regions',
            'services': 'services',
            'time_last_detected': 'timeLastDetected'
        }

        self._id = None
        self._sighting_id = None
        self._problem_id = None
        self._sighting_type = None
        self._sighting_type_display_name = None
        self._ip_address = None
        self._ip_address_type = None
        self._ip_classification_type = None
        self._country = None
        self._latitude = None
        self._longitude = None
        self._asn_number = None
        self._regions = None
        self._services = None
        self._time_last_detected = None

    @property
    def id(self):
        """
        **[Required]** Gets the id of this ProblemEndpointSummary.
        Unique identifier for problem endpoint.


        :return: The id of this ProblemEndpointSummary.
        :rtype: str
        """
        return self._id

    @id.setter
    def id(self, id):
        """
        Sets the id of this ProblemEndpointSummary.
        Unique identifier for problem endpoint.


        :param id: The id of this ProblemEndpointSummary.
        :type: str
        """
        self._id = id

    @property
    def sighting_id(self):
        """
        **[Required]** Gets the sighting_id of this ProblemEndpointSummary.
        Unique id for sighting associated with the endpoint.


        :return: The sighting_id of this ProblemEndpointSummary.
        :rtype: str
        """
        return self._sighting_id

    @sighting_id.setter
    def sighting_id(self, sighting_id):
        """
        Sets the sighting_id of this ProblemEndpointSummary.
        Unique id for sighting associated with the endpoint.


        :param sighting_id: The sighting_id of this ProblemEndpointSummary.
        :type: str
        """
        self._sighting_id = sighting_id

    @property
    def problem_id(self):
        """
        **[Required]** Gets the problem_id of this ProblemEndpointSummary.
        Unique id for cloudguard problem


        :return: The problem_id of this ProblemEndpointSummary.
        :rtype: str
        """
        return self._problem_id

    @problem_id.setter
    def problem_id(self, problem_id):
        """
        Sets the problem_id of this ProblemEndpointSummary.
        Unique id for cloudguard problem


        :param problem_id: The problem_id of this ProblemEndpointSummary.
        :type: str
        """
        self._problem_id = problem_id

    @property
    def sighting_type(self):
        """
        **[Required]** Gets the sighting_type of this ProblemEndpointSummary.
        Identifier for the sighting type


        :return: The sighting_type of this ProblemEndpointSummary.
        :rtype: str
        """
        return self._sighting_type

    @sighting_type.setter
    def sighting_type(self, sighting_type):
        """
        Sets the sighting_type of this ProblemEndpointSummary.
        Identifier for the sighting type


        :param sighting_type: The sighting_type of this ProblemEndpointSummary.
        :type: str
        """
        self._sighting_type = sighting_type

    @property
    def sighting_type_display_name(self):
        """
        **[Required]** Gets the sighting_type_display_name of this ProblemEndpointSummary.
        Display Name of the sighting type


        :return: The sighting_type_display_name of this ProblemEndpointSummary.
        :rtype: str
        """
        return self._sighting_type_display_name

    @sighting_type_display_name.setter
    def sighting_type_display_name(self, sighting_type_display_name):
        """
        Sets the sighting_type_display_name of this ProblemEndpointSummary.
        Display Name of the sighting type


        :param sighting_type_display_name: The sighting_type_display_name of this ProblemEndpointSummary.
        :type: str
        """
        self._sighting_type_display_name = sighting_type_display_name

    @property
    def ip_address(self):
        """
        **[Required]** Gets the ip_address of this ProblemEndpointSummary.
        IP Address of the Endpoint


        :return: The ip_address of this ProblemEndpointSummary.
        :rtype: str
        """
        return self._ip_address

    @ip_address.setter
    def ip_address(self, ip_address):
        """
        Sets the ip_address of this ProblemEndpointSummary.
        IP Address of the Endpoint


        :param ip_address: The ip_address of this ProblemEndpointSummary.
        :type: str
        """
        self._ip_address = ip_address

    @property
    def ip_address_type(self):
        """
        **[Required]** Gets the ip_address_type of this ProblemEndpointSummary.
        IP Address type of the Endpoint


        :return: The ip_address_type of this ProblemEndpointSummary.
        :rtype: str
        """
        return self._ip_address_type

    @ip_address_type.setter
    def ip_address_type(self, ip_address_type):
        """
        Sets the ip_address_type of this ProblemEndpointSummary.
        IP Address type of the Endpoint


        :param ip_address_type: The ip_address_type of this ProblemEndpointSummary.
        :type: str
        """
        self._ip_address_type = ip_address_type

    @property
    def ip_classification_type(self):
        """
        Gets the ip_classification_type of this ProblemEndpointSummary.
        IP Address classification type of the endpoint


        :return: The ip_classification_type of this ProblemEndpointSummary.
        :rtype: str
        """
        return self._ip_classification_type

    @ip_classification_type.setter
    def ip_classification_type(self, ip_classification_type):
        """
        Sets the ip_classification_type of this ProblemEndpointSummary.
        IP Address classification type of the endpoint


        :param ip_classification_type: The ip_classification_type of this ProblemEndpointSummary.
        :type: str
        """
        self._ip_classification_type = ip_classification_type

    @property
    def country(self):
        """
        Gets the country of this ProblemEndpointSummary.
        Country of the endpoint


        :return: The country of this ProblemEndpointSummary.
        :rtype: str
        """
        return self._country

    @country.setter
    def country(self, country):
        """
        Sets the country of this ProblemEndpointSummary.
        Country of the endpoint


        :param country: The country of this ProblemEndpointSummary.
        :type: str
        """
        self._country = country

    @property
    def latitude(self):
        """
        Gets the latitude of this ProblemEndpointSummary.
        Latitude of the endpoint


        :return: The latitude of this ProblemEndpointSummary.
        :rtype: float
        """
        return self._latitude

    @latitude.setter
    def latitude(self, latitude):
        """
        Sets the latitude of this ProblemEndpointSummary.
        Latitude of the endpoint


        :param latitude: The latitude of this ProblemEndpointSummary.
        :type: float
        """
        self._latitude = latitude

    @property
    def longitude(self):
        """
        Gets the longitude of this ProblemEndpointSummary.
        Longitude of the endpoint


        :return: The longitude of this ProblemEndpointSummary.
        :rtype: float
        """
        return self._longitude

    @longitude.setter
    def longitude(self, longitude):
        """
        Sets the longitude of this ProblemEndpointSummary.
        Longitude of the endpoint


        :param longitude: The longitude of this ProblemEndpointSummary.
        :type: float
        """
        self._longitude = longitude

    @property
    def asn_number(self):
        """
        Gets the asn_number of this ProblemEndpointSummary.
        ASN number of the endpoint


        :return: The asn_number of this ProblemEndpointSummary.
        :rtype: str
        """
        return self._asn_number

    @asn_number.setter
    def asn_number(self, asn_number):
        """
        Sets the asn_number of this ProblemEndpointSummary.
        ASN number of the endpoint


        :param asn_number: The asn_number of this ProblemEndpointSummary.
        :type: str
        """
        self._asn_number = asn_number

    @property
    def regions(self):
        """
        Gets the regions of this ProblemEndpointSummary.
        Regions where activities were performed from this IP


        :return: The regions of this ProblemEndpointSummary.
        :rtype: list[str]
        """
        return self._regions

    @regions.setter
    def regions(self, regions):
        """
        Sets the regions of this ProblemEndpointSummary.
        Regions where activities were performed from this IP


        :param regions: The regions of this ProblemEndpointSummary.
        :type: list[str]
        """
        self._regions = regions

    @property
    def services(self):
        """
        Gets the services of this ProblemEndpointSummary.
        Services where activities were performed from this IP


        :return: The services of this ProblemEndpointSummary.
        :rtype: list[str]
        """
        return self._services

    @services.setter
    def services(self, services):
        """
        Sets the services of this ProblemEndpointSummary.
        Services where activities were performed from this IP


        :param services: The services of this ProblemEndpointSummary.
        :type: list[str]
        """
        self._services = services

    @property
    def time_last_detected(self):
        """
        **[Required]** Gets the time_last_detected of this ProblemEndpointSummary.
        Time when activities were last detected


        :return: The time_last_detected of this ProblemEndpointSummary.
        :rtype: datetime
        """
        return self._time_last_detected

    @time_last_detected.setter
    def time_last_detected(self, time_last_detected):
        """
        Sets the time_last_detected of this ProblemEndpointSummary.
        Time when activities were last detected


        :param time_last_detected: The time_last_detected of this ProblemEndpointSummary.
        :type: datetime
        """
        self._time_last_detected = time_last_detected

    def __repr__(self):
        return formatted_flat_dict(self)

    def __eq__(self, other):
        if other is None:
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not self == other
