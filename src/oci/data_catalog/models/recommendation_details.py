# coding: utf-8
# Copyright (c) 2016, 2023, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.


from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class RecommendationDetails(object):
    """
    Details of a recommendation.
    """

    #: A constant which can be used with the recommendation_type property of a RecommendationDetails.
    #: This constant has a value of "LINK_GLOSSARY_TERM"
    RECOMMENDATION_TYPE_LINK_GLOSSARY_TERM = "LINK_GLOSSARY_TERM"

    #: A constant which can be used with the recommendation_status property of a RecommendationDetails.
    #: This constant has a value of "ACCEPTED"
    RECOMMENDATION_STATUS_ACCEPTED = "ACCEPTED"

    #: A constant which can be used with the recommendation_status property of a RecommendationDetails.
    #: This constant has a value of "REJECTED"
    RECOMMENDATION_STATUS_REJECTED = "REJECTED"

    #: A constant which can be used with the recommendation_status property of a RecommendationDetails.
    #: This constant has a value of "INFERRED"
    RECOMMENDATION_STATUS_INFERRED = "INFERRED"

    #: A constant which can be used with the source_object_type property of a RecommendationDetails.
    #: This constant has a value of "DATA_ENTITY"
    SOURCE_OBJECT_TYPE_DATA_ENTITY = "DATA_ENTITY"

    #: A constant which can be used with the source_object_type property of a RecommendationDetails.
    #: This constant has a value of "ATTRIBUTE"
    SOURCE_OBJECT_TYPE_ATTRIBUTE = "ATTRIBUTE"

    #: A constant which can be used with the source_object_type property of a RecommendationDetails.
    #: This constant has a value of "TERM"
    SOURCE_OBJECT_TYPE_TERM = "TERM"

    #: A constant which can be used with the source_object_type property of a RecommendationDetails.
    #: This constant has a value of "CATEGORY"
    SOURCE_OBJECT_TYPE_CATEGORY = "CATEGORY"

    #: A constant which can be used with the target_object_type property of a RecommendationDetails.
    #: This constant has a value of "DATA_ENTITY"
    TARGET_OBJECT_TYPE_DATA_ENTITY = "DATA_ENTITY"

    #: A constant which can be used with the target_object_type property of a RecommendationDetails.
    #: This constant has a value of "ATTRIBUTE"
    TARGET_OBJECT_TYPE_ATTRIBUTE = "ATTRIBUTE"

    #: A constant which can be used with the target_object_type property of a RecommendationDetails.
    #: This constant has a value of "TERM"
    TARGET_OBJECT_TYPE_TERM = "TERM"

    #: A constant which can be used with the target_object_type property of a RecommendationDetails.
    #: This constant has a value of "CATEGORY"
    TARGET_OBJECT_TYPE_CATEGORY = "CATEGORY"

    def __init__(self, **kwargs):
        """
        Initializes a new RecommendationDetails object with values from keyword arguments.
        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param recommendation_key:
            The value to assign to the recommendation_key property of this RecommendationDetails.
        :type recommendation_key: str

        :param recommendation_type:
            The value to assign to the recommendation_type property of this RecommendationDetails.
            Allowed values for this property are: "LINK_GLOSSARY_TERM", 'UNKNOWN_ENUM_VALUE'.
            Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.
        :type recommendation_type: str

        :param recommendation_status:
            The value to assign to the recommendation_status property of this RecommendationDetails.
            Allowed values for this property are: "ACCEPTED", "REJECTED", "INFERRED", 'UNKNOWN_ENUM_VALUE'.
            Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.
        :type recommendation_status: str

        :param confidence_score:
            The value to assign to the confidence_score property of this RecommendationDetails.
        :type confidence_score: float

        :param source_object_key:
            The value to assign to the source_object_key property of this RecommendationDetails.
        :type source_object_key: str

        :param source_object_name:
            The value to assign to the source_object_name property of this RecommendationDetails.
        :type source_object_name: str

        :param source_object_type:
            The value to assign to the source_object_type property of this RecommendationDetails.
            Allowed values for this property are: "DATA_ENTITY", "ATTRIBUTE", "TERM", "CATEGORY", 'UNKNOWN_ENUM_VALUE'.
            Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.
        :type source_object_type: str

        :param target_object_key:
            The value to assign to the target_object_key property of this RecommendationDetails.
        :type target_object_key: str

        :param target_object_name:
            The value to assign to the target_object_name property of this RecommendationDetails.
        :type target_object_name: str

        :param target_object_type:
            The value to assign to the target_object_type property of this RecommendationDetails.
            Allowed values for this property are: "DATA_ENTITY", "ATTRIBUTE", "TERM", "CATEGORY", 'UNKNOWN_ENUM_VALUE'.
            Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.
        :type target_object_type: str

        :param properties:
            The value to assign to the properties property of this RecommendationDetails.
        :type properties: dict(str, dict(str, str))

        """
        self.swagger_types = {
            'recommendation_key': 'str',
            'recommendation_type': 'str',
            'recommendation_status': 'str',
            'confidence_score': 'float',
            'source_object_key': 'str',
            'source_object_name': 'str',
            'source_object_type': 'str',
            'target_object_key': 'str',
            'target_object_name': 'str',
            'target_object_type': 'str',
            'properties': 'dict(str, dict(str, str))'
        }

        self.attribute_map = {
            'recommendation_key': 'recommendationKey',
            'recommendation_type': 'recommendationType',
            'recommendation_status': 'recommendationStatus',
            'confidence_score': 'confidenceScore',
            'source_object_key': 'sourceObjectKey',
            'source_object_name': 'sourceObjectName',
            'source_object_type': 'sourceObjectType',
            'target_object_key': 'targetObjectKey',
            'target_object_name': 'targetObjectName',
            'target_object_type': 'targetObjectType',
            'properties': 'properties'
        }

        self._recommendation_key = None
        self._recommendation_type = None
        self._recommendation_status = None
        self._confidence_score = None
        self._source_object_key = None
        self._source_object_name = None
        self._source_object_type = None
        self._target_object_key = None
        self._target_object_name = None
        self._target_object_type = None
        self._properties = None

    @property
    def recommendation_key(self):
        """
        **[Required]** Gets the recommendation_key of this RecommendationDetails.
        Unique identifier of the recommendation.


        :return: The recommendation_key of this RecommendationDetails.
        :rtype: str
        """
        return self._recommendation_key

    @recommendation_key.setter
    def recommendation_key(self, recommendation_key):
        """
        Sets the recommendation_key of this RecommendationDetails.
        Unique identifier of the recommendation.


        :param recommendation_key: The recommendation_key of this RecommendationDetails.
        :type: str
        """
        self._recommendation_key = recommendation_key

    @property
    def recommendation_type(self):
        """
        **[Required]** Gets the recommendation_type of this RecommendationDetails.
        Type of recommendation.

        Allowed values for this property are: "LINK_GLOSSARY_TERM", 'UNKNOWN_ENUM_VALUE'.
        Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.


        :return: The recommendation_type of this RecommendationDetails.
        :rtype: str
        """
        return self._recommendation_type

    @recommendation_type.setter
    def recommendation_type(self, recommendation_type):
        """
        Sets the recommendation_type of this RecommendationDetails.
        Type of recommendation.


        :param recommendation_type: The recommendation_type of this RecommendationDetails.
        :type: str
        """
        allowed_values = ["LINK_GLOSSARY_TERM"]
        if not value_allowed_none_or_none_sentinel(recommendation_type, allowed_values):
            recommendation_type = 'UNKNOWN_ENUM_VALUE'
        self._recommendation_type = recommendation_type

    @property
    def recommendation_status(self):
        """
        **[Required]** Gets the recommendation_status of this RecommendationDetails.
        Status of a recommendation.

        Allowed values for this property are: "ACCEPTED", "REJECTED", "INFERRED", 'UNKNOWN_ENUM_VALUE'.
        Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.


        :return: The recommendation_status of this RecommendationDetails.
        :rtype: str
        """
        return self._recommendation_status

    @recommendation_status.setter
    def recommendation_status(self, recommendation_status):
        """
        Sets the recommendation_status of this RecommendationDetails.
        Status of a recommendation.


        :param recommendation_status: The recommendation_status of this RecommendationDetails.
        :type: str
        """
        allowed_values = ["ACCEPTED", "REJECTED", "INFERRED"]
        if not value_allowed_none_or_none_sentinel(recommendation_status, allowed_values):
            recommendation_status = 'UNKNOWN_ENUM_VALUE'
        self._recommendation_status = recommendation_status

    @property
    def confidence_score(self):
        """
        Gets the confidence_score of this RecommendationDetails.
        Level of confidence, on a scale between 0 and 1, that the recommendation is applicable.


        :return: The confidence_score of this RecommendationDetails.
        :rtype: float
        """
        return self._confidence_score

    @confidence_score.setter
    def confidence_score(self, confidence_score):
        """
        Sets the confidence_score of this RecommendationDetails.
        Level of confidence, on a scale between 0 and 1, that the recommendation is applicable.


        :param confidence_score: The confidence_score of this RecommendationDetails.
        :type: float
        """
        self._confidence_score = confidence_score

    @property
    def source_object_key(self):
        """
        Gets the source_object_key of this RecommendationDetails.
        Unique identifier of the source object; the one for which a recommendation is made.


        :return: The source_object_key of this RecommendationDetails.
        :rtype: str
        """
        return self._source_object_key

    @source_object_key.setter
    def source_object_key(self, source_object_key):
        """
        Sets the source_object_key of this RecommendationDetails.
        Unique identifier of the source object; the one for which a recommendation is made.


        :param source_object_key: The source_object_key of this RecommendationDetails.
        :type: str
        """
        self._source_object_key = source_object_key

    @property
    def source_object_name(self):
        """
        Gets the source_object_name of this RecommendationDetails.
        Name of the source object; the one for which a recommendation is made.


        :return: The source_object_name of this RecommendationDetails.
        :rtype: str
        """
        return self._source_object_name

    @source_object_name.setter
    def source_object_name(self, source_object_name):
        """
        Sets the source_object_name of this RecommendationDetails.
        Name of the source object; the one for which a recommendation is made.


        :param source_object_name: The source_object_name of this RecommendationDetails.
        :type: str
        """
        self._source_object_name = source_object_name

    @property
    def source_object_type(self):
        """
        Gets the source_object_type of this RecommendationDetails.
        Type of the source object; the one for which a recommendation is made.

        Allowed values for this property are: "DATA_ENTITY", "ATTRIBUTE", "TERM", "CATEGORY", 'UNKNOWN_ENUM_VALUE'.
        Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.


        :return: The source_object_type of this RecommendationDetails.
        :rtype: str
        """
        return self._source_object_type

    @source_object_type.setter
    def source_object_type(self, source_object_type):
        """
        Sets the source_object_type of this RecommendationDetails.
        Type of the source object; the one for which a recommendation is made.


        :param source_object_type: The source_object_type of this RecommendationDetails.
        :type: str
        """
        allowed_values = ["DATA_ENTITY", "ATTRIBUTE", "TERM", "CATEGORY"]
        if not value_allowed_none_or_none_sentinel(source_object_type, allowed_values):
            source_object_type = 'UNKNOWN_ENUM_VALUE'
        self._source_object_type = source_object_type

    @property
    def target_object_key(self):
        """
        Gets the target_object_key of this RecommendationDetails.
        Unique identifier of the target object; the one which has been recommended.


        :return: The target_object_key of this RecommendationDetails.
        :rtype: str
        """
        return self._target_object_key

    @target_object_key.setter
    def target_object_key(self, target_object_key):
        """
        Sets the target_object_key of this RecommendationDetails.
        Unique identifier of the target object; the one which has been recommended.


        :param target_object_key: The target_object_key of this RecommendationDetails.
        :type: str
        """
        self._target_object_key = target_object_key

    @property
    def target_object_name(self):
        """
        Gets the target_object_name of this RecommendationDetails.
        Name of the target object; the one which has been recommended.


        :return: The target_object_name of this RecommendationDetails.
        :rtype: str
        """
        return self._target_object_name

    @target_object_name.setter
    def target_object_name(self, target_object_name):
        """
        Sets the target_object_name of this RecommendationDetails.
        Name of the target object; the one which has been recommended.


        :param target_object_name: The target_object_name of this RecommendationDetails.
        :type: str
        """
        self._target_object_name = target_object_name

    @property
    def target_object_type(self):
        """
        Gets the target_object_type of this RecommendationDetails.
        Type of the target object; the one which has been recommended.

        Allowed values for this property are: "DATA_ENTITY", "ATTRIBUTE", "TERM", "CATEGORY", 'UNKNOWN_ENUM_VALUE'.
        Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.


        :return: The target_object_type of this RecommendationDetails.
        :rtype: str
        """
        return self._target_object_type

    @target_object_type.setter
    def target_object_type(self, target_object_type):
        """
        Sets the target_object_type of this RecommendationDetails.
        Type of the target object; the one which has been recommended.


        :param target_object_type: The target_object_type of this RecommendationDetails.
        :type: str
        """
        allowed_values = ["DATA_ENTITY", "ATTRIBUTE", "TERM", "CATEGORY"]
        if not value_allowed_none_or_none_sentinel(target_object_type, allowed_values):
            target_object_type = 'UNKNOWN_ENUM_VALUE'
        self._target_object_type = target_object_type

    @property
    def properties(self):
        """
        Gets the properties of this RecommendationDetails.
        A map of maps that contains additional properties which are specific to the associated objects.
        Each associated object defines it's set of required and optional properties.
        Example: `{
                    \"DataEntity\": {
                      \"parentId\": \"entityId\"
                    },
                    \"Term\": {
                      \"parentId\": \"glossaryId\"
                    }
                  }`


        :return: The properties of this RecommendationDetails.
        :rtype: dict(str, dict(str, str))
        """
        return self._properties

    @properties.setter
    def properties(self, properties):
        """
        Sets the properties of this RecommendationDetails.
        A map of maps that contains additional properties which are specific to the associated objects.
        Each associated object defines it's set of required and optional properties.
        Example: `{
                    \"DataEntity\": {
                      \"parentId\": \"entityId\"
                    },
                    \"Term\": {
                      \"parentId\": \"glossaryId\"
                    }
                  }`


        :param properties: The properties of this RecommendationDetails.
        :type: dict(str, dict(str, str))
        """
        self._properties = properties

    def __repr__(self):
        return formatted_flat_dict(self)

    def __eq__(self, other):
        if other is None:
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not self == other
