# coding: utf-8
# Copyright (c) 2016, 2023, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

from .evaluation_result_summary import EvaluationResultSummary
from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class NamedEntityRecognitionEvaluationResult(EvaluationResultSummary):
    """
    Possible NER model error analysis
    """

    def __init__(self, **kwargs):
        """
        Initializes a new NamedEntityRecognitionEvaluationResult object with values from keyword arguments. The default value of the :py:attr:`~oci.ai_language.models.NamedEntityRecognitionEvaluationResult.model_type` attribute
        of this class is ``NAMED_ENTITY_RECOGNITION`` and it should not be changed.
        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param model_type:
            The value to assign to the model_type property of this NamedEntityRecognitionEvaluationResult.
        :type model_type: str

        :param freeform_tags:
            The value to assign to the freeform_tags property of this NamedEntityRecognitionEvaluationResult.
        :type freeform_tags: dict(str, str)

        :param defined_tags:
            The value to assign to the defined_tags property of this NamedEntityRecognitionEvaluationResult.
        :type defined_tags: dict(str, dict(str, object))

        :param record:
            The value to assign to the record property of this NamedEntityRecognitionEvaluationResult.
        :type record: str

        :param true_entities:
            The value to assign to the true_entities property of this NamedEntityRecognitionEvaluationResult.
        :type true_entities: list[oci.ai_language.models.EntityLabelErrorAnalysis]

        :param predicted_entities:
            The value to assign to the predicted_entities property of this NamedEntityRecognitionEvaluationResult.
        :type predicted_entities: list[oci.ai_language.models.EntityLabelErrorAnalysis]

        """
        self.swagger_types = {
            'model_type': 'str',
            'freeform_tags': 'dict(str, str)',
            'defined_tags': 'dict(str, dict(str, object))',
            'record': 'str',
            'true_entities': 'list[EntityLabelErrorAnalysis]',
            'predicted_entities': 'list[EntityLabelErrorAnalysis]'
        }

        self.attribute_map = {
            'model_type': 'modelType',
            'freeform_tags': 'freeformTags',
            'defined_tags': 'definedTags',
            'record': 'record',
            'true_entities': 'trueEntities',
            'predicted_entities': 'predictedEntities'
        }

        self._model_type = None
        self._freeform_tags = None
        self._defined_tags = None
        self._record = None
        self._true_entities = None
        self._predicted_entities = None
        self._model_type = 'NAMED_ENTITY_RECOGNITION'

    @property
    def record(self):
        """
        **[Required]** Gets the record of this NamedEntityRecognitionEvaluationResult.
        For CSV format location is rowId(1 is header) and for JSONL location is jsonL line sequence(1 is metadata)


        :return: The record of this NamedEntityRecognitionEvaluationResult.
        :rtype: str
        """
        return self._record

    @record.setter
    def record(self, record):
        """
        Sets the record of this NamedEntityRecognitionEvaluationResult.
        For CSV format location is rowId(1 is header) and for JSONL location is jsonL line sequence(1 is metadata)


        :param record: The record of this NamedEntityRecognitionEvaluationResult.
        :type: str
        """
        self._record = record

    @property
    def true_entities(self):
        """
        **[Required]** Gets the true_entities of this NamedEntityRecognitionEvaluationResult.
        List of true(actual) entities in test data for NER model


        :return: The true_entities of this NamedEntityRecognitionEvaluationResult.
        :rtype: list[oci.ai_language.models.EntityLabelErrorAnalysis]
        """
        return self._true_entities

    @true_entities.setter
    def true_entities(self, true_entities):
        """
        Sets the true_entities of this NamedEntityRecognitionEvaluationResult.
        List of true(actual) entities in test data for NER model


        :param true_entities: The true_entities of this NamedEntityRecognitionEvaluationResult.
        :type: list[oci.ai_language.models.EntityLabelErrorAnalysis]
        """
        self._true_entities = true_entities

    @property
    def predicted_entities(self):
        """
        **[Required]** Gets the predicted_entities of this NamedEntityRecognitionEvaluationResult.
        List of true(actual) entities in test data for NER model


        :return: The predicted_entities of this NamedEntityRecognitionEvaluationResult.
        :rtype: list[oci.ai_language.models.EntityLabelErrorAnalysis]
        """
        return self._predicted_entities

    @predicted_entities.setter
    def predicted_entities(self, predicted_entities):
        """
        Sets the predicted_entities of this NamedEntityRecognitionEvaluationResult.
        List of true(actual) entities in test data for NER model


        :param predicted_entities: The predicted_entities of this NamedEntityRecognitionEvaluationResult.
        :type: list[oci.ai_language.models.EntityLabelErrorAnalysis]
        """
        self._predicted_entities = predicted_entities

    def __repr__(self):
        return formatted_flat_dict(self)

    def __eq__(self, other):
        if other is None:
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not self == other
