# coding: utf-8
# Copyright (c) 2016, 2023, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

import oci  # noqa: F401
from oci.util import WAIT_RESOURCE_NOT_FOUND  # noqa: F401


class QueueAdminClientCompositeOperations(object):
    """
    This class provides a wrapper around :py:class:`~oci.queue.QueueAdminClient` and offers convenience methods
    for operations that would otherwise need to be chained together. For example, instead of performing an action
    on a resource (e.g. launching an instance, creating a load balancer) and then using a waiter to wait for the resource
    to enter a given state, you can call a single method in this class to accomplish the same functionality
    """

    def __init__(self, client, **kwargs):
        """
        Creates a new QueueAdminClientCompositeOperations object

        :param QueueAdminClient client:
            The service client which will be wrapped by this object
        """
        self.client = client

    def change_queue_compartment_and_wait_for_state(self, queue_id, change_queue_compartment_details, wait_for_states=[], operation_kwargs={}, waiter_kwargs={}):
        """
        Calls :py:func:`~oci.queue.QueueAdminClient.change_queue_compartment` and waits for the :py:class:`~oci.queue.models.WorkRequest`
        to enter the given state(s).

        :param str queue_id: (required)
            unique Queue identifier

        :param oci.queue.models.ChangeQueueCompartmentDetails change_queue_compartment_details: (required)
            The information to be updated.

        :param list[str] wait_for_states:
            An array of states to wait on. These should be valid values for :py:attr:`~oci.queue.models.WorkRequest.status`

        :param dict operation_kwargs:
            A dictionary of keyword arguments to pass to :py:func:`~oci.queue.QueueAdminClient.change_queue_compartment`

        :param dict waiter_kwargs:
            A dictionary of keyword arguments to pass to the :py:func:`oci.wait_until` function. For example, you could pass ``max_interval_seconds`` or ``max_interval_seconds``
            as dictionary keys to modify how long the waiter function will wait between retries and the maximum amount of time it will wait
        """
        operation_result = self.client.change_queue_compartment(queue_id, change_queue_compartment_details, **operation_kwargs)
        if not wait_for_states:
            return operation_result

        lowered_wait_for_states = [w.lower() for w in wait_for_states]
        wait_for_resource_id = operation_result.headers['opc-work-request-id']

        try:
            waiter_result = oci.wait_until(
                self.client,
                self.client.get_work_request(wait_for_resource_id),
                evaluate_response=lambda r: getattr(r.data, 'status') and getattr(r.data, 'status').lower() in lowered_wait_for_states,
                **waiter_kwargs
            )
            result_to_return = waiter_result

            return result_to_return
        except Exception as e:
            raise oci.exceptions.CompositeOperationError(partial_results=[operation_result], cause=e)

    def create_queue_and_wait_for_state(self, create_queue_details, wait_for_states=[], operation_kwargs={}, waiter_kwargs={}):
        """
        Calls :py:func:`~oci.queue.QueueAdminClient.create_queue` and waits for the :py:class:`~oci.queue.models.WorkRequest`
        to enter the given state(s).

        :param oci.queue.models.CreateQueueDetails create_queue_details: (required)
            Details for the new Queue.

        :param list[str] wait_for_states:
            An array of states to wait on. These should be valid values for :py:attr:`~oci.queue.models.WorkRequest.status`

        :param dict operation_kwargs:
            A dictionary of keyword arguments to pass to :py:func:`~oci.queue.QueueAdminClient.create_queue`

        :param dict waiter_kwargs:
            A dictionary of keyword arguments to pass to the :py:func:`oci.wait_until` function. For example, you could pass ``max_interval_seconds`` or ``max_interval_seconds``
            as dictionary keys to modify how long the waiter function will wait between retries and the maximum amount of time it will wait
        """
        operation_result = self.client.create_queue(create_queue_details, **operation_kwargs)
        if not wait_for_states:
            return operation_result

        lowered_wait_for_states = [w.lower() for w in wait_for_states]
        wait_for_resource_id = operation_result.headers['opc-work-request-id']

        try:
            waiter_result = oci.wait_until(
                self.client,
                self.client.get_work_request(wait_for_resource_id),
                evaluate_response=lambda r: getattr(r.data, 'status') and getattr(r.data, 'status').lower() in lowered_wait_for_states,
                **waiter_kwargs
            )
            result_to_return = waiter_result

            return result_to_return
        except Exception as e:
            raise oci.exceptions.CompositeOperationError(partial_results=[operation_result], cause=e)

    def delete_queue_and_wait_for_state(self, queue_id, wait_for_states=[], operation_kwargs={}, waiter_kwargs={}):
        """
        Calls :py:func:`~oci.queue.QueueAdminClient.delete_queue` and waits for the :py:class:`~oci.queue.models.WorkRequest`
        to enter the given state(s).

        :param str queue_id: (required)
            unique Queue identifier

        :param list[str] wait_for_states:
            An array of states to wait on. These should be valid values for :py:attr:`~oci.queue.models.WorkRequest.status`

        :param dict operation_kwargs:
            A dictionary of keyword arguments to pass to :py:func:`~oci.queue.QueueAdminClient.delete_queue`

        :param dict waiter_kwargs:
            A dictionary of keyword arguments to pass to the :py:func:`oci.wait_until` function. For example, you could pass ``max_interval_seconds`` or ``max_interval_seconds``
            as dictionary keys to modify how long the waiter function will wait between retries and the maximum amount of time it will wait
        """
        operation_result = None
        try:
            operation_result = self.client.delete_queue(queue_id, **operation_kwargs)
        except oci.exceptions.ServiceError as e:
            if e.status == 404:
                return WAIT_RESOURCE_NOT_FOUND
            else:
                raise e

        if not wait_for_states:
            return operation_result

        lowered_wait_for_states = [w.lower() for w in wait_for_states]
        wait_for_resource_id = operation_result.headers['opc-work-request-id']

        try:
            waiter_result = oci.wait_until(
                self.client,
                self.client.get_work_request(wait_for_resource_id),
                evaluate_response=lambda r: getattr(r.data, 'status') and getattr(r.data, 'status').lower() in lowered_wait_for_states,
                **waiter_kwargs
            )
            result_to_return = waiter_result

            return result_to_return
        except Exception as e:
            raise oci.exceptions.CompositeOperationError(partial_results=[operation_result], cause=e)

    def purge_queue_and_wait_for_state(self, queue_id, purge_queue_details, wait_for_states=[], operation_kwargs={}, waiter_kwargs={}):
        """
        Calls :py:func:`~oci.queue.QueueAdminClient.purge_queue` and waits for the :py:class:`~oci.queue.models.WorkRequest`
        to enter the given state(s).

        :param str queue_id: (required)
            unique Queue identifier

        :param oci.queue.models.PurgeQueueDetails purge_queue_details: (required)
            The information to be updated.

        :param list[str] wait_for_states:
            An array of states to wait on. These should be valid values for :py:attr:`~oci.queue.models.WorkRequest.status`

        :param dict operation_kwargs:
            A dictionary of keyword arguments to pass to :py:func:`~oci.queue.QueueAdminClient.purge_queue`

        :param dict waiter_kwargs:
            A dictionary of keyword arguments to pass to the :py:func:`oci.wait_until` function. For example, you could pass ``max_interval_seconds`` or ``max_interval_seconds``
            as dictionary keys to modify how long the waiter function will wait between retries and the maximum amount of time it will wait
        """
        operation_result = self.client.purge_queue(queue_id, purge_queue_details, **operation_kwargs)
        if not wait_for_states:
            return operation_result

        lowered_wait_for_states = [w.lower() for w in wait_for_states]
        wait_for_resource_id = operation_result.headers['opc-work-request-id']

        try:
            waiter_result = oci.wait_until(
                self.client,
                self.client.get_work_request(wait_for_resource_id),
                evaluate_response=lambda r: getattr(r.data, 'status') and getattr(r.data, 'status').lower() in lowered_wait_for_states,
                **waiter_kwargs
            )
            result_to_return = waiter_result

            return result_to_return
        except Exception as e:
            raise oci.exceptions.CompositeOperationError(partial_results=[operation_result], cause=e)

    def update_queue_and_wait_for_state(self, queue_id, update_queue_details, wait_for_states=[], operation_kwargs={}, waiter_kwargs={}):
        """
        Calls :py:func:`~oci.queue.QueueAdminClient.update_queue` and waits for the :py:class:`~oci.queue.models.WorkRequest`
        to enter the given state(s).

        :param str queue_id: (required)
            unique Queue identifier

        :param oci.queue.models.UpdateQueueDetails update_queue_details: (required)
            The information to be updated.

        :param list[str] wait_for_states:
            An array of states to wait on. These should be valid values for :py:attr:`~oci.queue.models.WorkRequest.status`

        :param dict operation_kwargs:
            A dictionary of keyword arguments to pass to :py:func:`~oci.queue.QueueAdminClient.update_queue`

        :param dict waiter_kwargs:
            A dictionary of keyword arguments to pass to the :py:func:`oci.wait_until` function. For example, you could pass ``max_interval_seconds`` or ``max_interval_seconds``
            as dictionary keys to modify how long the waiter function will wait between retries and the maximum amount of time it will wait
        """
        operation_result = self.client.update_queue(queue_id, update_queue_details, **operation_kwargs)
        if not wait_for_states:
            return operation_result

        lowered_wait_for_states = [w.lower() for w in wait_for_states]
        wait_for_resource_id = operation_result.headers['opc-work-request-id']

        try:
            waiter_result = oci.wait_until(
                self.client,
                self.client.get_work_request(wait_for_resource_id),
                evaluate_response=lambda r: getattr(r.data, 'status') and getattr(r.data, 'status').lower() in lowered_wait_for_states,
                **waiter_kwargs
            )
            result_to_return = waiter_result

            return result_to_return
        except Exception as e:
            raise oci.exceptions.CompositeOperationError(partial_results=[operation_result], cause=e)
