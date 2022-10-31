#!/usr/bin/env python3
##########################################################################
# Copyright (c) 2016, 2022, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.
#
# DISCLAIMER This is not an official Oracle application,  It does not supported by Oracle Support,
# It should NOT be used for utilization calculation purposes, and rather OCI's official
#
# usage2adw.py
#
# @author: Adi Zohar
#
# Supports Python 3 and above
#
# coding: utf-8
##########################################################################
# OCI Usage to ADWC:
#
# Required OCI user part of UsageDownloadGroup with below permission:
#   define tenancy usage-report as ocid1.tenancy.oc1..aaaaaaaaned4fkpkisbwjlr56u7cj63lf3wffbilvqknstgtvzub7vhqkggq
#   endorse group UsageDownloadGroup to read objects in tenancy usage-report
#   Allow group UsageDownloadGroup to inspect compartments in tenancy
#   Allow group UsageDownloadGroup to inspect tenancies in tenancy
#
# config file should contain:
#     [TENANT_NAME]
#     user        = user_ocid
#     fingerprint = fingerprint of the api ssh key
#     key_file    = the path to the private key
#     tenancy     = tenancy ocid
#     region      = region
#
##########################################################################
# Database user:
#     create user usage identified by PaSsw0rd2#_#;
#     grant connect, resource, dwrole, unlimited tablespace to usage;
##########################################################################
#
# Modules Included:
# - oci.object_storage.ObjectStorageClient
# - oci.identity.IdentityClient
#
# APIs Used:
# - IdentityClient.list_compartments          - Policy COMPARTMENT_INSPECT
# - IdentityClient.get_tenancy                - Policy TENANCY_INSPECT
# - IdentityClient.list_region_subscriptions  - Policy TENANCY_INSPECT
# - ObjectStorageClient.list_objects          - Policy OBJECT_INSPECT
# - ObjectStorageClient.get_object            - Policy OBJECT_READ
#
# Meter API for Public Rate:
# - https://itra.oraclecloud.com/itas/.anon/myservices/api/v1/products?partNumber=XX
#
##########################################################################
# Tables used:
# - OCI_USAGE - Raw data of the usage reports
# - OCI_USAGE_STATS - Summary Stats of the Usage Report for quick query if only filtered by tenant and date
# - OCI_USAGE_TAG_KEYS - Tag keys of the usage reports
# - OCI_COST - Raw data of the cost reports
# - OCI_COST_STATS - Summary Stats of the Cost Report for quick query if only filtered by tenant and date
# - OCI_COST_TAG_KEYS - Tag keys of the cost reports
# - OCI_COST_REFERENCE - Reference table of the cost filter keys - SERVICE, REGION, COMPARTMENT, PRODUCT, SUBSCRIPTION
# - OCI_PRICE_LIST - Hold the price list and the cost per product
##########################################################################
import sys
import argparse
import datetime
import timedelta
import oci
import gzip
import os
import csv
import cx_Oracle
import requests
import time
from operator import itemgetter
import pytz
import json
import re

utc=pytz.UTC

version = "22.08.12"
usage_report_namespace = "bling"
work_report_dir = os.curdir + "/work_report_dir"

# create the work dir if not exist
if not os.path.exists(work_report_dir):
    os.mkdir(work_report_dir)


##########################################################################
# Print header centered
##########################################################################
def print_header(name, category):
    options = {0: 90, 1: 60, 2: 30}
    chars = int(options[category])
    print("")
    print('#' * chars)
    print("#" + name.center(chars - 2, " ") + "#")
    print('#' * chars)

##########################################################################
# Get Column from Array
##########################################################################
def get_column_value_from_array(column, array):
    if column in array:
        return array[column]
    else:
        return ""


##########################################################################
# Create signer for Authentication
# Input - config_profile and is_instance_principals and is_delegation_token
# Output - config and signer objects
##########################################################################
def create_signer(config_profile, is_instance_principals, is_delegation_token):

    # if instance principals authentications
    if is_instance_principals:
        try:
            signer = oci.auth.signers.InstancePrincipalsSecurityTokenSigner()
            config = {'region': signer.region, 'tenancy': signer.tenancy_id}
            return config, signer

        except Exception:
            print_header("Error obtaining instance principals certificate, aborting")
            raise SystemExit

    # -----------------------------
    # Delegation Token
    # -----------------------------
    elif is_delegation_token:

        try:
            # check if env variables OCI_CONFIG_FILE, OCI_CONFIG_PROFILE exist and use them
            env_config_file = os.environ.get('OCI_CONFIG_FILE')
            env_config_section = os.environ.get('OCI_CONFIG_PROFILE')

            # check if file exist
            if env_config_file is None or env_config_section is None:
                print("*** OCI_CONFIG_FILE and OCI_CONFIG_PROFILE env variables not found, abort. ***")
                print("")
                raise SystemExit

            # check if file exist
            if not os.path.isfile(env_config_file):
                print("*** Config File " + env_config_file + " does not exist, Abort. ***")
                print("")
                raise SystemExit

            config = oci.config.from_file(env_config_file, env_config_section)
            delegation_token_location = config["delegation_token_file"]

            with open(delegation_token_location, 'r') as delegation_token_file:
                delegation_token = delegation_token_file.read().strip()
                # get signer from delegation token
                signer = oci.auth.signers.InstancePrincipalsDelegationTokenSigner(delegation_token=delegation_token)

                return config, signer

        except KeyError:
            print("* Key Error obtaining delegation_token_file")
            raise SystemExit

        except Exception:
            raise

    # -----------------------------
    # config file authentication
    # -----------------------------
    else:
        config = oci.config.from_file(
            oci.config.DEFAULT_LOCATION,
            (config_profile if config_profile else oci.config.DEFAULT_PROFILE)
        )
        signer = oci.signer.Signer(
            tenancy=config["tenancy"],
            user=config["user"],
            fingerprint=config["fingerprint"],
            private_key_file_location=config.get("key_file"),
            pass_phrase=oci.config.get_config_value_or_default(config, "pass_phrase"),
            private_key_content=config.get("key_content")
        )
        return config, signer


##########################################################################
# Load compartments
##########################################################################
def identity_read_compartments(identity, tenancy):

    compartments = []
    print("Loading Compartments...")

    try:
        # read all compartments to variable
        all_compartments = []
        try:
            all_compartments = oci.pagination.list_call_get_all_results(
                identity.list_compartments,
                tenancy.id,
                compartment_id_in_subtree=True
            ).data

        except oci.exceptions.ServiceError:
            raise

        ###################################################
        # Build Compartments - return nested compartment list
        ###################################################
        def build_compartments_nested(identity_client, cid, path):

            try:
                compartment_list = [item for item in all_compartments if str(item.compartment_id) == str(cid)]

                if path != "":
                    path = path + " / "

                for c in compartment_list:
                    if c.lifecycle_state == oci.identity.models.Compartment.LIFECYCLE_STATE_ACTIVE:
                        cvalue = {'id': str(c.id), 'name': str(c.name), 'path': path + str(c.name)}
                        compartments.append(cvalue)
                        build_compartments_nested(identity_client, c.id, cvalue['path'])

            except Exception as error:
                raise Exception("Error in build_compartments_nested: " + str(error.args))

        ###################################################
        # Add root compartment
        ###################################################
        value = {'id': str(tenancy.id), 'name': str(tenancy.name) + " (root)", 'path': "/ " + str(tenancy.name) + " (root)"}
        compartments.append(value)

        # Build the compartments
        build_compartments_nested(identity, str(tenancy.id), "")

        # sort the compartment
        sorted_compartments = sorted(compartments, key=lambda k: k['path'])
        print("    Total " + str(len(sorted_compartments)) + " compartments loaded.")
        return sorted_compartments

    except oci.exceptions.RequestException:
        raise
    except Exception as e:
        raise Exception("Error in identity_read_compartments: " + str(e.args))

##########################################################################
# set parser
##########################################################################
def set_parser_arguments():
    parser = argparse.ArgumentParser()

    parser.add_argument('-c', type=argparse.FileType('r'), dest='config', help="Config File")
    parser.add_argument('-t', default="", dest='profile', help='Config file section to use (tenancy profile)')
    parser.add_argument('-f', default="", dest='fileid', help='File Id to load')
    parser.add_argument('-ts', default="", dest='tagspecial', help='tag special key 1 to load the data to TAG_SPECIAL column')
    parser.add_argument('-ts2', default="", dest='tagspecial2', help='tag special key 2 to load the data to TAG_SPECIAL2 column')
    parser.add_argument('-d', default="", dest='filedate', help='Minimum File Date to load (i.e. yyyy-mm-dd)')
    parser.add_argument('-p', default="", dest='proxy', help='Set Proxy (i.e. www-proxy-server.com:80) ')
    parser.add_argument('-su', action='store_true', default=False, dest='skip_usage', help='Skip Load Usage Files')
    parser.add_argument('-sc', action='store_true', default=False, dest='skip_cost', help='Skip Load Cost Files')
    parser.add_argument('-sr', action='store_true', default=False, dest='skip_rate', help='Skip Public Rate API')
    parser.add_argument('-ip', action='store_true', default=False, dest='instance_principals', help='Use Instance Principals for Authentication')
    parser.add_argument('-dt', action='store_true', default=False, dest='delegation_token', help='Use Delegation Token for Authentication')
    parser.add_argument('-du', default="", dest='duser', help='ADB User')
    parser.add_argument('-dp', default="", dest='dpass', help='ADB Password')
    parser.add_argument('-dn', default="", dest='dname', help='ADB Name')
    parser.add_argument('--version', action='version', version='%(prog)s ' + version)

    result = parser.parse_args()

    #if not (result.duser and result.dpass and result.dname):
    #    parser.print_help()
    #    print_header("You must specify database credentials!!", 0)
    #    return None

    return result

def unique(cost_list):
  
    # initialize a null list
    unique_list = []
    unique_id_list = []
  
    # traverse for all elements
    for x in cost_list:
        # check if exists in unique_list or not
        id = x[10]

        if id not in unique_id_list:
            unique_id_list.append(id)
            unique_list.append(x)

    return unique_list

#########################################################################
# Load Cost File
##########################################################################
def load_cost_file(object_storage, object_file, max_file_id, cmd, tenancy, compartments):
    num_files = 0
    num_rows = 0
    cost_data = []

    try:
        o = object_file

        # keep tag keys per file
        tags_keys = []

        # get file name
        filename = o.name.rsplit('/', 1)[-1]
        file_id = filename[:-7]
        file_time = str(o.time_created)[0:16]

        # if file already loaded, skip (check if < max_file_id
        if str(max_file_id) != "None":
            if file_id <= str(max_file_id):
                return cost_data

        # if file id enabled, check
        if cmd.fileid:
            if file_id != cmd.fileid:
                return cost_data

        # check file date
        if cmd.filedate:
            if file_time <= cmd.filedate:
                return cost_data

        path_filename = work_report_dir + '/' + filename
        print("   Processing file " + o.name + " - " + str(o.size) + " bytes, " + file_time)

        # download file
        object_details = object_storage.get_object(usage_report_namespace, str(tenancy.id), o.name)
        with open(path_filename, 'wb') as f:
            for chunk in object_details.data.raw.stream(1024 * 1024, decode_content=False):
                f.write(chunk)

        # Read file to variable
        with gzip.open(path_filename, 'rt') as file_in:
            csv_reader = csv.DictReader(file_in)

            data = []
            id_list = []

            for row in csv_reader:

                # find compartment path
                compartment_path = ""
                for c in compartments:
                    if c['id'] == row['product/compartmentId']:
                        compartment_path = c['path']

                # Handle Tags up to 4000 chars with # seperator
                tag_special = ""
                tag_special2 = ""
                tags_data = ""
                for (key, value) in row.items():
                    if 'tags' in key and len(value) > 0:

                        # remove # and = from the tags keys and value
                        keyadj = str(key).replace("tags/", "").replace("#", "").replace("=", "")
                        valueadj = str(value).replace("#", "").replace("=", "")

                        # if tagspecial
                        if cmd.tagspecial:
                            if keyadj == cmd.tagspecial:
                                if len(valueadj) < 4000:
                                    tag_special = valueadj
                                    # remove oracle idcs from the e-mail
                                    tag_special = tag_special.replace("oracleidentitycloudservice/", "")

                        # if tagspecial2
                        if cmd.tagspecial2:
                            if keyadj == cmd.tagspecial2:
                                if len(valueadj) < 4000:
                                    tag_special2 = valueadj
                                    # remove oracle idcs from the e-mail
                                    tag_special2 = tag_special2.replace("oracleidentitycloudservice/", "")

                        # check if length < 4000 to avoid overflow database column
                        if len(tags_data) + len(keyadj) + len(valueadj) + 2 < 4000:
                            tags_data += ("#" if tags_data == "" else "") + keyadj + "=" + valueadj + "#"

                        # add tag key to tag_keys array
                            if keyadj not in tags_keys:
                                tags_keys.append(keyadj)

                # Assign each column to variable to avoid error if column missing from the file
                lineItem_tenantId = get_column_value_from_array('lineItem/tenantId', row)
                lineItem_intervalUsageStart = get_column_value_from_array('lineItem/intervalUsageStart', row)
                lineItem_intervalUsageEnd = get_column_value_from_array('lineItem/intervalUsageEnd', row)
                product_service = get_column_value_from_array('product/service', row)
                product_compartmentId = get_column_value_from_array('product/compartmentId', row)
                product_compartmentName = get_column_value_from_array('product/compartmentName', row)
                product_region = get_column_value_from_array('product/region', row)
                product_availabilityDomain = get_column_value_from_array('product/availabilityDomain', row)
                product_resourceId = get_column_value_from_array('product/resourceId', row)
                usage_billedQuantity = get_column_value_from_array('usage/billedQuantity', row)
                usage_billedQuantityOverage = get_column_value_from_array('usage/billedQuantityOverage', row)
                cost_subscriptionId = get_column_value_from_array('cost/subscriptionId', row)
                cost_productSku = get_column_value_from_array('cost/productSku', row)
                product_Description = get_column_value_from_array('product/Description', row)
                cost_unitPrice = get_column_value_from_array('cost/unitPrice', row)
                cost_unitPriceOverage = get_column_value_from_array('cost/unitPriceOverage', row)
                cost_myCost = get_column_value_from_array('cost/myCost', row)
                cost_myCostOverage = get_column_value_from_array('cost/myCostOverage', row)
                cost_currencyCode = get_column_value_from_array('cost/currencyCode', row)
                cost_overageFlag = get_column_value_from_array('cost/overageFlag', row)
                lineItem_isCorrection = get_column_value_from_array('lineItem/isCorrection', row)

                # OCI changed the column billingUnitReadable to skuUnitDescription
                if 'cost/skuUnitDescription' in row:
                    cost_billingUnitReadable = get_column_value_from_array('cost/skuUnitDescription', row)
                else:
                    cost_billingUnitReadable = get_column_value_from_array('cost/billingUnitReadable', row)

                # Fix OCI Data for missing product description for old SKUs
                if cost_productSku == "B88166" and product_Description == "":
                    product_Description = "Oracle Identity Cloud - Standard"
                    cost_billingUnitReadable = "Active User per Hour"

                elif cost_productSku == "B88167" and product_Description == "":
                    product_Description = "Oracle Identity Cloud - Basic"
                    cost_billingUnitReadable = "Active User per Hour"

                elif cost_productSku == "B88168" and product_Description == "":
                    product_Description = "Oracle Identity Cloud - Basic - Consumer User"
                    cost_billingUnitReadable = "Active User per Hour"

                # create array
                row_data = (
                    str(tenancy.name),
                    file_id,
                    lineItem_intervalUsageStart[0:10] + " " + lineItem_intervalUsageStart[11:16],
                    lineItem_intervalUsageEnd[0:10] + " " + lineItem_intervalUsageEnd[11:16],
                    product_service,
                    product_compartmentId,
                    product_compartmentName,
                    compartment_path,
                    product_region,
                    product_availabilityDomain,
                    product_resourceId,
                    usage_billedQuantity,
                    usage_billedQuantityOverage,
                    cost_subscriptionId,
                    cost_productSku,
                    product_Description,
                    cost_unitPrice,
                    cost_unitPriceOverage,
                    cost_myCost,
                    cost_myCostOverage,
                    cost_currencyCode,
                    cost_billingUnitReadable,
                    cost_overageFlag,
                    lineItem_isCorrection,
                    tags_data,
                    lineItem_tenantId[-6:],
                    tag_special,
                    tag_special2
                )

                if str(cost_unitPrice) != '' and float(cost_unitPrice) > 0 and product_resourceId.startswith("ocid1.bootvolume."):
                    # check if exists in unique_list or not
                    if product_resourceId not in id_list:
                        id_list.append(product_resourceId)
                        data.append(row_data)
                        num_rows += 1

            print("   Completed  file " + o.name + " - " + str(num_rows) + " Rows Inserted")

            cost_data = data
            
        num_files += 1

        # remove file
        os.remove(path_filename)

        return cost_data

    except Exception as e:
        print("\nload_cost_file() - Error Download Usage and insert to database - " + str(e))
        raise SystemExit

#########################################################################
# Load Usage File
##########################################################################
def load_usage_file(object_storage, object_file, max_file_id, cmd, tenancy, compartments):
    num_files = 0
    num_rows = 0
    try:
        o = object_file

        # keep tag keys per file
        tags_keys = []

        # get file name
        filename = o.name.rsplit('/', 1)[-1]
        file_id = filename[:-7]
        file_time = str(o.time_created)[0:16]

        # if file already loaded, skip (check if < max_usage_file_id)
        if str(max_file_id) != "None":
            if file_id <= str(max_file_id):
                return num_files
        
                # if file id enabled, check
        if cmd.fileid:
            if file_id != cmd.file_id:
                return num_files

        # check file date
        if cmd.filedate:
            if file_time <= cmd.filedate:
                return num_files

        path_filename = work_report_dir + '/' + filename
        print("   Processing file " + o.name + " - " + str(o.size) + " bytes, " + file_time)

        # download file
        object_details = object_storage.get_object(usage_report_namespace, str(tenancy.id), o.name)
        with open(path_filename, 'wb') as f:
            for chunk in object_details.data.raw.stream(1024 * 1024, decode_content=False):
                f.write(chunk)

        # Read file to variable
        with gzip.open(path_filename, 'rt') as file_in:
            csv_reader = csv.DictReader(file_in)

            data = []
            for row in csv_reader:

                # find compartment path
                compartment_path = ""
                for c in compartments:
                    if c['id'] == row['product/compartmentId']:
                        compartment_path = c['path']

                # Handle Tags up to 3500 chars with # seperator
                tags_data = ""
                tag_special = ""
                tag_special2 = ""
                for (key, value) in row.items():
                    if 'tags' in key and len(value) > 0:

                        # remove # and = from the tags keys and value
                        keyadj = str(key).replace("tags/", "").replace("#", "").replace("=", "")
                        valueadj = str(value).replace("#", "").replace("=", "")

                        # check if length < 3500 to avoid overflow database column
                        if len(tags_data) + len(keyadj) + len(valueadj) + 2 < 3500:
                            tags_data += ("#" if tags_data == "" else "") + keyadj + "=" + valueadj + "#"

                        # add tag key to tag_keys array
                            if keyadj not in tags_keys:
                                tags_keys.append(keyadj)

                # Assign each column to variable to avoid error if column missing from the file
                lineItem_tenantId = get_column_value_from_array('lineItem/tenantId', row)
                lineItem_intervalUsageStart = get_column_value_from_array('lineItem/intervalUsageStart', row)
                lineItem_intervalUsageEnd = get_column_value_from_array('lineItem/intervalUsageEnd', row)
                product_service = get_column_value_from_array('product/service', row)
                product_resource = get_column_value_from_array('product/resource', row)
                product_compartmentId = get_column_value_from_array('product/compartmentId', row)
                product_compartmentName = get_column_value_from_array('product/compartmentName', row)
                product_region = get_column_value_from_array('product/region', row)
                product_availabilityDomain = get_column_value_from_array('product/availabilityDomain', row)
                product_resourceId = get_column_value_from_array('product/resourceId', row)
                usage_billedQuantity = get_column_value_from_array('usage/billedQuantity', row)
                usage_consumedQuantity = get_column_value_from_array('usage/consumedQuantity', row)
                usage_consumedQuantityUnits = get_column_value_from_array('usage/consumedQuantityUnits', row)
                usage_consumedQuantityMeasure = get_column_value_from_array('usage/consumedQuantityMeasure', row)
                lineItem_isCorrection = get_column_value_from_array('lineItem/isCorrection', row)

                # create array for bulk insert
                row_data = (
                    str(tenancy.name),
                    file_id,
                    lineItem_intervalUsageStart[0:10] + " " + lineItem_intervalUsageStart[11:16],
                    lineItem_intervalUsageEnd[0:10] + " " + lineItem_intervalUsageEnd[11:16],
                    product_service,
                    product_resource,
                    product_compartmentId,
                    product_compartmentName,
                    compartment_path,
                    product_region,
                    product_availabilityDomain,
                    product_resourceId,
                    usage_billedQuantity,
                    usage_consumedQuantity,
                    usage_consumedQuantityUnits,
                    usage_consumedQuantityMeasure,
                    lineItem_isCorrection,
                    tags_data,
                    lineItem_tenantId[-6:],
                    tag_special,
                    tag_special2
                )
                data.append(row_data)
                print(product_resourceId)
                num_rows += 1

            print("   Completed  file " + o.name + " - " + str(num_rows) + " Rows Inserted")
            unique(data)

        num_files += 1

        return num_files

    except Exception as e:
        print("\nload_usage_file() - Error Download Usage and insert to database - " + str(e))
        raise SystemExit

##########################################################################
# 
##########################################################################
def check_existing_update_date(connection, resource_id):
    try:
        # open cursor
        cursor = connection.cursor()
        
        sql = "select update_date from OCI_RECOMMENDATIONS_UNUSED_INSTANCES where RESOURCE_ID = '" + resource_id + "'"
        cursor.execute(sql)
        val = cursor.fetchone()
        update_date = None

        if val:
            update_date = val[0]

        # close cursor
        cursor.close()

        return update_date

    except cx_Oracle.DatabaseError as e:
        print("\nError manipulating database at check_existing_update_date() - " + str(e) + "\n")
        raise SystemExit

    except Exception as e:
        raise Exception("\nError manipulating database at check_existing_update_date() - " + str(e))

##########################################################################
#
##########################################################################
def update_existing_update_date(connection, resource_id, update_date):
    try:
        # open cursor
        cursor = connection.cursor()

        sql = "update OCI_RECOMMENDATIONS_UNUSED_INSTANCES set UPDATE_DATE=:update_date where RESOURCE_ID = :resource_id"

        sql_variables = {
            "update_date": update_date,
            "resource_id": resource_id
        }
        cursor.execute(sql, sql_variables)

        connection.commit()
        # close cursor
        cursor.close()

        return update_date

    except cx_Oracle.DatabaseError as e:
        print("\nError manipulating database at update_existing_update_date() - " + str(e) + "\n")
        raise SystemExit

    except Exception as e:
        raise Exception("\nError manipulating database at update_existing_update_date*( - " + str(e))


##########################################################################
# Main
##########################################################################
def main_process():
    cmd = set_parser_arguments()
    if cmd is None:
        exit()    
    #config = oci.config.from_file()
    config, signer = create_signer(cmd.profile, cmd.instance_principals, cmd.delegation_token)

    # assign default values
    config_file = oci.config.DEFAULT_LOCATION
    config_section = oci.config.DEFAULT_PROFILE

    tenancy=config["tenancy"]

    ############################################
    # Start
    ############################################
    print_header("Running Usage Load to ADW", 0)
    print("Starts at " + str(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    print("Command Line : " + ' '.join(x for x in sys.argv[1:]))

    ############################################
    # Identity extract compartments
    ############################################
    compartments = []
    tenancy = None
    tenant_id = ""
    short_tenant_id = ""
    try:
        print("\nConnecting to Identity Service...")
        identity = oci.identity.IdentityClient(config)

        tenancy = identity.get_tenancy(config["tenancy"]).data
        tenant_id = str(tenancy.id)
        short_tenant_id = tenant_id[-6:]
        tenancy_home_region = ""

        # find home region full name
        subscribed_regions = identity.list_region_subscriptions(tenancy.id).data
        for reg in subscribed_regions:
            if reg.is_home_region:
                tenancy_home_region = str(reg.region_name)

        print("   Tenant Name : " + str(tenancy.name))
        print("   Tenant Id   : " + tenancy.id)
        print("   App Version : " + version)
        print("   Home Region : " + tenancy_home_region)
        print("")

        # set signer home region
        #signer.region = tenancy_home_region
        config['region'] = tenancy_home_region

        # Extract compartments
        compartments = identity_read_compartments(identity, tenancy)

    except Exception as e:
        print("\nError extracting compartments section - " + str(e) + "\n")
        raise SystemExit

    ############################################
    # connect to database
    ############################################
    max_usage_file_id = ""
    max_cost_file_id = ""
    connection = None
    try:
        print("\nConnecting to database " + cmd.dname)
        connection = cx_Oracle.connect(user=cmd.duser, password=cmd.dpass, dsn=cmd.dname, encoding="UTF-8", nencoding="UTF-8")
        cursor = connection.cursor()
        print("   Connected")

        # Check tables structure
        #print("\nChecking Database Structure...")
        #check_database_table_structure_usage(connection, tenancy.name)
        #check_database_table_structure_cost(connection, cmd.tagspecial, tenancy.name)
        #check_database_table_structure_price_list(connection, tenancy.name)

        ###############################
        # enable hints
        ###############################
        sql = "ALTER SESSION SET OPTIMIZER_IGNORE_HINTS=FALSE"
        cursor.execute(sql)
        sql = "ALTER SESSION SET OPTIMIZER_IGNORE_PARALLEL_HINTS=FALSE"
        cursor.execute(sql)

        ###############################
        # fetch max file id processed
        # for usage and cost
        ###############################
        print("\nChecking Last Loaded File...")
        sql = "select /*+ full(a) parallel(a,4) */ nvl(max(file_id),'0') as file_id from OCI_USAGE a where TENANT_NAME=:tenant_name"
        cursor.execute(sql, {"tenant_name": str(tenancy.name)})
        max_usage_file_id, = cursor.fetchone()

        sql = "select /*+ full(a) parallel(a,4) */ nvl(max(file_id),'0') as file_id from OCI_COST a where TENANT_NAME=:tenant_name"
        cursor.execute(sql, {"tenant_name": str(tenancy.name)})
        max_cost_file_id, = cursor.fetchone()

        print("   Max Usage File Id Processed = " + str(max_usage_file_id))
        print("   Max Cost  File Id Processed = " + str(max_cost_file_id))
        cursor.close()

    except cx_Oracle.DatabaseError as e:
        print("\nError manipulating database - " + str(e) + "\n")
        raise SystemExit

    except Exception as e:
        raise Exception("\nError manipulating database - " + str(e))

    ############################################
    # Download Usage, cost and insert to database
    ############################################
    try:
        print("\nConnecting to Object Storage Service...")

        object_storage = oci.object_storage.ObjectStorageClient(config)

        max_usage_file_id = ""
        max_cost_file_id = ""

        #############################
        # Handle Report Usage
        #############################
        #usage_num = 0

        #print("\nHandling Usage Report...")
        #objects = oci.pagination.list_call_get_all_results(object_storage.list_objects, usage_report_namespace, str(tenancy.id), fields="timeCreated,size", prefix="reports/usage-csv/", start="reports/usage-csv/" + max_usage_file_id).data
        #for object_file in objects.objects:
        #    usage_num += load_usage_file(object_storage, object_file, max_usage_file_id, cmd, tenancy, compartments)
        #print("\n   Total " + str(usage_num) + " Usage Files Loaded")

        #############################
        # Handle Cost Usage
        #############################
        cost_num = 0
        cost_data = []
        unique_cost_data = []

        print("\nHandling Cost Report...")
        objects = oci.pagination.list_call_get_all_results(object_storage.list_objects, usage_report_namespace, str(tenancy.id), fields="timeCreated,size", prefix="reports/cost-csv/", start="reports/cost-csv/" + max_cost_file_id).data
        for object_file in objects.objects:
            data = load_cost_file(object_storage, object_file, max_cost_file_id, cmd, tenancy, compartments)
            if len(data) != 0:
                cost_data.extend(data)
        
        unique_cost_data = unique(cost_data)
        unique_cost_data = sorted(unique_cost_data, key=itemgetter(8, 5))

        #############################
        # Check Unused Instances
        #############################
        current_region = ""
        current_compartment_id = ""
        # 실행일자 기준 90일 이전에 생성한 인스턴스에 대해서 정리 기준으로 정했을때
        start_datetime = datetime.datetime.now().replace(tzinfo=utc) + datetime.timedelta(days=-90)
        today = datetime.datetime.now().replace(tzinfo=utc)

        data = []
        num_rows = 0

        # Adjust the batch size to meet memory and performance requirements for cx_oracle
        batch_size = 1
        array_size = 1

        sql = "INSERT INTO OCI_RECOMMENDATIONS_UNUSED_INSTANCES ("
        sql += "TENANT_NAME, "
        sql += "TENANT_ID, "
        sql += "REGION, "
        sql += "COMPARTMENT_PATH, "
        sql += "COMPARTMENT_NAME, "
        # 6
        sql += "COMPARTMENT_ID, "
        sql += "RESOURCE_TYPE, "
        sql += "RESOURCE_NAME, "
        sql += "RESOURCE_ID, "
        sql += "CREATE_DATE, " #2022-02-08 14:47:16.595000+00:00
        # 11
        sql += "CREATE_BY, "
        sql += "START_DATE, "
        sql += "START_USER, "
        sql += "STOP_DATE, "
        sql += "STOP_USER, "
        # 16
        sql += "STATE, "
        sql += "STOPPED_DAYS, "
        sql += "UPDATE_DATE, "
        sql += "NTFY_OWNER_EMAIL "

        sql += ") VALUES ("
        sql += ":1, :2, :3, :4, :5, "
        sql += ":6, :7, :8, :9, to_date(:10,'YYYY-MM-DD HH24:MI:SS'), "
        sql += ":11, to_date(:12,'YYYY-MM-DD\"T\"HH24:MI:SS'), :13, to_date(:14,'YYYY-MM-DD\"T\"HH24:MI:SS'), :15, "
        sql += ":16, to_number(:17), :18, :19 "
        sql += ") "

        # insert bulk to database
        cursor = cx_Oracle.Cursor(connection)

        # Predefine the memory areas to match the table definition
        cursor.setinputsizes(None, array_size)

        #############################
        # Cloud Advisor: Block Storage
        #############################
        try:
            optimizer_client = oci.optimizer.OptimizerClient(config, signer=signer)
            core_client = oci.core.BlockstorageClient(config, signer=signer)

            list_categories_response = optimizer_client.list_categories(
                compartment_id=tenant_id,
                compartment_id_in_subtree=True,
                name="cost-management-name")

            category_id = list_categories_response.data.items[0].id

            print("category_id: " + category_id)

            list_recommendations_response = optimizer_client.list_recommendations(
                compartment_id=current_compartment_id,
                compartment_id_in_subtree=True,
                limit=1000,
                name="cost-management-block-volume-attachment-name",
                category_id=category_id
            )

            recommendation_id = list_recommendations_response.data.items[0].id

            print("recommendation_id: " + recommendation_id)

            list_resource_actions_response = optimizer_client.list_resource_actions(
                compartment_id=current_compartment_id,
                compartment_id_in_subtree=True,
                limit=1000,
                recommendation_id=recommendation_id
            )

            for item in list_resource_actions_response.data.items:
                #print("name: " + item.name)
                #print("resource_id: " + item.resource_id)
                #print("timeCreated: " + item.extended_metadata['timeCreated'])
                #print("unattachedSince: " + item.extended_metadata['unattachedSince'])
                #print("sizeInGBs: " + item.extended_metadata['sizeInGBs'])
                timeCreated = datetime.datetime.fromtimestamp(float(item.extended_metadata['timeCreated'])) + datetime.timedelta(hours=-9)
                unattachedSince = datetime.datetime.fromtimestamp(float(item.extended_metadata['unattachedSince'])) + datetime.timedelta(hours=-9)
                #print(timeCreated)
                #print()

                days = "";

                delta = today - unattachedSince.replace(tzinfo=utc)
                days = str(delta.days) 

                get_volume_response = core_client.get_volume(
                    volume_id = item.resource_id)

                try:
                    defined_tags = get_volume_response.data.defined_tags
                    created_by = defined_tags['Oracle-Tags']['CreatedBy']
                except Exception as e:
                    print("\nError appeared - " + str(e))
                    created_by = ''

                print("created_by: " + created_by)

                owner_email = ''
                if created_by != '':
                    owner_email = created_by.split('/')[-1]
                elif start_user != '':
                    owner_email = start_user.split('/')[-1]
                
                obj = re.search(r'[\w.]+\@[\w.]+', owner_email)
                if not obj:
                    owner_email = ''

                row_data = (
                    str(tenancy.name),
                    short_tenant_id,
                    region,
                    compartment_path,
                    current_compartment_name,
                    compartment_id,
                    "BlockVolume",
                    item.name,
                    item.resource_id,
                    str(timeCreated)[0:18],
                    created_by,
                    None,
                    None,
                    None,
                    None,
                    "DETACHED",
                    days,
                    today,
                    owner_email
                )

                print(row_data)
                data.append(row_data)
                num_rows += 1

                # executemany every batch size
                if len(data) % batch_size == 0:
                    cursor.executemany(sql, data)
                    connection.commit()
                    data = []

        except Exception as e:
            print("\nError appeared - " + str(e))

        connection.commit()


        #############################
        # Compute Instance
        #############################
        for row_data in unique_cost_data:
            region = row_data[8]
            compartment_id = row_data[5]
            compartment_path = row_data[7]

            if current_region != region:
                current_region = region

                print("\nRegion " + current_region + "...")

                if current_region != "ap-seoul-1":
                    continue;

                # set the region in the config and signer
                config['region'] = current_region
                signer.region = current_region

                # connect to virtual_network
                try:
                    compute_client = oci.core.ComputeClient(config, signer=signer)
                    loggingsearch_client = oci.loggingsearch.LogSearchClient(config, signer=signer)

                except Exception as e:
                    print("\nError appeared - " + str(e))
            
            if current_compartment_id != compartment_id:
                current_compartment_id = compartment_id
                current_compartment_name = row_data[6]

                print("\n  Compartment " + current_compartment_name + "...")
                
                try:
                    instances = oci.pagination.list_call_get_all_results(
                        compute_client.list_instances,
                        current_compartment_id,
                        lifecycle_state="STOPPED",
                        sort_by="DISPLAYNAME"
                    ).data

                    for instance in instances:
                        time_created = instance.time_created;
                              
                        if time_created < start_datetime:
                            #print(time_created)
                            #print(start_datetime)
                            print("    " + instance.display_name)
                            print("      " + str(time_created))

                            to_time = today;
                            to_time_limit = today + datetime.timedelta(days=-365)

                            if (time_created > to_time_limit):
                                to_time_limit = time_created

                            counter = 0

                            stop_user = ""
                            stop_time = ""
                            start_user = ""
                            start_time = ""

                            update_date = check_existing_update_date(connection, instance.id)
                            if update_date:
                                to_time_limit = update_date.replace(tzinfo=utc)
                            
                            while to_time_limit < to_time and counter < 2:
                                from_time = to_time + datetime.timedelta(days=-14)
                                print("      " + str(from_time) + " ~ " + str(to_time))

                                search_logs_response = loggingsearch_client.search_logs(
                                    search_logs_details=oci.loggingsearch.models.SearchLogsDetails(
                                        time_start=from_time,
                                        time_end=to_time,
                                        search_query="search \"" + current_compartment_id + "/_Audit\" | (source='" + instance.display_name + "') and (data.request.action='POST') and (type='com.oraclecloud.computeApi.InstanceAction.begin') | sort by datetime desc",
                                        is_return_field_info=False,
                                    ),
                                    limit=2,
                                    retry_strategy=oci.retry.DEFAULT_RETRY_STRATEGY
                                )
                                
                                counter += search_logs_response.data.summary.result_count

                                if search_logs_response.data.summary.result_count > 0:
                                    #print(search_logs_response.data)

                                    for log in search_logs_response.data.results:
                                        #print(log.data["datetime"])
                                        #print(log.data["logContent"]["data"]["additionalDetails"]["instanceActionType"])
                                        #print("  " + log.data["logContent"]["data"]["response"]["responseTime"])
                                        #print("  " + log.data["logContent"]["data"]["message"])
                                        #print("  " + log.data["logContent"]["data"]["identity"]["principalName"])

                                        if log.data["logContent"]["data"]["additionalDetails"]["instanceActionType"] == "stop" or log.data["logContent"]["data"]["additionalDetails"]["instanceActionType"] == "softstop":
                                            stop_time = log.data["logContent"]["data"]["response"]["responseTime"]
                                            stop_user = log.data["logContent"]["data"]["identity"]["principalName"]

                                        if log.data["logContent"]["data"]["additionalDetails"]["instanceActionType"] == "start":
                                            start_time = log.data["logContent"]["data"]["response"]["responseTime"]
                                            start_user = log.data["logContent"]["data"]["identity"]["principalName"]

                                    break                             
                                
                                to_time = from_time

                            if update_date:
                                if to_time_limit >= to_time:
                                    update_existing_update_date(connection, instance.id, today)
                                    continue

                            #print("Region " + instance.region)
                            #print("CompartmentPath " + compartment_path)
                            #print("CompartmentName " + current_compartment_name)
                            #print("CompartmentID " + compartment_id)
                            #print("Type	COMPUTE")
                            #print("Name " + instance.display_name)
                            #print("InstanceID " + instance.id)
                            #print("CreatedDate " + str(instance.time_created))
                            
                            #if start_user != "":
                                #print(start_user)
                                #print("LastStartedDate " + start_time)
                                #print("LastStartedUser " + start_user)
                            #else:
                                #print("LastStartedDate " + "90 days ago")
                                #print("LastStartedUser " + "90 days ago")

                            #if stop_user != "":
                                #print(stop_user)
                                #print("LastStopedDate "+ stop_time)
                                #print("LastStopedUser " + stop_user)
                            #else:
                                #print("LastStopedDate "+ "90 days ago")
                                #print("LastStopedUser " + "90 days ago")                               

                            #print("CurrentState " + instance.lifecycle_state)

                            days = "";

                            if stop_time != "":
                                delta = today - datetime.datetime.strptime(stop_time, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=utc)
                                days = str(delta.days)
                            else:
                                delta = today - to_time_limit.replace(tzinfo=utc)
                                days = str(delta.days)  

                            try:
                                defined_tags = instance.defined_tags
                                created_by = defined_tags['Oracle-Tags']['CreatedBy']
                            except Exception as e:
                                created_by = ''      

                            owner_email = ''
                            if created_by != '':
                                owner_email = created_by.split('/')[-1]
                            elif start_user != '':
                                owner_email = start_user.split('/')[-1]
                            
                            obj = re.search(r'[\w.]+\@[\w.]+', owner_email)
                            if not obj:
                                owner_email = ''

                            row_data = (
                                str(tenancy.name),
                                short_tenant_id,
                                instance.region,
                                compartment_path,
                                current_compartment_name,
                                compartment_id,
                                "COMPUTE",
                                instance.display_name,
                                instance.id,
                                str(instance.time_created)[0:18],
                                created_by,
                                str(start_time)[0:18],
                                start_user,
                                str(stop_time)[0:18],
                                stop_user,
                                instance.lifecycle_state,
                                days,
                                today,
                                owner_email
                            )

                            print(row_data)
                            data.append(row_data)
                            num_rows += 1

                            # executemany every batch size
                            if len(data) % batch_size == 0:
                                cursor.executemany(sql, data)
                                connection.commit()
                                data = []

                except Exception as e:
                    print("\nError appeared - " + str(e))

        # if data exist final execute
        if data:
            cursor.executemany(sql, data)

        connection.commit()



        cursor.close()

        print("\n   Total " + str(cost_num) + " Cost Files Loaded")

    except Exception as e:
        print("\nError appeared - " + str(e))

    #header = [ 'Region', 'CompartmentPath', 'CompartmentName', 'CompartmentID', 'Type', 'Name', 'InstanceID', 'CreatedDate', 'LastStartedDate', 'LastStartedUser', 'LastStopedDate', 'LastStopedUser', 'CurrentState', 'Days']

    #with open('oci-usage-with-status.csv', 'w', encoding='UTF8') as f:
    #    writer = csv.writer(f)

    #    # write the header
    #    writer.writerow(header)

    #    # write the data
    #    for row_data in data:
    #        writer.writerow(row_data)       

    ############################################
    # print completed
    ############################################
    print("\nCompleted at " + str(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")))


##########################################################################
# Execute Main Process
##########################################################################
main_process()
