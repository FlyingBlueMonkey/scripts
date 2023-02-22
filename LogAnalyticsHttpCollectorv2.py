#!/usr/bin/env python3
# LogAnalyticsHttpCollectorv2.py
# a very simple python script to log to Log Analytics
# written for api-version=2016-04-01 https://learn.microsoft.com/en-us/rest/api/loganalytics/create-request
# Matt Egen github.com/FlyingBlueMonkey January 2023

#Script signature:python3 LogAnalyticsHttpCollectorv2.py [workspaceID] [workspaceKey] [logtype] [data]

# Import libraries
import time
import sys # need this for parameters
import hmac
import hashlib
import base64
from wsgiref.handlers import format_date_time
from datetime import datetime
from time import mktime
import json
import requests




# retrieve parameters
workspaceId = sys.argv[1]
sharedKey = sys.argv[2]
logType = sys.argv[3]
logData = sys.argv[4]
contentType = "Content-Type: application/json" # used by Content-Type header

# Build the API signature
def build_signature(WORKSPACE_ID, WORKSPACE_SHARED_KEY, date, content_length, method, content_type, resource):
    x_headers = 'x-ms-date:' + date
    string_to_hash = method + "\n" + str(content_length) + "\n" + content_type + "\n" + x_headers + "\n" + resource
    bytes_to_hash = bytes(string_to_hash, encoding="utf-8") 
    decoded_key = base64.b64decode(WORKSPACE_SHARED_KEY)
    encoded_hash = base64.b64encode(hmac.new(decoded_key, bytes_to_hash, digestmod=hashlib.sha256).digest()).decode()
    authorization = f"SharedKey {WORKSPACE_ID}:{encoded_hash}"
    return authorization

# Build and send a request to the POST API
def post_data(WORKSPACE_ID, WORKSPACE_SHARED_KEY, body, LOG_TYPE):
    method = 'POST'
    content_type = 'application/json'
    resource = '/api/logs'
    now = datetime.now()
    stamp = mktime(now.timetuple())
    xmsdate = format_date_time(stamp) 
    #rfc1123date = datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
    content_length = len(body)
    signature = build_signature(WORKSPACE_ID, WORKSPACE_SHARED_KEY, xmsdate, content_length, method, content_type, resource)
    uri = 'https://' + WORKSPACE_ID + '.ods.opinsights.azure.com' + resource + '?api-version=2016-04-01'

    headers = {
        'content-type': content_type,
        'Authorization': signature,
        'Log-Type': LOG_TYPE,
        'x-ms-date': xmsdate
    }

    #print(f'{uri},{signature},{body}')
    response = requests.post(uri,data=body, headers=headers)
    if (response.status_code >= 200 and response.status_code <= 299):
        #print(f'Response code: {response.status_code} {response.reason} {response.raw}')
        return True
    else:
        print(f'Response code: {response.status_code} {response.reason} {response.raw}')


post_data(workspaceId, sharedKey, logData, logType)


