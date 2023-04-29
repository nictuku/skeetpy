#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Skeetpy is a Python library for interacting with the AT protocol."""

__version__ = "0.0.1"

import requests
import json
import jwt
import time
import os
import sys


class ATP:

    def __init__(self, pds, identifier, password):
        self.pds = pds
        self.identifier = identifier
        self.password = password
        self.token = None

    def describe_server(self):
        """Describe the server."""
        url = f'https://{self.pds}/xrpc/com.atproto.server.describeServer'
        headers = {'Content-Type': 'application/json'}
        headers['Authorization'] = f'Bearer {self.token}'
        response = requests.post(url, headers=headers, json={})
        if response.status_code == 200:
            return response.json()['data']
        else:
            raise Exception(f'Describe server failed with status code {response.status_code}')


    def authenticate(self):
        """Authenticate with the ATP server."""
        url = f'https://{self.pds}/xrpc/com.atproto.server.createSession'
        headers = {'Content-Type': 'application/json'}
        body = {'identifier': self.identifier, 'password': self.password}
        # print url, headers, body
        print(f'Authenticating with {url}')
        print(f'Headers: {headers}')
        print(f'Body: {body}')
        response = requests.post(url, headers=headers, json=body)
        print(f'Response: {response}')
        if response.status_code == 200:
            print(f'JSON: {response.json()}')
            self.token = response.json()['accessJwt']
        else:
            raise Exception(f'Authentication failed with status code {response.status_code}')

    def get_profile(self):
        """Get the user's profile."""
        url = f'https://{self.pds}/xrpc/app.bsky.actor.profile'
        headers = {'Content-Type': 'application/json'}
        headers['Authorization'] = f'Bearer {self.token}'
        response = requests.post(url, headers=headers, json={})
        print(f'Response: {response}')
        if response.status_code == 200:
            return response.json()['data']
        else:
            raise Exception(f'Get profile failed with status code {response.status_code}')



# Test for the ATP class.
if __name__ == '__main__':
    pds = os.environ['PDS']
    identifier = os.environ['IDENTIFIER']
    password = os.environ['PASSWORD']
    atp = ATP(pds, identifier, password)
    atp.authenticate()
    #profile = atp.get_profile()
    #print(profile)
