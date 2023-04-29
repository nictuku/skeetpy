#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Skeetpy is a Python library for interacting with the AT protocol."""

__version__ = "0.1.0"

import requests
import json
import jwt
import time
import os
import sys

# To log all requests sent with the requests library, uncomment the following
# two lines.
# import logging
# logging.basicConfig(level=logging.DEBUG)


class Label:
    """Metadata tag on an atproto resource (eg, repo or record)"""

    def __init__(self, src, uri, val, cts, cid=None, neg=False):
        self.src = src
        self.uri = uri
        self.cid = cid
        self.val = val
        self.neg = neg
        self.cts = cts

    def to_dict(self):
        return {
            "src": self.src,
            "uri": self.uri,
            "cid": self.cid,
            "val": self.val,
            "neg": self.neg,
            "cts": self.cts
        }


class InviteCodeUse:
    def __init__(self, used_by: str, used_at: str):
        self.used_by = used_by
        self.used_at = used_at


class InviteCode:
    def __init__(self, code: str, available: int, disabled: bool,
                 for_account: str, created_by: str, created_at: str, uses: []):
        self.code = code
        self.available = available
        self.disabled = disabled
        self.for_account = for_account
        self.created_by = created_by
        self.created_at = created_at
        self.uses = uses


class StrongRef:
    def __init__(self, uri, cid):
        self.uri = uri
        self.cid = cid

    def to_dict(self):
        return {
            'uri': self.uri,
            'cid': self.cid
        }

    @classmethod
    def from_dict(cls, data):
        return cls(
            uri=data['uri'],
            cid=data['cid']
        )


reason_spam = "com.atproto.moderation.defs#reasonSpam"
reason_violation = "com.atproto.moderation.defs#reasonViolation"
reason_misleading = "com.atproto.moderation.defs#reasonMisleading"
reason_sexual = "com.atproto.moderation.defs#reasonSexual"
reason_rude = "com.atproto.moderation.defs#reasonRude"
reason_other = "com.atproto.moderation.defs#reasonOther"


class ATP:

    def __init__(self, pds, identifier, password):
        self.pds = pds
        self.identifier = identifier
        self.password = password
        self.token = None

    def authenticate(self):
        """Authenticate with the ATP server."""
        url = f'https://{self.pds}/xrpc/com.atproto.server.createSession'
        headers = {'Content-Type': 'application/json'}
        body = {'identifier': self.identifier, 'password': self.password}
        # print url, headers, body
        response = requests.post(url, headers=headers, json=body)
        if response.status_code == 200:
            self.token = response.json()['accessJwt']
        else:
            raise Exception(
                f'Authentication failed with status code {response.status_code}')

    def resolve_handle(self, handle):
        """Resolve a handle to a DID."""
        url = f'https://{self.pds}/xrpc/com.atproto.identity.resolveHandle'
        headers = {'Content-Type': 'application/json'}
        headers['Authorization'] = f'Bearer {self.token}'
        body = {}
        if handle:
            body = {'handle': handle}
        response = requests.post(url, headers=headers, json=body)
        if response.status_code == 200:
            return response.json()['did']
        else:
            raise Exception(
                f'Resolve handle failed with status code {response.status_code}')

    def update_handle(self, handle):
        """Update the handle of the account."""
        url = f'https://{self.pds}/xrpc/com.atproto.identity.updateHandle'
        headers = {'Content-Type': 'application/json'}
        headers['Authorization'] = f'Bearer {self.token}'
        body = {'handle': handle}
        response = requests.post(url, headers=headers, json=body)
        if response.status_code == 200:
            return response.json()['did']
        else:
            raise Exception(
                f'Update handle failed with status code {response.status_code}')

    def request_password_reset(self, email):
        """Initiate a user account password reset via email."""
        url = f'https://{self.pds}/xrpc/com.atproto.server.requestPasswordReset'
        headers = {'Content-Type': 'application/json'}
        headers['Authorization'] = f'Bearer {self.token}'
        body = {'email': email}
        response = requests.post(url, headers=headers, json=body)
        if response.status_code != 200:
            raise Exception(
                f'Request password reset failed with status code {response.status_code}')

    def revoke_app_password(self, name):
        """Revoke an app-specific password by name."""
        url = f'https://{self.pds}/xrpc/com.atproto.server.revokeAppPassword'
        headers = {'Content-Type': 'application/json'}
        headers['Authorization'] = f'Bearer {self.token}'
        body = {'name': name}
        response = requests.post(url, headers=headers, json=body)
        if response.status_code != 200:
            raise Exception(
                f'Revoke app password failed with status code {response.status_code}')

    def disable_invite_codes(self, codes=None, accounts=None):
        """Disable some set of codes and/or all codes associated with a set of users."""
        url = f'https://{self.pds}/xrpc/com.atproto.admin.disableInviteCodes'
        headers = {'Content-Type': 'application/json'}
        headers['Authorization'] = f'Bearer {self.token}'
        body = {}
        if codes:
            body['codes'] = codes
        if accounts:
            body['accounts'] = accounts
        response = requests.post(url, headers=headers, json=body)
        if response.status_code == 200:
            return True
        else:
            raise Exception(
                f'Disable invite codes failed with status code {response.status_code}')

    def get_invite_codes(self, sort='recent', limit=100, cursor=None):
        """Admin view of invite codes."""
        url = f'https://{self.pds}/xrpc/com.atproto.admin.getInviteCodes'
        headers = {'Content-Type': 'application/json'}
        headers['Authorization'] = f'Bearer {self.token}'
        params = {'sort': sort, 'limit': limit}
        if cursor:
            params['cursor'] = cursor
        response = requests.get(url, headers=headers, params=params)
        if response.status_code == 200:
            return response.json()
        else:
            raise Exception(
                f'Get invite codes failed with status code {response.status_code}')

    def get_moderation_action(self, id):
        """View details about a moderation action."""
        url = f'https://{self.pds}/xrpc/com.atproto.admin.getModerationAction'
        headers = {'Content-Type': 'application/json'}
        headers['Authorization'] = f'Bearer {self.token}'
        params = {'id': id}
        response = requests.get(url, headers=headers, params=params)
        if response.status_code == 200:
            return response.json()
        else:
            raise Exception(
                f'Get moderation action failed with status code {response.status_code}')

    def get_moderation_actions(self, subject, limit=50, cursor=None):
        """List moderation actions related to a subject."""
        url = f'https://{self.pds}/xrpc/com.atproto.admin.getModerationActions'
        headers = {'Content-Type': 'application/json'}
        headers['Authorization'] = f'Bearer {self.token}'
        params = {'subject': subject, 'limit': limit}
        if cursor:
            params['cursor'] = cursor
        response = requests.get(url, headers=headers, params=params)
        if response.status_code == 200:
            return response.json()
        else:
            raise Exception(
                f'Get moderation actions failed with status code {response.status_code}')

    def get_moderation_report(self, id):
        """View details about a moderation report."""
        url = f'https://{self.pds}/xrpc/com.atproto.admin.getModerationReport'
        headers = {'Content-Type': 'application/json'}
        headers['Authorization'] = f'Bearer {self.token}'
        params = {'id': id}
        response = requests.get(url, headers=headers, params=params)
        if response.status_code == 200:
            return response.json()
        else:
            raise Exception(
                f'Get moderation report failed with status code {response.status_code}')

    def get_moderation_reports(
            self, subject, resolved=False, limit=50, cursor=None):
        """List moderation reports related to a subject."""
        url = f'https://{self.pds}/xrpc/com.atproto.admin.getModerationReports'
        headers = {'Content-Type': 'application/json'}
        headers['Authorization'] = f'Bearer {self.token}'
        params = {
            'subject': subject,
            'resolved': resolved,
            'limit': limit,
            'cursor': cursor}
        response = requests.get(url, headers=headers, params=params)
        if response.status_code == 200:
            return response.json()
        else:
            raise Exception(
                f'Get moderation reports failed with status code {response.status_code}')

    def get_record(self, uri, cid=None):
        """View details about a record."""
        url = f'https://{self.pds}/xrpc/com.atproto.admin.getRecord'
        headers = {'Content-Type': 'application/json'}
        headers['Authorization'] = f'Bearer {self.token}'
        params = {'uri': uri}
        if cid:
            params['cid'] = cid
        response = requests.get(url, headers=headers, params=params)
        if response.status_code == 200:
            return response.json()
        else:
            raise Exception(
                f'Get record failed with status code {response.status_code}')

    def get_repo(self, did):
        """View details about a repository."""
        url = f'https://{self.pds}/xrpc/com.atproto.admin.getRepo'
        headers = {'Content-Type': 'application/json'}
        headers['Authorization'] = f'Bearer {self.token}'
        params = {'did': did}
        response = requests.get(url, headers=headers, params=params)
        if response.status_code == 200:
            return response.json()
        else:
            raise Exception(
                f'Get repo failed with status code {response.status_code}')

    def resolve_moderation_reports(self, action_id, report_ids, created_by):
        """Resolve moderation reports by an action."""
        url = f'https://{self.pds}/xrpc/com.atproto.admin.resolveModerationReports'
        headers = {'Content-Type': 'application/json'}
        headers['Authorization'] = f'Bearer {self.token}'
        body = {
            'actionId': action_id,
            'reportIds': report_ids,
            'createdBy': created_by}
        response = requests.post(url, headers=headers, json=body)
        if response.status_code == 200:
            return response.json()
        else:
            raise Exception(
                f'Resolve moderation reports failed with status code {response.status_code}')

    def reverse_moderation_action(self, id, reason, created_by):
        """Reverse a moderation action."""
        url = f'https://{self.pds}/xrpc/com.atproto.admin.reverseModerationAction'
        headers = {'Content-Type': 'application/json'}
        headers['Authorization'] = f'Bearer {self.token}'
        body = {'id': id, 'reason': reason, 'createdBy': created_by}
        response = requests.post(url, headers=headers, json=body)
        if response.status_code == 200:
            return response.json()
        else:
            raise Exception(
                f'Reverse moderation action failed with status code {response.status_code}')

    def search_repos(self, term, invited_by=None, limit=50, cursor=None):
        """Find repositories based on a search term."""
        url = f'https://{self.pds}/xrpc/com.atproto.admin.searchRepos'
        headers = {'Content-Type': 'application/json'}
        headers['Authorization'] = f'Bearer {self.token}'
        params = {'term': term, 'limit': limit}
        if invited_by:
            params['invitedBy'] = invited_by
        if cursor:
            params['cursor'] = cursor
        response = requests.get(url, headers=headers, params=params)
        if response.status_code == 200:
            return response.json()
        else:
            raise Exception(
                f'Search repos failed with status code {response.status_code}')

    def take_moderation_action(self, action, subject, reason, created_by):
        """Take a moderation action on a repo."""
        url = f'https://{self.pds}/xrpc/com.atproto.admin.takeModerationAction'
        headers = {'Content-Type': 'application/json'}
        headers['Authorization'] = f'Bearer {self.token}'
        body = {
            'action': action,
            'subject': subject,
            'reason': reason,
            'createdBy': created_by
        }
        response = requests.post(url, headers=headers, json=body)
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 409:
            raise Exception('Subject has action')
        else:
            raise Exception(
                f'Take moderation action failed with status code {response.status_code}')

    def update_account_email(self, account, email):
        """Administrative action to update an account's email."""
        url = f'https://{self.pds}/xrpc/com.atproto.admin.updateAccountEmail'
        headers = {'Content-Type': 'application/json'}
        headers['Authorization'] = f'Bearer {self.token}'
        body = {'account': account, 'email': email}
        response = requests.post(url, headers=headers, json=body)
        if response.status_code == 200:
            return response.json()
        else:
            raise Exception(
                f'Update account email failed with status code {response.status_code}')

    def admin_update_account_handle(self, did, handle):
        """Administrative action to update an account's handle."""
        url = f'https://{self.pds}/xrpc/com.atproto.admin.updateAccountHandle'
        headers = {'Content-Type': 'application/json'}
        headers['Authorization'] = f'Bearer {self.token}'
        body = {'did': did, 'handle': handle}
        response = requests.post(url, headers=headers, json=body)
        if response.status_code == 200:
            return response.json()['success']
        else:
            raise Exception(
                f'Admin update account handle failed with status code {response.status_code}')

    def resolve_handle(self, handle=None):
        """Provides the DID of a repo."""
        url = f'https://{self.pds}/xrpc/com.atproto.identity.resolveHandle'
        headers = {'Content-Type': 'application/json'}
        headers['Authorization'] = f'Bearer {self.token}'
        params = {}
        if handle:
            params['handle'] = handle
        response = requests.get(url, headers=headers, params=params)
        if response.status_code == 200:
            return response.json()['did']
        else:
            raise Exception(
                f'Resolve handle failed with status code {response.status_code}')

    def update_handle(self, handle):
        url = f'https://{self.pds}/xrpc/com.atproto.identity.updateHandle'
        headers = {'Content-Type': 'application/json'}
        headers['Authorization'] = f'Bearer {self.token}'
        body = {'handle': handle}
        response = requests.post(url, headers=headers, json=body)
        if response.status_code == 200:
            return response.json()['did']
        else:
            raise Exception(
                f'Update handle failed with status code {response.status_code}')

    def query_labels(self, uri_patterns, sources=None, limit=50, cursor=None):
        """Find labels relevant to the provided URI patterns."""
        url = f'https://{self.pds}/xrpc/com.atproto.label.queryLabels'
        headers = {'Content-Type': 'application/json'}
        headers['Authorization'] = f'Bearer {self.token}'
        body = {'uriPatterns': uri_patterns, 'limit': limit}
        if sources:
            body['sources'] = sources
        if cursor:
            body['cursor'] = cursor
        response = requests.post(url, headers=headers, json=body)
        if response.status_code == 200:
            return response.json()
        else:
            raise Exception(
                f'Query labels failed with status code {response.status_code}')

    def subscribe_labels(self, cursor=None):
        """Subscribe to label updates."""
        url = f'https://{self.pds}/xrpc/com.atproto.label.subscribeLabels'
        headers = {'Content-Type': 'application/json'}
        headers['Authorization'] = f'Bearer {self.token}'
        params = {}
        if cursor is not None:
            params['cursor'] = cursor
        response = requests.get(
            url,
            headers=headers,
            params=params,
            stream=True)
        for line in response.iter_lines():
            if line:
                data = json.loads(line)
                if 'labels' in data:
                    yield data['labels']
                elif 'name' in data and data['name'] == 'OutdatedCursor':
                    raise Exception('Cursor is outdated')
                else:
                    raise Exception(f'Unexpected message: {data}')

    def create_report(self, reason_type, subject, reason=None):
        """Report a repo or a record."""
        url = f'https://{self.pds}/xrpc/com.atproto.moderation.createReport'
        headers = {'Content-Type': 'application/json'}
        headers['Authorization'] = f'Bearer {self.token}'
        body = {'reasonType': reason_type, 'subject': subject}
        if reason:
            body['reason'] = reason
        response = requests.post(url, headers=headers, json=body)
        if response.status_code == 200:
            return response.json()
        else:
            raise Exception(
                f'Create report failed with status code {response.status_code}')

    def apply_writes(self, repo, writes, validate=True, swap_commit=None):
        """Apply a batch transaction of creates, updates, and deletes."""
        url = f'https://{self.pds}/xrpc/com.atproto.repo.applyWrites'
        headers = {'Content-Type': 'application/json'}
        headers['Authorization'] = f'Bearer {self.token}'
        body = {'repo': repo, 'writes': writes, 'validate': validate}
        if swap_commit:
            body['swapCommit'] = swap_commit
        response = requests.post(url, headers=headers, json=body)
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 400 and 'InvalidSwap' in response.json()['errors']:
            raise Exception('Invalid swap commit')
        else:
            raise Exception(
                f'Apply writes failed with status code {response.status_code}')

    def create_record(self, repo, collection, record,
                      rkey=None, validate=True, swapCommit=None):
        """Create a new record."""
        url = f'https://{self.pds}/xrpc/com.atproto.repo.createRecord'
        headers = {'Content-Type': 'application/json'}
        headers['Authorization'] = f'Bearer {self.token}'
        body = {
            'repo': repo,
            'collection': collection,
            'record': record,
            'validate': validate
        }
        if rkey:
            body['rkey'] = rkey
        if swapCommit:
            body['swapCommit'] = swapCommit
        response = requests.post(url, headers=headers, json=body)
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 400 and response.json()['name'] == 'InvalidSwap':
            raise Exception('Invalid swap commit')
        else:
            raise Exception(
                f'Create record failed with status code {response.status_code}')

    def delete_record(self, repo, collection, rkey,
                      swapRecord=None, swapCommit=None):
        """Delete a record, or ensure it doesn't exist."""
        url = f'https://{self.pds}/xrpc/com.atproto.repo.deleteRecord'
        headers = {'Content-Type': 'application/json'}
        headers['Authorization'] = f'Bearer {self.token}'
        body = {'repo': repo, 'collection': collection, 'rkey': rkey}
        if swapRecord:
            body['swapRecord'] = swapRecord
        if swapCommit:
            body['swapCommit'] = swapCommit
        response = requests.post(url, headers=headers, json=body)
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 400 and response.json()['error'] == 'InvalidSwap':
            raise Exception('Invalid swap')
        else:
            raise Exception(
                f'Delete record failed with status code {response.status_code}')

    def describe_repo(self, repo):
        """Get information about the repo, including the list of collections."""
        url = f'https://{self.pds}/xrpc/com.atproto.repo.describeRepo'
        headers = {'Content-Type': 'application/json'}
        headers['Authorization'] = f'Bearer {self.token}'
        body = {'repo': repo}
        response = requests.post(url, headers=headers, json=body)
        if response.status_code == 200:
            return response.json()
        else:
            raise Exception(
                f'Describe repo failed with status code {response.status_code}')

    def get_record(self, repo, collection, rkey, cid=None):
        """Get a record."""
        url = f'https://{self.pds}/xrpc/com.atproto.repo.getRecord'
        headers = {'Content-Type': 'application/json'}
        headers['Authorization'] = f'Bearer {self.token}'
        params = {'repo': repo, 'collection': collection, 'rkey': rkey}
        if cid:
            params['cid'] = cid
        response = requests.get(url, headers=headers, params=params)
        if response.status_code == 200:
            return response.json()
        else:
            raise Exception(
                f'Get record failed with status code {response.status_code}')

    def list_records(self, repo, collection, limit=50, cursor=None,
                     rkeyStart=None, rkeyEnd=None, reverse=False):
        """List a range of records in a collection."""
        url = f'https://{self.pds}/xrpc/com.atproto.repo.listRecords'
        headers = {'Content-Type': 'application/json'}
        headers['Authorization'] = f'Bearer {self.token}'
        params = {
            'repo': repo,
            'collection': collection,
            'limit': limit,
            'cursor': cursor,
            'rkeyStart': rkeyStart,
            'rkeyEnd': rkeyEnd,
            'reverse': reverse}
        response = requests.get(url, headers=headers, params=params)
        if response.status_code == 200:
            return response.json()['records']
        else:
            raise Exception(
                f'List records failed with status code {response.status_code}')

    def put_record(self, repo, collection, rkey, record,
                   validate=True, swapRecord=None, swapCommit=None):
        """Write a record, creating or updating it as needed."""
        url = f'https://{self.pds}/xrpc/com.atproto.repo.putRecord'
        headers = {'Content-Type': 'application/json'}
        headers['Authorization'] = f'Bearer {self.token}'
        body = {
            'repo': repo,
            'collection': collection,
            'rkey': rkey,
            'validate': validate,
            'record': record,
            'swapRecord': swapRecord,
            'swapCommit': swapCommit
        }
        response = requests.post(url, headers=headers, json=body)
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 400 and response.json()['name'] == 'InvalidSwap':
            raise Exception('Invalid swap')
        else:
            raise Exception(
                f'Put record failed with status code {response.status_code}')

    def upload_blob(self, blob):
        """Upload a new blob to be added to repo in a later request."""
        url = f'https://{self.pds}/xrpc/com.atproto.repo.uploadBlob'
        headers = {'Content-Type': 'application/octet-stream'}
        headers['Authorization'] = f'Bearer {self.token}'
        response = requests.post(url, headers=headers, data=blob)
        if response.status_code == 200:
            return response.json()['blob']
        else:
            raise Exception(
                f'Upload blob failed with status code {response.status_code}')

    def create_account(self, handle, email, password,
                       invite_code=None, recovery_key=None):
        """Create an account."""
        url = f'https://{self.pds}/xrpc/com.atproto.server.createAccount'
        headers = {'Content-Type': 'application/json'}
        body = {
            'handle': handle,
            'email': email,
            'password': password
        }
        if invite_code:
            body['inviteCode'] = invite_code
        if recovery_key:
            body['recoveryKey'] = recovery_key
        headers['Authorization'] = f'Bearer {self.token}'
        response = requests.post(url, headers=headers, json=body)
        if response.status_code == 200:
            return response.json()
        else:
            raise Exception(
                f'Create account failed with status code {response.status_code}')

    def create_app_password(self, name):
        """Create an app-specific password."""
        url = f'https://{self.pds}/xrpc/com.atproto.server.createAppPassword'
        headers = {'Content-Type': 'application/json'}
        headers['Authorization'] = f'Bearer {self.token}'
        body = {'name': name}
        response = requests.post(url, headers=headers, json=body)
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 400:
            raise AccountTakedown(response.json()['message'])
        else:
            raise Exception(
                f'Create app password failed with status code {response.status_code}')

    def create_invite_code(self, use_count, for_account=None):
        """Create an invite code."""
        url = f'https://{self.pds}/xrpc/com.atproto.server.createInviteCode'
        headers = {'Content-Type': 'application/json'}
        headers['Authorization'] = f'Bearer {self.token}'
        body = {'useCount': use_count}
        if for_account:
            body['forAccount'] = for_account
        response = requests.post(url, headers=headers, json=body)
        if response.status_code == 200:
            return response.json()['code']
        else:
            raise Exception(
                f'Create invite code failed with status code {response.status_code}')

    def create_invite_codes(
            self, codeCount=1, useCount=None, forAccounts=None):
        """Create an invite code."""
        url = f'https://{self.pds}/xrpc/com.atproto.server.createInviteCodes'
        headers = {'Content-Type': 'application/json'}
        headers['Authorization'] = f'Bearer {self.token}'
        body = {
            'codeCount': codeCount,
            'useCount': useCount,
            'forAccounts': forAccounts}
        response = requests.post(url, headers=headers, json=body)
        if response.status_code == 200:
            return response.json()['codes']
        else:
            raise Exception(
                f'Create invite codes failed with status code {response.status_code}')

    def create_session(self, identifier, password):
        """Create an authentication session."""
        url = f'https://{self.server}/xrpc/com.atproto.server.createSession'
        headers = {'Content-Type': 'application/json'}
        body = {'identifier': identifier, 'password': password}
        response = requests.post(url, headers=headers, json=body)
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 403:
            raise AccountTakedown()
        else:
            raise Exception(
                f'Create session failed with status code {response.status_code}')

    def delete_account(self, did, password, token):
        """Delete a user account with a token and password."""
        url = f'https://{self.server}/xrpc/com.atproto.server.deleteAccount'
        headers = {'Content-Type': 'application/json'}
        headers['Authorization'] = f'Bearer {token}'
        body = {'did': did, 'password': password, 'token': token}
        response = requests.post(url, headers=headers, json=body)
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 401:
            raise Exception('Invalid token')
        elif response.status_code == 403:
            raise Exception('Expired token')
        else:
            raise Exception(
                f'Delete account failed with status code {response.status_code}')

    def delete_session(self):
        """Delete the current session."""
        url = f'https://{self.pds}/xrpc/com.atproto.server.deleteSession'
        headers = {'Content-Type': 'application/json'}
        headers['Authorization'] = f'Bearer {self.token}'
        response = requests.post(url, headers=headers)
        if response.status_code != 200:
            raise Exception(
                f'Delete session failed with status code {response.status_code}')

    def describe_server(self):
        """Get a document describing the service's accounts configuration."""
        url = f'https://{self.pds}/xrpc/com.atproto.server.describeServer'
        headers = {'Content-Type': 'application/json'}
        headers['Authorization'] = f'Bearer {self.token}'
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            return response.json()
        else:
            raise Exception(
                f'Describe server failed with status code {response.status_code}')

    def get_account_invite_codes(
            self, include_used=True, create_available=True):
        """Get all invite codes for a given account."""
        url = f'https://{self.pds}/xrpc/com.atproto.server.getAccountInviteCodes'
        headers = {'Content-Type': 'application/json'}
        headers['Authorization'] = f'Bearer {self.token}'
        params = {
            'includeUsed': include_used,
            'createAvailable': create_available}
        response = requests.get(url, headers=headers, params=params)
        if response.status_code == 200:
            return response.json()['codes']
        else:
            raise Exception(
                f'Get account invite codes failed with status code {response.status_code}')

    def list_app_passwords(self):
        """List all app-specific passwords."""
        url = f'https://{self.pds}/xrpc/com.atproto.server.listAppPasswords'
        headers = {'Content-Type': 'application/json'}
        headers['Authorization'] = f'Bearer {self.token}'
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            return response.json()['passwords']
        elif response.status_code == 403:
            raise AccountTakedown()
        else:
            raise Exception(
                f'List app passwords failed with status code {response.status_code}')

    def refresh_session(self):
        """Refresh an authentication session."""
        url = f'https://{self.pds}/xrpc/com.atproto.server.refreshSession'
        headers = {'Content-Type': 'application/json'}
        headers['Authorization'] = f'Bearer {self.token}'
        response = requests.post(url, headers=headers)
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 400 and response.json()['error'] == 'AccountTakedown':
            raise AccountTakedownError()
        else:
            raise Exception(
                f'Refresh session failed with status code {response.status_code}')

    def request_account_delete(self):
        """Initiate a user account deletion via email."""
        url = f'https://{self.pds}/xrpc/com.atproto.server.requestAccountDelete'
        headers = {'Content-Type': 'application/json'}
        headers['Authorization'] = f'Bearer {self.token}'
        response = requests.post(url, headers=headers)
        if response.status_code == 200:
            return True
        else:
            raise Exception(
                f'Request account deletion failed with status code {response.status_code}')

    def request_password_reset(self, email):
        """Initiate a user account password reset via email."""
        url = f'https://{self.pds}/xrpc/com.atproto.server.requestPasswordReset'
        headers = {'Content-Type': 'application/json'}
        headers['Authorization'] = f'Bearer {self.token}'
        body = {'email': email}
        response = requests.post(url, headers=headers, json=body)
        if response.status_code == 200:
            return response.json()
        else:
            raise Exception(
                f'Request password reset failed with status code {response.status_code}')

    def reset_password(self, token, password):
        """Reset a user account password using a token."""
        url = f'https://{self.server}/xrpc/com.atproto.server.resetPassword'
        headers = {'Content-Type': 'application/json'}
        headers['Authorization'] = f'Bearer {self.token}'
        body = {'token': token, 'password': password}
        response = requests.post(url, headers=headers, json=body)
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 400:
            error = response.json()['error']
            if error == 'ExpiredToken':
                raise ExpiredTokenError()
            elif error == 'InvalidToken':
                raise InvalidTokenError()
        raise Exception(
            f'Reset password failed with status code {response.status_code}')

    def revoke_app_password(self, name):
        """Revoke an app-specific password by name."""
        url = f'https://{self.pds}/xrpc/com.atproto.server.revokeAppPassword'
        headers = {'Content-Type': 'application/json'}
        headers['Authorization'] = f'Bearer {self.token}'
        body = {'name': name}
        response = requests.post(url, headers=headers, json=body)
        if response.status_code == 200:
            return True
        else:
            raise Exception(
                f'Revoke app password failed with status code {response.status_code}')

    def get_blob(self, did, cid):
        """Get a blob associated with a given repo."""
        url = f'https://{self.pds}/xrpc/com.atproto.sync.getBlob'
        headers = {'Content-Type': 'application/json'}
        headers['Authorization'] = f'Bearer {self.token}'
        params = {'did': did, 'cid': cid}
        response = requests.get(url, headers=headers, params=params)
        if response.status_code == 200:
            return response.content
        else:
            raise Exception(
                f'Get blob failed with status code {response.status_code}')

    def get_blocks(self, did, cids):
        """Gets blocks from a given repo."""
        url = f'https://{self.pds}/xrpc/com.atproto.sync.getBlocks'
        headers = {'Content-Type': 'application/json'}
        headers['Authorization'] = f'Bearer {self.token}'
        body = {'did': did, 'cids': cids}
        response = requests.post(url, headers=headers, json=body)
        if response.status_code == 200:
            return response.content
        else:
            raise Exception(
                f'Get blocks failed with status code {response.status_code}')

    def get_checkout(self, did, commit=None):
        """Gets the repo state."""
        url = f'https://{self.pds}/xrpc/com.atproto.sync.getCheckout'
        headers = {'Content-Type': 'application/json'}
        headers['Authorization'] = f'Bearer {self.token}'
        params = {'did': did}
        if commit:
            params['commit'] = commit
        response = requests.get(url, headers=headers, params=params)
        if response.status_code == 200:
            return response.content
        else:
            raise Exception(
                f'Get checkout failed with status code {response.status_code}')

    def get_commit_path(self, did, latest=None, earliest=None):
        """Gets the path of repo commits."""
        url = f'https://{self.pds}/xrpc/com.atproto.sync.getCommitPath'
        headers = {'Content-Type': 'application/json'}
        headers['Authorization'] = f'Bearer {self.token}'
        params = {'did': did}
        if latest:
            params['latest'] = latest
        if earliest:
            params['earliest'] = earliest
        response = requests.get(url, headers=headers, params=params)


# Test for the ATP class.
if __name__ == '__main__':
    pds = os.environ['PDS']
    identifier = os.environ['IDENTIFIER']
    password = os.environ['PASSWORD']
    atp = ATP(pds, identifier, password)
    atp.authenticate()
    print(atp.describe_server())
    print(atp.list_app_passwords())

    # These don't seem to work
    # print(atp.refresh_session())
    # get my DID using resolve handle. Dont provide an arg.
    # print(atp.resolve_handle())
    # print(atp.get_invite_codes())
