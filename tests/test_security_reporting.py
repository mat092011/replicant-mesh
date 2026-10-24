"""Visibility must never change as a side effect of reporting setup."""

import unittest

from scripts.verify_security_reporting import REPOSITORY_ID, verify


class SecurityReportingTests(unittest.TestCase):
    def test_private_repository_never_enables_or_changes_visibility(self):
        calls = []
        def api(path, method='GET'):
            calls.append((path, method))
            return {'visibility': 'private', 'full_name': 'mat092011/replicant-mesh'}
        self.assertFalse(verify(api, enable=True)['verified'])
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][1], 'GET')

    def test_public_repository_enables_then_reads_back_the_setting(self):
        calls = []
        def api(path, method='GET'):
            calls.append((path, method))
            if path == f'repositories/{REPOSITORY_ID}':
                return {'visibility': 'public', 'full_name': 'mat092011/replicant-mesh'}
            return {'enabled': len(calls) == 4}
        self.assertTrue(verify(api, enable=True)['verified'])
        self.assertEqual([method for path, method in calls], ['GET', 'GET', 'PUT', 'GET'])

    def test_public_disabled_setting_is_not_reported_as_verified(self):
        def api(path, method='GET'):
            return ({'visibility': 'public', 'full_name': 'mat092011/replicant-mesh'}
                    if path == f'repositories/{REPOSITORY_ID}' else {'enabled': False})
        self.assertFalse(verify(api)['verified'])

    def test_reporting_url_and_setting_follow_the_live_repository_name(self):
        calls = []
        def api(path, method='GET'):
            calls.append((path, method))
            if path == f'repositories/{REPOSITORY_ID}':
                return {'visibility': 'public', 'full_name': 'owner/renamed-project'}
            return {'enabled': True}
        report = verify(api)
        self.assertTrue(report['verified'])
        self.assertEqual(report['repository'], 'owner/renamed-project')
        self.assertEqual(report['report_url'],
                         'https://github.com/owner/renamed-project/security/advisories/new')
        self.assertEqual(calls[-1],
                         ('repos/owner/renamed-project/private-vulnerability-reporting', 'GET'))
