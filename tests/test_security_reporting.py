"""Visibility must never change as a side effect of reporting setup."""

import unittest

from scripts.verify_security_reporting import verify


class SecurityReportingTests(unittest.TestCase):
    def test_private_repository_never_enables_or_changes_visibility(self):
        calls = []
        def api(path, method='GET'):
            calls.append((path, method))
            return {'visibility': 'private'}
        self.assertFalse(verify(api, enable=True)['verified'])
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][1], 'GET')

    def test_public_repository_enables_then_reads_back_the_setting(self):
        calls = []
        def api(path, method='GET'):
            calls.append((path, method))
            if path.endswith('steamboat_net'):
                return {'visibility': 'public'}
            return {'enabled': len(calls) == 4}
        self.assertTrue(verify(api, enable=True)['verified'])
        self.assertEqual([method for path, method in calls], ['GET', 'GET', 'PUT', 'GET'])

    def test_public_disabled_setting_is_not_reported_as_verified(self):
        def api(path, method='GET'):
            return {'visibility': 'public'} if path.endswith('steamboat_net') else {'enabled': False}
        self.assertFalse(verify(api)['verified'])
