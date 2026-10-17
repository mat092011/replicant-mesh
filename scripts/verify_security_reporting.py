"""Verify GitHub private reporting without changing repository visibility."""

import argparse
import json
import subprocess


REPOSITORY = 'mat092011/steamboat_net'


def github(path, method='GET'):
    result = subprocess.run(['gh', 'api', '--method', method, path],
                            check=True, capture_output=True, text=True)
    return json.loads(result.stdout) if result.stdout.strip() else {}


def verify(api=github, enable=False):
    repository = api('repos/' + REPOSITORY)
    report = {'repository': REPOSITORY, 'visibility': repository['visibility'],
              'report_url': f'https://github.com/{REPOSITORY}/security/advisories/new'}
    if repository['visibility'] != 'public':
        return {**report, 'verified': False, 'status': 'blocked_private_repository',
                'reason': 'GitHub private vulnerability reporting requires a public repository'}
    endpoint = 'repos/' + REPOSITORY + '/private-vulnerability-reporting'
    status = api(endpoint)
    if enable and not status.get('enabled'):
        api(endpoint, method='PUT')
        status = api(endpoint)
    return {**report, 'verified': status.get('enabled') is True,
            'status': 'enabled' if status.get('enabled') is True else 'disabled',
            'verification_scope': 'repository setting; no test report sent'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--enable', action='store_true',
                        help='Enable reporting only if the repository is already public')
    args = parser.parse_args()
    report = verify(enable=args.enable)
    print(json.dumps(report, indent=2))
    return int(not report['verified'])


if __name__ == '__main__':
    raise SystemExit(main())
