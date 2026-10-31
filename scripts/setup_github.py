#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Run in the owner's terminal to complete setup when agent Git/network access is blocked.

Creates a public EternalTimes/Yachiyo repository only if it is absent. Never
changes an existing repository's visibility, overwrites history or prints tokens.
"""

from pathlib import Path
import json
import os
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
OWNER = 'EternalTimes'
REPO = f'{OWNER}/Yachiyo'
URL = f'https://github.com/{REPO}.git'
GH = '/opt/homebrew/bin/gh' if Path('/opt/homebrew/bin/gh').is_file() else shutil.which('gh')
GIT = shutil.which('git')


def run(args, *, data=None, check=True):
    result = subprocess.run(args, cwd=ROOT, input=data, text=True, capture_output=True)
    if check and result.returncode:
        raise RuntimeError(f'Command failed: {args[0]} {args[1]}\n{result.stderr.strip()}')
    return result


def api(endpoint, method='GET', body=None, check=True):
    args = [GH, 'api', endpoint, '--method', method]
    if body is not None:
        args += ['--input', '-']
    return run(args, data=json.dumps(body) if body is not None else None, check=check)


def main():
    if not GH or not GIT:
        raise RuntimeError('Install Git and GitHub CLI first.')
    run([sys.executable, '-B', 'scripts/check_repository.py'])
    user = json.loads(api('user').stdout)
    if user['login'].lower() != OWNER.lower():
        raise RuntimeError(f'Expected GitHub account {OWNER}; no changes made.')
    # Query before creating anything; distinguish a missing repo from connection errors.
    response = api(f'repos/{REPO}', check=False)
    if response.returncode and 'HTTP 404' not in response.stderr:
        raise RuntimeError('Cannot inspect the target repository. Check gh authentication and connectivity.')
    remote = json.loads(response.stdout) if response.returncode == 0 else None
    if remote and not remote.get('permissions', {}).get('admin'):
        raise RuntimeError('Repository administrator permission is required.')
    if not (ROOT / '.git').exists():
        run([GIT, 'init', '-b', 'main', '--object-format=sha1'])
    top = Path(run([GIT, 'rev-parse', '--show-toplevel']).stdout.strip()).resolve()
    if top != ROOT:
        raise RuntimeError('The project must be its own Git working tree.')
    if run([GIT, 'branch', '--show-current']).stdout.strip() != 'main':
        raise RuntimeError('Switch to main manually before setup; no branch changes were made.')
    for key, value in [('user.name', OWNER),
                       ('user.email', f'{user["id"]}+{OWNER}@users.noreply.github.com')]:
        if run([GIT, 'config', '--local', '--get', key], check=False).returncode:
            run([GIT, 'config', '--local', key, value])
    existing = run([GIT, 'remote', 'get-url', 'origin'], check=False)
    if existing.returncode == 0 and existing.stdout.strip() not in [URL, f'git@github.com:{REPO}.git']:
        raise RuntimeError('An unrelated origin exists; it was not changed.')
    head = run([GIT, 'rev-parse', '--verify', 'HEAD'], check=False)
    if head.returncode:
        # Stage only known project material; never add personal CA inventories or local data.
        tracked = ['README.md', 'AGENTS.md', 'CONTRIBUTING.md', 'LICENSE',
                   '.gitignore', '.gitattributes', '.editorconfig', 'docs', '.github', 'scripts']
        run([GIT, 'add', '--', *tracked])
        staged = run([GIT, 'diff', '--cached', '--name-only']).stdout.splitlines()
        for name in staged:
            p = Path(name)
            if any(part in {'private', 'local', '.venv', 'node_modules', '__pycache__'} for part in p.parts) or p.suffix in {'.key', '.p12', '.pfx', '.log'}:
                raise RuntimeError(f'Review staged sensitive/local file before proceeding: {name}')
        run([GIT, 'commit', '-m', 'chore: initialize Yachiyo planning and repository automation'])
    elif run([GIT, 'status', '--porcelain']).stdout.strip():
        raise RuntimeError('Existing history has uncommitted changes; review and commit them before setup.')
    if not remote:
        remote = json.loads(api('user/repos', 'POST', {
            'name': 'Yachiyo', 'description': 'A macOS-first cross-platform proxy core. Planning stage. AGPL-3.0-only.',
            'private': False, 'auto_init': False, 'has_issues': True, 'has_wiki': False,
        }).stdout)
    if existing.returncode:
        run([GIT, 'remote', 'add', 'origin', URL])
    # Keep the credential helper scoped to this one push; do not alter global Git settings.
    push = [GIT, '-c', 'credential.helper=', '-c', f'credential.helper=!{GH} auth git-credential',
            'push', '-u', 'origin', 'main']
    run(push)
    api(f'repos/{REPO}', 'PATCH', {
        'default_branch': 'main', 'has_issues': True, 'has_wiki': False,
        'allow_squash_merge': True, 'allow_merge_commit': False, 'allow_rebase_merge': False,
        'delete_branch_on_merge': True, 'allow_auto_merge': False,
    })
    api(f'repos/{REPO}/actions/permissions/workflow', 'PUT', {
        'default_workflow_permissions': 'read', 'can_approve_pull_request_reviews': False,
    })
    api(f'repos/{REPO}/vulnerability-alerts', 'PUT')
    # Single maintainer: PRs and CI required, but zero external approvals to avoid deadlock.
    api(f'repos/{REPO}/branches/main/protection', 'PUT', {
        'required_status_checks': {'strict': True, 'contexts': ['Repository checks']},
        'enforce_admins': True, 'restrictions': None,
        'required_pull_request_reviews': {
            'dismiss_stale_reviews': True, 'require_code_owner_reviews': False,
            'required_approving_review_count': 0,
        },
        'required_linear_history': True, 'allow_force_pushes': False, 'allow_deletions': False,
        'required_conversation_resolution': True,
    })
    # Read back externally stored settings. The CI run itself may still be pending.
    verify = json.loads(api(f'repos/{REPO}/branches/main/protection').stdout)
    if 'Repository checks' not in verify['required_status_checks']['contexts']:
        raise RuntimeError('Required CI check was not confirmed.')
    settings = json.loads(api(f'repos/{REPO}/actions/permissions/workflow').stdout)
    if settings['default_workflow_permissions'] != 'read':
        raise RuntimeError('Read-only Actions permission was not confirmed.')
    run([GIT, 'status', '--short'])
    print(f'Configured: https://github.com/{REPO}')
    print('Configured: main PR/CI protection, squash-only merges, read-only Actions, Dependabot config.')
    print(f'Check the first workflow run: {GH} run list --repo {REPO} --limit 5')
    print('No third-party AI bot, paid service, automatic merge, or runtime release was enabled.')


if __name__ == '__main__':
    try:
        main()
    except (RuntimeError, ValueError, OSError) as exc:
        print(f'Setup stopped: {exc}', file=sys.stderr)
        raise SystemExit(1)
