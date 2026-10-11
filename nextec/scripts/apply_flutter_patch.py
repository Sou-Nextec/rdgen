"""Apply a Flutter SDK patch once, including SDKs restored from Actions cache."""
import subprocess
import sys
from pathlib import Path


def apply_patch(sdk, patch):
    patch = str(Path(patch).resolve())
    git = ['git', '-c', 'safe.directory=*', '-C', str(sdk), 'apply']
    def check(*args):
        return subprocess.run(git + list(args) + [patch], capture_output=True, text=True)
    forward = check('--check')
    if forward.returncode == 0:
        subprocess.run(git + [patch], check=True)
        return 'applied'
    if check('--reverse', '--check').returncode == 0:
        return 'already applied'
    raise RuntimeError('Flutter patch is incompatible with this SDK; no changes applied.\n' + forward.stderr)


if __name__ == '__main__':
    try:
        print('Flutter patch: ' + apply_patch(sys.argv[1], sys.argv[2]))
    except (RuntimeError, subprocess.CalledProcessError) as exc:
        sys.exit(str(exc))
