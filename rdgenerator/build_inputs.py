"""Shared validation before exporting encrypted build values to GITHUB_ENV."""
import re
import uuid

FIELDS = set('server serverPort key apiServer custom uuid token iconlink_url iconlink_uuid '
             'iconlink_file logolink_url logolink_uuid logolink_file privacylink_url '
             'privacylink_uuid privacylink_file appname genurl urlLink downloadLink '
             'delayFix rdgen xOffline removeNewVersionNotif compname androidappid filename'.split())
UNSAFE = re.compile(r'[&\\|\'"$`\r\n\x00]')
APP_NAME = re.compile(r'[A-Za-z0-9-]+')
ANDROID_ID = re.compile(r'[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+')


def validate_build_inputs(payload):
    if not isinstance(payload, dict):
        raise ValueError('Build inputs must be an object')
    for key, value in payload.items():
        if key not in FIELDS:
            raise ValueError('Unknown build field')
        if not isinstance(value, str) or UNSAFE.search(value):
            raise ValueError(f'{key}: invalid build value')
        if not value:
            continue
        if key == 'appname' and not APP_NAME.fullmatch(value):
            raise ValueError('appname: use letters, digits and hyphen')
        if key == 'androidappid' and not ANDROID_ID.fullmatch(value):
            raise ValueError('androidappid: invalid application ID')
        if key == 'filename' and not re.fullmatch(r'[A-Za-z0-9_-]+', value):
            raise ValueError('filename: invalid name')
        if key == 'server' and not re.fullmatch(r'[A-Za-z0-9_.:\[\]-]+', value):
            raise ValueError('server: invalid hostname')
        if key == 'serverPort' and (not value.isdigit() or not 1 <= int(value) <= 65532):
            raise ValueError('serverPort: invalid ID server port')
        if key in ('custom', 'key') and not re.fullmatch(r'[A-Za-z0-9+/=_-]+', value):
            raise ValueError(f'{key}: invalid encoded value')
        if key == 'token' and not re.fullmatch(r'[A-Za-z0-9_-]+', value):
            raise ValueError('token: invalid build token')
        if key in ('apiServer', 'genurl', 'urlLink', 'downloadLink') or key.endswith('_url'):
            if not re.fullmatch(r'[A-Za-z0-9._:/?%#=+@~\[\]-]+', value):
                raise ValueError(f'{key}: invalid build URL')
        if key == 'uuid' or key.endswith('_uuid'):
            if value != 'false':
                try:
                    if str(uuid.UUID(value)) != value.lower():
                        raise ValueError('non-canonical UUID')
                except ValueError:
                    raise ValueError(f'{key}: invalid UUID')
        if key.endswith('_file') and value not in ('false', 'icon.png', 'logo.png', 'privacy.png'):
            raise ValueError(f'{key}: invalid image filename')
        if key in ('delayFix', 'rdgen', 'xOffline', 'removeNewVersionNotif') and value not in ('true', 'false'):
            raise ValueError(f'{key}: invalid boolean')
    return payload
