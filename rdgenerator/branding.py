"""Persistent, validated Nextec artwork used by future client builds."""
import os
from io import BytesIO
from pathlib import Path
from tempfile import NamedTemporaryFile

from PIL import Image, UnidentifiedImageError


MAX_UPLOAD_BYTES = 3 * 1024 * 1024
MAX_IMAGE_PIXELS = 16_000_000
ASSETS = {
    'icon': {'filename': 'icon.png', 'format': 'PNG', 'label': 'Ícone do aplicativo', 'dimensions': 'PNG quadrado, até 2048 × 2048 px', 'max_side': 2048},
    'logo': {'filename': 'logo.png', 'format': 'PNG', 'label': 'Logo padrão', 'dimensions': 'PNG, até 2048 × 2048 px', 'max_side': 2048},
    'logo_light': {'filename': 'logo_light.png', 'format': 'PNG', 'label': 'Logo para tema claro', 'dimensions': 'PNG, até 2048 × 2048 px; fundo transparente recomendado', 'max_side': 2048},
    'logo_dark': {'filename': 'logo_dark.png', 'format': 'PNG', 'label': 'Logo para tema escuro', 'dimensions': 'PNG, até 2048 × 2048 px; fundo transparente recomendado', 'max_side': 2048},
    'privacy': {'filename': 'privacy.png', 'format': 'PNG', 'label': 'Tela de privacidade', 'dimensions': 'PNG, até 1920 × 1080 px', 'max_width': 1920, 'max_height': 1080},
    'msi_dialog': {'filename': 'WixUIDialogBmp.bmp', 'format': 'BMP', 'label': 'Lateral do instalador MSI', 'dimensions': 'PNG ou BMP, exatamente 493 × 312 px', 'size': (493, 312)},
    'msi_banner': {'filename': 'WixUIBannerBmp.bmp', 'format': 'BMP', 'label': 'Faixa superior do instalador MSI', 'dimensions': 'PNG ou BMP, exatamente 493 × 58 px', 'size': (493, 58)},
}


def branding_dir():
    return Path(os.environ.get('NX_BRANDING_DIR', '/opt/rdgen/data/branding'))


def managed_path(kind):
    spec = ASSETS.get(kind)
    return branding_dir() / spec['filename'] if spec else None


def get_path(kind):
    """Return the managed upload, or the packaged Nextec default when available."""
    path = managed_path(kind)
    if path and path.is_file():
        return path
    if kind in ('icon', 'logo', 'logo_light', 'logo_dark', 'msi_dialog', 'msi_banner'):
        packaged = Path(__file__).resolve().parent.parent / 'nextec' / 'branding' / ASSETS[kind]['filename']
        return packaged if packaged.is_file() else None
    return None


def list_assets():
    rows = []
    for key, spec in ASSETS.items():
        path = get_path(key)
        rows.append({
            'key': key,
            **spec,
            'configured': bool(path),
            'managed': bool(path and path == managed_path(key)),
            'url': f'/get_artwork/{key}' if path else '',
            'revision': path.stat().st_mtime_ns if path else 0,
        })
    return rows


def save_upload(kind, uploaded):
    """Validate and normalize an image before replacing a managed brand asset."""
    spec = ASSETS.get(kind)
    if not spec:
        raise ValueError('Tipo de imagem desconhecido.')
    if not uploaded or uploaded.size <= 0 or uploaded.size > MAX_UPLOAD_BYTES:
        raise ValueError('O arquivo deve ter entre 1 byte e 3 MB.')
    try:
        raw = uploaded.read()
        with Image.open(BytesIO(raw)) as source:
            source.verify()
        with Image.open(BytesIO(raw)) as source:
            if source.width * source.height > MAX_IMAGE_PIXELS:
                raise ValueError('A imagem excede o limite de pixels permitido.')
            accepted = ('PNG', 'BMP') if spec['format'] == 'BMP' else (spec['format'],)
            if source.format not in accepted:
                raise ValueError(f"Envie um arquivo {' ou '.join(accepted)} para {spec['label'].lower()}.")
            if 'size' in spec and source.size != spec['size']:
                width, height = spec['size']
                raise ValueError(f"A imagem deve ter exatamente {width} × {height} px.")
            if 'max_side' in spec and max(source.size) > spec['max_side']:
                raise ValueError(f"A imagem deve ter no máximo {spec['max_side']} px por lado.")
            if ('max_width' in spec and source.width > spec['max_width']) or ('max_height' in spec and source.height > spec['max_height']):
                max_width = spec.get('max_width', spec.get('max_side'))
                max_height = spec.get('max_height', spec.get('max_side'))
                raise ValueError(f'A imagem deve ter no máximo {max_width} × {max_height} px.')
            if kind == 'icon' and source.width != source.height:
                raise ValueError('O ícone precisa ser quadrado.')
            source.load()
            image = source.convert('RGB') if spec['format'] == 'BMP' else source.convert('RGBA')
    except (UnidentifiedImageError, OSError, Image.DecompressionBombError) as exc:
        raise ValueError('O arquivo não é uma imagem válida.') from exc

    destination = managed_path(kind)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with NamedTemporaryFile(dir=destination.parent, suffix='.tmp', delete=False) as temporary:
        temporary_path = Path(temporary.name)
    try:
        image.save(temporary_path, format=spec['format'], optimize=(spec['format'] == 'PNG'))
        temporary_path.replace(destination)
    finally:
        temporary_path.unlink(missing_ok=True)
    return destination
