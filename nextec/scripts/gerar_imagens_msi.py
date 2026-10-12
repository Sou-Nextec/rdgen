"""Gera as imagens padrão do instalador MSI (WixUI) a partir do logo Nextec.

Uso: python nextec/scripts/gerar_imagens_msi.py
Saída: nextec/branding/WixUIDialogBmp.bmp (493x312) e WixUIBannerBmp.bmp (493x58), BMP 24 bits.
"""
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

BASE = Path(__file__).resolve().parent.parent / 'branding'
ROXO = (76, 0, 255)
CLARO = (255, 255, 255)
PAINEL = (243, 240, 255)
TEXTO = (40, 30, 90)


def fonte(tamanho, negrito=False):
    for nome in (('segoeuib.ttf' if negrito else 'segoeui.ttf'), ('DejaVuSans-Bold.ttf' if negrito else 'DejaVuSans.ttf')):
        try:
            return ImageFont.truetype(nome, tamanho)
        except OSError:
            continue
    return ImageFont.load_default()


def logo(lado):
    with Image.open(BASE / 'logo.png') as origem:
        return origem.convert('RGBA').resize((lado, lado), Image.LANCZOS)


def colar(tela, simbolo, x, y):
    tela.paste(simbolo, (x, y), simbolo)


def dialogo():
    tela = Image.new('RGB', (493, 312), CLARO)
    d = ImageDraw.Draw(tela)
    d.rectangle((0, 0, 163, 311), fill=PAINEL)
    d.rectangle((163, 0, 164, 311), fill=ROXO)
    colar(tela, logo(112), 26, 70)
    texto = 'Nextec'
    f = fonte(26, True)
    largura = d.textlength(texto, font=f)
    d.text(((164 - largura) / 2, 192), texto, font=f, fill=ROXO)
    sub = 'Connect'
    f2 = fonte(15)
    d.text(((164 - d.textlength(sub, font=f2)) / 2, 228), sub, font=f2, fill=TEXTO)
    return tela


def faixa():
    tela = Image.new('RGB', (493, 58), CLARO)
    d = ImageDraw.Draw(tela)
    d.rectangle((0, 56, 492, 57), fill=ROXO)
    colar(tela, logo(40), 493 - 40 - 12, 8)
    return tela


if __name__ == '__main__':
    dialogo().save(BASE / 'WixUIDialogBmp.bmp', format='BMP')
    faixa().save(BASE / 'WixUIBannerBmp.bmp', format='BMP')
