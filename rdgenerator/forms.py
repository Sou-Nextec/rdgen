import re

from django import forms
from PIL import Image

# App/company names are interpolated into single/double-quoted bash sed
# scripts in every generator workflow: & \ | corrupt the substitution
# silently, ' " $ ` break shell quoting, CR/LF break sed addressing.
UNSAFE_NAME_CHARS = re.compile(r'[&\\|\'"$`\r\n]')

# O instalador do RustDesk (ui_interface.rs) recusa instalar se o nome do app nao
# casar com [a-zA-Z0-9-]+. Com espaco ou acento o .exe abre, mas o botao Instalar
# fecha o app sem nenhuma mensagem. Barramos aqui, antes de gastar 30 a 45 min de build.
APP_NAME_ALLOWED = re.compile(r'^[A-Za-z0-9-]+$')

class GenerateForm(forms.Form):
    sh_secret_field = forms.CharField(required=False)
    #Platform
    platform = forms.ChoiceField(choices=[('windows','Windows 64 bits'),('linux','Linux')], initial='windows')
    version = forms.ChoiceField(choices=[('master','Desenvolvimento (nightly)'),('1.5.0','1.5.0'),('1.4.9','1.4.9'),('1.4.8','1.4.8'),('1.4.7','1.4.7'),('1.4.6','1.4.6'),('1.4.5','1.4.5'),('1.4.4','1.4.4'),('1.4.3','1.4.3'),('1.4.2','1.4.2'),('1.4.1','1.4.1'),('1.4.0','1.4.0')], initial='1.5.0', label='Versão-base do RustDesk')
    help_text="A versão de desenvolvimento traz os recursos mais novos e pode ser menos estável."
    delayFix = forms.BooleanField(initial=True, required=False)

    #General
    exename = forms.CharField(label="Nome do arquivo de instalação", required=True)
    appname = forms.CharField(label="Nome exibido no aplicativo", required=False)
    direction = forms.ChoiceField(widget=forms.RadioSelect, choices=[
        ('incoming', 'Receber conexões'),
        ('outgoing', 'Iniciar conexões'),
        ('both', 'Receber e iniciar conexões')
    ], initial='both')
    installation = forms.ChoiceField(label="Instalação", choices=[
        ('installationY', 'Permitir instalação'),
        ('installationN', 'Desativar instalação')
    ], initial='installationY')
    settings = forms.ChoiceField(label="Configurações", choices=[
        ('settingsY', 'Permitir configurações'),
        ('settingsN', 'Desativar configurações')
    ], initial='settingsY')
    androidappid = forms.CharField(label="ID do aplicativo Android", required=False)

    #Custom Server
    serverIP = forms.CharField(label="Servidor de ID", required=False)
    serverPort = forms.CharField(label="Porta do servidor de ID", required=False)
    apiServer = forms.CharField(label="Endereço da API", required=False)
    # mascarada como senha: nao aparece em captura de tela (e o navegador nao tenta preencher com a senha do login)
    key = forms.CharField(label="Chave pública", required=False, widget=forms.PasswordInput(render_value=True, attrs={'autocomplete': 'new-password'}))
    urlLink = forms.CharField(label="Endereço dos links", required=False)
    downloadLink = forms.CharField(label="Endereço para baixar atualizações", required=False)
    compname = forms.CharField(label="Empresa",required=False)

    #Visual
    iconfile = forms.FileField(label="Ícone do aplicativo (PNG)", required=False, widget=forms.FileInput(attrs={'accept': 'image/png'}))
    logofile = forms.FileField(label="Logo do aplicativo (PNG)", required=False, widget=forms.FileInput(attrs={'accept': 'image/png'}))
    privacyfile = forms.FileField(label="Tela de privacidade (PNG)", required=False, widget=forms.FileInput(attrs={'accept': 'image/png'}))
    iconbase64 = forms.CharField(required=False)
    logobase64 = forms.CharField(required=False)
    privacybase64 = forms.CharField(required=False)
    theme = forms.ChoiceField(choices=[
        ('light', 'Claro'),
        ('dark', 'Escuro'),
        ('system', 'Seguir o sistema')
    ], initial='system')
    themeDorO = forms.ChoiceField(choices=[('default', 'Padrão'),('override', 'Obrigatório')], initial='default')

    #Security
    passApproveMode = forms.ChoiceField(choices=[('password','Aceitar com senha'),('click','Aceitar com confirmação'),('password-click','Aceitar com senha ou confirmação')],initial='password-click')
    permanentPassword = forms.CharField(widget=forms.PasswordInput(), required=False)
    #runasadmin = forms.ChoiceField(choices=[('false','No'),('true','Yes')], initial='false')
    denyLan = forms.BooleanField(initial=False, required=False)
    enableDirectIP = forms.BooleanField(initial=False, required=False)
    #ipWhitelist = forms.BooleanField(initial=False, required=False)
    autoClose = forms.BooleanField(initial=False, required=False)

    #Permissions
    permissionsDorO = forms.ChoiceField(choices=[('default', 'Padrão editável pelo cliente'),('override', 'Obrigatório')], initial='default')
    permissionsType = forms.ChoiceField(choices=[('custom', 'Personalizado'),('full', 'Acesso total'),('view','Somente visualizar')], initial='custom')
    enableKeyboard =  forms.BooleanField(initial=True, required=False)
    enableClipboard = forms.BooleanField(initial=True, required=False)
    enableFileTransfer = forms.BooleanField(initial=True, required=False)
    enableAudio = forms.BooleanField(initial=True, required=False)
    enableTCP = forms.BooleanField(initial=True, required=False)
    enableRemoteRestart = forms.BooleanField(initial=True, required=False)
    enableRecording = forms.BooleanField(initial=True, required=False)
    enableBlockingInput = forms.BooleanField(initial=True, required=False)
    enableRemoteModi = forms.BooleanField(initial=False, required=False)
    hidecm = forms.BooleanField(initial=False, required=False)
    enablePrinter = forms.BooleanField(initial=True, required=False)
    enableCamera = forms.BooleanField(initial=True, required=False)
    enableTerminal = forms.BooleanField(initial=True, required=False)

    #Other
    removeWallpaper = forms.BooleanField(initial=True, required=False)

    defaultManual = forms.CharField(widget=forms.Textarea, required=False)
    overrideManual = forms.CharField(widget=forms.Textarea, required=False)

    #custom added features
    xOffline = forms.BooleanField(initial=False, required=False)
    removeNewVersionNotif = forms.BooleanField(initial=False, required=False)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Padroes Nextec: com a trava ligada, o servidor/chave/API ficam fixos (o servidor tambem reforca ao gerar)
        from . import nextec
        if nextec.is_locked():
            defaults = nextec.server_defaults()
            if self.is_bound:
                # modelo carregado (ou POST antigo) com porta/servidor diferentes: vale o fixo, senao o campo travado
                # ficava com um valor recusado e sem como corrigir
                self.data = self.data.copy()
                for name in nextec.locked_fields():
                    self.data[name] = defaults.get(name, '')
            for name in nextec.locked_fields():
                if name in self.fields:
                    self.fields[name].widget.attrs['readonly'] = 'readonly'
                    self.fields[name].widget.attrs['title'] = 'Fixo pela Nextec'
                    self.fields[name].required = False

    def clean_iconfile(self):
        image = self.cleaned_data['iconfile']
        if image:
            try:
                # Open the image using Pillow
                img = Image.open(image)

                # Check if the image is a PNG (optional, but good practice)
                if img.format != 'PNG':
                    raise forms.ValidationError("Envie uma imagem PNG.")

                # Get image dimensions
                width, height = img.size

                # Check for square dimensions
                if width != height:
                    raise forms.ValidationError("O ícone do aplicativo deve ser quadrado.")
                
                return image
            except OSError:  # Handle cases where the uploaded file is not a valid image
                raise forms.ValidationError("O arquivo de ícone é inválido.")
            except Exception as e: # Catch any other image processing errors
                raise forms.ValidationError(f"Não foi possível processar o ícone: {e}")

    def _reject_unsafe_name_chars(self, field):
        value = self.cleaned_data.get(field, '')
        if value and UNSAFE_NAME_CHARS.search(value):
            raise forms.ValidationError(
                "O texto contém caracteres não aceitos nos scripts de geração "
                "(& \\ | ' \" $ ` ou quebras de linha)."
            )
        return value

    def clean_appname(self):
        value = self._reject_unsafe_name_chars('appname')
        if value and not APP_NAME_ALLOWED.match(value):
            raise forms.ValidationError(
                "Use apenas letras sem acento, números e hífen, sem espaços. "
                "Exemplo: Nextec-Connect. O instalador do RustDesk recusa outros nomes."
            )
        return value

    def clean_serverPort(self):
        # O workflow deriva todo o bloco de portas a partir deste valor (relay = +1, websocket = +2 e +3).
        # 21117 (relay) no lugar de 21116 faz o app registrar no hbbr e ficar eternamente "nao esta pronto".
        value = (self.cleaned_data.get('serverPort') or '').strip()
        if not value:
            return value
        if not value.isdigit() or not (1 <= int(value) <= 65532):
            raise forms.ValidationError("Informe somente o número da porta do servidor de ID (padrão: 21116).")
        if int(value) in (21117, 21118, 21119):
            raise forms.ValidationError(
                "As portas 21117 a 21119 são do relay e do websocket, não do servidor de ID. "
                "Deixe em branco ou use 21116."
            )
        return value

    def clean_key(self):
        # Servidor Nextec configurado e sem chave (nem padrao, nem digitada): o build sairia com a chave publica do RustDesk
        # original e o app nunca falaria com o nosso servidor.
        value = (self.cleaned_data.get('key') or '').strip()
        from . import nextec
        if not value and nextec.is_configured():
            raise forms.ValidationError(
                "Informe a chave pública do servidor (painel: Ajustes do servidor > Dados do servidor)."
            )
        return value

    def clean_compname(self):
        return self._reject_unsafe_name_chars('compname')

    def clean(self):
        cleaned = super().clean()
        from .build_inputs import UNSAFE, ANDROID_ID
        # Manual settings are encoded as JSON/base64 and may contain multiple lines.
        for field in ('serverIP', 'key', 'apiServer', 'urlLink', 'downloadLink', 'androidappid'):
            value = cleaned.get(field, '')
            if value and UNSAFE.search(value):
                self.add_error(field, 'O valor contém caracteres não aceitos na geração.')
        value = cleaned.get('androidappid', '')
        if value and not ANDROID_ID.fullmatch(value):
            self.add_error('androidappid', 'O ID do aplicativo Android é inválido.')
        return cleaned


def validate_generate_params(data):
    """Use the form's choices, defaults and validation for JSON/internal callers."""
    if not isinstance(data, dict):
        return {}, {'body': 'Must be a JSON object.'}
    values, errors = {}, {}
    for name, field in GenerateForm.base_fields.items():
        if isinstance(field, forms.FileField):
            continue
        value = data.get(name, field.initial if field.initial is not None else '')
        if isinstance(field, forms.BooleanField):
            if name not in data:
                value = bool(field.initial)
            if not isinstance(value, bool):
                errors[name] = 'Must be a boolean.'
        elif not isinstance(value, str):
            errors[name] = 'Must be a string.'
        values[name] = value
    if errors:
        return {}, errors
    from . import nextec
    form = GenerateForm(nextec.apply(values), files={
        name: data[name] for name in ('iconfile', 'logofile', 'privacyfile') if data.get(name)
    })
    if not form.is_valid():
        return {}, {name: list(messages) for name, messages in form.errors.items()}
    return form.cleaned_data, {}
