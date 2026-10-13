param(
    [Parameter(Mandatory)][string]$MsiPath,
    [Parameter(Mandatory)][string]$PortablePath,
    [Parameter(Mandatory)][string]$OutputPath,
    [Parameter(Mandatory)][string]$DisplayName,
    # Nome do EXE portatil extraido; vazio = o nome do app (DisplayName). Qualquer nome vale, nada e fixo.
    [string]$PortableName = ''
)
$ErrorActionPreference = 'Stop'
if (!(Test-Path -LiteralPath $MsiPath)) { throw 'MSI payload missing' }
if (!(Test-Path -LiteralPath $PortablePath)) { throw 'Portable payload missing' }
if (!$PortableName) { $PortableName = $DisplayName }
$PortableName = ($PortableName -replace '[^A-Za-z0-9_-]', '')
if (!$PortableName) { $PortableName = 'App' }
$compiler = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if (!(Test-Path -LiteralPath $compiler)) { throw '.NET Framework C# compiler unavailable' }
$hash = (Get-FileHash -LiteralPath $MsiPath -Algorithm SHA256).Hash.ToLowerInvariant()
$portableHash = (Get-FileHash -LiteralPath $PortablePath -Algorithm SHA256).Hash.ToLowerInvariant()
$source = Join-Path $env:RUNNER_TEMP 'nextec-setup-wrapper.cs'
$manifest = Join-Path $env:RUNNER_TEMP 'nextec-setup-wrapper.manifest'
@'
using System;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Security.Cryptography;
using System.Text;
using System.Windows.Forms;

internal static class NextecSetup {
    private const string ExpectedHash = "__HASH__";
    private const string PortableHash = "__PORTABLE_HASH__";
    private static bool Administrator() {
        return new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);
    }
    private static void Extract(string resource, string path, string expected) {
        using (var input = Assembly.GetExecutingAssembly().GetManifestResourceStream(resource)) {
            if (input == null) throw new InvalidDataException("Arquivo incorporado ausente.");
            using (var output = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None)) input.CopyTo(output);
        }
        string actual;
        using (var sha = SHA256.Create()) using (var input = File.OpenRead(path))
            actual = BitConverter.ToString(sha.ComputeHash(input)).Replace("-", "").ToLowerInvariant();
        if (!String.Equals(actual, expected, StringComparison.Ordinal)) throw new InvalidDataException("Falha na verificação de integridade.");
    }
    [STAThread]
    private static int Main(string[] args) {
        string folder = null;
        try {
            bool install = args.Length == 1 && args[0] == "--install";
            if (!install) {
                Application.EnableVisualStyles();
                using (var choice = new Form()) {
                    choice.Text = "__DISPLAY__";
                    choice.Width = 440; choice.Height = 235;
                    choice.FormBorderStyle = FormBorderStyle.FixedDialog;
                    choice.MaximizeBox = false; choice.MinimizeBox = false;
                    choice.StartPosition = FormStartPosition.CenterScreen;
                    var label = new Label { Left = 22, Top = 20, Width = 385, Height = 65,
                        Text = "Como deseja usar o __DISPLAY__?\nExecute agora para suporte avulso ou instale para manter o aplicativo atualizado nesta máquina." };
                    var portable = new Button { Text = "Executar sem instalar", Left = 22, Top = 98, Width = 180, Height = 42, DialogResult = DialogResult.No };
                    var setup = new Button { Text = "Instalar nesta máquina", Left = 216, Top = 98, Width = 185, Height = 42, DialogResult = DialogResult.Yes };
                    var cancel = new Button { Text = "Cancelar", Left = 300, Top = 153, Width = 100, DialogResult = DialogResult.Cancel };
                    choice.Controls.AddRange(new Control[] { label, portable, setup, cancel });
                    choice.AcceptButton = portable; choice.CancelButton = cancel;
                    var answer = choice.ShowDialog();
                    if (answer != DialogResult.Yes && answer != DialogResult.No) return 0;
                    install = answer == DialogResult.Yes;
                }
            }
            if (install && !Administrator()) {
                var elevated = Process.Start(new ProcessStartInfo(Assembly.GetExecutingAssembly().Location, "--install") { UseShellExecute = true, Verb = "runas" });
                elevated.WaitForExit();
                return elevated.ExitCode;
            }
            var sid = WindowsIdentity.GetCurrent().User;
            folder = Path.Combine(Environment.GetFolderPath(install ? Environment.SpecialFolder.CommonApplicationData : Environment.SpecialFolder.LocalApplicationData),
                "Nextec", "Setup", Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(folder);
            var acl = new DirectorySecurity();
            acl.SetAccessRuleProtection(true, false);
            foreach (var identity in new [] {
                new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
                new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null) }) {
                acl.AddAccessRule(new FileSystemAccessRule(identity, FileSystemRights.FullControl,
                    InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                    PropagationFlags.None, AccessControlType.Allow));
            }
            if (!install) acl.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
            Directory.SetAccessControl(folder, acl);
            if (!install) {
                string portable = Path.Combine(folder, "__EXE__.exe");
                Extract("Nextec.Client.portable.exe", portable, PortableHash);
                var client = Process.Start(new ProcessStartInfo(portable) { UseShellExecute = false, WorkingDirectory = folder });
                client.WaitForExit();
                return client.ExitCode;
            }
            string msi = Path.Combine(folder, "client.msi");
            Extract("Nextec.Client.msi", msi, ExpectedHash);
            string log = Path.Combine(folder, "instalacao.log");
            var process = Process.Start(new ProcessStartInfo("msiexec.exe", "/i \"" + msi + "\" /L*v \"" + log + "\"") { UseShellExecute = false });
            process.WaitForExit();
            if (process.ExitCode != 0 && process.ExitCode != 3010) {
                // Preserve diagnostics on failure; the folder is restricted to SYSTEM/admins.
                folder = null;
                throw new InvalidOperationException("A instalação falhou (código " + process.ExitCode + "). Log: " + log);
            }
            return process.ExitCode;
        } catch (Exception ex) {
            MessageBox.Show(ex.Message, "__DISPLAY__ Setup", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return 1;
        } finally {
            if (folder != null) { try { Directory.Delete(folder, true); } catch { } }
        }
    }
}
'@.Replace('__HASH__', $hash).Replace('__PORTABLE_HASH__', $portableHash).Replace('__DISPLAY__', ($DisplayName -replace '[^A-Za-z0-9 _-]', '')).Replace('__EXE__', $PortableName) | Set-Content -LiteralPath $source -Encoding UTF8
@'
<?xml version="1.0" encoding="utf-8"?>
<assembly manifestVersion="1.0" xmlns="urn:schemas-microsoft-com:asm.v1">
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3"><security><requestedPrivileges><requestedExecutionLevel level="asInvoker" uiAccess="false" /></requestedPrivileges></security></trustInfo>
</assembly>
'@ | Set-Content -LiteralPath $manifest -Encoding UTF8
$resource = [IO.Path]::GetFullPath($MsiPath)
$output = [IO.Path]::GetFullPath($OutputPath)
Remove-Item -LiteralPath $output -Force -ErrorAction SilentlyContinue
$portableResource = [IO.Path]::GetFullPath($PortablePath)
& $compiler /nologo /target:winexe /platform:anycpu "/out:$output" "/win32manifest:$manifest" /reference:System.Windows.Forms.dll /reference:System.Security.dll "/resource:$resource,Nextec.Client.msi" "/resource:$portableResource,Nextec.Client.portable.exe" $source
if ($LASTEXITCODE -ne 0 -or !(Test-Path -LiteralPath $output)) { throw 'Could not compile the Nextec EXE installer wrapper' }
Write-Output "Built $output with MSI SHA-256 $hash"

