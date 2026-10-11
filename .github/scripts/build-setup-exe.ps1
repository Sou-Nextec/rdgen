param(
    [Parameter(Mandatory)][string]$MsiPath,
    [Parameter(Mandatory)][string]$OutputPath,
    [Parameter(Mandatory)][string]$DisplayName
)
$ErrorActionPreference = 'Stop'
if (!(Test-Path -LiteralPath $MsiPath)) { throw 'MSI payload missing' }
$compiler = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if (!(Test-Path -LiteralPath $compiler)) { throw '.NET Framework C# compiler unavailable' }
$hash = (Get-FileHash -LiteralPath $MsiPath -Algorithm SHA256).Hash.ToLowerInvariant()
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
    private static int Main() {
        string folder = null;
        try {
            var sid = WindowsIdentity.GetCurrent().User;
            folder = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "Nextec", "Setup", Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(folder);
            var acl = new DirectorySecurity();
            acl.SetAccessRuleProtection(true, false);
            foreach (var identity in new [] {
                new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
                new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null), sid }) {
                acl.AddAccessRule(new FileSystemAccessRule(identity, FileSystemRights.FullControl,
                    InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                    PropagationFlags.None, AccessControlType.Allow));
            }
            Directory.SetAccessControl(folder, acl);
            string msi = Path.Combine(folder, "client.msi");
            using (var input = Assembly.GetExecutingAssembly().GetManifestResourceStream("Nextec.Client.msi")) {
                if (input == null) throw new InvalidDataException("MSI payload is missing.");
                using (var output = new FileStream(msi, FileMode.CreateNew, FileAccess.Write, FileShare.None)) input.CopyTo(output);
            }
            string actual;
            using (var sha = SHA256.Create()) using (var input = File.OpenRead(msi))
                actual = BitConverter.ToString(sha.ComputeHash(input)).Replace("-", "").ToLowerInvariant();
            if (!String.Equals(actual, ExpectedHash, StringComparison.Ordinal)) throw new InvalidDataException("MSI integrity check failed.");
            var process = Process.Start(new ProcessStartInfo("msiexec.exe", "/i \"" + msi + "\"") { UseShellExecute = false });
            process.WaitForExit();
            if (process.ExitCode != 0 && process.ExitCode != 3010) throw new InvalidOperationException("Installer failed with code " + process.ExitCode + ".");
            return process.ExitCode;
        } catch (Exception ex) {
            MessageBox.Show(ex.Message, "__DISPLAY__ Setup", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return 1;
        } finally {
            if (folder != null) { try { Directory.Delete(folder, true); } catch { } }
        }
    }
}
'@.Replace('__HASH__', $hash).Replace('__DISPLAY__', $DisplayName -replace '[^A-Za-z0-9 _-]', '') | Set-Content -LiteralPath $source -Encoding UTF8
@'
<?xml version="1.0" encoding="utf-8"?>
<assembly manifestVersion="1.0" xmlns="urn:schemas-microsoft-com:asm.v1">
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3"><security><requestedPrivileges><requestedExecutionLevel level="requireAdministrator" uiAccess="false" /></requestedPrivileges></security></trustInfo>
</assembly>
'@ | Set-Content -LiteralPath $manifest -Encoding UTF8
$resource = [IO.Path]::GetFullPath($MsiPath)
$output = [IO.Path]::GetFullPath($OutputPath)
Remove-Item -LiteralPath $output -Force -ErrorAction SilentlyContinue
& $compiler /nologo /target:winexe /platform:anycpu /out:$output /win32manifest:$manifest /reference:System.Windows.Forms.dll /reference:System.Security.dll /resource:$resource,Nextec.Client.msi $source
if ($LASTEXITCODE -ne 0 -or !(Test-Path -LiteralPath $output)) { throw 'Could not compile the Nextec EXE installer wrapper' }
Write-Output "Built $output with MSI SHA-256 $hash"

