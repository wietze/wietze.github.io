---
layout: post
title: Save the Environment (Variable)
tldr: By manipulating environment variables on process level, it is possible to let trusted applications load arbitrary DLLs and execute malicious code. This post lists nearly 100 executables vulnerable to this type of DLL Hijacking on Windows 11 (21H2); it is demonstrated how this can achieved with just three lines of VBScript.
image: /assets/2022-08-16-vbscript-example.png
tags: [dll hijacking, environment variable, env variable, envvar, systemroot, windir, envvar dll hijacking, environment variable-based hijacking, hijacklibs]
js: true
tweet: 1559358985764933632
---

_This research was first presented at DEF CON 30; you can find the recording [here](https://www.youtube.com/watch?v=LxjnI5h_kls) and the slides [here](/literature/Beukema,%20WJB%20-%20Save%20The%20Environment%20(Variable).pdf)._

----

## Environment variables

Environment variables were introduced in the late 1970s in Unix V7 [[1], _p.99-101_] as an easy way to pass on information to a process. It proved popular: a few years later it was also adopted in PC DOS 2.0 [[2], _p.477_], which would ultimately evolve into the Windows operating system. Roughly forty years later, environment variables are still around in Windows - although other developments, such as the introduction of the Registry in Windows 3.1, have changed its role somewhat.

The concept of an environment variables is simple: a collection of key-value pairs is made available to a process when it starts, and can be used as part of the program flow. As the name suggests, these variables typically contain information about the operating system environment. For example, if environment variable `HOMEDRIVE` with value `C:` is given to a process, it might use that information to decide to store files to the `C:` drive, and not to any other drives.

[![Diagram showing the structure of a PEB](/assets/2022-08-16-peb-structure.svg)](/assets/2022-08-16-peb-structure.svg)
*Diagram showing where environment variables are stored within the Process Environment Block (PEB).*

Every process in Windows has an associated Process Environment Block (PEB), a data structure that contains all sorts of information that is made available to the process [[3]]. As shown in the diagram above, environment variables are part of that structure: all variable keys and values are stored in a single string, and can contain up to 32,767 (2<sup>15</sup>-1) characters in total [[4]].

Crucially, this means that environment variables can be changed from process to process. When a new process starts, the parent process is responsible for providing the environment variables; these will be included in the new process' PEB. In most cases, the parent will simply pass on the environment variables it received when it was started itself.

This begs the question where the most parent process gets its environment variables from. In Windows, you can set an environment variable on three[^i] different levels: System, User and Process [[5]]. Environment variables set on System level apply to all users; User-level variables apply only to the current user. Both are stored in the Registry, the former under HKLM, the latter under HKCU. When Windows is started, it first takes all System environment variables. When a user logs in, it then adds (and possibly overwrites) any User environment variables. For example, `HOMEDRIVE` may be set to `C:` on System level, but an individual user might have decided to set it to `D:`. When a new process is started in the context of this user, it will receive `HOMEDRIVE=D:` as environment variable. Finally, when an environment variable is set on Process level, it is changed within a single process, and although it could be passed on to all new child processes, it isn't as "persistent" as System- and User-level environment variables. A good example of this is running `set HOMEDRIVE=X:` within a Windows Command Prompt; any new processes started from this prompt will receive `HOMEDRIVE=X:` as environment variable, but if the prompt is closed and reopened, the `HOMEDRIVE` variable will be reset to its original value.

<!-- The reason for this is that environment variables (including their values) are provided by a process' parent upon creation. Typically, they are not 'refreshed' during the execution of a process.  -->

There are a number of environment variables defined by Windows out of the box. Although the values can be overwritten, these are typically set when Windows is installed, and are never changed. Various programs, including system components, rely on these variables; for example, some programs use `SYSTEMROOT` (or the older `WINDIR`) to get the path to the Windows folder, which is usually `C:\Windows`.

## Hijacking opportunities
As stated before, programs may rely on these 'standard' environment variables to determine paths to certain files. For example, it turns out there are quite a few programs that rely on `SYSTEMROOT` and `WINDIR` to load DLLs located in `C:\Windows\System32` folder. `hostname.exe` for example tries to load a DLL with the path `%SYSTEMROOT%\System32\mswsock.dll` when it is run; under normal circumstances, this will resolve to `C:\Windows\System32\mswsock.dll`. Because this is an absolute path, the DLL Search Order is not invoked, and therefore one might conclude this does not provide us with a DLL Hijacking opportunity [[6]].

Yet, because a variable is involved, this could still be exploited: if one were to change the value of `SYSTEMROOT` to `C:\Evil`, the program would try to load `C:\Evil\System32\mswsock.dll` instead. If an attacker puts a malicious DLL in that location, it would result in the legitimate `hostname.exe` being tricked into loading the attacker's DLL; therefore, this provides us with a new type of DLL Hijacking[^ii] after all.

It could be argued that performing this technique this is easier said than done. A major issue with changing the value of `SYSTEMROOT` on either System or User level, is that it would practically break the entire operating system. So many system components rely on `SYSTEMROOT` that many programs would fail to work properly if you point it to a directory that does not contain the DLLs they are expecting. It would result in an unstable system, or it may even cause the operating system to stop working altogether. In most cases, it would therefore defeat the purpose of performing the DLL Hijacking in the first place.

However, as we have seen, it is also possible to alter environment variables just on Process level. This means that only that single, new process will have the updated value (or, if it happens to create any child processes, those likely too). As such, other programs will remain unaffected, and the system should not become unstable as a result.

There are a number of advantages of this approach over other DLL Hijacking approaches [[6]]. For example, the vulnerable executable does not have to be moved around: simply changing the environment variable before executing the vulnerable program from its normal location will cause the malicious DLL to be loaded. Furthermore, because it is possible to start a program with altered environment variables without having to perform noisy operations such as file writes or registry changes, it is less likely detection mechanisms will pick up on the hijacking itself. Finally, there are various way in which one can start a new process with a changed environment variable. Next to doing it from a compiled executable, built-in scripting engines such as PowerShell, VBScript and JScript support this too.

[![Diagram showing the working of environment variable-based DLL Hijacking.](/assets/2022-08-16-env-dll-hijacking.svg)](/assets/2022-08-16-env-dll-hijacking.svg)
*Diagram showing the working of environment variable-based DLL Hijacking.*

The above diagram shows from a high level what successful environment variable-based DLL Hijacking might look like. The VBScript does not have to be particularly complicated; for example, the below code will suffice:

```vb
Set shell = WScript.CreateObject("WScript.Shell")
shell.Environment("Process")("SYSTEMROOT") = "C:\Evil"
shell.Exec("C:\windows\system32\hostname.exe")
```

On Windows 11, running this script after having created `C:\Evil\system32\mswsock.dll` will indeed let `hostname.exe` load the DLL, as demonstrated below:

[![Screenshot demonstrating environment variable-based DLL Hijacking using VBScript.](/assets/2022-08-16-vbscript-example.png)](/assets/2022-08-16-vbscript-example.png)
*An example showing the execution of a VBScript file resulting in the legitimate hostname.exe, located in C:\windows\system32, being executed and successfully loading a malicious version of mswsock.dll.*

Doing this in PowerShell can be achieved by a simple `$env:SYSTEMROOT="C:\Evil"` statement before calling the target process; however, as PowerShell will itself also use this new value, it may generate cause PowerShell to break in some instances. A more reliable way of starting a new process and only updating the environment variable of the new process, is as follows:

```powershell
$s = New-Object System.Diagnostics.ProcessStartInfo
$s.FileName="C:\windows\system32\hostname.exe"
$s.EnvironmentVariables.Remove("SYSTEMROOT")
$s.EnvironmentVariables.Add("SYSTEMROOT", "C:\Evil")
$s.UseShellExecute = $false
$p = New-Object System.Diagnostics.Process
$p.StartInfo = $s
$p.Start()
```

## Identifying vulnerable executables
To understand the scale of the problem that is introduced with this technique, it should be investigated how common being vulnerable to this type of DLL Hijacking is by testing against a larger group of executables. Limiting ourselves to signed executables in the `System32` folder on a standard Windows 11 installation, we have a test group of just over 600 executables.

A simple approach would be to set an interesting environment variable on process level, such as `SYSTEMROOT` or `WINDIR`, pointing it to a unique directory, and execute every executable in our test group (without any special command-line arguments). Using Procmon [[9]], attempted DLL loads located under our directory can be monitored efficiently. Although this immediately gives us many possible candidates, it does not provide us with any proof that if malicious DLL files were present, they would actually be loaded.

If one were to put custom DLL files in the provided location, and validate which ones are successfully loaded, it would provide us with better, practical evidence. In the case of `SYSTEMROOT` and `WINDIR`, which normally resolve to `C:\Windows`, this would mean over 20,000 'custom' DLL files would have to be compiled for the test to be as complete as it can be. Compiling custom DLLs is not as straight-forward as it may sound [[6]], let alone when several thousand DLLs have to be compiled.

In the approach taken for this research, the compiled DLL files will, upon being loaded, write a fingerprint file to disk, identifying which DLL was loaded by what process. If these 'implant' DLLs are all copied to the unique folder mentioned before, executing every executable in our test group should generate a number of fingerprint files being created; telling us exactly which processes are vulnerable, and which DLLs are involved.

Supporting code, which can be used to compile many DLLs at once for the purpose of DLL Hijacking, leveraging open-source tooling and using 'DLL export proxying' and 'DLL resource cloning' to maximise compatibility with the tested executables, can be found on GitHub [[10]]. A more thorough and technical explanation of the approach taken is provided there as well.

## Applications that are confirmed to be vulnerable

Having applied this methodology, the following table lists all executables in `C:\windows\system32` on Windows 11 (21H2) that are vulnerable to environment variable-based DLL Hijacking. The first column shows what environment variable was changed, the second column shows the vulnerable application and the third column shows what DLL was loaded from the altered location (relative to the environment variable). As explained in the previous section, these are not mere theoretical targets, these are **tested and confirmed to be working**. The list comprises 82 executables and 91 unique DLLs.

{:.data-table .env-table}
| Environment variable                                  | Executable                                    | DLL (relative to variable)                               |
|---------------------------------------------|----------------------------------------|------------------------------------------|
|%SYSTEMROOT%|AppHostRegistrationVerifier.exe|\system32\npmproxy.dll|
|%SYSTEMROOT%|ApplicationFrameHost.exe|\system32\ApplicationFrame.dll|
|%WINDIR%|BdeHdCfg.exe|\system32\dbghelp.dll|
|%SYSTEMROOT%|calc.exe|\system32\twinui.appcore.dll|
|%SYSTEMROOT%|calc.exe|\system32\propsys.dll|
|%SYSTEMROOT%|calc.exe|\system32\execmodelproxy.dll|
|%SYSTEMROOT%|calc.exe|\system32\windows.storage.dll|
|%SYSTEMROOT%|certreq.exe|\system32\NetworkExplorer.dll|
|%SYSTEMROOT%|certreq.exe|\system32\wpdshext.dll|
|%SYSTEMROOT%|certreq.exe|\system32\explorerframe.dll|
|%SYSTEMROOT%|certreq.exe|\system32\comdlg32.dll|
|%SYSTEMROOT%|certreq.exe|\system32\MMDevApi.dll|
|%SYSTEMROOT%|certreq.exe|\system32\p9np.dll|
|%SYSTEMROOT%|certreq.exe|\system32\cscobj.dll|
|%SYSTEMROOT%|certreq.exe|\system32\windows.storage.dll|
|%SYSTEMROOT%|certreq.exe|\system32\dataexchange.dll|
|%SYSTEMROOT%|certreq.exe|\system32\drprov.dll|
|%SYSTEMROOT%|certreq.exe|\system32\propsys.dll|
|%SYSTEMROOT%|certreq.exe|\system32\davclnt.dll|
|%SYSTEMROOT%|certreq.exe|\system32\windowscodecs.dll|
|%SYSTEMROOT%|certreq.exe|\system32\Windows.Storage.Search.dll|
|%SYSTEMROOT%|certreq.exe|\system32\ntlanman.dll|
|%SYSTEMROOT%|certreq.exe|\system32\shell32.dll|
|%SYSTEMROOT%|certreq.exe|\system32\cscui.dll|
|%SYSTEMROOT%|certreq.exe|\system32\StructuredQuery.dll|
|%SYSTEMROOT%|charmap.exe|\system32\dataexchange.dll|
|%SYSTEMROOT%|cleanmgr.exe|\system32\propsys.dll|
|%SYSTEMROOT%|CloudNotifications.exe|\system32\UIAnimation.dll|
|%SYSTEMROOT%|CompMgmtLauncher.exe|\system32\rsaenh.dll|
|%SYSTEMROOT%|CompMgmtLauncher.exe|\system32\SspiCli.dll|
|%SYSTEMROOT%|CompMgmtLauncher.exe|\system32\cscui.dll|
|%SYSTEMROOT%|CompMgmtLauncher.exe|\system32\propsys.dll|
|%SYSTEMROOT%|CompMgmtLauncher.exe|\system32\WindowsCodecs.dll|
|%SYSTEMROOT%|CompMgmtLauncher.exe|\system32\windowsudk.shellcommon.dll|
|%SYSTEMROOT%|CompMgmtLauncher.exe|\system32\cscobj.dll|
|%SYSTEMROOT%|CompMgmtLauncher.exe|\system32\XmlLite.dll|
|%SYSTEMROOT%|CompMgmtLauncher.exe|\system32\ntshrui.dll|
|%SYSTEMROOT%|CompMgmtLauncher.exe|\system32\twext.dll|
|%SYSTEMROOT%|CompMgmtLauncher.exe|\system32\windows.storage.dll|
|%SYSTEMROOT%|conhost.exe|\system32\msctf.dll|
|%SYSTEMROOT%|control.exe|\system32\StructuredQuery.dll|
|%SYSTEMROOT%|control.exe|\system32\windows.storage.dll|
|%SYSTEMROOT%|control.exe|\system32\propsys.dll|
|%SYSTEMROOT%|control.exe|\system32\MSWB7.dll|
|%SYSTEMROOT%|control.exe|\system32\explorerframe.dll|
|%SYSTEMROOT%|control.exe|\system32\shell32.dll|
|%SYSTEMROOT%|control.exe|\system32\Windows.Storage.Search.dll|
|%SYSTEMROOT%|cttune.exe|\system32\fastprox.dll|
|%SYSTEMROOT%|cttune.exe|\system32\wbemsvc.dll|
|%SYSTEMROOT%|cttune.exe|\system32\wbemprox.dll|
|%SYSTEMROOT%|curl.exe|\system32\mswsock.dll|
|%SYSTEMROOT%|ddodiag.exe|\system32\PROPSYS.dll|
|%SYSTEMROOT%|ddodiag.exe|\system32\FdDevQuery.dll|
|%WINDIR%|deploymentcsphelper.exe|\system32\dbghelp.dll|
|%SYSTEMROOT%|DeviceCensus.exe|\system32\IDStore.dll|
|%SYSTEMROOT%|DeviceCensus.exe|\system32\FlightSettings.dll|
|%SYSTEMROOT%|DeviceCensus.exe|\system32\npmproxy.dll|
|%SYSTEMROOT%|DeviceCensus.exe|\system32\wlidprov.dll|
|%SYSTEMROOT%|DeviceCensus.exe|\system32\sapi_onecore.dll|
|%SYSTEMROOT%|DeviceCensus.exe|\system32\MMDevApi.dll|
|%SYSTEMROOT%|DeviceCensus.exe|\system32\wbemprox.dll|
|%SYSTEMROOT%|DeviceCensus.exe|\system32\mswsock.dll|
|%SYSTEMROOT%|DeviceCensus.exe|\system32\wbemsvc.dll|
|%SYSTEMROOT%|DeviceCensus.exe|\system32\fastprox.dll|
|%SYSTEMROOT%|DevicePairingWizard.exe|\system32\xwtpw32.dll|
|%SYSTEMROOT%|DevicePairingWizard.exe|\system32\DevicePairing.dll|
|%SYSTEMROOT%|DevicePairingWizard.exe|\system32\xwizards.dll|
|%SYSTEMROOT%|dfrgui.exe|\system32\defragproxy.dll|
|%SYSTEMROOT%|dfrgui.exe|\system32\windows.storage.dll|
|%SYSTEMROOT%|dfrgui.exe|\system32\propsys.dll|
|%SYSTEMROOT%|dfrgui.exe|\system32\windowscodecs.dll|
|%SYSTEMROOT%|directxdatabaseupdater.exe|\system32\npmproxy.dll|
|%SYSTEMROOT%|DiskSnapshot.exe|\system32\rsaenh.dll|
|%WINDIR%|djoin.exe|\system32\dbghelp.dll|
|%WINDIR%|dnscacheugc.exe|\system32\dbghelp.dll|
|%SYSTEMROOT%|DpiScaling.exe|\system32\ndfapi.dll|
|%SYSTEMROOT%|DpiScaling.exe|\system32\IPHLPAPI.DLL|
|%SYSTEMROOT%|DpiScaling.exe|\system32\shell32.dll|
|%SYSTEMROOT%|DpiScaling.exe|\system32\wdi.dll|
|%SYSTEMROOT%|driverquery.exe|\system32\wbemsvc.dll|
|%SYSTEMROOT%|driverquery.exe|\system32\wbemprox.dll|
|%SYSTEMROOT%|driverquery.exe|\system32\fastprox.dll|
|%SYSTEMROOT%|explorer.exe|\system32\explorerframe.dll|
|%SYSTEMROOT%|explorer.exe|\system32\cscui.dll|
|%SYSTEMROOT%|explorer.exe|\system32\Windows.Storage.Search.dll|
|%SYSTEMROOT%|explorer.exe|\system32\propsys.dll|
|%SYSTEMROOT%|explorer.exe|\system32\StructuredQuery.dll|
|%SYSTEMROOT%|explorer.exe|\system32\WindowsCodecs.dll|
|%SYSTEMROOT%|explorer.exe|\system32\XmlLite.dll|
|%SYSTEMROOT%|explorer.exe|\system32\windows.storage.dll|
|%SYSTEMROOT%|explorer.exe|\system32\MSWB7.dll|
|%SYSTEMROOT%|explorer.exe|\system32\windowsudk.shellcommon.dll|
|%SYSTEMROOT%|FileHistory.exe|\system32\ncrypt.dll|
|%SYSTEMROOT%|FileHistory.exe|\system32\EFSUTIL.dll|
|%SYSTEMROOT%|FileHistory.exe|\system32\windows.storage.dll|
|%SYSTEMROOT%|FileHistory.exe|\system32\MPR.dll|
|%SYSTEMROOT%|FileHistory.exe|\system32\XmlLite.dll|
|%SYSTEMROOT%|FileHistory.exe|\system32\DSROLE.dll|
|%SYSTEMROOT%|FileHistory.exe|\system32\windowscodecs.dll|
|%SYSTEMROOT%|FileHistory.exe|\system32\rsaenh.dll|
|%SYSTEMROOT%|FileHistory.exe|\system32\wevtapi.dll|
|%SYSTEMROOT%|FileHistory.exe|\system32\fhcfg.dll|
|%SYSTEMROOT%|FileHistory.exe|\system32\msctf.dll|
|%SYSTEMROOT%|FileHistory.exe|\system32\explorerframe.dll|
|%SYSTEMROOT%|ftp.exe|\system32\napinsp.dll|
|%SYSTEMROOT%|ftp.exe|\system32\nlansp_c.dll|
|%SYSTEMROOT%|ftp.exe|\system32\winrnr.dll|
|%SYSTEMROOT%|ftp.exe|\system32\wshbth.dll|
|%SYSTEMROOT%|ftp.exe|\system32\mswsock.dll|
|%SYSTEMROOT%|ftp.exe|\system32\pnrpnsp.dll|
|%SYSTEMROOT%|FXSCOVER.exe|\system32\netprofm.dll|
|%SYSTEMROOT%|FXSCOVER.exe|\system32\propsys.dll|
|%SYSTEMROOT%|FXSCOVER.exe|\system32\npmproxy.dll|
|%SYSTEMROOT%|GamePanel.exe|\system32\UIAnimation.dll|
|%SYSTEMROOT%|GamePanel.exe|\system32\windowscodecs.dll|
|%SYSTEMROOT%|getmac.exe|\system32\fastprox.dll|
|%SYSTEMROOT%|getmac.exe|\system32\wbemprox.dll|
|%SYSTEMROOT%|getmac.exe|\system32\wbemsvc.dll|
|%SYSTEMROOT%|gpresult.exe|\system32\wbemprox.dll|
|%SYSTEMROOT%|HOSTNAME.EXE|\system32\napinsp.dll|
|%SYSTEMROOT%|HOSTNAME.EXE|\system32\nlansp_c.dll|
|%SYSTEMROOT%|HOSTNAME.EXE|\system32\pnrpnsp.dll|
|%SYSTEMROOT%|HOSTNAME.EXE|\system32\mswsock.dll|
|%SYSTEMROOT%|HOSTNAME.EXE|\system32\wshbth.dll|
|%SYSTEMROOT%|HOSTNAME.EXE|\system32\winrnr.dll|
|%WINDIR%|ieUnatt.exe|\system32\dbghelp.dll|
|%SYSTEMROOT%|licensingdiag.exe|\system32\wbemprox.dll|
|%SYSTEMROOT%|licensingdiag.exe|\system32\propsys.dll|
|%SYSTEMROOT%|licensingdiag.exe|\system32\rsaenh.dll|
|%SYSTEMROOT%|licensingdiag.exe|\system32\wbemsvc.dll|
|%SYSTEMROOT%|licensingdiag.exe|\system32\Windows.Storage.dll|
|%WINDIR%|licensingdiag.exe|\system32\LicensingDiagSpp.dll|
|%SYSTEMROOT%|licensingdiag.exe|\system32\fastprox.dll|
|%SYSTEMROOT%|logman.exe|\system32\wevtapi.dll|
|%SYSTEMROOT%|logman.exe|\system32\pla.dll|
|%SYSTEMROOT%|logman.exe|\system32\Cabinet.dll|
|%SYSTEMROOT%|logman.exe|\system32\pdh.dll|
|%SYSTEMROOT%|LogonUI.exe|\system32\logoncontroller.dll|
|%SYSTEMROOT%|lpksetup.exe|\system32\lpksetupproxyserv.dll|
|%SYSTEMROOT%|lpksetup.exe|\system32\rsaenh.dll|
|%SYSTEMROOT%|mblctr.exe|\system32\MMDevApi.dll|
|%SYSTEMROOT%|Microsoft.Uev.SyncController.exe|\system32\rsaenh.dll|
|%SYSTEMROOT%|Microsoft.Uev.SyncController.exe|\system32\npmproxy.dll|
|%SYSTEMROOT%|mobsync.exe|\system32\shell32.dll|
|%SYSTEMROOT%|msdt.exe|\system32\drprov.dll|
|%SYSTEMROOT%|msdt.exe|\system32\propsys.dll|
|%SYSTEMROOT%|msdt.exe|\system32\ntlanman.dll|
|%SYSTEMROOT%|msdt.exe|\system32\p9np.dll|
|%SYSTEMROOT%|msdt.exe|\system32\davclnt.dll|
|%SYSTEMROOT%|msdt.exe|\system32\windows.storage.dll|
|%SYSTEMROOT%|msinfo32.exe|\system32\wbemprox.dll|
|%SYSTEMROOT%|msinfo32.exe|\system32\fastprox.dll|
|%SYSTEMROOT%|msinfo32.exe|\system32\wbemsvc.dll|
|%SYSTEMROOT%|mstsc.exe|\system32\Windows.Storage.dll|
|%SYSTEMROOT%|mstsc.exe|\system32\shell32.dll|
|%SYSTEMROOT%|mstsc.exe|\system32\windowscodecs.dll|
|%SYSTEMROOT%|mstsc.exe|\system32\msctf.dll|
|%SYSTEMROOT%|mstsc.exe|\system32\explorerframe.dll|
|%WINDIR%|MuiUnattend.exe|\system32\dbghelp.dll|
|%WINDIR%|netbtugc.exe|\system32\dbghelp.dll|
|%WINDIR%|netiougc.exe|\system32\dbghelp.dll|
|%SYSTEMROOT%|Notepad.exe|\system32\cscobj.dll|
|%SYSTEMROOT%|Notepad.exe|\system32\dataexchange.dll|
|%SYSTEMROOT%|Notepad.exe|\system32\comdlg32.dll|
|%SYSTEMROOT%|Notepad.exe|\system32\NetworkExplorer.dll|
|%SYSTEMROOT%|Notepad.exe|\system32\MMDevApi.dll|
|%SYSTEMROOT%|Notepad.exe|\system32\drprov.dll|
|%SYSTEMROOT%|Notepad.exe|\system32\wpdshext.dll|
|%SYSTEMROOT%|Notepad.exe|\system32\shell32.dll|
|%SYSTEMROOT%|Notepad.exe|\system32\windowscodecs.dll|
|%SYSTEMROOT%|Notepad.exe|\system32\davclnt.dll|
|%SYSTEMROOT%|Notepad.exe|\system32\explorerframe.dll|
|%SYSTEMROOT%|Notepad.exe|\system32\p9np.dll|
|%SYSTEMROOT%|Notepad.exe|\system32\ntlanman.dll|
|%SYSTEMROOT%|Notepad.exe|\system32\Windows.Storage.Search.dll|
|%SYSTEMROOT%|Notepad.exe|\system32\ntshrui.dll|
|%SYSTEMROOT%|Notepad.exe|\system32\StructuredQuery.dll|
|%SYSTEMROOT%|Notepad.exe|\system32\propsys.dll|
|%SYSTEMROOT%|Notepad.exe|\system32\windows.storage.dll|
|%SYSTEMROOT%|Notepad.exe|\system32\cscui.dll|
|%SYSTEMROOT%|Notepad.exe|\system32\cabview.dll|
|%SYSTEMROOT%|nslookup.exe|\system32\mswsock.dll|
|%SYSTEMROOT%|phoneactivate.exe|\system32\rsaenh.dll|
|%WINDIR%|PnPUnattend.exe|\system32\dbghelp.dll|
|%SYSTEMROOT%|powershell.exe|\system32\windows.storage.dll|
|%SYSTEMROOT%|powershell.exe|\system32\propsys.dll|
|%SYSTEMROOT%|powershell.exe|\system32\p9np.dll|
|%SYSTEMROOT%|powershell.exe|\system32\davclnt.dll|
|%SYSTEMROOT%|powershell.exe|\system32\rsaenh.dll|
|%SYSTEMROOT%|powershell.exe|\system32\ntlanman.dll|
|%SYSTEMROOT%|powershell.exe|\system32\drprov.dll|
|%SYSTEMROOT%|PresentationSettings.exe|\system32\windowscodecs.dll|
|%SYSTEMROOT%|PresentationSettings.exe|\system32\windows.storage.dll|
|%SYSTEMROOT%|PresentationSettings.exe|\system32\shell32.dll|
|%SYSTEMROOT%|PresentationSettings.exe|\system32\MMDevApi.dll|
|%SYSTEMROOT%|PresentationSettings.exe|\system32\propsys.dll|
|%SYSTEMROOT%|rasphone.exe|\system32\IPHLPAPI.DLL|
|%SYSTEMROOT%|rasphone.exe|\system32\DUI70.dll|
|%SYSTEMROOT%|rasphone.exe|\system32\SspiCli.dll|
|%SYSTEMROOT%|rasphone.exe|\system32\connect.dll|
|%SYSTEMROOT%|rasphone.exe|\system32\eappcfg.dll|
|%SYSTEMROOT%|rasphone.exe|\system32\netshell.dll|
|%SYSTEMROOT%|rasphone.exe|\system32\TWINAPI.dll|
|%SYSTEMROOT%|rasphone.exe|\system32\xwizards.dll|
|%SYSTEMROOT%|rasphone.exe|\system32\rasgcw.dll|
|%SYSTEMROOT%|rasphone.exe|\system32\NetSetupApi.dll|
|%SYSTEMROOT%|rasphone.exe|\system32\xwtpw32.dll|
|%SYSTEMROOT%|rasphone.exe|\system32\credui.dll|
|%SYSTEMROOT%|rdpclip.exe|\system32\twinapi.dll|
|%SYSTEMROOT%|rdpclip.exe|\system32\windows.storage.dll|
|%SYSTEMROOT%|rdpclip.exe|\system32\netprofm.dll|
|%SYSTEMROOT%|rdpclip.exe|\system32\npmproxy.dll|
|%WINDIR%|ReAgentc.exe|\system32\dbghelp.dll|
|%SYSTEMROOT%|RMActivate|\system32\isv.exe_rsaenh.dll|
|%SYSTEMROOT%|RMActivate|\system32\ssp_isv.exe_rsaenh.dll|
|%SYSTEMROOT%|RMActivate|\system32\ssp.exe_rsaenh.dll|
|%SYSTEMROOT%|RMActivate.exe|\system32\rsaenh.dll|
|%SYSTEMROOT%|RpcPing.exe|\system32\mswsock.dll|
|%SYSTEMROOT%|ScriptRunner.exe|\system32\rsaenh.dll|
|%WINDIR%|setupugc.exe|\system32\dbghelp.dll|
|%SYSTEMROOT%|ShellAppRuntime.exe|\system32\IDStore.dll|
|%SYSTEMROOT%|ShellAppRuntime.exe|\system32\shell32.dll|
|%SYSTEMROOT%|ShellAppRuntime.exe|\system32\wlidprov.dll|
|%SYSTEMROOT%|ShellAppRuntime.exe|\system32\bcrypt.dll|
|%SYSTEMROOT%|sihost.exe|\system32\desktopshellext.dll|
|%SYSTEMROOT%|slui.exe|\system32\ndfapi.dll|
|%SYSTEMROOT%|slui.exe|\system32\IPHLPAPI.DLL|
|%SYSTEMROOT%|slui.exe|\system32\wdi.dll|
|%SYSTEMROOT%|SndVol.exe|\system32\MMDevApi.dll|
|%SYSTEMROOT%|SppExtComObj.Exe|\system32\rsaenh.dll|
|%SYSTEMROOT%|stordiag.exe|\system32\fwpuclnt.dll|
|%SYSTEMROOT%|stordiag.exe|\system32\davclnt.dll|
|%SYSTEMROOT%|stordiag.exe|\system32\wmidcom.dll|
|%SYSTEMROOT%|stordiag.exe|\system32\wbemsvc.dll|
|%SYSTEMROOT%|stordiag.exe|\system32\wshbth.dll|
|%SYSTEMROOT%|stordiag.exe|\system32\wmiutils.dll|
|%SYSTEMROOT%|stordiag.exe|\system32\drprov.dll|
|%SYSTEMROOT%|stordiag.exe|\system32\nlansp_c.dll|
|%SYSTEMROOT%|stordiag.exe|\system32\fastprox.dll|
|%SYSTEMROOT%|stordiag.exe|\system32\p9np.dll|
|%SYSTEMROOT%|stordiag.exe|\system32\winrnr.dll|
|%SYSTEMROOT%|stordiag.exe|\system32\mswsock.dll|
|%SYSTEMROOT%|stordiag.exe|\system32\napinsp.dll|
|%SYSTEMROOT%|stordiag.exe|\system32\pnrpnsp.dll|
|%SYSTEMROOT%|stordiag.exe|\system32\wbemprox.dll|
|%SYSTEMROOT%|stordiag.exe|\system32\ntlanman.dll|
|%SYSTEMROOT%|stordiag.exe|\system32\rsaenh.dll|
|%SYSTEMROOT%|systeminfo.exe|\system32\wbemprox.dll|
|%SYSTEMROOT%|systeminfo.exe|\system32\fastprox.dll|
|%SYSTEMROOT%|systeminfo.exe|\system32\wbemsvc.dll|
|%SYSTEMROOT%|tabcal.exe|\system32\davclnt.dll|
|%SYSTEMROOT%|tabcal.exe|\system32\ntlanman.dll|
|%SYSTEMROOT%|tabcal.exe|\system32\windows.storage.dll|
|%SYSTEMROOT%|tabcal.exe|\system32\p9np.dll|
|%SYSTEMROOT%|tabcal.exe|\system32\drprov.dll|
|%SYSTEMROOT%|tabcal.exe|\system32\propsys.dll|
|%SYSTEMROOT%|taskkill.exe|\system32\wbemprox.dll|
|%SYSTEMROOT%|tasklist.exe|\system32\fastprox.dll|
|%SYSTEMROOT%|tasklist.exe|\system32\wbemprox.dll|
|%SYSTEMROOT%|tasklist.exe|\system32\wbemsvc.dll|
|%SYSTEMROOT%|tasklist.exe|\system32\wmiutils.dll|
|%SYSTEMROOT%|tzsync.exe|\system32\rsaenh.dll|
|%SYSTEMROOT%|UevAppMonitor.exe|\system32\rsaenh.dll|
|%SYSTEMROOT%|UserAccountControlSettings.exe|\system32\rsaenh.dll|
|%SYSTEMROOT%|verifier.exe|\system32\ntlanman.dll|
|%SYSTEMROOT%|verifier.exe|\system32\windows.storage.dll|
|%SYSTEMROOT%|verifier.exe|\system32\p9np.dll|
|%SYSTEMROOT%|verifier.exe|\system32\drprov.dll|
|%SYSTEMROOT%|verifier.exe|\system32\davclnt.dll|
|%SYSTEMROOT%|verifier.exe|\system32\propsys.dll|
|%SYSTEMROOT%|WallpaperHost.exe|\system32\shell32.dll|
|%SYSTEMROOT%|WFS.exe|\system32\windowscodecsext.dll|
|%SYSTEMROOT%|WFS.exe|\system32\windows.storage.dll|
|%SYSTEMROOT%|WFS.exe|\system32\windowscodecs.dll|
|%SYSTEMROOT%|WFS.exe|\system32\propsys.dll|
|%SYSTEMROOT%|winver.exe|\system32\windowscodecs.dll|
|%SYSTEMROOT%|wordpad.exe|\system32\dataexchange.dll|
|%SYSTEMROOT%|wordpad.exe|\system32\bcrypt.dll|
|%SYSTEMROOT%|wordpad.exe|\system32\windowscodecs.dll|
|%SYSTEMROOT%|wordpad.exe|\system32\netprofm.dll|
|%SYSTEMROOT%|wordpad.exe|\system32\npmproxy.dll|
|%SYSTEMROOT%|wordpad.exe|\system32\msxml3.dll|
|%SYSTEMROOT%|wordpad.exe|\system32\msctf.dll|
|%SYSTEMROOT%|wordpad.exe|\system32\UIRibbon.dll|
|%SYSTEMROOT%|WorkFolders.exe|\system32\davclnt.dll|
|%SYSTEMROOT%|WorkFolders.exe|\system32\propsys.dll|
|%SYSTEMROOT%|WorkFolders.exe|\system32\windows.storage.dll|
|%SYSTEMROOT%|WorkFolders.exe|\system32\p9np.dll|
|%SYSTEMROOT%|WorkFolders.exe|\system32\drprov.dll|
|%SYSTEMROOT%|WorkFolders.exe|\system32\ntlanman.dll|
|%SYSTEMROOT%|write.exe|\system32\davclnt.dll|
|%SYSTEMROOT%|write.exe|\system32\drprov.dll|
|%SYSTEMROOT%|write.exe|\system32\windows.storage.dll|
|%SYSTEMROOT%|write.exe|\system32\p9np.dll|
|%SYSTEMROOT%|write.exe|\system32\propsys.dll|
|%SYSTEMROOT%|write.exe|\system32\ntlanman.dll|
|%SYSTEMROOT%|WSCollect.exe|\system32\windows.storage.dll|
|%SYSTEMROOT%|WSCollect.exe|\system32\windowscodecs.dll|


If we take into account other popular/standard software, the list grows even bigger:

{:.data-table .env-table}
| Environment variable     | Application                     | Executable                                    | DLL (relative to variable)                               |
|---------------------------------------------|----------------------------------------|------------------------------------------|
|%SYSTEMROOT%|Microsoft Teams (built-in)|C:\Program Files\WindowsApps\MicrosoftTeams_21253.510.996.1465_x64__8wekyb3d8bbwe\msteams.exe|\system32\mswsock.dll|
|%SYSTEMROOT%|Microsoft Teams (built-in)|C:\Program Files\WindowsApps\MicrosoftTeams_21253.510.996.1465_x64__8wekyb3d8bbwe\msteams.exe|\system32\netprofm.dll|
|%SYSTEMROOT%|Microsoft Teams (built-in)|C:\Program Files\WindowsApps\MicrosoftTeams_21253.510.996.1465_x64__8wekyb3d8bbwe\msteams.exe|\system32\propsys.dll|
|%SYSTEMROOT%|Microsoft Teams (built-in)|C:\Program Files\WindowsApps\MicrosoftTeams_21253.510.996.1465_x64__8wekyb3d8bbwe\msteams.exe|\system32\twinui.dll|
|%SYSTEMROOT%|Microsoft Teams (built-in)|C:\Program Files\WindowsApps\MicrosoftTeams_21253.510.996.1465_x64__8wekyb3d8bbwe\msteams.exe|\system32\windows.storage.dll|
|%SYSTEMROOT%|Microsoft Teams (built-in)|C:\Program Files (x86)\Microsoft\EdgeWebView\Application\90.0.818.66\msedgewebview2.exe|\system32\dataexchange.dll|
|%SYSTEMROOT%|Microsoft Teams (built-in)|C:\Program Files (x86)\Microsoft\EdgeWebView\Application\90.0.818.66\msedgewebview2.exe|\system32\msctf.dll|
|%SYSTEMROOT%|Microsoft Teams (built-in)|C:\Program Files (x86)\Microsoft\EdgeWebView\Application\90.0.818.66\msedgewebview2.exe|\system32\mswsock.dll|
|%SYSTEMROOT%|Microsoft Teams (built-in)|C:\Program Files (x86)\Microsoft\EdgeWebView\Application\90.0.818.66\msedgewebview2.exe|\system32\ntmarta.dll|
|%SYSTEMROOT%|Microsoft Office 2021|C:\Program Files (x86)\Microsoft Office\root\Office16\excel.exe|\system32\directmanipulation.dll|
|%SYSTEMROOT%|Microsoft Office 2021|C:\Program Files (x86)\Microsoft Office\root\Office16\excel.exe|\system32\msctf.dll|
|%SYSTEMROOT%|Microsoft Office 2021|C:\Program Files (x86)\Microsoft Office\root\Office16\excel.exe|\system32\mswsock.dll|
|%SYSTEMROOT%|Microsoft Office 2021|C:\Program Files (x86)\Microsoft Office\root\Office16\excel.exe|\system32\netprofm.dll|
|%SYSTEMROOT%|Microsoft Office 2021|C:\Program Files (x86)\Microsoft Office\root\Office16\excel.exe|\system32\npmproxy.dll|
|%SYSTEMROOT%|Microsoft Office 2021|C:\Program Files (x86)\Microsoft Office\root\Office16\excel.exe|\system32\rsaenh.dll|
|%SYSTEMROOT%|Microsoft Office 2021|C:\Program Files (x86)\Microsoft Office\root\Office16\excel.exe|\system32\twinapi.dll|
|%SYSTEMROOT%|Microsoft Office 2021|C:\Program Files (x86)\Microsoft Office\root\Office16\excel.exe|\system32\windows.storage.dll|
|%SYSTEMROOT%|Microsoft Office 2021|C:\Program Files (x86)\Microsoft Office\root\Office16\excel.exe|\system32\windowscodecs.dll|
|%SYSTEMROOT%|Microsoft Office 2021|C:\Program Files (x86)\Microsoft Office\root\Office16\outlook.exe|\system32\msctf.dll|
|%SYSTEMROOT%|Microsoft Office 2021|C:\Program Files (x86)\Microsoft Office\root\Office16\outlook.exe|\system32\mswsock.dll|
|%SYSTEMROOT%|Microsoft Office 2021|C:\Program Files (x86)\Microsoft Office\root\Office16\outlook.exe|\system32\netprofm.dll|
|%SYSTEMROOT%|Microsoft Office 2021|C:\Program Files (x86)\Microsoft Office\root\Office16\outlook.exe|\system32\npmproxy.dll|
|%SYSTEMROOT%|Microsoft Office 2021|C:\Program Files (x86)\Microsoft Office\root\Office16\outlook.exe|\system32\rsaenh.dll|
|%SYSTEMROOT%|Microsoft Office 2021|C:\Program Files (x86)\Microsoft Office\root\Office16\outlook.exe|\system32\windows.storage.dll|
|%SYSTEMROOT%|Microsoft Office 2021|C:\Program Files (x86)\Microsoft Office\root\Office16\outlook.exe|\system32\windowscodecs.dll|
|%SYSTEMROOT%|Microsoft Office 2021|C:\Program Files (x86)\Microsoft Office\root\Office16\powerpnt.exe|\system32\dataexchange.dll|
|%SYSTEMROOT%|Microsoft Office 2021|C:\Program Files (x86)\Microsoft Office\root\Office16\powerpnt.exe|\system32\msctf.dll|
|%SYSTEMROOT%|Microsoft Office 2021|C:\Program Files (x86)\Microsoft Office\root\Office16\powerpnt.exe|\system32\mswsock.dll|
|%SYSTEMROOT%|Microsoft Office 2021|C:\Program Files (x86)\Microsoft Office\root\Office16\powerpnt.exe|\system32\netprofm.dll|
|%SYSTEMROOT%|Microsoft Office 2021|C:\Program Files (x86)\Microsoft Office\root\Office16\powerpnt.exe|\system32\npmproxy.dll|
|%SYSTEMROOT%|Microsoft Office 2021|C:\Program Files (x86)\Microsoft Office\root\Office16\powerpnt.exe|\system32\propsys.dll|
|%SYSTEMROOT%|Microsoft Office 2021|C:\Program Files (x86)\Microsoft Office\root\Office16\powerpnt.exe|\system32\rsaenh.dll|
|%SYSTEMROOT%|Microsoft Office 2021|C:\Program Files (x86)\Microsoft Office\root\Office16\powerpnt.exe|\system32\twinapi.dll|
|%SYSTEMROOT%|Microsoft Office 2021|C:\Program Files (x86)\Microsoft Office\root\Office16\powerpnt.exe|\system32\windows.storage.dll|
|%SYSTEMROOT%|Microsoft Office 2021|C:\Program Files (x86)\Microsoft Office\root\Office16\powerpnt.exe|\system32\windowscodecs.dll|
|%SYSTEMROOT%|Microsoft Office 2021|C:\Program Files (x86)\Microsoft Office\root\Office16\winword.exe|\system32\explorerframe.dll|
|%SYSTEMROOT%|Microsoft Office 2021|C:\Program Files (x86)\Microsoft Office\root\Office16\winword.exe|\system32\msctf.dll|
|%SYSTEMROOT%|Microsoft Office 2021|C:\Program Files (x86)\Microsoft Office\root\Office16\winword.exe|\system32\mswsock.dll|
|%SYSTEMROOT%|Microsoft Office 2021|C:\Program Files (x86)\Microsoft Office\root\Office16\winword.exe|\system32\netprofm.dll|
|%SYSTEMROOT%|Microsoft Office 2021|C:\Program Files (x86)\Microsoft Office\root\Office16\winword.exe|\system32\npmproxy.dll|
|%SYSTEMROOT%|Microsoft Office 2021|C:\Program Files (x86)\Microsoft Office\root\Office16\winword.exe|\system32\propsys.dll|
|%SYSTEMROOT%|Microsoft Office 2021|C:\Program Files (x86)\Microsoft Office\root\Office16\winword.exe|\system32\rsaenh.dll|
|%SYSTEMROOT%|Microsoft Office 2021|C:\Program Files (x86)\Microsoft Office\root\Office16\winword.exe|\system32\twinapi.dll|
|%SYSTEMROOT%|Microsoft Office 2021|C:\Program Files (x86)\Microsoft Office\root\Office16\winword.exe|\system32\windows.storage.dll|
|%SYSTEMROOT%|Microsoft Office 2021|C:\Program Files (x86)\Microsoft Office\root\Office16\winword.exe|\system32\windowscodecs.dll|
|%SYSTEMROOT%|Microsoft Edge 90|C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe|\system32\dataexchange.dll|
|%SYSTEMROOT%|Microsoft Edge 90|C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe|\system32\fastprox.dll|
|%SYSTEMROOT%|Microsoft Edge 90|C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe|\system32\msctf.dll|
|%SYSTEMROOT%|Microsoft Edge 90|C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe|\system32\mswsock.dll|
|%SYSTEMROOT%|Microsoft Edge 90|C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe|\system32\ntmarta.dll|
|%SYSTEMROOT%|Microsoft Edge 90|C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe|\system32\propsys.dll|
|%SYSTEMROOT%|Microsoft Edge 90|C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe|\system32\shcore.dll|
|%SYSTEMROOT%|Microsoft Edge 90|C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe|\system32\srumapi.dll|
|%SYSTEMROOT%|Microsoft Edge 90|C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe|\system32\wbemprox.dll|
|%SYSTEMROOT%|Microsoft Edge 90|C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe|\system32\wbemsvc.dll|
|%SYSTEMROOT%|Microsoft Edge 90|C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe|\system32\windows.storage.dll|
|%SYSTEMROOT%|Microsoft Edge 90|C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe|\system32\windowsudk.shellcommon.dll|
|%SYSTEMROOT%|Microsoft Edge 90|C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe|\system32\XmlLite.dll|
|%SYSTEMROOT%|Chrome 90|C:\Program Files\Google\Chrome\Application\chrome.exe|\system32\dataexchange.dll|
|%SYSTEMROOT%|Chrome 90|C:\Program Files\Google\Chrome\Application\chrome.exe|\system32\explorerframe.dll|
|%SYSTEMROOT%|Chrome 90|C:\Program Files\Google\Chrome\Application\chrome.exe|\system32\mswsock.dll|
|%SYSTEMROOT%|Chrome 90|C:\Program Files\Google\Chrome\Application\chrome.exe|\system32\ntmarta.dll|
|%SYSTEMROOT%|Chrome 90|C:\Program Files\Google\Chrome\Application\chrome.exe|\system32\propsys.dll|
|%SYSTEMROOT%|Chrome 90|C:\Program Files\Google\Chrome\Application\chrome.exe|\system32\windows.storage.dll|
|%SYSTEMROOT%|Mozilla Firefox 100|C:\Program Files\Mozilla Firefox\firefox.exe|\system32\dataexchange.dll|
|%SYSTEMROOT%|Mozilla Firefox 100|C:\Program Files\Mozilla Firefox\firefox.exe|\system32\explorerframe.dll|
|%SYSTEMROOT%|Mozilla Firefox 100|C:\Program Files\Mozilla Firefox\firefox.exe|\system32\mswsock.dll|
|%SYSTEMROOT%|Mozilla Firefox 100|C:\Program Files\Mozilla Firefox\firefox.exe|\system32\netprofm.dll|
|%SYSTEMROOT%|Mozilla Firefox 100|C:\Program Files\Mozilla Firefox\firefox.exe|\system32\propsys.dll|
|%SYSTEMROOT%|Mozilla Firefox 100|C:\Program Files\Mozilla Firefox\firefox.exe|\system32\rsaenh.dll|
|%SYSTEMROOT%|Mozilla Firefox 100|C:\Program Files\Mozilla Firefox\firefox.exe|\system32\windows.storage.dll|
|%SYSTEMROOT%|Mozilla Firefox 100|C:\Program Files\Mozilla Firefox\firefox.exe|\system32\winrnr.dll|
|%SYSTEMROOT%|Zoom 5.9.3|C:\Users\%username%\AppData\Roaming\Zoom\bin\Zoom.exe|\system32\mswsock.dll|
|%SYSTEMROOT%|Zoom 5.9.3|C:\Users\%username%\AppData\Roaming\Zoom\bin\Zoom.exe|\system32\propsys.dll|
|%SYSTEMROOT%|Zoom 5.9.3|C:\Users\%username%\AppData\Roaming\Zoom\bin\Zoom.exe|\system32\rsaenh.dll|
|%SYSTEMROOT%|Zoom 5.9.3|C:\Users\%username%\AppData\Roaming\Zoom\bin\Zoom.exe|\system32\windows.storage.dll|

The above list is non-exhaustive; many other software solutions and executables could have been tested, and/or under different circumstances (e.g. with certain command-line arguments, with elevated privileges, and so on). The overarching point of the above listing is that this new type of DLL Hijacking is commonly found in trusted executables, meaning detecting individual cases won't scale.

## Implications for Privilege Escalation and Persistence
With all this in mind, it is worth exploring whether and how this type of DLL Hijacking can be used in conjunction with tactics beyond plain execution. A key aspect of this approach is that the vulnerable executable has to be started in a slightly different way than usual, as the process-level environment variables need to be updated. This is what makes creating proper persistence with it somewhat challenging: traditional persistence mechanisms, such as auto-start registry entries and .LNK files in startup folders, do not provide means to specify environment variables that should be set when executing the target command. It is of course still possible to use an 'intermediate' or 'bootstrap' command that sets an environment variable and then runs the vulnerable program, similar to running the VBScript or PowerShell script discussed before, but this is not very novel compared to alternative persistence methods.

There are, however, persistence mechanisms that do allow environment variables to be set. One example is Windows Services: the rarely used registry value `Environment` can be used to set process-level environment variables for the service's target executable (specified in `ImagePath`). If the target executable is vulnerable to environment variable-based DLL Hijacking, it is possible to leverage it in a persistent way.

Consider for example the Printer Spooler service, which executes `C:\Windows\System32\spoolsv.exe` when started. Setting the `Environment` value to overwrite `SYSTEMROOT` with a different path, and either restarting the service or (since Printer Spooler is enabled by default) rebooting the machine, will cause `spoolsv.exe` to use the manipulated path instead. Because `spoolsv.exe` tries to load `%SYSTEMROOT%\System32\mswsock.dll`, it will now be tricked into loading a malicious version of `mswsock.dll`. In fact, since the service runs under the _SYSTEM_ user, the DLL will be executed in that context.

[![Screenshot showing the successful DLL Hijacking of the Printer Spooler service, executing a malicious DLL file as SYSTEM.](/assets/2022-08-16-spooler-service-hijack.png)](/assets/2022-08-16-spooler-service-hijack.png)
*A demonstration of the successful DLL Hijacking of mswsock.dll within the printer Spooler service, loading a malicious version of the DLL as SYSTEM.*

Since altering Services registry keys requires administrative permissions, this does not lead to 'proper' privilege escalation. After all, if someone has elevated permissions anyway, they may as well change the `ImagePath` value and elevate to _SYSTEM_ in that way. However, altering `ImagePath` is more likely to be detected by defence mechanisms, whereas adding an `Environment` value may go unnoticed. Also, because the execution relies on a legitimate service executable, executing code this way is considerably more stealthy than running a malicious executable or, say, a malicious PowerShell command. Furthermore, if the DLL Hijacking is performed properly, the service will continue to work as intended, whereas changing the service's command is likely to result in missing functionality, which could lead to system instability.

Getting 'proper' privilege escalation or even just User Account Control (UAC) bypass using this type of DLL Hijacking is challenging. As stated before, in most circumstances, newly spawned processes obtain their environment variables from the parent process. There is an exception to this: when a low-integrity process starts a high-integrity process, the high-integrity process' environment variables are 'reset' to the System-level environment variables. Thus, if a new process causes UAC to be invoked, the new process will be provided with the environment variables as specified on System level, regardless of what environment variables the parent itself has set or has provided when creating the new process. Microsoft likely made this design decision in an attempt to limit the scope for privilege escalation opportunities via environment variables (e.g. `%PATH%` interception [[11]]); it has to be said that in this case it is rather successful in doing so. Even though there are documented cases for applications overriding this behaviour [[12]], these appears to be rare.

## Prevention and detection
As with every type of DLL hijacking, the best way to prevent this from happening altogether would be for applications to always use absolute and unambiguous (i.e. fully resolved) paths instead. There are various Windows API calls available that completely eliminate the need for relying on environment variables to obtain paths; the function `GetWindowsDirectory` [[13]] for example is a substitute for the `SYSTEMROOT` variable. Even better would be to always verify the validity of DLLs before they are loaded into memory.

As for environment variables specifically: as mentioned at the very start, with the introduction of the Windows Registry, there is no obvious need for the concept of environment variables in Windows. System setting-type parameters, such as static paths, usernames, and so on, can be set in the Registry or obtained via API calls; process-type parameters can be set on the command line. Backward compatibility is therefore likely the reason we still have environment variables in Windows.

From a detection point of view, a few obvious things that can be done is to check whether DLLs are loaded from unexpected locations. For example, executables located in `C:\Windows\System32` are very unlikely to load DLLs from for example 'temp' or AppData folders - DLL loads from such locations would therefore be worth a closer look. Applications outside the System32 folder may however load DLLs legitimately from such folders (e.g. Microsoft Teams and Slack), making it hard to turn this into a universal rule.

Hunting for the creation of DLL files with names that are known to be loaded by vulnerable applications, is an approach that won't work well [[14]]. A related but slightly more viable approach would be to look for the creation of certain folder structures in unexpected locations. For example, nearly all hijacking approaches that rely on `%SYSTEMROOT%` or `%WINDIR%` require a folder called `System32` to be created in a user-writable location. Generally, this should be rare - although some legitimate software appear to be doing this too, after excluding such instances this might be an easy approach to detect the most obvious form of environment variable-based DLL hijacking.

That being said, if a vulnerable executable uses another environment variable, the above approach may not work either. It is therefore important not to focus solely on detecting the DLL hijacking itself, but more so on the activity that follows. Detecting activity that is rare for the process that performed it, is at the end of the day the best indicator something is wrong. Therefore, while your defences might not detect everything, the more they can detect, the harder it is for an attacker to go completely unnoticed.

[1]: https://www.livingcomputers.org/UI/UserDocs/Unix-v7-1/UNIX_Programmers_Manual_Seventh_Edition_Vol_2_1983.pdf
[2]: https://winworldpc.com/download/941ee628-bc8e-11e9-b7f9-fa163e9022f0
[3]: https://docs.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb
[4]: https://devblogs.microsoft.com/oldnewthing/?p=15083
[5]: https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_environment_variables?view=powershell-7.2
[6]: /blog/hijacking-dlls-in-windows
[7]: https://attack.mitre.org/
[8]: /literature/Beukema,%20WJB%20-%20A%20Single%20Sub-Technique%20for%20DLL%20Hijacking.pdf
[9]: https://docs.microsoft.com/en-us/sysinternals/downloads/procmon
[10]: https://www.github.com/wietze/windows-dll-env-hijacking
[11]: https://attack.mitre.org/techniques/T1574/007/
[12]: https://www.fortinet.com/blog/threat-research/elastic-boundaries-elevating-privileges-with-environment-variables-expansion.
[13]: https://docs.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya
[14]: /blog/hijacking-dlls-in-windows#prevention-and-detection



[^i]: Technically, there is an under-documented fourth type, VOLATILE. This is the same as USER-level environment variables, but are reset after the user logs off.
[^ii]: As a side note, environment variable-based DLL Hijacking currently unfortunately does not map very well to MITRE ATT&amp;CK [[7]]. For this and other reasons mentioned in my previous DLL Hijacking blog post, I have submitted a proposal [[8]] which I hope MITRE will take into account when working on the next version of the framework.

*[HKLM]: HKEY_LOCAL_MACHINE, a Windows Registry location that generally requires elevated privileges to change.
*[HKCU]: HKEY_CURRENT_USER, a Windows Registry location that generally can be changed with normal user rights.
