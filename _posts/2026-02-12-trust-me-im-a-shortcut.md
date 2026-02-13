---
layout: post
title: Trust Me, I'm a Shortcut
tldr: Windows' primary mechanism for shortcuts, LNK files, is frequently abused by threat actors for payload delivery and persistence. This blog post introduces several new LNK file flaws that, amongst other things, allow attackers to fully spoof an LNK's target. It also introduces [lnk-it-up](https://www.github.com/wietze/lnk-it-up), a tool suite that can generate such deceptive LNK files, as well as detect anomalous ones.
image: /assets/2026-02-12-lnk.png
tags: [lnk, shortcut, CVE-2025-9491, lnk files, shortcut files, lnk spoofing, shortcut spoofed, lnk vulnerability, lnk abuse, malicious shortcuts, attacker shortcuts, bad lnks]
js: false
tweet: 2022053455792132370
---

## Shortcuts in Windows

Windows shortcuts exist to make life easier. Attackers noticed.

In an effort to improve the usability of the Windows operating system, LNK files were introduced with the launch of Windows 95 [[1]]. The concept of a pointer to another file or directory was not unique: symbolic links were introduced in 1982 in 4.1a BSD Unix [[2]]. The Windows LNK file is, however, different in a number of ways: its complex binary file format [[3]] can point to files, directories, but also start programs with command-line arguments. Various optional metadata fields allow the operating system to find the intended target even when it has been renamed or moved; additionally, it is possible to store window settings, set the working directory the target should operate in, and a custom icon can be specified.

<figure style="width: 25%; float: right;margin:0; margin-left: 1em;">
<img src="/assets/2026-02-12-trust-me.jpg" alt='The meme "Totally not a virus.Trust me...im a dolphin". The source/copyright are unknown.'>
<figcaption>The meme "<span style="font-variant: small-caps;">Totally not a virus.Trust me...im a dolphin</span>". The source/copyright are unknown.</figcaption>
</figure>

Although LNK files can be opened from a command prompt or script, they remain largely a GUI feature. Shortcuts can be recognised by the white square containing an arrow rendered on top of the shortcut’s icon in the bottom left corner. This visual cue is, in a way, a security feature: it makes it clear to users that upon double-clicking the file, something else will be opened. From an end-user perspective, the only practical way to inspect what an LNK file points to is by right-clicking it and clicking _Properties_. This opens the Properties dialog, which reveals the target of the LNK file.

Ever since their introduction, LNK files have been used by threat actors. A notable example is the Stuxnet campaign, which exploited critical Windows vulnerability CVE-2010-2568, where specially crafted LNK files could trick the system into loading arbitrary DLL files without the user even opening them [[4]]. More commonly, however, LNK files are used in social engineering attacks: email phishing [[5]], social media phishing [[6]], torrents/Usenet downloads [[7]], USB worms [[8], [9]] and fake downloads [[10]]. In all of these attacks, the shortcuts disguise themselves as something else, e.g. a PDF document, a drive folder or a legitimate piece of software, and lure the user into opening them. Upon triggering, the attacker's payload is executed - as the aforementioned examples show, these often rely on Living off the Land Binaries and Scripts (LOLBINs/LOLBAS) [[11]].

Thus, the fact that LNKs still work as an attack vector, comes down to trust: users are made to believe that the shortcut opens something they are after or trust. The best defence is therefore to validate the target of an (unknown) LNK file prior to opening it.

But can Windows Explorer's File Properties dialog be trusted?

## LNK Structure

To understand LNK attacks, let's consider how they work. Unlike symbolic links and Microsoft's own .URL files [[12]], which are in plain text, LNKs use a binary file format. Microsoft provides detailed information [[3]] on the structure of LNK files, which tells us that LNK files have up to 5 sections, that are specified in the following order:

* `ShellLinkHeader`, which is always present;
* `LinkTargetIDList`, which is only present if the `HasLinkTargetIDList` flag is set;
* `LinkInfo`, which is only present if the `HasLinkInfo` flag is set;
* `StringData`, which is only present if at least one of 5 specific flags are set;
* `ExtraData`, which is a generic structure of which 0 or more can be present, depending on certain flags being set.

### ShellLinkHeader


<figure class="bytes">
<div id='target'></div>
<figcaption>An example <code>ShellLinkHeader</code>. Hover over the byte fields to see what they represent.</figcaption>
</figure>


<script>
const data = {'HeaderSize': [[0x4c, 0, 0, 0], 'set to 76, this value is fixed']
             ,'LinkCLSID': [[0x01, 0x14, 0x02, 0, 0, 0, 0, 0, 0xc0, 0, 0, 0, 0, 0, 0, 46], 'set to 00021401-0000-0000-C000-000000000046, this value is fixed']
             ,'LinkFlags': [[0x01, 0, 0, 0], 'HasLinkTargetIDList is the only flag set here. 25 flags can be set, ~33.5M possibilities']
             ,'FileAttributes': [[0x80, 0, 0, 0], 'FileAttributeNormal is the only flag set here. 13 flags can be set, 8,192 possibilities']
             ,'CreationTime': [[0, 0xf4, 0xb9, 0x14, 0x04, 0x5b, 0xdc, 0x01], 'set to 2025-11-21 16:00:00 UTC here']
             ,'AccessTime': [[0, 0xf4, 0xb9, 0x14, 0x04, 0x5b, 0xdc, 0x01],'set to 2025-11-21 16:00:00 UTC here']
             ,'WriteTime': [[0, 0xf4, 0xb9, 0x14, 0x04, 0x5b, 0xdc, 0x01],'set to 2025-11-21 16:00:00 UTC here']
             ,'FileSize': [[0, 0, 0, 0], 'set to 0 here']
             ,'IconIndex': [[0x01, 0, 0, 0], 'set to 1 here']
             ,'ShowCommand': [[0x07, 0, 0, 0], 'set to SW_SHOWMINNOACTIVE here (0x07)']
             ,'HotKey': [[0,0], 'set to 0 here']
             ,'Reserved': [[0, 0, 0, 0, 0, 0, 0, 0, 0, 0], 'must be 0']
}

function addBox(text, color, comment, target){
    let b = document.createElement('span')
    b.classList.add = 'byte'
    b.style.backgroundColor = color
    b.style.color = `contrast-color(${b.style.backgroundColor})`
    b.style.padding = padding
    b.style.flex = `0 0 calc((100% - (${split-1} * 2px)) / ${split})`
    b.style.boxSizing = 'border-box';
    b.style.textAlign = 'center';
    b.title = comment
    b.innerText = text
    target.appendChild(b)
}

const split = 16
const padding = '0.2em'
let i = 0;
const colours = ['#023EFF','#FF7C00','#1AC938','#E8000B','#8B2BE2','#9F4800','#F14CC1','#A3A3A3','#FFC400','#00D7FF', '#ffffff', '#000000']
Object.entries(data).forEach(([k, [v, comment]]) => {
    v.forEach(x => addBox(x.toString(16).padStart(2, '0'), colours[i % colours.length], `${k}: ${comment}`, document.getElementById('target')))
    i++
})
</script>

The `ShellLinkHeader` has a fixed length of 76 bytes; it is the only required structure in any LNK file. It contains a number of common data fields, and defines the layout of the LNK file.

The first two fields have predefined values that the documentation warns should not be changed.

The third field `LinkFlags` is, albeit just 4 bytes in size, perhaps the most fundamental field: this value sets out what the remainder of the LNK file will look like. For example, setting `HasTargetIdField` (`0x01`) indicates a `LinkTargetIDList` will be present, `HasLinkInfo` (`0x02`) indicates `LinkInfo` will be present, `HasArguments` (`0x40`) indicates `StringData` will contain command-line arguments, and so on. The documentation defines 25 possible flags that can be set here; meaning there are 2<sup>25</sup> ≈ 33.5 million possibilities.

This flags field is followed by `FileAttributes`, which indicates what file attributes the target has set; these are merely hints for how Explorer should display the target. Similarly, the following `CreationTime`, `AccessTime` and `WriteTime` represent timestamps of the target - these can be useful forensic artifacts. Finally, some integer/enum fields are defined: `FileSize`, `IconIndex`, `ShowCommand` (which controls if the target should be opened minimised, maximised, or normal), `HotKey`, and some reserved fields.

### LinkTargetIDList
<figure class="bytes">
<div id='target4'></div>
<figcaption>An example representing <code>c:\test\a.txt</code>. Hover over the byte fields to see what they represent.</figcaption>
</figure>

This structure is the main mechanism to represent the target file/directory of the LNK. Although not required, it is commonly found in LNK files - for example, an LNK file generated through Windows Explorer will always specify this structure. Typically, you will find an absolute path here: it could be on the local drive, a removable drive, a network path, or any other location that can be accessed through UNC [[13]].

The `LinkTargetIDList` structure represents a path as a list of Shell Items [[14]], which unlike LNKs themselves, are not formally documented. Each part of a path may contain extra metadata, such as size, last modified, and optionally even NTFS attributes. This allows Windows to find targets even if they have been renamed or moved on disk. Next to this, special locations (e.g. My Computer, Network Locations, Control Panel) as well as special file types (e.g. Control Panel items) can be represented. For the purpose of this post, we will limit ourselves to normal, on-disk paths.

<script>
let path = 'test\\a.txt'.split('\\')


let ItemIDs = path.map(part => new Uint8Array([...part].map(c => c.charCodeAt(0))))
const totalLength = 2+20+25+ItemIDs.map(x=> x.length+15).reduce((a, b)=>a+b) + 2

let data4 = {'IDListSize': [[totalLength, 0], `set to ${totalLength}, the size of the entire ListTargetIDList block`]
              ,'ItemIDSize.0': [[20, 0], `set to 20, the size of this and the next block`]
              ,'Data.0': [[0x1F, 0x50, 0xE0, 0x4F, 0xD0, 0x20, 0xEA, 0x3A, 0x69, 0x10, 0xA2, 0xD8, 0x08, 0x00, 0x2B, 0x30, 0x30, 0x9D], `representing the root folder, i.e. 'this computer'`]
              ,'ItemIDSize.1': [[0x19, 0], `set to ${0x19}, the size of this and the next block`]
              ,'Data.1': [[0x2f,0x43,0x3a,0x5c,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0], `data representing 'c:\\'`]
}

let chunks = ItemIDs.map(x => ({
  [`ItemIDSize.${ItemIDs.indexOf(x)+2}`]: [[x.length+15, 00], `set to ${x.length+15}, the size of this and the next block`],
  [`Data.${ItemIDs.indexOf(x)+2}`]: [[ItemIDs.indexOf(x) == ItemIDs.length-1 ? 0x32 : 0x31,0, 0,0,0,0, 0,0,0,0, ItemIDs.indexOf(x) == ItemIDs.length-1 ?0x80:0x10, 0, ...x, 0], `data representing '${path[ItemIDs.indexOf(x)]}'`]
})).forEach(x => data4 = {...data4, ...x})

data4['TerminalID'] = [[0, 0], 'indicating the end of the LinkTargetIDList']

i = 0;
Object.entries(data4).forEach(([k, [v, comment]]) => {
    v.forEach(x => addBox(x.toString(16).padStart(2, '0'), colours[i % colours.length], `${k}: ${comment}`, document.getElementById('target4')))
    i++
})
</script>

### LinkInfo

Regarding this optional structure, the documentation states it "specifies information necessary to resolve a link target if it is not found in its original location" [[3], p. 19]. To that end, it can contain both a local path and one or more network-based representations of the same target, including UNC paths and volume identifiers. By combining filesystem-specific details such as volume serial numbers with path data, this field enables more robust target resolution than a simple string path, but also exposes a rich source of forensic artefacts that can reveal original file locations, network shares, and execution environments.

### StringData
<figure class="bytes">
<div id='target3'></div>
<figcaption>An example representing <code>COMMAND_LINE_ARGUMENTS</code> set to <code>--my-command-line-flag</code>. Hover over the byte fields to see what they represent.</figcaption>
</figure>

The next section contains, as the name suggests, strings. Depending on which `LinkFlags` are set, up to five strings could be defined here; this includes the working directory, the LNK's icon location, and any applicable command-line arguments.

The layout for a string captured in this section is simple: a byte sequence representing an ANSI-encoded string is provided, preceded by a two-byte field denoting the character length of the string; non-NULL terminated. This implies that strings can be up to 2<sup>16</sup> = 65,536 characters long. If the `LinkFlag` of `IsUnicode` is set, a Unicode-encoded string is expected.

<script>
let cmd = '--my-command-line-flag'
let ansi2 = new Uint8Array(cmd.length)
ansi2.set([...cmd].map(c => c.charCodeAt(0)));

const data3 = {'CountCharacters': [[cmd.length, 0], `set to ${cmd.length} here, the length of the string without NULL terminator`]
              ,'String': [ansi2, `set to ${cmd}, with UTF-8 encoding, not NULL terminated`]
}

i = 0;
Object.entries(data3).forEach(([k, [v, comment]]) => {
    v.forEach(x => addBox(x.toString(16).padStart(2, '0'), colours[i % colours.length], `${k}: ${comment}`, document.getElementById('target3')))
    i++
})
</script>

### ExtraData: EnvironmentVariableDataBlock

<figure class="bytes">
<div id='target2'></div>
<figcaption>An example representing <code>c:\hello.txt</code>. Hover over the byte fields to see what they represent.</figcaption>
</figure>

The final section in an LNK file is the `ExtraData` section, which contains 0 or more `ExtraDataBlock` structures. The documentation [[3], p. 28] defines 11 distinct subtypes, each with its own structure and rules.

For the purposes of this post, let's look at the `EnvironmentVariableDataBlock` subtype, which is expected when the `HasExpString` flag is set. This structure has 4 fields, which all have a fixed length. The `BlockSize` should always be set to `0x0314` (788); followed by a static `BlockSignature` field (which declares that this block is an `EnvironmentVariableDataBlock`). After this, we see two more fields: `TargetAnsi` and `TargetUnicode`, which, as their names suggest, contain the target path with ANSI encoding (e.g. Windows-1252 [[15]]) and Unicode encoding (UTF-16LE [[16]]), respectively. Both have fixed lengths of 260 and 520 bytes, respectively. It is worth noting that this structure is always the same, regardless of whether the `IsUnicode` flag is set.

<script>
let target = 'c:\\hello.txt'
let ansi = new Uint8Array(target.length)
ansi.set([...target].map(c => c.charCodeAt(0)));
let unicode = new Uint8Array(target.length * 2)
unicode.set([...target].flatMap(c => (x => [x & 0xff, x >> 8])(c.charCodeAt(0))));

const data2 = {'BlockSize': [[0x14, 0x03, 0, 0], 'set to 0x0314, this value is fixed']
              ,'BlockSignature': [[0x01, 0x00, 0x00, 0xA0], 'this value is fixed']
              ,'TargetAnsi': [ansi, `set to ${target}, with UTF-8 encoding (260 bytes)`]
              ,'TargetUnicode': [unicode, `set to ${target}, with UTF-16LE encoding (520 bytes)`]
}

i = 0;
Object.entries(data2).forEach(([k, [v, comment]]) => {
    v.forEach(x => addBox(x.toString(16).padStart(2, '0'), colours[i % colours.length], `${k}: ${comment}`, document.getElementById('target2')))
    if(i > 1){
        addBox('00', colours[i % colours.length], `${k}: ${comment}`, document.getElementById('target2'))
        addBox('……', colours[i % colours.length], `${k}: ${comment}`, document.getElementById('target2'))
        addBox('00', colours[i % colours.length], `${k}: ${comment}`, document.getElementById('target2'))
    }
    i++
})
</script>

## Explorer is forgiving, when it shouldn't be

### Variant 0: CVE-2025-9491

With this background in mind, let's start by understanding the much-debated [[17], [18]] CVE-2025-9491 that has been abused in the wild for quite some time [[19]].

As discussed before, the LNK format can specify command-line arguments with a length of up to 65,536 characters [[20]]. For whatever reason, in Explorer, the Target field only displays the first 256 characters of a command-line string. As such, it is possible to "hide" command-line arguments by padding the provided command-line arguments: whitespaces for example are typically ignored by the target process [[21]]. This means that although the target program will receive the full, padded command-line arguments, in most cases it will ignore all whitespace and simply interpret the remainder of the command-line argument string.

The original post highlighting this [[22]] describes how threat actors have been observed to pad with plain spaces (`\x20`) or tabs (`\x09`). When viewing the Properties dialog of such LNKs, it immediately suggests something is off.
The same post mentions a more stealthy approach, in which line feeds (`\n`, i.e. `\x0A`) and carriage returns (`\r`, i.e. `\x0D`) are used. This works because Windows treats these characters as whitespace, and are rendered in Explorer as a single character, even when repeated many times.

{% include figure.vid.html url='/assets/2026-02-12-cve.mp4' description="A video demonstrating CVE-2025-9491 on Windows 11 25H2, with Windows Defender disabled. The shortcut was created with [lnk-it-up](#prevention-and-detection)." codec='video/mp4; codecs="avc1.640028"' %}
<!-- Run on Windows 11 25H2, 26200.6584 -->

This is useful, because:

* The command-line arguments are hidden.

Its effectiveness is limited by:

* The target executable is still visible. Thus, if the target does not match the presented goal, it stands out as anomalous (e.g. `invoice.pdf.lnk` with a target of `%COMSPEC%` is unexpected);
* The process execution will still carry all whitespace characters, making it easily detectable; and,
* The technique has been used in the wild for many years. Defensive software like Windows Defender detect these out-of-the-box.

### Variant 1: Trust me, I have an ExpString

Now consider this similar variant, which is lesser known despite having been documented before [[23]]. The LNK Format Definition states that if the `HasExpString` flag is specified, an `EnvironmentVariableDataBlock` must be provided.

When `HasExpString` is specified, and an `EnvironmentVariableDataBlock` is specified with a `TargetAnsi`/`TargetUnicode` value of just null bytes, Explorer does two unexpected things. First, it disables the target field, meaning the target field becomes read-only and cannot be selected. Secondly, it hides the command-line arguments; yet when the LNK is opened, it still passes them on.

{% include figure.vid.html url='/assets/2026-02-12-example1.mp4' description="A video demonstrating a shortcut that suggests it will open a blank Windows Terminal, but upon opening executing `mshta.exe` code. The shortcut was created with [lnk-it-up](#prevention-and-detection)." codec='video/mp4; codecs="avc1.640028"' %}
<!-- Run on Windows 11 25H2, 26200.6584 -->

This is useful, because:

* The command-line arguments are hidden; and,
* The target cannot be modified.

Its effectiveness is limited by:

* The target executable is still visible. Thus, if the target does not match the presented goal, it stands out as anomalous; and,
* Targets with environment variables cannot be used, due to the flaw's reliance on `TargetIDList`s.

It is therefore similar to CVE-2025-9491's behaviour, but has the advantage of being less easily detected due to it not having padded command lines.

### Variant 2: Trust me, ""I know what I'm doing""

At this point, let's look at a new variant that has, to my knowledge, not been documented before. The LNK File Definition shows that it is possible to specify a target in multiple places. For example, one can set the `HasTargetIDList` and `HasExpString` flags and provide the a path as in the `TargetIDList` structure and one in the `EnvironmentVariableDataBlock` structure.

Now, which does Explorer prefer when both are defined? By default, it will show the Environment Variable version. Even if you set conflicting values, e.g. if `TargetIDList` is set to `c:\file1.exe` and the `EnvironmentVariableDataBlock` to `c:\file2.exe`, the latter will take precedence: `file2.exe` will be shown in the Properties dialog, and will be executed when the LNK is opened. In this scenario, if `c:\file2.exe` does not exist, you will be told so - even if `c:\file1.exe` _does_ exist. The `TargetIDList` version is thus completely ignored here.

However, it turns out that Explorer does something unexpected if you provide a path to the `EnvironmentVariableDataBlock` that does not meet Windows' file path definition: although it _shows_ the value of `EnvironmentVariableDataBlock` in the Properties dialog, upon realising the path is invalid, it falls back to the value provided in `TargetIDList`, which is not visible in the UI at all. This can lead to the strange situation in which Explorer will show one target in the Properties dialog, but executes a completely different one when the LNK is opened.

{% include figure.vid.html url='/assets/2026-02-12-example2.mp4' description="A video demonstrating a shortcut to (seemingly) `README.pdf`, but when opened, executing Windows Calculator. The shortcut was created with [lnk-it-up](#prevention-and-detection)." codec='video/mp4; codecs="avc1.640028"' %}
<!-- Run on Windows 11 25H2, 26200.6584 -->

Generating an invalid Windows path does not have to be difficult: simply including one of Windows' reserved path characters will do [[24]]. For example, setting `EnvironmentVariableDataBlock` to `"c:\path2.exe"` (note the double-quote characters at the start and end) will make the path appear valid, even though it is not: double quotes are not allowed in Windows paths.

This behaviour is useful, because:

* The target program/file/directory is completely spoofed.

Its effectiveness is limited by:

* If command-line arguments are present, they will be visible (unless this technique is combined with e.g. CVE-2025-9491); and,
* Targets with environment variables cannot be used, due to the flaw's reliance on `TargetIDList`s.

### Variant 3: Trust me, I have a valid LinkTargetIDList

Let's look another, previously undocumented example. There is yet another place where an LNK's target may be documented: the `LinkInfo` field.

Here is when again something unexpected happens: if you specify the `HasExpString` flag and `EnvironmentVariableDataBlock` is set to any value; then also set the `HasLinkTargetIDList` flag and provide a non-conforming `LinkTargetIDList` value, the `LinkInfo` field is used as a fallback to identify the "real" path. Yet for unclear reasons, Explorer's Properties window will display the `EnvironmentVariableDataBlock` value, despite never actually executing it.

<!-- diagram -->

This results in the strange situation where the user sees one path in the Target field, but upon execution, a completely other path is executed. Due to the field being disabled, it is also possible to "hide" any command-line arguments that are provided.

{% include figure.vid.html url='/assets/2026-02-12-example3.mp4' description="A video demonstrating a shortcut to (seemingly) `c:\README.txt`, but when opening, executing Windows Calculator. Note that this was tested on Windows 11 23H2. The shortcut was created with [lnk-it-up](#prevention-and-detection)." codec='video/mp4; codecs="avc1.640028"' %}
<!-- Run on Windows 11 23H2, 22631.6060 -->

This behaviour is useful, because:

* The target program/file/directory is completely spoofed.
* Any command-line arguments can be hidden.

Its effectiveness is limited by:

* The LNK has to be executed twice; the first time the LNK will repair itself without executing anything, the second time the execution will take place.
* Targets with environment variables cannot be used, due to the flaw's reliance on `TargetIDList` and `LinkInfo`.
* In Windows 11 24H2, this trick no longer appears to be working.

### Variant 4: Trust me, I have a Unicode target

Bringing it all together, consider this final example that, despite its relative simplicity, is arguably the most powerful.

As discussed earlier, the `EnvironmentVariableDataBlock` has a somewhat unusual structure: regardless of whether or not the `IsUnicode` flag is set, the block includes a fixed-length field for both ANSI and Unicode (`TargetAnsi` and `TargetUnicode`, respectively) [[25]]. What happens if you only provide one of them? When you set only `TargetAnsi` and fill out `TargetUnicode` with NULL bytes, Explorer realises something is wrong and will show the `LinkTargetIDList` value in the Properties dialog instead. It also disables the Target field and for reasons unclear, it hides any command-line arguments provided. However, when you execute the LNK something weird happens: it still executes the ANSI value in the `EnvironmentVariableDataBlock`, _with_ any command-line arguments present.

{% include figure.vid.html url='/assets/2026-02-12-example4.mp4' description="A video demonstrating a shortcut to (seemingly) `c:\your-invoice.pdf`, but when opened, executing Windows PowerShell code. The shortcut was created with [lnk-it-up](#prevention-and-detection)." codec='video/mp4; codecs="avc1.640028"' %}
<!-- Run on Windows 11 25H2, 26200.6584 -->

Unlike the previous variant we looked at, opening the LNK executes the "actual" target immediately, not having to open it twice. Additionally, because in this case the spoofed target is in `TargetIdList` and the actual target in `EnvironmentVariableDataBlock`, the actual target may utilise environment variables.

This behaviour is useful, because:

* The target program/file/directory is completely spoofed.
* Any command-line arguments are hidden.

Its effectiveness is limited by:

* The LNK will repair itself after the first execution. However, as discussed before, this will not be a limitation if your goal is social engineering.

## Prevention and detection

To some, the findings presented above may come across as full-on security vulnerabilities. Microsoft however argues that as it requires the user to do something, without breaking any security boundaries [[26]], it is not a security vulnerability. This is not entirely unreasonable as ultimately, most of these boil down to being UI bugs. Yet, they are UI bugs that affect the trust a user may put in a file, and can be the start of a more elaborate intrusion. Although a CVE was assigned for one of these bugs [[27]], Microsoft still seems hesitant to address findings like the ones presented in this post as security issues.

In lieu of these flaws being fixed, it may be worth proactively detecting them.  Defensive software like EDR does often not monitor what is inside an LNK file until opened. There is an opportunity to inspect LNK files manually with specialised tools [[28], [29], [30] and others], but be aware that unlike Windows Explorer, these tools are very strict: non-standard LNK files may not be parsed at all despite working without problem in Windows Explorer. Another, possibly more robust approach may therefore be to look for commonly used suspicious terms in LNK files [[31]]. However, this makes assumptions about flags set and/or keywords used.

To help with both the creation and identification of the deceptive LNK files discussed in this post, the open-source project **lnk-it-up** [[32]] is now available. It contains two tools: the _lnk-generator_ tool [[33]] can create LNK files taking advantage of any of the five variants discussed in this post. The _lnk-tester_ tool [[34]] uses native Windows APIs to predict, for a given LNK file, what Windows Explorer will display as target and what will be executed upon opening; meaning it can identify various LNK spoofing techniques.

{% include figure.img.html url='/assets/2026-02-12-lnk-it-up.png' description="A screenshot showing a shortcut with variant 4 being created using `lnk-generator`, and the resulting LNK file being tested with `lnk-tester`, warning that there is a mismatch between the expected target and the actual target." %}

In summary, we have seen that LNK files are unpredictable because crucial pieces of information might be hidden or entirely spoofed, meaning it is not straightforward to anticipate what will happen when an LNK file is opened.

Don't trust LNK files. Even when a dolphin tells you to.

*[ANSI]: American National Standards Institute (ANSI) is how Windows refers to the default code page, which in the Western world is Windows-1252.
*[EDR]: Endpoint Detection & Response, commonly found in enterprise

[1]: https://www.loc.gov/preservation/digital/formats/fdd/fdd000596.shtml
[2]: https://github.com/dspinellis/unix-history-repo/blob/BSD-4_1c_2/usr/man/man0/changes.4-82#L28
[3]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/16cb4ca1-9339-4d0c-a68d-bf1d6cc0f943
[4]: https://euvd.enisa.europa.eu/vulnerability/CVE-2010-2568
[5]: https://www.securonix.com/blog/analyzing-deepdrive-north-korean-threat-actors-observed-exploiting-trusted-platforms-for-targeted-attacks/
[6]: https://labs.k7computing.com/index.php/from-lnk-to-rat-deep-dive-into-the-lnk-malware-infection-chain/
[7]: https://www.reddit.com/r/usenet/comments/1ffvk70/malicious_files_lnk_downloaded_from_ninjacentral/
[8]: https://www.threatdown.com/blog/usb-worms-still-wriggling-on-to-under-protected-computers-after-all-these-years/
[9]: https://asec.ahnlab.com/en/91280/
[10]: https://cloud.google.com/blog/topics/threat-intelligence/lnk-between-browsers/
[11]: https://lolbas-project.github.io/
[12]: https://www.cyanwerks.com/formats/file-format-url.html
[13]: https://learn.microsoft.com/en-us/dotnet/standard/io/file-path-formats#unc-paths
[14]: https://github.com/libyal/libfwsi/blob/main/documentation/Windows%20Shell%20Item%20format.asciidoc#extension_block_0xbeef0026
[15]: https://en.wikipedia.org/wiki/Windows-1252
[16]: https://en.wikipedia.org/wiki/Unicode_in_Microsoft_Windows
[17]: https://x.com/AliakbarZahravi/status/1902019189067395508
[18]: https://x.com/malwrhunterteam/status/1984206344262459760
[19]: https://thehackernews.com/2025/12/microsoft-silently-patches-windows-lnk.html
[20]: #stringdata
[21]: /blog/why-bother-with-argv0
[22]: https://www.trendmicro.com/en_us/research/25/c/windows-shortcut-zero-day-exploit.html
[23]: https://lifeinhex.com/analyzing-malicious-lnk-file/
[24]: https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-file
[25]: #extradata-environmentvariabledatablock
[26]: https://www.microsoft.com/en-us/msrc/windows-security-servicing-criteria
[27]: #variant-0-cve-2025-9491
[28]: https://github.com/EricZimmerman/Lnk
[29]: https://tzworks.com/prototype_page.php?proto_id=11
[30]: https://github.com/Matmaus/LnkParse3
[31]: https://github.com/Neo23x0/signature-base/blob/master/yara/gen_susp_lnk_files.yar
[32]: https://www.github.com/wietze/lnk-it-up
[33]: https://github.com/wietze/lnk-it-up/tree/main/lnk-generator
[34]: https://github.com/wietze/lnk-it-up/tree/main/lnk-tester
