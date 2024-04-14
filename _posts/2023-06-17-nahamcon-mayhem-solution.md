---
title: NahamCon CTF 2023 - Mayhem
date: 2023-06-17 09:19:00 +0700
categories: [Writeup, Reverse Engineering]
tags: [ctf, reverse engineering, malware, DFIR]
---

Last weekend I spent my free time to play NahamCon CTF with idek team. We managed to get 3rd place and first blood on Mayhem challenge. Here is a quick write up for the challenge.

## Challenge overview

```
The SOC team noticed a system periodically beaconing to a suspicious IP address. A snapshot of the suspicious 
process' memory was taken but the IR team wants to know what exactly is going on with this system.
```

The description tell us that there is a process memory dump and we have find a way to extract the flag from it. Also it provide us the diff file.

### The diff file

![Image](/commons/2023-06-17-nahamcon-mayhem-solution/img001.PNG)

With a few google search, I was able to find out the orginial [github repos](https://github.com/HavocFramework/Havoc/blob/main/payloads/Demon/Source/Demon.c). For anyone who doesn't know, Havoc is an open source post-exploitation command and control framework. Because it's open source, so the reverse engineering task become much more easier.  

### The dump file

Enough with the diff file, let's look at the dump file. To analyze the dump file, I use windbg preview. Windbg is too old so I should change to windbg preview instead. By enter command `!address`, windbg preview show us the memory region.

```
        BaseAddress      EndAddress+1        RegionSize     Type       State                 Protect             Usage
--------------------------------------------------------------------------------------------------------------------------
+     7ff5`fbd91000     7ff5`fbda0000        0`0000f000             MEM_FREE    PAGE_NOACCESS                      Free       
+     7ff5`fbda0000     7ff5`fbdc3000        0`00023000 MEM_MAPPED  MEM_COMMIT  PAGE_READONLY                      Other      [NLS Tables]
+     7ff5`fbdc3000     7ff7`96f50000        1`9b18d000             MEM_FREE    PAGE_NOACCESS                      Free       
+     7ff7`96f50000     7ff7`96f68000        0`00018000 MEM_IMAGE   MEM_COMMIT  PAGE_READWRITE                     Image      [demon; "C:\Users\lowpriv1\Downloads\demon.exe"]
+     7ff7`96f68000     7ffe`5f5e0000        6`c8678000             MEM_FREE    PAGE_NOACCESS                      Free       
```


Cool. Now we know that malware process named `demon.exe` and allocated at `0x7ff796f50000`. But the page protection is weird. `PAGE_READWRITE`? No execution flag set?. It's more weird if you view the page with windbg. Totally no PE header and only junk data.

![Image](/commons/2023-06-17-nahamcon-mayhem-solution/img002.PNG)

This really confused me a bit. After spend some time to dig into demon code, I found a nice feature of demon payload called [Ekko](https://github.com/Cracked5pider/Ekko).

## The detection mechanism of Antivirus (optional)

This does not releate to the challenge but I want to spend few lines to talk about it. Usually Antivirus have 3 kind of detection
- Static detection: Based on signature matching. This is easy to bypass. Most malware can bypass this.
- Emulation detection: Some malware use packer/crypter to hide real payload. The real payload is unpacked during execution. That would fail the static detection but some AVs are able to emulate the code to get the real payload and doing some signature matching. Still a lot of malware can bypass this.
- Realtime detection: Monitor the malware during execution and terminate it before it execute malicious payload. Only few malware can bypass this.

Now what is Ekko? It's a method to hide malware payload during runtime execution. By using this, demon payload belong to the fews that can hide itself from runtime detection. Ekko works by encrypt the malware payload while it is sleeping. If an AV scan the payload's memory during its sleeping time (and malware sleep almost of time), it would found nothing in the memory.

## Getting the decryption key and decrypt the payload

Now we know that the demon payload is encrypted because of Ekko. To decrypt this, we have to find out how does Ekko encrypt the payload. Digging through the code I found something interesting.

```c
VOID FoliageObf( PSLEEP_PARAM Param )
{
    USTRING             Key         = { 0 };
    USTRING             Rc4         = { 0 };
    UCHAR               Random[16]  = { 0 };
    
    //.......
    
    ImageBase = Instance.Session.ModuleBase;
    ImageSize = IMAGE_SIZE( Instance.Session.ModuleBase );

    // Generate random keys
    for ( SHORT i = 0; i < 16; i++ )
        Random[ i ] = RandomNumber32( );

    Key.Buffer = &Random;
    Key.Length = Key.MaximumLength = 0x10;

    Rc4.Buffer = ImageBase;
    Rc4.Length = Rc4.MaximumLength = ImageSize;
    //.....
```

Payload is encrypted by using RC4. The type of key variable is `UString` and the key is 16 bytes long. Quickly look at `UString` structure

```c
typedef struct
{
    DWORD	Length;
    DWORD	MaximumLength;
    PVOID	Buffer;
} USTRING ;
```

Now we know that RC4 `Key` variable should begin with `10 00 00 00 10 00 00 00`. Using any hex editor to search in dump file we found 85 results.

![Image](/commons/2023-06-17-nahamcon-mayhem-solution/img004.PNG)

Choose the result which have `Buffer` field belong to stack region. Luckily it's first hit. We found the address of RC4 key is `0xA42C3FD6B0`

![Image](/commons/2023-06-17-nahamcon-mayhem-solution/img005.PNG)

RC4 key is `00 B0 0E 44 60 28 AC B2 E8 5C D0 72 84 44 EC EA`  

Now the final step is decrypt the payload.
- Using command `.writemem` to dump the payload. `.writemem demon_region.exe.mem 0x7ff796f50000 L?0x00018000`
- Wring the script to decrypt dumped payload

```python
from Crypto.Cipher import ARC4

if __name__ == "__main__":
    key = bytes.fromhex("00 B0 0E 44 60 28 AC B2 E8 5C D0 72 84 44 EC EA")
    cipher = ARC4.new(key)
    
    f = open("demon_region.exe.mem", "rb")
    enc = f.read()
    f.close()
    
    de = cipher.decrypt(enc)
    
    f = open("binary.exe", "wb")
    f.write(de)
    f.close()
```

- Search through decrypted payload and find the flag.

![Image](/commons/2023-06-17-nahamcon-mayhem-solution/img006.PNG)