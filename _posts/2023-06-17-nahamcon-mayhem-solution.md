---
title: NahamCon CTF 2023 - Mayhem
date: 2023-06-17 09:19:00 +0700
categories: [Writeup, Reverse Engineering]
tags: [ctf, reverse engineering, malware]
---

Last weekend I spent my free time to play NahamCon CTF with idek team. We managed to get 3rd place and first blood on Mayhem challenge. Here is a quick write up for the challenge.

## Challenge overview

```
The SOC team noticed a system periodically beaconing to a suspicious IP address. A snapshot of the suspicious process' memory was taken but the IR team wants to know what exactly is going on with this system.
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
+        0`00000000        0`7ffe0000        0`7ffe0000             MEM_FREE    PAGE_NOACCESS                      Free       
+        0`7ffe0000        0`7ffe1000        0`00001000 MEM_PRIVATE MEM_COMMIT  PAGE_READONLY                      Other      [User Shared Data]
+        0`7ffe1000        0`7ffe9000        0`00008000             MEM_FREE    PAGE_NOACCESS                      Free       
+        0`7ffe9000        0`7ffea000        0`00001000 MEM_PRIVATE MEM_COMMIT  PAGE_READONLY                      <unknown>  [........Q.......]
+        0`7ffea000       a4`2c000000       a3`ac016000             MEM_FREE    PAGE_NOACCESS                      Free       
+       a4`2c000000       a4`2c078000        0`00078000 MEM_PRIVATE MEM_RESERVE                                    <unknown>  
        a4`2c078000       a4`2c079000        0`00001000 MEM_PRIVATE MEM_COMMIT  PAGE_READWRITE                     PEB        [5b8]
        a4`2c079000       a4`2c07b000        0`00002000 MEM_PRIVATE MEM_COMMIT  PAGE_READWRITE                     TEB        [~0; 5b8.1a04]
        a4`2c07b000       a4`2c07d000        0`00002000 MEM_PRIVATE MEM_COMMIT  PAGE_READWRITE                     TEB        [~1; 5b8.1e78]
        a4`2c07d000       a4`2c07f000        0`00002000 MEM_PRIVATE MEM_RESERVE                                    <unknown>  
        a4`2c07f000       a4`2c081000        0`00002000 MEM_PRIVATE MEM_COMMIT  PAGE_READWRITE                     TEB        [~2; 5b8.2194]
        a4`2c081000       a4`2c083000        0`00002000 MEM_PRIVATE MEM_COMMIT  PAGE_READWRITE                     TEB        [~3; 5b8.1910]
        a4`2c083000       a4`2c085000        0`00002000 MEM_PRIVATE MEM_COMMIT  PAGE_READWRITE                     TEB        [~4; 5b8.fe4]
        a4`2c085000       a4`2c087000        0`00002000 MEM_PRIVATE MEM_COMMIT  PAGE_READWRITE                     TEB        [~5; 5b8.15b0]
        a4`2c087000       a4`2c089000        0`00002000 MEM_PRIVATE MEM_COMMIT  PAGE_READWRITE                     TEB        [~6; 5b8.2a4]
        a4`2c089000       a4`2c08b000        0`00002000 MEM_PRIVATE MEM_COMMIT  PAGE_READWRITE                     TEB        [~7; 5b8.1414]
        a4`2c08b000       a4`2c200000        0`00175000 MEM_PRIVATE MEM_RESERVE                                    <unknown>  
+       a4`2c200000       a4`2c3f9000        0`001f9000 MEM_PRIVATE MEM_RESERVE                                    Stack      [~0; 5b8.1a04]
        a4`2c3f9000       a4`2c3fc000        0`00003000 MEM_PRIVATE MEM_COMMIT  PAGE_READWRITE | PAGE_GUARD        Stack      [~0; 5b8.1a04]
        a4`2c3fc000       a4`2c400000        0`00004000 MEM_PRIVATE MEM_COMMIT  PAGE_READWRITE                     Stack      [~0; 5b8.1a04]
+       a4`2c400000       a4`2c5fb000        0`001fb000 MEM_PRIVATE MEM_RESERVE                                    Stack      [~1; 5b8.1e78]
        a4`2c5fb000       a4`2c5fe000        0`00003000 MEM_PRIVATE MEM_COMMIT  PAGE_READWRITE | PAGE_GUARD        Stack      [~1; 5b8.1e78]
        a4`2c5fe000       a4`2c600000        0`00002000 MEM_PRIVATE MEM_COMMIT  PAGE_READWRITE                     Stack      [~1; 5b8.1e78]
+       a4`2c600000       a4`2c800000        0`00200000             MEM_FREE    PAGE_NOACCESS                      Free       
+       a4`2c800000       a4`2c9f9000        0`001f9000 MEM_PRIVATE MEM_RESERVE                                    Stack      [~2; 5b8.2194]
        a4`2c9f9000       a4`2c9fc000        0`00003000 MEM_PRIVATE MEM_COMMIT  PAGE_READWRITE | PAGE_GUARD        Stack      [~2; 5b8.2194]
        a4`2c9fc000       a4`2ca00000        0`00004000 MEM_PRIVATE MEM_COMMIT  PAGE_READWRITE                     Stack      [~2; 5b8.2194]
+       a4`2ca00000       a4`2cbfa000        0`001fa000 MEM_PRIVATE MEM_RESERVE                                    Stack      [~3; 5b8.1910]
        a4`2cbfa000       a4`2cbfd000        0`00003000 MEM_PRIVATE MEM_COMMIT  PAGE_READWRITE | PAGE_GUARD        Stack      [~3; 5b8.1910]
        a4`2cbfd000       a4`2cc00000        0`00003000 MEM_PRIVATE MEM_COMMIT  PAGE_READWRITE                     Stack      [~3; 5b8.1910]
+       a4`2cc00000       a4`2cdfb000        0`001fb000 MEM_PRIVATE MEM_RESERVE                                    Stack      [~4; 5b8.fe4]
        a4`2cdfb000       a4`2cdfe000        0`00003000 MEM_PRIVATE MEM_COMMIT  PAGE_READWRITE | PAGE_GUARD        Stack      [~4; 5b8.fe4]
        a4`2cdfe000       a4`2ce00000        0`00002000 MEM_PRIVATE MEM_COMMIT  PAGE_READWRITE                     Stack      [~4; 5b8.fe4]
+       a4`2ce00000       a4`2cffb000        0`001fb000 MEM_PRIVATE MEM_RESERVE                                    Stack      [~5; 5b8.15b0]
        a4`2cffb000       a4`2cffe000        0`00003000 MEM_PRIVATE MEM_COMMIT  PAGE_READWRITE | PAGE_GUARD        Stack      [~5; 5b8.15b0]
        a4`2cffe000       a4`2d000000        0`00002000 MEM_PRIVATE MEM_COMMIT  PAGE_READWRITE                     Stack      [~5; 5b8.15b0]
+       a4`2d000000       a4`2d1fb000        0`001fb000 MEM_PRIVATE MEM_RESERVE                                    Stack      [~6; 5b8.2a4]
        a4`2d1fb000       a4`2d1fe000        0`00003000 MEM_PRIVATE MEM_COMMIT  PAGE_READWRITE | PAGE_GUARD        Stack      [~6; 5b8.2a4]
        a4`2d1fe000       a4`2d200000        0`00002000 MEM_PRIVATE MEM_COMMIT  PAGE_READWRITE                     Stack      [~6; 5b8.2a4]
+       a4`2d200000       a4`2d3fb000        0`001fb000 MEM_PRIVATE MEM_RESERVE                                    Stack      [~7; 5b8.1414]
        a4`2d3fb000       a4`2d3fe000        0`00003000 MEM_PRIVATE MEM_COMMIT  PAGE_READWRITE | PAGE_GUARD        Stack      [~7; 5b8.1414]
        a4`2d3fe000       a4`2d400000        0`00002000 MEM_PRIVATE MEM_COMMIT  PAGE_READWRITE                     Stack      [~7; 5b8.1414]
+       a4`2d400000      234`0f1e0000      18f`e1de0000             MEM_FREE    PAGE_NOACCESS                      Free       
+      234`0f1e0000      234`0f1f0000        0`00010000 MEM_MAPPED  MEM_COMMIT  PAGE_READWRITE                     Heap       [ID: 1; Handle: 000002340f1e0000; Type: Segment]
+      234`0f1f0000      234`0f1f2000        0`00002000 MEM_PRIVATE MEM_COMMIT  PAGE_READWRITE                     Heap       [ID: 0; Handle: 000002340f320000; Type: Front End]
       234`0f1f2000      234`0f1fd000        0`0000b000 MEM_PRIVATE MEM_RESERVE                                    Heap       [ID: 0; Handle: 000002340f320000; Type: Front End]
+      234`0f1fd000      234`0f200000        0`00003000             MEM_FREE    PAGE_NOACCESS                      Free       
+      234`0f200000      234`0f21d000        0`0001d000 MEM_MAPPED  MEM_COMMIT  PAGE_READONLY                      Other      [API Set Map]
+      234`0f21d000      234`0f220000        0`00003000             MEM_FREE    PAGE_NOACCESS                      Free       
+      234`0f220000      234`0f224000        0`00004000 MEM_MAPPED  MEM_COMMIT  PAGE_READONLY                      Other      [System Default Activation Context Data]
+      234`0f224000      234`0f230000        0`0000c000             MEM_FREE    PAGE_NOACCESS                      Free       
+      234`0f230000      234`0f232000        0`00002000 MEM_PRIVATE MEM_COMMIT  PAGE_READWRITE                     <unknown>  [................]
+      234`0f232000      234`0f240000        0`0000e000             MEM_FREE    PAGE_NOACCESS                      Free       
+      234`0f240000      234`0f309000        0`000c9000 MEM_MAPPED  MEM_COMMIT  PAGE_READONLY                      <unknown>  [................]
+      234`0f309000      234`0f310000        0`00007000             MEM_FREE    PAGE_NOACCESS                      Free       
+      234`0f310000      234`0f311000        0`00001000 MEM_PRIVATE MEM_COMMIT  PAGE_EXECUTE_READ                  <unknown>  [L...3...I....q..]
+      234`0f311000      234`0f320000        0`0000f000             MEM_FREE    PAGE_NOACCESS                      Free       
+      234`0f320000      234`0f3a4000        0`00084000 MEM_PRIVATE MEM_COMMIT  PAGE_READWRITE                     Heap       [ID: 0; Handle: 000002340f320000; Type: Segment]
       234`0f3a4000      234`0f41f000        0`0007b000 MEM_PRIVATE MEM_RESERVE                                    Heap       [ID: 0; Handle: 000002340f320000; Type: Segment]
       234`0f41f000      234`0f420000        0`00001000 MEM_PRIVATE MEM_RESERVE                                    <unknown>  
+      234`0f420000      234`0f610000        0`001f0000 MEM_MAPPED  MEM_COMMIT  PAGE_READONLY                      <unknown>  [MZ..............]
+      234`0f610000      234`0f620000        0`00010000 MEM_PRIVATE MEM_COMMIT  PAGE_EXECUTE_READWRITE             <unknown>  [L.......I....q..]
+      234`0f620000      234`0f621000        0`00001000 MEM_PRIVATE MEM_COMMIT  PAGE_READWRITE                     Heap       [ID: 2; Handle: 000002340f680000; Type: Front End]
       234`0f621000      234`0f62d000        0`0000c000 MEM_PRIVATE MEM_RESERVE                                    Heap       [ID: 2; Handle: 000002340f680000; Type: Front End]
+      234`0f62d000      234`0f630000        0`00003000             MEM_FREE    PAGE_NOACCESS                      Free       
+      234`0f630000      234`0f631000        0`00001000 MEM_MAPPED  MEM_COMMIT  PAGE_READONLY                      <unknown>  [6....Uk.........]
+      234`0f631000      234`0f640000        0`0000f000             MEM_FREE    PAGE_NOACCESS                      Free       
+      234`0f640000      234`0f641000        0`00001000 MEM_MAPPED  MEM_COMMIT  PAGE_READONLY                      <unknown>  [6....Uk.........]
+      234`0f641000      234`0f650000        0`0000f000             MEM_FREE    PAGE_NOACCESS                      Free       
+      234`0f650000      234`0f651000        0`00001000 MEM_MAPPED  MEM_COMMIT  PAGE_READONLY                      <unknown>  [....f.I.....u...]
+      234`0f651000      234`0f660000        0`0000f000             MEM_FREE    PAGE_NOACCESS                      Free       
+      234`0f660000      234`0f661000        0`00001000 MEM_PRIVATE MEM_COMMIT  PAGE_READWRITE                     Heap       [ID: 3; Handle: 000002340f6c0000; Type: Front End]
       234`0f661000      234`0f66d000        0`0000c000 MEM_PRIVATE MEM_RESERVE                                    Heap       [ID: 3; Handle: 000002340f6c0000; Type: Front End]
+      234`0f66d000      234`0f670000        0`00003000             MEM_FREE    PAGE_NOACCESS                      Free       
+      234`0f670000      234`0f674000        0`00004000 MEM_MAPPED  MEM_COMMIT  PAGE_READONLY                      <unknown>  [..........dk....]
       234`0f674000      234`0f678000        0`00004000 MEM_MAPPED  MEM_RESERVE                                    <unknown>  
+      234`0f678000      234`0f680000        0`00008000             MEM_FREE    PAGE_NOACCESS                      Free       
+      234`0f680000      234`0f687000        0`00007000 MEM_PRIVATE MEM_COMMIT  PAGE_READWRITE                     Heap       [ID: 2; Handle: 000002340f680000; Type: Segment]
       234`0f687000      234`0f68f000        0`00008000 MEM_PRIVATE MEM_RESERVE                                    Heap       [ID: 2; Handle: 000002340f680000; Type: Segment]
       234`0f68f000      234`0f690000        0`00001000 MEM_PRIVATE MEM_RESERVE                                    <unknown>  
+      234`0f690000      234`0f695000        0`00005000 MEM_MAPPED  MEM_COMMIT  PAGE_READONLY                      <unknown>  [MZ..............]
+      234`0f695000      234`0f6a0000        0`0000b000             MEM_FREE    PAGE_NOACCESS                      Free       
+      234`0f6a0000      234`0f6b0000        0`00010000 MEM_MAPPED  MEM_COMMIT  PAGE_READONLY                      <unknown>  [MZ..............]
+      234`0f6b0000      234`0f6b1000        0`00001000 MEM_MAPPED  MEM_COMMIT  PAGE_READONLY                      <unknown>  [................]
+      234`0f6b1000      234`0f6c0000        0`0000f000             MEM_FREE    PAGE_NOACCESS                      Free       
+      234`0f6c0000      234`0f6c7000        0`00007000 MEM_PRIVATE MEM_COMMIT  PAGE_READWRITE                     Heap       [ID: 3; Handle: 000002340f6c0000; Type: Segment]
       234`0f6c7000      234`0f6cf000        0`00008000 MEM_PRIVATE MEM_RESERVE                                    Heap       [ID: 3; Handle: 000002340f6c0000; Type: Segment]
       234`0f6cf000      234`0f6d0000        0`00001000 MEM_PRIVATE MEM_RESERVE                                    <unknown>  
+      234`0f6d0000      234`0f6d9000        0`00009000 MEM_MAPPED  MEM_COMMIT  PAGE_READONLY                      <unknown>  [................]
       234`0f6d9000      234`0f8d0000        0`001f7000 MEM_MAPPED  MEM_RESERVE                                    <unknown>  
+      234`0f8d0000      234`0fa51000        0`00181000 MEM_MAPPED  MEM_COMMIT  PAGE_READONLY                      Other      [GDI Shared Handle Table]
+      234`0fa51000      234`0fa60000        0`0000f000             MEM_FREE    PAGE_NOACCESS                      Free       
+      234`0fa60000      234`0faac000        0`0004c000 MEM_MAPPED  MEM_COMMIT  PAGE_READONLY                      <unknown>  [.........v.j....]
       234`0faac000      234`10e61000        0`013b5000 MEM_MAPPED  MEM_RESERVE                                    <unknown>  
+      234`10e61000      234`10e70000        0`0000f000             MEM_FREE    PAGE_NOACCESS                      Free       
+      234`10e70000      234`111a8000        0`00338000 MEM_MAPPED  MEM_COMMIT  PAGE_READONLY                      <unknown>  [........hL..xw..]
+      234`111a8000      234`111b0000        0`00008000             MEM_FREE    PAGE_NOACCESS                      Free       
+      234`111b0000      234`111b3000        0`00003000 MEM_MAPPED  MEM_COMMIT  PAGE_READONLY                      <unknown>  [MZ..............]
+      234`111b3000     7ff4`f9c60000     7dc0`e8aad000             MEM_FREE    PAGE_NOACCESS                      Free       
+     7ff4`f9c60000     7ff4`f9c65000        0`00005000 MEM_MAPPED  MEM_COMMIT  PAGE_READONLY                      Other      [Read Only Shared Memory]
      7ff4`f9c65000     7ff4`f9d60000        0`000fb000 MEM_MAPPED  MEM_RESERVE                                    <unknown>  
+     7ff4`f9d60000     7ff5`f9d80000        1`00020000 MEM_PRIVATE MEM_RESERVE                                    <unknown>  
+     7ff5`f9d80000     7ff5`fbd80000        0`02000000 MEM_PRIVATE MEM_RESERVE                                    <unknown>  
      7ff5`fbd80000     7ff5`fbd81000        0`00001000 MEM_PRIVATE MEM_COMMIT  PAGE_READWRITE                     <unknown>  [................]
+     7ff5`fbd81000     7ff5`fbd90000        0`0000f000             MEM_FREE    PAGE_NOACCESS                      Free       
+     7ff5`fbd90000     7ff5`fbd91000        0`00001000 MEM_MAPPED  MEM_COMMIT  PAGE_READONLY                      <unknown>  [................]
+     7ff5`fbd91000     7ff5`fbda0000        0`0000f000             MEM_FREE    PAGE_NOACCESS                      Free       
+     7ff5`fbda0000     7ff5`fbdc3000        0`00023000 MEM_MAPPED  MEM_COMMIT  PAGE_READONLY                      Other      [NLS Tables]
+     7ff5`fbdc3000     7ff7`96f50000        1`9b18d000             MEM_FREE    PAGE_NOACCESS                      Free       
+     7ff7`96f50000     7ff7`96f68000        0`00018000 MEM_IMAGE   MEM_COMMIT  PAGE_READWRITE                     Image      [demon; "C:\Users\lowpriv1\Downloads\demon.exe"]
+     7ff7`96f68000     7ffe`5f5e0000        6`c8678000             MEM_FREE    PAGE_NOACCESS                      Free       
+     7ffe`5f5e0000     7ffe`5f5e1000        0`00001000 MEM_IMAGE   MEM_COMMIT  PAGE_READONLY                      Image      [netapi32; "C:\Windows\System32\netapi32.dll"]
      7ffe`5f5e1000     7ffe`5f5ed000        0`0000c000 MEM_IMAGE   MEM_COMMIT  PAGE_EXECUTE_READ                  Image      [netapi32; "C:\Windows\System32\netapi32.dll"]
      7ffe`5f5ed000     7ffe`5f5f4000        0`00007000 MEM_IMAGE   MEM_COMMIT  PAGE_READONLY                      Image      [netapi32; "C:\Windows\System32\netapi32.dll"]
      7ffe`5f5f4000     7ffe`5f5f5000        0`00001000 MEM_IMAGE   MEM_COMMIT  PAGE_READWRITE                     Image      [netapi32; "C:\Windows\System32\netapi32.dll"]
      7ffe`5f5f5000     7ffe`5f5f9000        0`00004000 MEM_IMAGE   MEM_COMMIT  PAGE_READONLY                      Image      [netapi32; "C:\Windows\System32\netapi32.dll"]
+     7ffe`5f5f9000     7ffe`5f810000        0`00217000             MEM_FREE    PAGE_NOACCESS                      Free       
+     7ffe`5f810000     7ffe`5f811000        0`00001000 MEM_IMAGE   MEM_COMMIT  PAGE_READONLY                      Image      [mscoree; "C:\Windows\System32\mscoree.dll"]
      7ffe`5f811000     7ffe`5f851000        0`00040000 MEM_IMAGE   MEM_COMMIT  PAGE_EXECUTE_READ                  Image      [mscoree; "C:\Windows\System32\mscoree.dll"]
      7ffe`5f851000     7ffe`5f869000        0`00018000 MEM_IMAGE   MEM_COMMIT  PAGE_READONLY                      Image      [mscoree; "C:\Windows\System32\mscoree.dll"]
      7ffe`5f869000     7ffe`5f86f000        0`00006000 MEM_IMAGE   MEM_COMMIT  PAGE_READWRITE                     Image      [mscoree; "C:\Windows\System32\mscoree.dll"]
      7ffe`5f86f000     7ffe`5f875000        0`00006000 MEM_IMAGE   MEM_COMMIT  PAGE_READONLY                      Image      [mscoree; "C:\Windows\System32\mscoree.dll"]
+     7ffe`5f875000     7ffe`631c0000        0`0394b000             MEM_FREE    PAGE_NOACCESS                      Free       
+     7ffe`631c0000     7ffe`631c1000        0`00001000 MEM_IMAGE   MEM_COMMIT  PAGE_READONLY                      Image      [webio; "C:\Windows\System32\webio.dll"]
      7ffe`631c1000     7ffe`6322a000        0`00069000 MEM_IMAGE   MEM_COMMIT  PAGE_EXECUTE_READ                  Image      [webio; "C:\Windows\System32\webio.dll"]
      7ffe`6322a000     7ffe`6323c000        0`00012000 MEM_IMAGE   MEM_COMMIT  PAGE_READONLY                      Image      [webio; "C:\Windows\System32\webio.dll"]
      7ffe`6323c000     7ffe`63240000        0`00004000 MEM_IMAGE   MEM_COMMIT  PAGE_READWRITE                     Image      [webio; "C:\Windows\System32\webio.dll"]
      7ffe`63240000     7ffe`63258000        0`00018000 MEM_IMAGE   MEM_COMMIT  PAGE_READONLY                      Image      [webio; "C:\Windows\System32\webio.dll"]
+     7ffe`63258000     7ffe`66250000        0`02ff8000             MEM_FREE    PAGE_NOACCESS                      Free       
+     7ffe`66250000     7ffe`66251000        0`00001000 MEM_IMAGE   MEM_COMMIT  PAGE_READONLY                      Image      [samcli; "C:\Windows\System32\samcli.dll"]
      7ffe`66251000     7ffe`66260000        0`0000f000 MEM_IMAGE   MEM_COMMIT  PAGE_EXECUTE_READ                  Image      [samcli; "C:\Windows\System32\samcli.dll"]
      7ffe`66260000     7ffe`66264000        0`00004000 MEM_IMAGE   MEM_COMMIT  PAGE_READONLY                      Image      [samcli; "C:\Windows\System32\samcli.dll"]
      7ffe`66264000     7ffe`66265000        0`00001000 MEM_IMAGE   MEM_COMMIT  PAGE_READWRITE                     Image      [samcli; "C:\Windows\System32\samcli.dll"]
      7ffe`66265000     7ffe`66269000        0`00004000 MEM_IMAGE   MEM_COMMIT  PAGE_READONLY                      Image      [samcli; "C:\Windows\System32\samcli.dll"]
+     7ffe`66269000     7ffe`66880000        0`00617000             MEM_FREE    PAGE_NOACCESS                      Free       
+     7ffe`66880000     7ffe`66881000        0`00001000 MEM_IMAGE   MEM_COMMIT  PAGE_READONLY                      Image      [winhttp; "C:\Windows\System32\winhttp.dll"]
      7ffe`66881000     7ffe`66950000        0`000cf000 MEM_IMAGE   MEM_COMMIT  PAGE_EXECUTE_READ                  Image      [winhttp; "C:\Windows\System32\winhttp.dll"]
      7ffe`66950000     7ffe`66973000        0`00023000 MEM_IMAGE   MEM_COMMIT  PAGE_READONLY                      Image      [winhttp; "C:\Windows\System32\winhttp.dll"]
      7ffe`66973000     7ffe`66975000        0`00002000 MEM_IMAGE   MEM_COMMIT  PAGE_READWRITE                     Image      [winhttp; "C:\Windows\System32\winhttp.dll"]
      7ffe`66975000     7ffe`6698a000        0`00015000 MEM_IMAGE   MEM_COMMIT  PAGE_READONLY                      Image      [winhttp; "C:\Windows\System32\winhttp.dll"]
+     7ffe`6698a000     7ffe`684d0000        0`01b46000             MEM_FREE    PAGE_NOACCESS                      Free       
+     7ffe`684d0000     7ffe`684d1000        0`00001000 MEM_IMAGE   MEM_COMMIT  PAGE_READONLY                      Image      [dhcpcsvc; "C:\Windows\System32\dhcpcsvc.dll"]
      7ffe`684d1000     7ffe`684e0000        0`0000f000 MEM_IMAGE   MEM_COMMIT  PAGE_EXECUTE_READ                  Image      [dhcpcsvc; "C:\Windows\System32\dhcpcsvc.dll"]
      7ffe`684e0000     7ffe`684e8000        0`00008000 MEM_IMAGE   MEM_COMMIT  PAGE_READONLY                      Image      [dhcpcsvc; "C:\Windows\System32\dhcpcsvc.dll"]
      7ffe`684e8000     7ffe`684e9000        0`00001000 MEM_IMAGE   MEM_COMMIT  PAGE_READWRITE                     Image      [dhcpcsvc; "C:\Windows\System32\dhcpcsvc.dll"]
      7ffe`684e9000     7ffe`684ed000        0`00004000 MEM_IMAGE   MEM_COMMIT  PAGE_READONLY                      Image      [dhcpcsvc; "C:\Windows\System32\dhcpcsvc.dll"]
+     7ffe`684ed000     7ffe`68df0000        0`00903000             MEM_FREE    PAGE_NOACCESS                      Free       
+     7ffe`68df0000     7ffe`68df1000        0`00001000 MEM_IMAGE   MEM_COMMIT  PAGE_READONLY                      Image      [winnsi; "C:\Windows\System32\winnsi.dll"]
      7ffe`68df1000     7ffe`68df4000        0`00003000 MEM_IMAGE   MEM_COMMIT  PAGE_EXECUTE_READ                  Image      [winnsi; "C:\Windows\System32\winnsi.dll"]
      7ffe`68df4000     7ffe`68df7000        0`00003000 MEM_IMAGE   MEM_COMMIT  PAGE_READONLY                      Image      [winnsi; "C:\Windows\System32\winnsi.dll"]
      7ffe`68df7000     7ffe`68df8000        0`00001000 MEM_IMAGE   MEM_COMMIT  PAGE_READWRITE                     Image      [winnsi; "C:\Windows\System32\winnsi.dll"]
      7ffe`68df8000     7ffe`68dfb000        0`00003000 MEM_IMAGE   MEM_COMMIT  PAGE_READONLY                      Image      [winnsi; "C:\Windows\System32\winnsi.dll"]
+     7ffe`68dfb000     7ffe`6bfa0000        0`031a5000             MEM_FREE    PAGE_NOACCESS                      Free       
+     7ffe`6bfa0000     7ffe`6bfa1000        0`00001000 MEM_IMAGE   MEM_COMMIT  PAGE_READONLY                      Image      [apphelp; "C:\Windows\System32\apphelp.dll"]
      7ffe`6bfa1000     7ffe`6bfef000        0`0004e000 MEM_IMAGE   MEM_COMMIT  PAGE_EXECUTE_READ                  Image      [apphelp; "C:\Windows\System32\apphelp.dll"]
      7ffe`6bfef000     7ffe`6c011000        0`00022000 MEM_IMAGE   MEM_COMMIT  PAGE_READONLY                      Image      [apphelp; "C:\Windows\System32\apphelp.dll"]
      7ffe`6c011000     7ffe`6c014000        0`00003000 MEM_IMAGE   MEM_COMMIT  PAGE_READWRITE                     Image      [apphelp; "C:\Windows\System32\apphelp.dll"]
      7ffe`6c014000     7ffe`6c030000        0`0001c000 MEM_IMAGE   MEM_COMMIT  PAGE_READONLY                      Image      [apphelp; "C:\Windows\System32\apphelp.dll"]
+     7ffe`6c030000     7ffe`6d6c0000        0`01690000             MEM_FREE    PAGE_NOACCESS                      Free       
+     7ffe`6d6c0000     7ffe`6d6c1000        0`00001000 MEM_IMAGE   MEM_COMMIT  PAGE_READONLY                      Image      [srvcli; "C:\Windows\System32\srvcli.dll"]
      7ffe`6d6c1000     7ffe`6d6cf000        0`0000e000 MEM_IMAGE   MEM_COMMIT  PAGE_EXECUTE_READ                  Image      [srvcli; "C:\Windows\System32\srvcli.dll"]
      7ffe`6d6cf000     7ffe`6d6db000        0`0000c000 MEM_IMAGE   MEM_COMMIT  PAGE_READONLY                      Image      [srvcli; "C:\Windows\System32\srvcli.dll"]
      7ffe`6d6db000     7ffe`6d6e0000        0`00005000 MEM_IMAGE   MEM_COMMIT  PAGE_READWRITE                     Image      [srvcli; "C:\Windows\System32\srvcli.dll"]
      7ffe`6d6e0000     7ffe`6d6e4000        0`00004000 MEM_IMAGE   MEM_COMMIT  PAGE_WRITECOPY                     Image      [srvcli; "C:\Windows\System32\srvcli.dll"]
      7ffe`6d6e4000     7ffe`6d6e8000        0`00004000 MEM_IMAGE   MEM_COMMIT  PAGE_READONLY                      Image      [srvcli; "C:\Windows\System32\srvcli.dll"]
+     7ffe`6d6e8000     7ffe`6dba0000        0`004b8000             MEM_FREE    PAGE_NOACCESS                      Free       
+     7ffe`6dba0000     7ffe`6dba1000        0`00001000 MEM_IMAGE   MEM_COMMIT  PAGE_READONLY                      Image      [wkscli; "C:\Windows\System32\wkscli.dll"]
      7ffe`6dba1000     7ffe`6dbad000        0`0000c000 MEM_IMAGE   MEM_COMMIT  PAGE_EXECUTE_READ                  Image      [wkscli; "C:\Windows\System32\wkscli.dll"]
      7ffe`6dbad000     7ffe`6dbb4000        0`00007000 MEM_IMAGE   MEM_COMMIT  PAGE_READONLY                      Image      [wkscli; "C:\Windows\System32\wkscli.dll"]
      7ffe`6dbb4000     7ffe`6dbb5000        0`00001000 MEM_IMAGE   MEM_COMMIT  PAGE_READWRITE                     Image      [wkscli; "C:\Windows\System32\wkscli.dll"]
      7ffe`6dbb5000     7ffe`6dbb9000        0`00004000 MEM_IMAGE   MEM_COMMIT  PAGE_READONLY                      Image      [wkscli; "C:\Windows\System32\wkscli.dll"]
+     7ffe`6dbb9000     7ffe`6de10000        0`00257000             MEM_FREE    PAGE_NOACCESS                      Free       
+     7ffe`6de10000     7ffe`6de11000        0`00001000 MEM_IMAGE   MEM_COMMIT  PAGE_READONLY                      Image      [IPHLPAPI; "C:\Windows\System32\IPHLPAPI.DLL"]
      7ffe`6de11000     7ffe`6de3b000        0`0002a000 MEM_IMAGE   MEM_COMMIT  PAGE_EXECUTE_READ                  Image      [IPHLPAPI; "C:\Windows\System32\IPHLPAPI.DLL"]
      7ffe`6de3b000     7ffe`6de46000        0`0000b000 MEM_IMAGE   MEM_COMMIT  PAGE_READONLY                      Image      [IPHLPAPI; "C:\Windows\System32\IPHLPAPI.DLL"]
      7ffe`6de46000     7ffe`6de47000        0`00001000 MEM_IMAGE   MEM_COMMIT  PAGE_READWRITE                     Image      [IPHLPAPI; "C:\Windows\System32\IPHLPAPI.DLL"]
      7ffe`6de47000     7ffe`6de4c000        0`00005000 MEM_IMAGE   MEM_COMMIT  PAGE_READONLY                      Image      [IPHLPAPI; "C:\Windows\System32\IPHLPAPI.DLL"]
+     7ffe`6de4c000     7ffe`6df20000        0`000d4000             MEM_FREE    PAGE_NOACCESS                      Free       
+     7ffe`6df20000     7ffe`6df21000        0`00001000 MEM_IMAGE   MEM_COMMIT  PAGE_READONLY                      Image      [netutils; "C:\Windows\System32\netutils.dll"]
      7ffe`6df21000     7ffe`6df26000        0`00005000 MEM_IMAGE   MEM_COMMIT  PAGE_EXECUTE_READ                  Image      [netutils; "C:\Windows\System32\netutils.dll"]
      7ffe`6df26000     7ffe`6df28000        0`00002000 MEM_IMAGE   MEM_COMMIT  PAGE_READONLY                      Image      [netutils; "C:\Windows\System32\netutils.dll"]
      7ffe`6df28000     7ffe`6df29000        0`00001000 MEM_IMAGE   MEM_COMMIT  PAGE_READWRITE                     Image      [netutils; "C:\Windows\System32\netutils.dll"]
      7ffe`6df29000     7ffe`6df2c000        0`00003000 MEM_IMAGE   MEM_COMMIT  PAGE_READONLY                      Image      [netutils; "C:\Windows\System32\netutils.dll"]
+     7ffe`6df2c000     7ffe`6e120000        0`001f4000             MEM_FREE    PAGE_NOACCESS                      Free       
+     7ffe`6e120000     7ffe`6e121000        0`00001000 MEM_IMAGE   MEM_COMMIT  PAGE_READONLY                      Image      [mswsock; "C:\Windows\System32\mswsock.dll"]
      7ffe`6e121000     7ffe`6e174000        0`00053000 MEM_IMAGE   MEM_COMMIT  PAGE_EXECUTE_READ                  Image      [mswsock; "C:\Windows\System32\mswsock.dll"]
      7ffe`6e174000     7ffe`6e182000        0`0000e000 MEM_IMAGE   MEM_COMMIT  PAGE_READONLY                      Image      [mswsock; "C:\Windows\System32\mswsock.dll"]
      7ffe`6e182000     7ffe`6e184000        0`00002000 MEM_IMAGE   MEM_COMMIT  PAGE_READWRITE                     Image      [mswsock; "C:\Windows\System32\mswsock.dll"]
      7ffe`6e184000     7ffe`6e18a000        0`00006000 MEM_IMAGE   MEM_COMMIT  PAGE_READONLY                      Image      [mswsock; "C:\Windows\System32\mswsock.dll"]
+     7ffe`6e18a000     7ffe`6e310000        0`00186000             MEM_FREE    PAGE_NOACCESS                      Free       
+     7ffe`6e310000     7ffe`6e311000        0`00001000 MEM_IMAGE   MEM_COMMIT  PAGE_READONLY                      Image      [cryptsp; "C:\Windows\System32\cryptsp.dll"]
      7ffe`6e311000     7ffe`6e31d000        0`0000c000 MEM_IMAGE   MEM_COMMIT  PAGE_EXECUTE_READ                  Image      [cryptsp; "C:\Windows\System32\cryptsp.dll"]
      7ffe`6e31d000     7ffe`6e323000        0`00006000 MEM_IMAGE   MEM_COMMIT  PAGE_READONLY                      Image      [cryptsp; "C:\Windows\System32\cryptsp.dll"]
      7ffe`6e323000     7ffe`6e324000        0`00001000 MEM_IMAGE   MEM_COMMIT  PAGE_READWRITE                     Image      [cryptsp; "C:\Windows\System32\cryptsp.dll"]
      7ffe`6e324000     7ffe`6e328000        0`00004000 MEM_IMAGE   MEM_COMMIT  PAGE_READONLY                      Image      [cryptsp; "C:\Windows\System32\cryptsp.dll"]
+     7ffe`6e328000     7ffe`6e930000        0`00608000             MEM_FREE    PAGE_NOACCESS                      Free       
+     7ffe`6e930000     7ffe`6e931000        0`00001000 MEM_IMAGE   MEM_COMMIT  PAGE_READONLY                      Image      [sspicli; "C:\Windows\System32\sspicli.dll"]
      7ffe`6e931000     7ffe`6e950000        0`0001f000 MEM_IMAGE   MEM_COMMIT  PAGE_EXECUTE_READ                  Image      [sspicli; "C:\Windows\System32\sspicli.dll"]
      7ffe`6e950000     7ffe`6e95b000        0`0000b000 MEM_IMAGE   MEM_COMMIT  PAGE_READONLY                      Image      [sspicli; "C:\Windows\System32\sspicli.dll"]
      7ffe`6e95b000     7ffe`6e95d000        0`00002000 MEM_IMAGE   MEM_COMMIT  PAGE_READWRITE                     Image      [sspicli; "C:\Windows\System32\sspicli.dll"]
      7ffe`6e95d000     7ffe`6e962000        0`00005000 MEM_IMAGE   MEM_COMMIT  PAGE_READONLY                      Image      [sspicli; "C:\Windows\System32\sspicli.dll"]
+     7ffe`6e962000     7ffe`6ea90000        0`0012e000             MEM_FREE    PAGE_NOACCESS                      Free       
+     7ffe`6ea90000     7ffe`6ea91000        0`00001000 MEM_IMAGE   MEM_COMMIT  PAGE_READONLY                      Image      [bcryptprimitives; "C:\Windows\System32\bcryptprimitives.dll"]
      7ffe`6ea91000     7ffe`6eaf5000        0`00064000 MEM_IMAGE   MEM_COMMIT  PAGE_EXECUTE_READ                  Image      [bcryptprimitives; "C:\Windows\System32\bcryptprimitives.dll"]
      7ffe`6eaf5000     7ffe`6eb0b000        0`00016000 MEM_IMAGE   MEM_COMMIT  PAGE_READONLY                      Image      [bcryptprimitives; "C:\Windows\System32\bcryptprimitives.dll"]
      7ffe`6eb0b000     7ffe`6eb0c000        0`00001000 MEM_IMAGE   MEM_COMMIT  PAGE_READWRITE                     Image      [bcryptprimitives; "C:\Windows\System32\bcryptprimitives.dll"]
      7ffe`6eb0c000     7ffe`6eb12000        0`00006000 MEM_IMAGE   MEM_COMMIT  PAGE_READONLY                      Image      [bcryptprimitives; "C:\Windows\System32\bcryptprimitives.dll"]
+     7ffe`6eb12000     7ffe`6eb20000        0`0000e000             MEM_FREE    PAGE_NOACCESS                      Free       
+     7ffe`6eb20000     7ffe`6eb21000        0`00001000 MEM_IMAGE   MEM_COMMIT  PAGE_READONLY                      Image      [KERNELBASE; "C:\Windows\System32\KERNELBASE.dll"]
      7ffe`6eb21000     7ffe`6ec3e000        0`0011d000 MEM_IMAGE   MEM_COMMIT  PAGE_EXECUTE_READ                  Image      [KERNELBASE; "C:\Windows\System32\KERNELBASE.dll"]
      7ffe`6ec3e000     7ffe`6edbb000        0`0017d000 MEM_IMAGE   MEM_COMMIT  PAGE_READONLY                      Image      [KERNELBASE; "C:\Windows\System32\KERNELBASE.dll"]
      7ffe`6edbb000     7ffe`6edbf000        0`00004000 MEM_IMAGE   MEM_COMMIT  PAGE_READWRITE                     Image      [KERNELBASE; "C:\Windows\System32\KERNELBASE.dll"]
      7ffe`6edbf000     7ffe`6edc0000        0`00001000 MEM_IMAGE   MEM_COMMIT  PAGE_WRITECOPY                     Image      [KERNELBASE; "C:\Windows\System32\KERNELBASE.dll"]
      7ffe`6edc0000     7ffe`6edfa000        0`0003a000 MEM_IMAGE   MEM_COMMIT  PAGE_READONLY                      Image      [KERNELBASE; "C:\Windows\System32\KERNELBASE.dll"]
+     7ffe`6edfa000     7ffe`6ee00000        0`00006000             MEM_FREE    PAGE_NOACCESS                      Free       
+     7ffe`6ee00000     7ffe`6ee01000        0`00001000 MEM_IMAGE   MEM_COMMIT  PAGE_READONLY                      Image      [bcrypt; "C:\Windows\System32\bcrypt.dll"]
      7ffe`6ee01000     7ffe`6ee1b000        0`0001a000 MEM_IMAGE   MEM_COMMIT  PAGE_EXECUTE_READ                  Image      [bcrypt; "C:\Windows\System32\bcrypt.dll"]
      7ffe`6ee1b000     7ffe`6ee21000        0`00006000 MEM_IMAGE   MEM_COMMIT  PAGE_READONLY                      Image      [bcrypt; "C:\Windows\System32\bcrypt.dll"]
      7ffe`6ee21000     7ffe`6ee22000        0`00001000 MEM_IMAGE   MEM_COMMIT  PAGE_READWRITE                     Image      [bcrypt; "C:\Windows\System32\bcrypt.dll"]
      7ffe`6ee22000     7ffe`6ee27000        0`00005000 MEM_IMAGE   MEM_COMMIT  PAGE_READONLY                      Image      [bcrypt; "C:\Windows\System32\bcrypt.dll"]
+     7ffe`6ee27000     7ffe`6ee30000        0`00009000             MEM_FREE    PAGE_NOACCESS                      Free       
+     7ffe`6ee30000     7ffe`6ee31000        0`00001000 MEM_IMAGE   MEM_COMMIT  PAGE_READONLY                      Image      [win32u; "C:\Windows\System32\win32u.dll"]
      7ffe`6ee31000     7ffe`6ee3c000        0`0000b000 MEM_IMAGE   MEM_COMMIT  PAGE_EXECUTE_READ                  Image      [win32u; "C:\Windows\System32\win32u.dll"]
      7ffe`6ee3c000     7ffe`6ee4b000        0`0000f000 MEM_IMAGE   MEM_COMMIT  PAGE_READONLY                      Image      [win32u; "C:\Windows\System32\win32u.dll"]
      7ffe`6ee4b000     7ffe`6ee4c000        0`00001000 MEM_IMAGE   MEM_COMMIT  PAGE_READWRITE                     Image      [win32u; "C:\Windows\System32\win32u.dll"]
      7ffe`6ee4c000     7ffe`6ee52000        0`00006000 MEM_IMAGE   MEM_COMMIT  PAGE_READONLY                      Image      [win32u; "C:\Windows\System32\win32u.dll"]
+     7ffe`6ee52000     7ffe`6ef10000        0`000be000             MEM_FREE    PAGE_NOACCESS                      Free       
+     7ffe`6ef10000     7ffe`6ef11000        0`00001000 MEM_IMAGE   MEM_COMMIT  PAGE_READONLY                      Image      [crypt32; "C:\Windows\System32\crypt32.dll"]
      7ffe`6ef11000     7ffe`6f017000        0`00106000 MEM_IMAGE   MEM_COMMIT  PAGE_EXECUTE_READ                  Image      [crypt32; "C:\Windows\System32\crypt32.dll"]
      7ffe`6f017000     7ffe`6f04e000        0`00037000 MEM_IMAGE   MEM_COMMIT  PAGE_READONLY                      Image      [crypt32; "C:\Windows\System32\crypt32.dll"]
      7ffe`6f04e000     7ffe`6f055000        0`00007000 MEM_IMAGE   MEM_COMMIT  PAGE_READWRITE                     Image      [crypt32; "C:\Windows\System32\crypt32.dll"]
      7ffe`6f055000     7ffe`6f066000        0`00011000 MEM_IMAGE   MEM_COMMIT  PAGE_READONLY                      Image      [crypt32; "C:\Windows\System32\crypt32.dll"]
+     7ffe`6f066000     7ffe`6f070000        0`0000a000             MEM_FREE    PAGE_NOACCESS                      Free       
+     7ffe`6f070000     7ffe`6f071000        0`00001000 MEM_IMAGE   MEM_COMMIT  PAGE_READONLY                      Image      [ucrtbase; "C:\Windows\System32\ucrtbase.dll"]
      7ffe`6f071000     7ffe`6f125000        0`000b4000 MEM_IMAGE   MEM_COMMIT  PAGE_EXECUTE_READ                  Image      [ucrtbase; "C:\Windows\System32\ucrtbase.dll"]
      7ffe`6f125000     7ffe`6f15f000        0`0003a000 MEM_IMAGE   MEM_COMMIT  PAGE_READONLY                      Image      [ucrtbase; "C:\Windows\System32\ucrtbase.dll"]
      7ffe`6f15f000     7ffe`6f162000        0`00003000 MEM_IMAGE   MEM_COMMIT  PAGE_READWRITE                     Image      [ucrtbase; "C:\Windows\System32\ucrtbase.dll"]
      7ffe`6f162000     7ffe`6f170000        0`0000e000 MEM_IMAGE   MEM_COMMIT  PAGE_READONLY                      Image      [ucrtbase; "C:\Windows\System32\ucrtbase.dll"]
+     7ffe`6f170000     7ffe`6f171000        0`00001000 MEM_IMAGE   MEM_COMMIT  PAGE_READONLY                      Image      [gdi32full; "C:\Windows\System32\gdi32full.dll"]
      7ffe`6f171000     7ffe`6f211000        0`000a0000 MEM_IMAGE   MEM_COMMIT  PAGE_EXECUTE_READ                  Image      [gdi32full; "C:\Windows\System32\gdi32full.dll"]
      7ffe`6f211000     7ffe`6f25f000        0`0004e000 MEM_IMAGE   MEM_COMMIT  PAGE_READONLY                      Image      [gdi32full; "C:\Windows\System32\gdi32full.dll"]
      7ffe`6f25f000     7ffe`6f264000        0`00005000 MEM_IMAGE   MEM_COMMIT  PAGE_READWRITE                     Image      [gdi32full; "C:\Windows\System32\gdi32full.dll"]
      7ffe`6f264000     7ffe`6f280000        0`0001c000 MEM_IMAGE   MEM_COMMIT  PAGE_READONLY                      Image      [gdi32full; "C:\Windows\System32\gdi32full.dll"]
+     7ffe`6f280000     7ffe`6f2f0000        0`00070000             MEM_FREE    PAGE_NOACCESS                      Free       
+     7ffe`6f2f0000     7ffe`6f2f1000        0`00001000 MEM_IMAGE   MEM_COMMIT  PAGE_READONLY                      Image      [msvcp_win; "C:\Windows\System32\msvcp_win.dll"]
      7ffe`6f2f1000     7ffe`6f345000        0`00054000 MEM_IMAGE   MEM_COMMIT  PAGE_EXECUTE_READ                  Image      [msvcp_win; "C:\Windows\System32\msvcp_win.dll"]
      7ffe`6f345000     7ffe`6f381000        0`0003c000 MEM_IMAGE   MEM_COMMIT  PAGE_READONLY                      Image      [msvcp_win; "C:\Windows\System32\msvcp_win.dll"]
      7ffe`6f381000     7ffe`6f382000        0`00001000 MEM_IMAGE   MEM_COMMIT  PAGE_WRITECOPY                     Image      [msvcp_win; "C:\Windows\System32\msvcp_win.dll"]
      7ffe`6f382000     7ffe`6f385000        0`00003000 MEM_IMAGE   MEM_COMMIT  PAGE_READWRITE                     Image      [msvcp_win; "C:\Windows\System32\msvcp_win.dll"]
      7ffe`6f385000     7ffe`6f38d000        0`00008000 MEM_IMAGE   MEM_COMMIT  PAGE_READONLY                      Image      [msvcp_win; "C:\Windows\System32\msvcp_win.dll"]
+     7ffe`6f38d000     7ffe`6f390000        0`00003000             MEM_FREE    PAGE_NOACCESS                      Free       
+     7ffe`6f390000     7ffe`6f391000        0`00001000 MEM_IMAGE   MEM_COMMIT  PAGE_READONLY                      Image      [oleaut32; "C:\Windows\System32\oleaut32.dll"]
      7ffe`6f391000     7ffe`6f426000        0`00095000 MEM_IMAGE   MEM_COMMIT  PAGE_EXECUTE_READ                  Image      [oleaut32; "C:\Windows\System32\oleaut32.dll"]
      7ffe`6f426000     7ffe`6f44c000        0`00026000 MEM_IMAGE   MEM_COMMIT  PAGE_READONLY                      Image      [oleaut32; "C:\Windows\System32\oleaut32.dll"]
      7ffe`6f44c000     7ffe`6f44f000        0`00003000 MEM_IMAGE   MEM_COMMIT  PAGE_READWRITE                     Image      [oleaut32; "C:\Windows\System32\oleaut32.dll"]
      7ffe`6f44f000     7ffe`6f45d000        0`0000e000 MEM_IMAGE   MEM_COMMIT  PAGE_READONLY                      Image      [oleaut32; "C:\Windows\System32\oleaut32.dll"]
+     7ffe`6f45d000     7ffe`6f460000        0`00003000             MEM_FREE    PAGE_NOACCESS                      Free       
+     7ffe`6f460000     7ffe`6f461000        0`00001000 MEM_IMAGE   MEM_COMMIT  PAGE_READONLY                      Image      [advapi32; "C:\Windows\System32\advapi32.dll"]
      7ffe`6f461000     7ffe`6f4c9000        0`00068000 MEM_IMAGE   MEM_COMMIT  PAGE_EXECUTE_READ                  Image      [advapi32; "C:\Windows\System32\advapi32.dll"]
      7ffe`6f4c9000     7ffe`6f500000        0`00037000 MEM_IMAGE   MEM_COMMIT  PAGE_READONLY                      Image      [advapi32; "C:\Windows\System32\advapi32.dll"]
      7ffe`6f500000     7ffe`6f501000        0`00001000 MEM_IMAGE   MEM_COMMIT  PAGE_READWRITE                     Image      [advapi32; "C:\Windows\System32\advapi32.dll"]
      7ffe`6f501000     7ffe`6f502000        0`00001000 MEM_IMAGE   MEM_COMMIT  PAGE_WRITECOPY                     Image      [advapi32; "C:\Windows\System32\advapi32.dll"]
      7ffe`6f502000     7ffe`6f504000        0`00002000 MEM_IMAGE   MEM_COMMIT  PAGE_READWRITE                     Image      [advapi32; "C:\Windows\System32\advapi32.dll"]
      7ffe`6f504000     7ffe`6f505000        0`00001000 MEM_IMAGE   MEM_COMMIT  PAGE_WRITECOPY                     Image      [advapi32; "C:\Windows\System32\advapi32.dll"]
      7ffe`6f505000     7ffe`6f50e000        0`00009000 MEM_IMAGE   MEM_COMMIT  PAGE_READONLY                      Image      [advapi32; "C:\Windows\System32\advapi32.dll"]
+     7ffe`6f50e000     7ffe`6fb10000        0`00602000             MEM_FREE    PAGE_NOACCESS                      Free       
+     7ffe`6fb10000     7ffe`6fb11000        0`00001000 MEM_IMAGE   MEM_COMMIT  PAGE_READONLY                      Image      [sechost; "C:\Windows\System32\sechost.dll"]
      7ffe`6fb11000     7ffe`6fb76000        0`00065000 MEM_IMAGE   MEM_COMMIT  PAGE_EXECUTE_READ                  Image      [sechost; "C:\Windows\System32\sechost.dll"]
      7ffe`6fb76000     7ffe`6fb9e000        0`00028000 MEM_IMAGE   MEM_COMMIT  PAGE_READONLY                      Image      [sechost; "C:\Windows\System32\sechost.dll"]
      7ffe`6fb9e000     7ffe`6fb9f000        0`00001000 MEM_IMAGE   MEM_COMMIT  PAGE_READWRITE                     Image      [sechost; "C:\Windows\System32\sechost.dll"]
      7ffe`6fb9f000     7ffe`6fba0000        0`00001000 MEM_IMAGE   MEM_COMMIT  PAGE_WRITECOPY                     Image      [sechost; "C:\Windows\System32\sechost.dll"]
      7ffe`6fba0000     7ffe`6fba2000        0`00002000 MEM_IMAGE   MEM_COMMIT  PAGE_READWRITE                     Image      [sechost; "C:\Windows\System32\sechost.dll"]
      7ffe`6fba2000     7ffe`6fbac000        0`0000a000 MEM_IMAGE   MEM_COMMIT  PAGE_READONLY                      Image      [sechost; "C:\Windows\System32\sechost.dll"]
+     7ffe`6fbac000     7ffe`6fbb0000        0`00004000             MEM_FREE    PAGE_NOACCESS                      Free       
+     7ffe`6fbb0000     7ffe`6fbb1000        0`00001000 MEM_IMAGE   MEM_COMMIT  PAGE_READONLY                      Image      [kernel32; "C:\Windows\System32\kernel32.dll"]
      7ffe`6fbb1000     7ffe`6fc30000        0`0007f000 MEM_IMAGE   MEM_COMMIT  PAGE_EXECUTE_READ                  Image      [kernel32; "C:\Windows\System32\kernel32.dll"]
      7ffe`6fc30000     7ffe`6fc64000        0`00034000 MEM_IMAGE   MEM_COMMIT  PAGE_READONLY                      Image      [kernel32; "C:\Windows\System32\kernel32.dll"]
      7ffe`6fc64000     7ffe`6fc65000        0`00001000 MEM_IMAGE   MEM_COMMIT  PAGE_READWRITE                     Image      [kernel32; "C:\Windows\System32\kernel32.dll"]
      7ffe`6fc65000     7ffe`6fc66000        0`00001000 MEM_IMAGE   MEM_COMMIT  PAGE_WRITECOPY                     Image      [kernel32; "C:\Windows\System32\kernel32.dll"]
      7ffe`6fc66000     7ffe`6fc6f000        0`00009000 MEM_IMAGE   MEM_COMMIT  PAGE_READONLY                      Image      [kernel32; "C:\Windows\System32\kernel32.dll"]
+     7ffe`6fc6f000     7ffe`6fc70000        0`00001000             MEM_FREE    PAGE_NOACCESS                      Free       
+     7ffe`6fc70000     7ffe`6fc71000        0`00001000 MEM_IMAGE   MEM_COMMIT  PAGE_READONLY                      Image      [gdi32; "C:\Windows\System32\gdi32.dll"]
      7ffe`6fc71000     7ffe`6fc80000        0`0000f000 MEM_IMAGE   MEM_COMMIT  PAGE_EXECUTE_READ                  Image      [gdi32; "C:\Windows\System32\gdi32.dll"]
      7ffe`6fc80000     7ffe`6fc94000        0`00014000 MEM_IMAGE   MEM_COMMIT  PAGE_READONLY                      Image      [gdi32; "C:\Windows\System32\gdi32.dll"]
      7ffe`6fc94000     7ffe`6fc95000        0`00001000 MEM_IMAGE   MEM_COMMIT  PAGE_READWRITE                     Image      [gdi32; "C:\Windows\System32\gdi32.dll"]
      7ffe`6fc95000     7ffe`6fc9b000        0`00006000 MEM_IMAGE   MEM_COMMIT  PAGE_READONLY                      Image      [gdi32; "C:\Windows\System32\gdi32.dll"]
+     7ffe`6fc9b000     7ffe`6fdc0000        0`00125000             MEM_FREE    PAGE_NOACCESS                      Free       
+     7ffe`6fdc0000     7ffe`6fdc1000        0`00001000 MEM_IMAGE   MEM_COMMIT  PAGE_READONLY                      Image      [shell32; "C:\Windows\System32\shell32.dll"]
      7ffe`6fdc1000     7ffe`7034a000        0`00589000 MEM_IMAGE   MEM_COMMIT  PAGE_EXECUTE_READ                  Image      [shell32; "C:\Windows\System32\shell32.dll"]
      7ffe`7034a000     7ffe`70493000        0`00149000 MEM_IMAGE   MEM_COMMIT  PAGE_READONLY                      Image      [shell32; "C:\Windows\System32\shell32.dll"]
      7ffe`70493000     7ffe`7049b000        0`00008000 MEM_IMAGE   MEM_COMMIT  PAGE_READWRITE                     Image      [shell32; "C:\Windows\System32\shell32.dll"]
      7ffe`7049b000     7ffe`7049d000        0`00002000 MEM_IMAGE   MEM_COMMIT  PAGE_WRITECOPY                     Image      [shell32; "C:\Windows\System32\shell32.dll"]
      7ffe`7049d000     7ffe`70504000        0`00067000 MEM_IMAGE   MEM_COMMIT  PAGE_READONLY                      Image      [shell32; "C:\Windows\System32\shell32.dll"]
+     7ffe`70504000     7ffe`70510000        0`0000c000             MEM_FREE    PAGE_NOACCESS                      Free       
+     7ffe`70510000     7ffe`70511000        0`00001000 MEM_IMAGE   MEM_COMMIT  PAGE_READONLY                      Image      [rpcrt4; "C:\Windows\System32\rpcrt4.dll"]
      7ffe`70511000     7ffe`705f3000        0`000e2000 MEM_IMAGE   MEM_COMMIT  PAGE_EXECUTE_READ                  Image      [rpcrt4; "C:\Windows\System32\rpcrt4.dll"]
      7ffe`705f3000     7ffe`7061f000        0`0002c000 MEM_IMAGE   MEM_COMMIT  PAGE_READONLY                      Image      [rpcrt4; "C:\Windows\System32\rpcrt4.dll"]
      7ffe`7061f000     7ffe`70621000        0`00002000 MEM_IMAGE   MEM_COMMIT  PAGE_READWRITE                     Image      [rpcrt4; "C:\Windows\System32\rpcrt4.dll"]
      7ffe`70621000     7ffe`70636000        0`00015000 MEM_IMAGE   MEM_COMMIT  PAGE_READONLY                      Image      [rpcrt4; "C:\Windows\System32\rpcrt4.dll"]
+     7ffe`70636000     7ffe`70710000        0`000da000             MEM_FREE    PAGE_NOACCESS                      Free       
+     7ffe`70710000     7ffe`70711000        0`00001000 MEM_IMAGE   MEM_COMMIT  PAGE_READONLY                      Image      [combase; "C:\Windows\System32\combase.dll"]
      7ffe`70711000     7ffe`7094a000        0`00239000 MEM_IMAGE   MEM_COMMIT  PAGE_EXECUTE_READ                  Image      [combase; "C:\Windows\System32\combase.dll"]
      7ffe`7094a000     7ffe`70a10000        0`000c6000 MEM_IMAGE   MEM_COMMIT  PAGE_READONLY                      Image      [combase; "C:\Windows\System32\combase.dll"]
      7ffe`70a10000     7ffe`70a16000        0`00006000 MEM_IMAGE   MEM_COMMIT  PAGE_READWRITE                     Image      [combase; "C:\Windows\System32\combase.dll"]
      7ffe`70a16000     7ffe`70a64000        0`0004e000 MEM_IMAGE   MEM_COMMIT  PAGE_READONLY                      Image      [combase; "C:\Windows\System32\combase.dll"]
+     7ffe`70a64000     7ffe`70b00000        0`0009c000             MEM_FREE    PAGE_NOACCESS                      Free       
+     7ffe`70b00000     7ffe`70b01000        0`00001000 MEM_IMAGE   MEM_COMMIT  PAGE_READONLY                      Image      [msvcrt; "C:\Windows\System32\msvcrt.dll"]
      7ffe`70b01000     7ffe`70b76000        0`00075000 MEM_IMAGE   MEM_COMMIT  PAGE_EXECUTE_READ                  Image      [msvcrt; "C:\Windows\System32\msvcrt.dll"]
      7ffe`70b76000     7ffe`70b8f000        0`00019000 MEM_IMAGE   MEM_COMMIT  PAGE_READONLY                      Image      [msvcrt; "C:\Windows\System32\msvcrt.dll"]
      7ffe`70b8f000     7ffe`70b91000        0`00002000 MEM_IMAGE   MEM_COMMIT  PAGE_READWRITE                     Image      [msvcrt; "C:\Windows\System32\msvcrt.dll"]
      7ffe`70b91000     7ffe`70b94000        0`00003000 MEM_IMAGE   MEM_COMMIT  PAGE_WRITECOPY                     Image      [msvcrt; "C:\Windows\System32\msvcrt.dll"]
      7ffe`70b94000     7ffe`70b96000        0`00002000 MEM_IMAGE   MEM_COMMIT  PAGE_READWRITE                     Image      [msvcrt; "C:\Windows\System32\msvcrt.dll"]
      7ffe`70b96000     7ffe`70b97000        0`00001000 MEM_IMAGE   MEM_COMMIT  PAGE_WRITECOPY                     Image      [msvcrt; "C:\Windows\System32\msvcrt.dll"]
      7ffe`70b97000     7ffe`70b9e000        0`00007000 MEM_IMAGE   MEM_COMMIT  PAGE_READONLY                      Image      [msvcrt; "C:\Windows\System32\msvcrt.dll"]
+     7ffe`70b9e000     7ffe`70c20000        0`00082000             MEM_FREE    PAGE_NOACCESS                      Free       
+     7ffe`70c20000     7ffe`70c21000        0`00001000 MEM_IMAGE   MEM_COMMIT  PAGE_READONLY                      Image      [nsi; "C:\Windows\System32\nsi.dll"]
      7ffe`70c21000     7ffe`70c23000        0`00002000 MEM_IMAGE   MEM_COMMIT  PAGE_EXECUTE_READ                  Image      [nsi; "C:\Windows\System32\nsi.dll"]
      7ffe`70c23000     7ffe`70c24000        0`00001000 MEM_IMAGE   MEM_COMMIT  PAGE_READONLY                      Image      [nsi; "C:\Windows\System32\nsi.dll"]
      7ffe`70c24000     7ffe`70c25000        0`00001000 MEM_IMAGE   MEM_COMMIT  PAGE_READWRITE                     Image      [nsi; "C:\Windows\System32\nsi.dll"]
      7ffe`70c25000     7ffe`70c28000        0`00003000 MEM_IMAGE   MEM_COMMIT  PAGE_READONLY                      Image      [nsi; "C:\Windows\System32\nsi.dll"]
+     7ffe`70c28000     7ffe`70d20000        0`000f8000             MEM_FREE    PAGE_NOACCESS                      Free       
+     7ffe`70d20000     7ffe`70d21000        0`00001000 MEM_IMAGE   MEM_COMMIT  PAGE_READONLY                      Image      [imm32; "C:\Windows\System32\imm32.dll"]
      7ffe`70d21000     7ffe`70d3f000        0`0001e000 MEM_IMAGE   MEM_COMMIT  PAGE_EXECUTE_READ                  Image      [imm32; "C:\Windows\System32\imm32.dll"]
      7ffe`70d3f000     7ffe`70d46000        0`00007000 MEM_IMAGE   MEM_COMMIT  PAGE_READONLY                      Image      [imm32; "C:\Windows\System32\imm32.dll"]
      7ffe`70d46000     7ffe`70d47000        0`00001000 MEM_IMAGE   MEM_COMMIT  PAGE_READWRITE                     Image      [imm32; "C:\Windows\System32\imm32.dll"]
      7ffe`70d47000     7ffe`70d50000        0`00009000 MEM_IMAGE   MEM_COMMIT  PAGE_READONLY                      Image      [imm32; "C:\Windows\System32\imm32.dll"]
+     7ffe`70d50000     7ffe`70f30000        0`001e0000             MEM_FREE    PAGE_NOACCESS                      Free       
+     7ffe`70f30000     7ffe`70f31000        0`00001000 MEM_IMAGE   MEM_COMMIT  PAGE_READONLY                      Image      [user32; "C:\Windows\System32\user32.dll"]
      7ffe`70f31000     7ffe`70fbf000        0`0008e000 MEM_IMAGE   MEM_COMMIT  PAGE_EXECUTE_READ                  Image      [user32; "C:\Windows\System32\user32.dll"]
      7ffe`70fbf000     7ffe`70fe0000        0`00021000 MEM_IMAGE   MEM_COMMIT  PAGE_READONLY                      Image      [user32; "C:\Windows\System32\user32.dll"]
      7ffe`70fe0000     7ffe`70fe2000        0`00002000 MEM_IMAGE   MEM_COMMIT  PAGE_READWRITE                     Image      [user32; "C:\Windows\System32\user32.dll"]
      7ffe`70fe2000     7ffe`710cd000        0`000eb000 MEM_IMAGE   MEM_COMMIT  PAGE_READONLY                      Image      [user32; "C:\Windows\System32\user32.dll"]
+     7ffe`710cd000     7ffe`710d0000        0`00003000             MEM_FREE    PAGE_NOACCESS                      Free       
+     7ffe`710d0000     7ffe`710d1000        0`00001000 MEM_IMAGE   MEM_COMMIT  PAGE_READONLY                      Image      [ws2_32; "C:\Windows\System32\ws2_32.dll"]
      7ffe`710d1000     7ffe`71115000        0`00044000 MEM_IMAGE   MEM_COMMIT  PAGE_EXECUTE_READ                  Image      [ws2_32; "C:\Windows\System32\ws2_32.dll"]
      7ffe`71115000     7ffe`71122000        0`0000d000 MEM_IMAGE   MEM_COMMIT  PAGE_READONLY                      Image      [ws2_32; "C:\Windows\System32\ws2_32.dll"]
      7ffe`71122000     7ffe`71123000        0`00001000 MEM_IMAGE   MEM_COMMIT  PAGE_READWRITE                     Image      [ws2_32; "C:\Windows\System32\ws2_32.dll"]
      7ffe`71123000     7ffe`7113b000        0`00018000 MEM_IMAGE   MEM_COMMIT  PAGE_READONLY                      Image      [ws2_32; "C:\Windows\System32\ws2_32.dll"]
+     7ffe`7113b000     7ffe`71330000        0`001f5000             MEM_FREE    PAGE_NOACCESS                      Free       
+     7ffe`71330000     7ffe`71331000        0`00001000 MEM_IMAGE   MEM_COMMIT  PAGE_READONLY                      Image      [ntdll; "C:\Windows\System32\ntdll.dll"]
      7ffe`71331000     7ffe`7144d000        0`0011c000 MEM_IMAGE   MEM_COMMIT  PAGE_EXECUTE_READ                  Image      [ntdll; "C:\Windows\System32\ntdll.dll"]
      7ffe`7144d000     7ffe`71496000        0`00049000 MEM_IMAGE   MEM_COMMIT  PAGE_READONLY                      Image      [ntdll; "C:\Windows\System32\ntdll.dll"]
      7ffe`71496000     7ffe`71497000        0`00001000 MEM_IMAGE   MEM_COMMIT  PAGE_READWRITE                     Image      [ntdll; "C:\Windows\System32\ntdll.dll"]
      7ffe`71497000     7ffe`71499000        0`00002000 MEM_IMAGE   MEM_COMMIT  PAGE_WRITECOPY                     Image      [ntdll; "C:\Windows\System32\ntdll.dll"]
      7ffe`71499000     7ffe`714a2000        0`00009000 MEM_IMAGE   MEM_COMMIT  PAGE_READWRITE                     Image      [ntdll; "C:\Windows\System32\ntdll.dll"]
      7ffe`714a2000     7ffe`71528000        0`00086000 MEM_IMAGE   MEM_COMMIT  PAGE_READONLY                      Image      [ntdll; "C:\Windows\System32\ntdll.dll"]
+     7ffe`71528000     7fff`ffff0000        1`8eac8000             MEM_FREE    PAGE_NOACCESS                      Free       

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
- Using command `.writefile` to dump the payload. `.writefile demon_region.exe.mem 0x7ff796f50000 L?0x00018000`
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