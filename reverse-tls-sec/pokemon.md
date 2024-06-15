# Reverse - Pikachu to Dracaufeu Dynamax
![Rev](https://github.com/Maksence/write-ups/blob/main/reverse-tls-sec/images/Rev.png)

## Index
  - [The challenge](https://github.com/Maksence/write-ups/blob/main/reverse-tls-sec/pokemon.md#the-challenge)
  - [Analysis](https://github.com/Maksence/write-ups/blob/main/reverse-tls-sec/pokemon.md#analysis)
    - [Getting started](https://github.com/Maksence/write-ups/blob/main/reverse-tls-sec/pokemon.md#getting-started)
    - [Unpacking the program](https://github.com/Maksence/write-ups/blob/main/reverse-tls-sec/pokemon.md#unpacking-the-program)
    - [Static analysis](https://github.com/Maksence/write-ups/blob/main/reverse-tls-sec/pokemon.md#static-analysis)
    - [Thread Local Storage](https://github.com/Maksence/write-ups/blob/main/reverse-tls-sec/pokemon.md#thread-local-storage)
      - [1st condition](https://github.com/Maksence/write-ups/blob/main/reverse-tls-sec/pokemon.md#1st-condition)
      - [2nd condition](https://github.com/Maksence/write-ups/blob/main/reverse-tls-sec/pokemon.md#2nd-condition)
      - [3rd condition](https://github.com/Maksence/write-ups/blob/main/reverse-tls-sec/pokemon.md#3rd-condition)
    - [Finding the argument](https://github.com/Maksence/write-ups/blob/main/reverse-tls-sec/pokemon.md#finding-the-argument)
      - [Fourth conditions block](https://github.com/Maksence/write-ups/blob/main/reverse-tls-sec/pokemon.md#fourth-conditions-block)
    - [Obfuscated code](https://github.com/Maksence/write-ups/blob/main/reverse-tls-sec/pokemon.md#obfuscated-code)
      - [First off, **VirtualProtect.**](https://github.com/Maksence/write-ups/blob/main/reverse-tls-sec/pokemon.md#first-off-virtualprotect)
      - [Then, **memcpy**.](https://github.com/Maksence/write-ups/blob/main/reverse-tls-sec/pokemon.md#then-memcpy)
    - [Final code block in tls_callback](https://github.com/Maksence/write-ups/blob/main/reverse-tls-sec/pokemon.md#final-code-block-in-tls_callback)
      - [Python function](https://github.com/Maksence/write-ups/blob/main/reverse-tls-sec/pokemon.md#python-function)
  - [Deobfuscating the powershell code](https://github.com/Maksence/write-ups/blob/main/reverse-tls-sec/pokemon.md#deobfuscating-the-powershell-code)
    - [The 1+1 function](https://github.com/Maksence/write-ups/blob/main/reverse-tls-sec/pokemon.md#the-11-function)
    - [$Wrm8EMP](https://github.com/Maksence/write-ups/blob/main/reverse-tls-sec/pokemon.md#wrm8emp)
  - [Solution](https://github.com/Maksence/write-ups/blob/main/reverse-tls-sec/pokemon.md#solution)
  - [Conclusion](https://github.com/Maksence/write-ups/blob/main/reverse-tls-sec/pokemon.md#conclusion)

## The challenge
The goal is to transform Pikachu into a Charizard (Dracaufeu in french).
This was originally done as a homework assignement with some guiding questions, but I decided to revisit it as if it were a CTF challenge to go a bit further.

## Analysis

### Getting started
We are given a pikachu.exe file. Let's take a look at the file signature and at the first bytes of the file to confirm that it's a Windows executable.

```shell
$ file pikachu.exe 
pikachu.exe: PE32+ executable (console) x86-64, for MS Windows, 3 sections
$ xxd pikachu.exe | head
00000000: 4d5a 9000 0300 0000 0400 0000 ffff 0000  MZ..............
00000010: b800 0000 0000 0000 4000 0000 0000 0000  ........@.......
00000020: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000030: 0000 0000 0000 0000 0000 0000 f000 0000  ................
00000040: 0e1f ba0e 00b4 09cd 21b8 014c cd21 5468  ........!..L.!Th
00000050: 6973 2070 726f 6772 616d 2063 616e 6e6f  is program canno
00000060: 7420 6265 2072 756e 2069 6e20 444f 5320  t be run in DOS 
00000070: 6d6f 6465 2e0d 0d0a 2400 0000 0000 0000  mode....$.......
```
So far so good. Let's run the program in powershell :

![pikachu](https://github.com/Maksence/write-ups/blob/main/reverse-tls-sec/images/pikachu.png)

Cute but not very helpful. Next we can try to analyse it with Ghidra to try and understand what the program does.

The auto-analysis isn't conclusive.
We do notice one thing though:

![UPX](https://github.com/Maksence/write-ups/blob/main/reverse-tls-sec/images/upx.png)

UPX sections. [UPX](https://upx.github.io/) is one of the most commonly used binary packer, used (if you're a good guy) to reduce the file size of your program, and/or (if you're a bad guy) to obfuscate your malware's code to evade anti-viruses. 

### Unpacking the program

Let's open our program in a program identifier such as [CFF Explorer](https://ntcore.com/explorer-suite/) or [Detect-It-Easy (DiE)](https://github.com/horsicq/Detect-It-Easy) and have a look at the section Headers

![CFF](https://github.com/Maksence/write-ups/blob/main/reverse-tls-sec/images/CFF.png)
Indeed the raw size of the the first Section UPX0 is 0 bytes whereas its Virtual Size is F000. This is a good indication that the program is packed and this data section will only be filled up during execution. 

So let's unpack it. First download UPX, and then use if with the "-d" option to decompress

```shell
$ ./upx -d pokemon/pikachu.exe 
                       Ultimate Packer for eXecutables
                          Copyright (C) 1996 - 2024
UPX 4.2.4       Markus Oberhumer, Laszlo Molnar & John Reiser    May 9th 2024

        File size         Ratio      Format      Name
   --------------------   ------   -----------   -----------
     52736 <-     17408   33.01%    win64/pe     pikachu.exe
```

Now we can really get started with our analysis.

### Static analysis

Let's switch from Ghidra to IDA as it seems to provide a better analysis of our program.

![main](https://github.com/Maksence/write-ups/blob/main/reverse-tls-sec/images/main.png)

A few noticable things:
Apart from the memory initialization functions at the beginning, our program
- Prints "Loading..."
- Sleep 2 seconds to simulate a loading time
- Creates a string variable containing the powershell command "powershell.exe -noprofile -executionpolicy bypass -encodedcommand" + a big data payload
- And then creates a new child process with "CreateProcessA" windows API function and executes our string as the lpCommandLine argument.

The big chunk of data looks an awful lot like base64. Using cyberchef and removing null bytes we can get a better idea of what it is:

![cyberchef](https://github.com/Maksence/write-ups/blob/main/reverse-tls-sec/images/cyberchef.png)

Write-Output is the powershell equivalent of a "print". So the function just prints the payload that's afterward. The payload kind of looks like ASCII art, and since the function gets called unconditionally I'm going to assume that's the data that gets turned into our Pikachu.

### Thread Local Storage
But we still haven't found any kind of condition that could make our Pikachu evolve...
However looking at the functions that reference the payload we see one that we have not yet come across.
![tls](https://github.com/Maksence/write-ups/blob/main/reverse-tls-sec/images/tls.png)

"tls_callback". What are those ?
From [infosecinstitute](https://www.infosecinstitute.com/resources/reverse-engineering/debugging-tls-callbacks/):
>TLS (thread local storage) calls are subroutines that are executed before the entry point. There is a section in the PE header that describes the place of a TLS callback. Malwares employ TLS callbacks to evade debugger messages. When a particular malware employed with TLS callbacks is loaded into a debugger, the malware finishes its work before the debugger stops at the entry point.

So that's the actual entry point of our program.
For clarity I will also edit the function signature now.

```c#
void __fastcall TlsCallback_0(PVOID DllHandle, DWORD dwReason, PVOID Reserved)
{
  __int64 (*v3)(void); // r14
  void (__fastcall *v4)(const char *, __int64, __int64, __int64 *); // r12
  __int64 v5; // rsi
  unsigned int *v6; // rdx
  __int64 v7; // r13
  unsigned int *v8; // r15
  unsigned __int16 *v9; // rdi
  __int64 v10; // rbp
  unsigned __int64 v11; // rdx
  char *v12; // rcx
  int v13; // eax
  __int64 v14; // rax
  __int64 v16; // rcx
  char *v17; // r10
  int i; // r9d
  __int64 v19; // rax
  __int64 v20; // [rsp+20h] [rbp-48h] BYREF
  __int64 v21; // [rsp+28h] [rbp-40h]

  if ( dwReason == 1 )
  {
    v3 = 0i64;
    v4 = 0i64;
    v21 = 0x78616D616E7964i64;
    v5 = sub_7FF6B28F10A0(DllHandle);
    v6 = (unsigned int *)(v5 + *(unsigned int *)(*(int *)(v5 + 60) + v5 + 136));
    v7 = v5 + v6[7];
    v8 = (unsigned int *)(v5 + v6[8]);
    v9 = (unsigned __int16 *)(v5 + v6[9]);
    if ( v6[6] )
    {
      v10 = -1i64;
      v20 = v6[6];
      do
      {
        v11 = -1i64;
        v12 = (char *)(v5 + *v8);
        do
          ++v11;
        while ( v12[v11] );
        v13 = sub_7FF6B28F13B0(v12, v11);
        if ( v13 == -305803260 )
        {
          v3 = (__int64 (*)(void))(v5 + *(unsigned int *)(v7 + 4i64 * *v9));
        }
        else if ( v13 == -72948286 )
        {
          v4 = (void (__fastcall *)(const char *, __int64, __int64, __int64 *))(v5 + *(unsigned int *)(v7 + 4i64 * *v9));
        }
        ++v8;
        ++v9;
        --v20;
      }
      while ( v20 );
      if ( v4 )
      {
        if ( v3 )
        {
          v14 = v3();
          while ( *(_BYTE *)(v14 + v10++ + 1) != 0 )
            ;
          v16 = v14 + v10;
          if ( *(_DWORD *)(v14 + v10 - 7) == 1634629988
            && *(_WORD *)(v16 - 3) == WORD2(v21)
            && *(_BYTE *)(v16 - 1) == BYTE6(v21) )
          {
            v4(
              "VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIABAACIACgAAKAAoACgAKAAoACgAKAAoACgAKAAoACiAKPQoRigAKAAoACgAKAAoACgAKAAoAC"
              "gAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAoAACgAKAAoACgAKAAoACgAKAAoACgAKIAo/ij/KOcoACgA"
              "KAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgKAAAoACgAKAAoACgAKAAoACgAKA"
              "AogCj+KP8o/yj/KAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoCgAAKAAo"
              "ACgAKAAoACgAKAAoACgAKH4oCygJKAAoRygAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoAC"
              "gAKAAoACgAKAoAACgAKAAoACgAKAAoACgAKAAo/CgDKAAoACgAKEcoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgA"
              "KAAoACgAKAAoACgAKAAoACgAKAAoACgKAAAoACgAKAAoACgAKAAoACiAKE8oACgAKAAoAChHKAAoACgAKAAoACgAKAAoACgAKAAoACgAKA"
              "AoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoCgAAKAAoACgAKAAoACgAKAAouCgAKAAoACgAKAAoRygAKAAoACgAKAAo"
              "ACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACiAKMAowCjgKOQo5CjkKOQoACgAKAoAACgAKAAoACgAKAAoACgAKE8oACgAKAAoAC"
              "i4KAMoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAowChkKDQoEigKKAkoCSgAKAAo/yj/KP8oPygLKAAoACgKAAAoACgAKAAoACgA"
              "KAAoAChHKAAoACiAKGAoPCg0KBIoEigSKBIoJigkKCQoxCjAKAAogCjgKDQoGigJKAAoACgAKAAoACgAKAAoACj8KD8oCygBKAAoACgAKA"
              "AoCgAAKAAoACgAKAAoACgAKAAoxygUKAIoCCgAKAAoACgAKAAoACgAKAAoACgAKAAoqCg/KAsoACgAKAAoACgAKAAoACgAKMAoZCgWKAso"
              "ASgAKAAoACgAKAAoACgAKAoAACgAKAAoACgAKAAoACiwKAsoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKMAo4C"
              "gkKBIoCygBKAAoACgAKAAoACgAKAAoACgAKAAoACgKAAAoACgAKAAoACgAKIAoXygAKOAoxChAKAAoACgAKAAoACgAKAAoACgAKAAoACgA"
              "KAAoACgIKAkouygBKAAoACgAKAAoACgAKAAoACgAKIAo4CjkKOQoZCgkKLQoCgAAKAAoACgAKAAoACj4KAEo/ij/KMAo/ShGKAAoACgAKA"
              "AoACgAKAAooCj+KAkovyjmKAAoACgAKLgoQCgAKAAogCjgKCQoFCgSKAsoCSgJKAAoACgAKAAogCheKAoAACgAKAAoACgAKIAoTygAKDko"
              "Pyg/KB8oASgAKDAoJigAKAAoACgAKDgo/yj/KP8ofygAKAAoACiYKGcoFigLKAEoACgAKAAoACgAKAAoACgAKAAoACgAKHwoACgKAAAoAC"
              "gAKAAoACj8KCYoxCgAKAAooCjAKMAo9CgfKDYoxChAKAAoAChAKAAoCSgBKAAoACgAKAAouCgHKAAoACgAKAAoACgAKAAoACgAKAAoACgA"
              "KAAo+CgBKAAoCgAAKAAoACgAKLAoRygAKAgoRygAKAAoOCh+KAEoACgAKAAoCSgJKE8oACgAKAAo4CgWKAkoEyikKLgoACgAKAAoACgAKA"
              "AoACgAKAAoACgAKAAoACjwKAMoACgAKAoAACgAKAAoACgAKKcowCh8KAMoACgAKAAopygAKAAoACgAKAAouCgDKAAoACgAKOcoACgAKAAo"
              "+Ci5KAAoACgAKAAoACgAKAAoACgAKAAoACgAKHAoAygAKAAoACgKAAAoACgAKAAoACgIKKcoQCgAKAAoACgAKBgoxigAKAAoACigKA8oAC"
              "gAKAAoACgIKDMoJCgWKAMoXygAKAAoACi+KBsoGygbKBsoGygbKBsoGygBKAAoACgAKAAoCgAAKAAoACgAKAAoACgAKBkoxigAKAAoACgA"
              "KAgoJijAKHQoCygAKAAoACgAKAAoACgAKAAogCj8KBkopigAKAAoGChHKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAoAACgAKAAoACgAKA"
              "AoACigKEcoGSgmKMQoACgAKAAoACgAKAAoACgAKAAoACgAKIAo4Cg0KAsoOChHKAgosyhAKAAouShAKAAoACgAKAAoACgAKAAoACgAKAAo"
              "ACgKAAAoACgAKAAoACgAKAAofCjAKAAoACgIKBkoAigAKAAoACgAKAAoACgAKAAoACgJKAAoACgAKAAo9yg0KBooASgAKMAo9ygAKAAoAC"
              "gAKAAoACgAKAAoACgAKAAoCgAAKAAoACgAKAAoACh0KAEoTygAKAAoACgAKAAoACgAKAAoACigKAAoACgAKAAoACgAKAAoACgAKBgoxih0"
              "KBooCSgJKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAoA/Ci3KEYoACjgKHQoJyjEKMcoACgAKAAoACgAKAAoACiyKAAoXygAKAAoACgAKA"
              "AoACgAKIAoRyjgKP0opijEKIAo9Cj2KAAoACgAKAAoACgAKAAoACgAKAAoACgKAH8o/Cj9KF4oASgAKAAoACi5KEAoACgAKAAoACgAKAAo"
              "CCj3KAMoACgAKAAoACgAKAAoACj8KAkoASgAKAAooCifKP8o/ygBKAAoACgAKAAoACgAKAAoACgAKAAoCgD3KAkoASizKAAoACgAKAAoCC"
              "jnKAAoACgAKAAoACgAKAAo+ygAKAAoACgAKAAoACgAKPAoAygAKAAoACgAKA8oACgAKH8oACgAKAAoACgAKAAoACgAKAAoACgAKAoAOShG"
              "KAAoCChHKAAoACgAKAAoGCjGKAAoACgAKAAoACgAKEcoACgAKAAoACgAKAAo8CgDKAAoACgAKAAoACgAKAAo+CgBKAAoACgAKAAoACgAKA"
              "AoACgAKAAoACgKAAAosyhAKAAoGSgAKAAoACgAKAAoGCjGKAAoACgAKAAoAChHKAAoACgAKAAoACjwKAMoACgAKAAoACiAKEQoACigKAco"
              "ACgAKAAoACgAKAAoACgAKAAoACgAKAAoCgAAKAAosyhAKPAowCjAKMAoACgAKAAoGCjmKMAoACgAKAAoRygAKAAoACiAKHQoAygAKAAoAC"
              "gAKAAouChHKKAoDygAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAoAACgAKAAoCSgJKAAoACgIKAkoCSgJKBkoOyg/KD4oPig7KBMopigm"
              "KHYodig/KBsoGygTKBIoEigaKBsoGygBKAoAIgBAAA==",
              20480i64,
              4i64,
              &v20);
            memcpy(
              "VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIABAACIACgAAKAAoACgAKAAoACgAKAAoACgAKAAoACiAKPQoRigAKAAoACgAKAAoACgAKAAoAC"
              "gAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAoAACgAKAAoACgAKAAoACgAKAAoACgAKIAo/ij/KOcoACgA"
              "KAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgKAAAoACgAKAAoACgAKAAoACgAKA"
              "AogCj+KP8o/yj/KAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoCgAAKAAo"
              "ACgAKAAoACgAKAAoACgAKH4oCygJKAAoRygAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoAC"
              "gAKAAoACgAKAoAACgAKAAoACgAKAAoACgAKAAo/CgDKAAoACgAKEcoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgA"
              "KAAoACgAKAAoACgAKAAoACgAKAAoACgKAAAoACgAKAAoACgAKAAoACiAKE8oACgAKAAoAChHKAAoACgAKAAoACgAKAAoACgAKAAoACgAKA"
              "AoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoCgAAKAAoACgAKAAoACgAKAAouCgAKAAoACgAKAAoRygAKAAoACgAKAAo"
              "ACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACiAKMAowCjgKOQo5CjkKOQoACgAKAoAACgAKAAoACgAKAAoACgAKE8oACgAKAAoAC"
              "i4KAMoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAowChkKDQoEigKKAkoCSgAKAAo/yj/KP8oPygLKAAoACgKAAAoACgAKAAoACgA"
              "KAAoAChHKAAoACiAKGAoPCg0KBIoEigSKBIoJigkKCQoxCjAKAAogCjgKDQoGigJKAAoACgAKAAoACgAKAAoACj8KD8oCygBKAAoACgAKA"
              "AoCgAAKAAoACgAKAAoACgAKAAoxygUKAIoCCgAKAAoACgAKAAoACgAKAAoACgAKAAoqCg/KAsoACgAKAAoACgAKAAoACgAKMAoZCgWKAso"
              "ASgAKAAoACgAKAAoACgAKAoAACgAKAAoACgAKAAoACiwKAsoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKMAo4C"
              "gkKBIoCygBKAAoACgAKAAoACgAKAAoACgAKAAoACgKAAAoACgAKAAoACgAKIAoXygAKOAoxChAKAAoACgAKAAoACgAKAAoACgAKAAoACgA"
              "KAAoACgIKAkouygBKAAoACgAKAAoACgAKAAoACgAKIAo4CjkKOQoZCgkKLQoCgAAKAAoACgAKAAoACj4KAEo/ij/KMAo/ShGKAAoACgAKA"
              "AoACgAKAAooCj+KAkovyjmKAAoACgAKLgoQCgAKAAogCjgKCQoFCgSKAsoCSgJKAAoACgAKAAogCheKAoAACgAKAAoACgAKIAoTygAKDko"
              "Pyg/KB8oASgAKDAoJigAKAAoACgAKDgo/yj/KP8ofygAKAAoACiYKGcoFigLKAEoACgAKAAoACgAKAAoACgAKAAoACgAKHwoACgKAAAoAC"
              "gAKAAoACj8KCYoxCgAKAAooCjAKMAo9CgfKDYoxChAKAAoAChAKAAoCSgBKAAoACgAKAAouCgHKAAoACgAKAAoACgAKAAoACgAKAAoACgA"
              "KAAo+CgBKAAoCgAAKAAoACgAKLAoRygAKAgoRygAKAAoOCh+KAEoACgAKAAoCSgJKE8oACgAKAAo4CgWKAkoEyikKLgoACgAKAAoACgAKA"
              "AoACgAKAAoACgAKAAoACjwKAMoACgAKAoAACgAKAAoACgAKKcowCh8KAMoACgAKAAopygAKAAoACgAKAAouCgDKAAoACgAKOcoACgAKAAo"
              "+Ci5KAAoACgAKAAoACgAKAAoACgAKAAoACgAKHAoAygAKAAoACgKAAAoACgAKAAoACgIKKcoQCgAKAAoACgAKBgoxigAKAAoACigKA8oAC"
              "gAKAAoACgIKDMoJCgWKAMoXygAKAAoACi+KBsoGygbKBsoGygbKBsoGygBKAAoACgAKAAoCgAAKAAoACgAKAAoACgAKBkoxigAKAAoACgA"
              "KAgoJijAKHQoCygAKAAoACgAKAAoACgAKAAogCj8KBkopigAKAAoGChHKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAoAACgAKAAoACgAKA"
              "AoACigKEcoGSgmKMQoACgAKAAoACgAKAAoACgAKAAoACgAKIAo4Cg0KAsoOChHKAgosyhAKAAouShAKAAoACgAKAAoACgAKAAoACgAKAAo"
              "ACgKAAAoACgAKAAoACgAKAAofCjAKAAoACgIKBkoAigAKAAoACgAKAAoACgAKAAoACgJKAAoACgAKAAo9yg0KBooASgAKMAo9ygAKAAoAC"
              "gAKAAoACgAKAAoACgAKAAoCgAAKAAoACgAKAAoACh0KAEoTygAKAAoACgAKAAoACgAKAAoACigKAAoACgAKAAoACgAKAAoACgAKBgoxih0"
              "KBooCSgJKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAoA/Ci3KEYoACjgKHQoJyjEKMcoACgAKAAoACgAKAAoACiyKAAoXygAKAAoACgAKA"
              "AoACgAKIAoRyjgKP0opijEKIAo9Cj2KAAoACgAKAAoACgAKAAoACgAKAAoACgKAH8o/Cj9KF4oASgAKAAoACi5KEAoACgAKAAoACgAKAAo"
              "CCj3KAMoACgAKAAoACgAKAAoACj8KAkoASgAKAAooCifKP8o/ygBKAAoACgAKAAoACgAKAAoACgAKAAoCgD3KAkoASizKAAoACgAKAAoCC"
              "jnKAAoACgAKAAoACgAKAAo+ygAKAAoACgAKAAoACgAKPAoAygAKAAoACgAKA8oACgAKH8oACgAKAAoACgAKAAoACgAKAAoACgAKAoAOShG"
              "KAAoCChHKAAoACgAKAAoGCjGKAAoACgAKAAoACgAKEcoACgAKAAoACgAKAAo8CgDKAAoACgAKAAoACgAKAAo+CgBKAAoACgAKAAoACgAKA"
              "AoACgAKAAoACgKAAAosyhAKAAoGSgAKAAoACgAKAAoGCjGKAAoACgAKAAoAChHKAAoACgAKAAoACjwKAMoACgAKAAoACiAKEQoACigKAco"
              "ACgAKAAoACgAKAAoACgAKAAoACgAKAAoCgAAKAAosyhAKPAowCjAKMAoACgAKAAoGCjmKMAoACgAKAAoRygAKAAoACiAKHQoAygAKAAoAC"
              "gAKAAouChHKKAoDygAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAoAACgAKAAoCSgJKAAoACgIKAkoCSgJKBkoOyg/KD4oPig7KBMopigm"
              "KHYodig/KBsoGygTKBIoEigaKBsoGygBKAoAIgBAAA==",
              &unk_7FF6B28F82E0,
              0x5000ui64);
            v17 = "wByAGkAdABlAC0ATwB1AHQAcAB1AHQAIABAACIACgAAKAAoACgAKAAoACgAKAAoACgAKAAoACiAKPQoRigAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAoAACgAKAAoACgAKAAoACgAKAAoACgAKIAo/ij/KOcoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgKAAAoACgAKAAoACgAKAAoACgAKAAogCj+KP8o/yj/KAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoCgAAKAAoACgAKAAoACgAKAAoACgAKH4oCygJKAAoRygAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAoAACgAKAAoACgAKAAoACgAKAAo/CgDKAAoACgAKEcoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgKAAAoACgAKAAoACgAKAAoACiAKE8oACgAKAAoAChHKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoCgAAKAAoACgAKAAoACgAKAAouCgAKAAoACgAKAAoRygAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACiAKMAowCjgKOQo5CjkKOQoACgAKAoAACgAKAAoACgAKAAoACgAKE8oACgAKAAoACi4KAMoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAowChkKDQoEigKKAkoCSgAKAAo/yj/KP8oPygLKAAoACgKAAAoACgAKAAoACgAKAAoAChHKAAoACiAKGAoPCg0KBIoEigSKBIoJigkKCQoxCjAKAAogCjgKDQoGigJKAAoACgAKAAoACgAKAAoACj8KD8oCygBKAAoACgAKAAoCgAAKAAoACgAKAAoACgAKAAoxygUKAIoCCgAKAAoACgAKAAoACgAKAAoACgAKAAoqCg/KAsoACgAKAAoACgAKAAoACgAKMAoZCgWKAsoASgAKAAoACgAKAAoACgAKAoAACgAKAAoACgAKAAoACiwKAsoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKMAo4CgkKBIoCygBKAAoACgAKAAoACgAKAAoACgAKAAoACgKAAAoACgAKAAoACgAKIAoXygAKOAoxChAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgIKAkouygBKAAoACgAKAAoACgAKAAoACgAKIAo4CjkKOQoZCgkKLQoCgAAKAAoACgAKAAoACj4KAEo/ij/KMAo/ShGKAAoACgAKAAoACgAKAAooCj+KAkovyjmKAAoACgAKLgoQCgAKAAogCjgKCQoFCgSKAsoCSgJKAAoACgAKAAogCheKAoAACgAKAAoACgAKIAoTygAKDkoPyg/KB8oASgAKDAoJigAKAAoACgAKDgo/yj/KP8ofygAKAAoACiYKGcoFigLKAEoACgAKAAoACgAKAAoACgAKAAoACgAKHwoACgKAAAoACgAKAAoACj8KCYoxCgAKAAooCjAKMAo9CgfKDYoxChAKAAoAChAKAAoCSgBKAAoACgAKAAouCgHKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAo+CgBKAAoCgAAKAAoACgAKLAoRygAKAgoRygAKAAoOCh+KAEoACgAKAAoCSgJKE8oACgAKAAo4CgWKAkoEyikKLgoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACjwKAMoACgAKAoAACgAKAAoACgAKKcowCh8KAMoACgAKAAopygAKAAoACgAKAAouCgDKAAoACgAKOcoACgAKAAo+Ci5KAAoACgAKAAoACgAKAAoACgAKAAoACgAKHAoAygAKAAoACgKAAAoACgAKAAoACgIKKcoQCgAKAAoACgAKBgoxigAKAAoACigKA8oACgAKAAoACgIKDMoJCgWKAMoXygAKAAoACi+KBsoGygbKBsoGygbKBsoGygBKAAoACgAKAAoCgAAKAAoACgAKAAoACgAKBkoxigAKAAoACgAKAgoJijAKHQoCygAKAAoACgAKAAoACgAKAAogCj8KBkopigAKAAoGChHKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAoAACgAKAAoACgAKAAoACigKEcoGSgmKMQoACgAKAAoACgAKAAoACgAKAAoACgAKIAo4Cg0KAsoOChHKAgosyhAKAAouShAKAAoACgAKAAoACgAKAAoACgAKAAoACgKAAAoACgAKAAoACgAKAAofCjAKAAoACgIKBkoAigAKAAoACgAKAAoACgAKAAoACgJKAAoACgAKAAo9yg0KBooASgAKMAo9ygAKAAoACgAKAAoACgAKAAoACgAKAAoCgAAKAAoACgAKAAoACh0KAEoTygAKAAoACgAKAAoACgAKAAoACigKAAoACgAKAAoACgAKAAoACgAKBgoxih0KBooCSgJKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAoA/Ci3KEYoACjgKHQoJyjEKMcoACgAKAAoACgAKAAoACiyKAAoXygAKAAoACgAKAAoACgAKIAoRyjgKP0opijEKIAo9Cj2KAAoACgAKAAoACgAKAAoACgAKAAoACgKAH8o/Cj9KF4oASgAKAAoACi5KEAoACgAKAAoACgAKAAoCCj3KAMoACgAKAAoACgAKAAoACj8KAkoASgAKAAooCifKP8o/ygBKAAoACgAKAAoACgAKAAoACgAKAAoCgD3KAkoASizKAAoACgAKAAoCCjnKAAoACgAKAAoACgAKAAo+ygAKAAoACgAKAAoACgAKPAoAygAKAAoACgAKA8oACgAKH8oACgAKAAoACgAKAAoACgAKAAoACgAKAoAOShGKAAoCChHKAAoACgAKAAoGCjGKAAoACgAKAAoACgAKEcoACgAKAAoACgAKAAo8CgDKAAoACgAKAAoACgAKAAo+CgBKAAoACgAKAAoACgAKAAoACgAKAAoACgKAAAosyhAKAAoGSgAKAAoACgAKAAoGCjGKAAoACgAKAAoAChHKAAoACgAKAAoACjwKAMoACgAKAAoACiAKEQoACigKAcoACgAKAAoACgAKAAoACgAKAAoACgAKAAoCgAAKAAosyhAKPAowCjAKMAoACgAKAAoGCjmKMAoACgAKAAoRygAKAAoACiAKHQoAygAKAAoACgAKAAouChHKKAoDygAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAoAACgAKAAoCSgJKAAoACgIKAkoCSgJKBkoOyg/KD4oPig7KBMopigmKHYodig/KBsoGygTKBIoEigaKBsoGygBKAoAIgBAAA==";
            for ( i = 0; i < 19392; i += 6 )
            {
              *(v17 - 1) ^= *((_BYTE *)&v21 + i % 7u);
              *v17 ^= *((_BYTE *)&v21 + (int)(i - 7 * ((i + 1) / 7u) + 1));
              v17[1] ^= *((_BYTE *)&v21 + (int)(i - 7 * ((i + 2) / 7u) + 2));
              v17[2] ^= *((_BYTE *)&v21 + (int)(i - 7 * ((i + 3) / 7u) + 3));
              v17[3] ^= *((_BYTE *)&v21 + (int)(i - 7 * ((i + 4) / 7u) + 4));
              v19 = (int)(i - 7 * ((i + 5) / 7u) + 5);
              v17 += 6;
              *(v17 - 2) ^= *((_BYTE *)&v21 + v19);
            }
          }
        }
      }
    }
  }
}
```

Something is clearly happening to our data at the heart of the callback.
Let's do some static analysis to try and figure what conditions the function wants to get to that data manipulation part.

#### 1st condition:
```c
 if (dwReason == 1)
```

So, what is dwReason ? From the [microsoft website](https://learn.microsoft.com/en-us/windows/win32/dlls/dllmain):

>fdwReason [in]
   > The reason code that indicates why the DLL entry-point function is being called. 
  
And if we take a look at the corresponding value "1" and its meaning:


|  Value | Meaning   |
|---|---|
|  DLL_PROCESS_ATTACH (1) | The DLL is being loaded into the virtual address space of the current process as a result of the process starting up or as a result of a call to LoadLibrary  |

So the function is just checking that the DLL is being loaded in the process. We will assume that this is always the case here.


#### 2nd condition:
```c
  if ( dwReason == 1 )
  {
    v3 = 0i64;
    v4 = 0i64;
    v21 = 0x78616D616E7964i64;
    v5 = sub_7FF6B28F10A0(DllHandle);
    v6 = (unsigned int *)(v5 + *(unsigned int *)(*(int *)(v5 + 60) + v5 + 136));
    v7 = v5 + v6[7];
    v8 = (unsigned int *)(v5 + v6[8]);
    v9 = (unsigned __int16 *)(v5 + v6[9]);
    if ( v6[6] )
```
The second condition is dependent on v6, which is dependendent on the return value of sub_7FF6308510A0. Let's have a look

![flink](https://github.com/Maksence/write-ups/blob/main/reverse-tls-sec/images/flink.png)

Not so easy to understand, but our function creates a variable accessing the local Process Environment Block (PEB). 
[@yo-yo-yo-jbo sums its up quite nicely:](https://github.com/yo-yo-yo-jbo/anti_debugging_intro?tab=readme-ov-file)
>every process in Windows has some memory structure in its address space called the PEB, which saves useful information about the process in userspace. This is useful because the process doesn't have to talk to the kernel when it wants to get that information.


Here is a graph of the structure of the Ldr object in our PEB that is being accessed *(credit: [@BK](https://aroundthemalware.wordpress.com/2021/12/05/peb-malwares-favourite/))*

![PEB](https://github.com/Maksence/write-ups/blob/main/reverse-tls-sec/images/PEB.png)

It's a double linked list, with each element _PEB_Element_Data item referencing the next and the previous one (Flink = forward Link).
First our function checks that the second element of the list is different from the first (in which case the list would be empty). 
Then it accesses the loaded dlls in order until it reaches the 3rd one. If it's able to, then it will return the LIST_ENTRY element of this dll. 

In a nutshell, it tries to return a reference to the 3rd loaded dll in the process, and if it can't it returns 0. 

But what module is the program actually loading ? We can check by attaching WinDbg to the executable, or debugging it in IDA.

![windbg](https://github.com/Maksence/write-ups/blob/main/reverse-tls-sec/images/windbg.png)

**Kernel32.dll** -> what is it ?

>The Kernel32.dll file is an essential component of the Windows operating system. It is a dynamic link library file that contains various functions and resources required for the proper functioning of the Windows kernel. [...]
>
>Kernel32.dll provides a set of functions that allow applications to interact with the operating system. These functions include memory management, process creation and termination, file input/output, and error handling. In simpler terms, Kernel32.dll acts as a bridge between the software applications and the operating system, enabling them to communicate and perform tasks.

So the second condition seems to be: get a reference to the loaded Kernel32.dll.

Let's rename our variables as we go to make it clearer what is being accessed. We'll call the return value of the function "Kernel32reference", and the other values "k32ossetvX".

#### 3rd condition

```c
      v10 = -1i64;
      v20 = k32offsetv6[6];
      do
      {
        v11 = -1i64;
        v12 = (char *)Kernel32reference + *k32offsetv8;
        do
          ++v11;
        while ( v12[v11] );
        v13 = sub_7FF6308513B0(v12, v11);
        if ( v13 == -305803260 )
        {
          v3 = (__int64 (*)(void))((char *)Kernel32reference + *(unsigned int *)&v7[4 * *k32offsetv9]);
        }
        else if ( v13 == -72948286 )
        {
          v4 = (struct _LIST_ENTRY *)((char *)Kernel32reference + *(unsigned int *)&v7[4 * *k32offsetv9]);
        }
        ++k32offsetv8;
        ++k32offsetv9;
        --v20;
      }
      while ( v20 );
      if ( v4 )
```

The sub_7FF6308513B0 function's signature was not correctly analyzed by IDA, so I edited it manually. 
Now it takes some references to our kernel32 dll as parameters.

The program loops on a couple of conditions, and it checks that the return value of sub_7FF6308513B0 is equal to some hardcoded values.

Let's take a look inside:

```c
__int64 __fastcall sub_7FF6308513B0(char *a1, unsigned __int64 a2)
{
  __int64 result; // rax
  int i; // r10d
  int v5; // ecx
  int v6; // eax

  result = 0i64;
  for ( i = 0; i < a2; result = (32 * (unsigned __int8)v6) ^ (v6 << 12) ^ (unsigned int)v6 )
  {
    v5 = *a1++;
    ++i;
    v6 = ((unsigned __int8)(v5 ^ BYTE1(result)) >> 4) ^ v5 ^ (BYTE1(result) | ((_DWORD)result << 8));
  }
  return result;
}
```

The function performs some arithmetic operations. It looks a lot like a [cyclic redundancy check function](https://github.com/lammertb/libcrc/blob/master/src/crc16.c#L52)

So it's pretty safe to assume at this point that sub_7FF6308513B0 is just a sort of signature for functions/elements in the Kernel32 module, which we'll call crc16.

We can now put a breakpoint after these conditions are met to try and see dynamically what it is actually loading.


![functions](https://github.com/Maksence/write-ups/blob/main/reverse-tls-sec/images/functions.png)

And here we have them, third condition: load the kernel32 functions GetCommandLineA and VirtualProtect.


### Finding the argument
#### Fourth conditions block
```c
//offset=-1
      if ( VirtualProtect )
      {
        if ( GetCommandLineA )
        {
          argv = GetCommandLineA();
          while ( *(argv + offset++ + 1) != 0 )
            ;
          endOfargv = argv + offset;
          if ( *(argv + offset - 7) == 'anyd' && *(endOfargv - 3) == WORD2(v21) && *(endOfargv - 1) == BYTE6(v21) )
          {
```

The first two ifs are pretty straightforward and will be met if we've found the two functions

All the while loop does is increase an offset value until it has reached the end of argv, i.e. offset=len(argv).

Finally:
- if the 4 characters 7 bytes away from the last argv character are equal to "dyna" (endianess needs to be reversed);
- if the 2 characters 3 bytes away are equal to WORD2(v21) (this is an IDA function, but a word is usually 2 bytes long)
- if the last character is equal to the first byte of v21

Then the condition will be met.
But what is v21? Well if we change its value from hex to characters,
```cal=
    v21 = 'xamanyd';
```
Altough the inner workings of WORD2() and BYTE6() are unclear to me, it seems that this condition is equivalent to:

```
if *(argv+offset)[::-7]=="dynamax":
```
So the program is just looking for "dynamax" as the final argument passed!
Let's try it out.

![dynamax](https://github.com/Maksence/write-ups/blob/main/reverse-tls-sec/images/dynamax.png)

We get a new message: "Pikachu is not available in dynamax". We must be missing another condition, but that's good progress.

Just to check, we can try to have some random text in front of the "dynamax" payload

![dynamaxtest](https://github.com/Maksence/write-ups/blob/main/reverse-tls-sec/images/dynamaxtest.png)

Still works, so we were right.

### Obfuscated code

Okay now let's try to digest the final stage of the payload. For clarity, I'll call the big base64 data String "BigB64DataString"

```cal
          if ( *(argv + offset - 7) == 'anyd' && *(v16 - 3) == WORD2(v21) && *(v16 - 1) == BYTE6(v21) )
          {
            (VirtualProtect)(
              "BigB64DataString",
              20480i64,
              4i64,
              &v20);
            memcpy(
              "BigB64DataString",
              &unk_7FF7138F82E0,
              0x5000ui64);
            v17 = "BigB64DataString[1::]"";
 
```
#### First off, **VirtualProtect.** 
From the microsoft documentation:

>Changes the protection on a region of committed pages in the virtual address space of the calling process.
    > >BOOL VirtualProtect(
  [in]  LPVOID lpAddress,
  [in]  SIZE_T dwSize,
  [in]  DWORD  flNewProtect,
  [out] PDWORD lpflOldProtect

We're changing the permissions in memory for the 20480 bytes at the base adress of BigB54DataString. 
We're giving it the permission equal to 0x04, which is PAGE_READWRITE.

Dynamically we can take a look at the content of v20 after the instruction, and see that the old permission was 0x02 PAGE_READONLY.

Interestingly, "BigB64DataString" is actually interpreted by IDA as a string, but that doesn't make sense so I'll assume that it's just pointing to the area in memory where that data currently is.

#### Then, **memcpy**.
Same goes here with the string instead of an address issue, but all this does is copy the 20,480 bytes (0x5000 in hexadecimal) at unk_7FF7138F82E0 to the BigB64DataString memory area.

In a nutshell, this snippet grants the process write permissions to this memory zone and copies some payload into it.

### Final code block in tls_callback


```c
            //BigB64DataStringPlus1 = v17 = "BigB64DataString[1::]"";
             BigB64DataStringPlus1 = "wByAGkAdABlAC0ATwB1AHQAcAB1AHQAIABAACIACgAAKAAoACgAKAAoACgAKAAoACgAKAAoACiAKPQoRigAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAoAACgAKAAoACgAKAAoACgAKAAoACgAKIAo/ij/KOcoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgKAAAoACgAKAAoACgAKAAoACgAKAAogCj+KP8o/yj/KAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoCgAAKAAoACgAKAAoACgAKAAoACgAKH4oCygJKAAoRygAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAoAACgAKAAoACgAKAAoACgAKAAo/CgDKAAoACgAKEcoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgKAAAoACgAKAAoACgAKAAoACiAKE8oACgAKAAoAChHKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoCgAAKAAoACgAKAAoACgAKAAouCgAKAAoACgAKAAoRygAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACiAKMAowCjgKOQo5CjkKOQoACgAKAoAACgAKAAoACgAKAAoACgAKE8oACgAKAAoACi4KAMoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAowChkKDQoEigKKAkoCSgAKAAo/yj/KP8oPygLKAAoACgKAAAoACgAKAAoACgAKAAoAChHKAAoACiAKGAoPCg0KBIoEigSKBIoJigkKCQoxCjAKAAogCjgKDQoGigJKAAoACgAKAAoACgAKAAoACj8KD8oCygBKAAoACgAKAAoCgAAKAAoACgAKAAoACgAKAAoxygUKAIoCCgAKAAoACgAKAAoACgAKAAoACgAKAAoqCg/KAsoACgAKAAoACgAKAAoACgAKMAoZCgWKAsoASgAKAAoACgAKAAoACgAKAoAACgAKAAoACgAKAAoACiwKAsoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKMAo4CgkKBIoCygBKAAoACgAKAAoACgAKAAoACgAKAAoACgKAAAoACgAKAAoACgAKIAoXygAKOAoxChAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgIKAkouygBKAAoACgAKAAoACgAKAAoACgAKIAo4CjkKOQoZCgkKLQoCgAAKAAoACgAKAAoACj4KAEo/ij/KMAo/ShGKAAoACgAKAAoACgAKAAooCj+KAkovyjmKAAoACgAKLgoQCgAKAAogCjgKCQoFCgSKAsoCSgJKAAoACgAKAAogCheKAoAACgAKAAoACgAKIAoTygAKDkoPyg/KB8oASgAKDAoJigAKAAoACgAKDgo/yj/KP8ofygAKAAoACiYKGcoFigLKAEoACgAKAAoACgAKAAoACgAKAAoACgAKHwoACgKAAAoACgAKAAoACj8KCYoxCgAKAAooCjAKMAo9CgfKDYoxChAKAAoAChAKAAoCSgBKAAoACgAKAAouCgHKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAo+CgBKAAoCgAAKAAoACgAKLAoRygAKAgoRygAKAAoOCh+KAEoACgAKAAoCSgJKE8oACgAKAAo4CgWKAkoEyikKLgoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACjwKAMoACgAKAoAACgAKAAoACgAKKcowCh8KAMoACgAKAAopygAKAAoACgAKAAouCgDKAAoACgAKOcoACgAKAAo+Ci5KAAoACgAKAAoACgAKAAoACgAKAAoACgAKHAoAygAKAAoACgKAAAoACgAKAAoACgIKKcoQCgAKAAoACgAKBgoxigAKAAoACigKA8oACgAKAAoACgIKDMoJCgWKAMoXygAKAAoACi+KBsoGygbKBsoGygbKBsoGygBKAAoACgAKAAoCgAAKAAoACgAKAAoACgAKBkoxigAKAAoACgAKAgoJijAKHQoCygAKAAoACgAKAAoACgAKAAogCj8KBkopigAKAAoGChHKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAoAACgAKAAoACgAKAAoACigKEcoGSgmKMQoACgAKAAoACgAKAAoACgAKAAoACgAKIAo4Cg0KAsoOChHKAgosyhAKAAouShAKAAoACgAKAAoACgAKAAoACgAKAAoACgKAAAoACgAKAAoACgAKAAofCjAKAAoACgIKBkoAigAKAAoACgAKAAoACgAKAAoACgJKAAoACgAKAAo9yg0KBooASgAKMAo9ygAKAAoACgAKAAoACgAKAAoACgAKAAoCgAAKAAoACgAKAAoACh0KAEoTygAKAAoACgAKAAoACgAKAAoACigKAAoACgAKAAoACgAKAAoACgAKBgoxih0KBooCSgJKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAoA/Ci3KEYoACjgKHQoJyjEKMcoACgAKAAoACgAKAAoACiyKAAoXygAKAAoACgAKAAoACgAKIAoRyjgKP0opijEKIAo9Cj2KAAoACgAKAAoACgAKAAoACgAKAAoACgKAH8o/Cj9KF4oASgAKAAoACi5KEAoACgAKAAoACgAKAAoCCj3KAMoACgAKAAoACgAKAAoACj8KAkoASgAKAAooCifKP8o/ygBKAAoACgAKAAoACgAKAAoACgAKAAoCgD3KAkoASizKAAoACgAKAAoCCjnKAAoACgAKAAoACgAKAAo+ygAKAAoACgAKAAoACgAKPAoAygAKAAoACgAKA8oACgAKH8oACgAKAAoACgAKAAoACgAKAAoACgAKAoAOShGKAAoCChHKAAoACgAKAAoGCjGKAAoACgAKAAoACgAKEcoACgAKAAoACgAKAAo8CgDKAAoACgAKAAoACgAKAAo+CgBKAAoACgAKAAoACgAKAAoACgAKAAoACgKAAAosyhAKAAoGSgAKAAoACgAKAAoGCjGKAAoACgAKAAoAChHKAAoACgAKAAoACjwKAMoACgAKAAoACiAKEQoACigKAcoACgAKAAoACgAKAAoACgAKAAoACgAKAAoCgAAKAAosyhAKPAowCjAKMAoACgAKAAoGCjmKMAoACgAKAAoRygAKAAoACiAKHQoAygAKAAoACgAKAAouChHKKAoDygAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAoAACgAKAAoCSgJKAAoACgIKAkoCSgJKBkoOyg/KD4oPig7KBMopigmKHYodig/KBsoGygTKBIoEigaKBsoGygBKAoAIgBAAA==";
            for ( i = 0; i < 19392; i += 6 )
            {
              *(BigB64DataStringPlus1 - 1) ^= *((_BYTE *)&dynamax + i % 7u);
              *BigB64DataStringPlus1 ^= *((_BYTE *)&dynamax + (int)(i - 7 * ((i + 1) / 7u) + 1));
              BigB64DataStringPlus1[1] ^= *((_BYTE *)&dynamax + (int)(i - 7 * ((i + 2) / 7u) + 2));
              BigB64DataStringPlus1[2] ^= *((_BYTE *)&dynamax + (int)(i - 7 * ((i + 3) / 7u) + 3));
              BigB64DataStringPlus1[3] ^= *((_BYTE *)&dynamax + (int)(i - 7 * ((i + 4) / 7u) + 4));
              v19 = (int)(i - 7 * ((i + 5) / 7u) + 5);
              BigB64DataStringPlus1 += 6;
              *(BigB64DataStringPlus1 - 2) ^= *((_BYTE *)&dynamax + v19);
            }
```
A bunch of xor operations on our previous payload, with the "dynamax" string
With a little coding, we can reproduce these operations in Python, extract the payload at the &unk_7FF7138F82E0 adress from the program's memory and figure out exactly what the program is doing here.


#### Python function

Let's extract our payload.
```shell
vim pikachu.exe
:%!xxd
/2e38 2c0a
```

![payload](https://github.com/Maksence/write-ups/blob/main/reverse-tls-sec/images/payload.png)

```
Ctrl+v to enver visual mode
j + k to select the columns
x to delete the selected characters
:%s/ //g to replaces all continuous whitespaces 
```
and we get a nice hex string which we can save in a file.

Now we can write our python program
```python
import base64

with open("pikachu.hex", "r") as f:
    hex = f.read()
    hex = hex.replace('\n', '')

hex = bytes.fromhex(hex)
string = ''.join(chr(i) for i in hex)

print("Len of parameter data: ", len(string))

# Initialize the buffer and key schedules
dynamax = "dynamax"
# Decipher the buffer
buffer_1 = [ord(x) for x in string]
dynamax = [ord(x) for x in dynamax]

for i in range(0, 19392, 6):
    try:
        buffer_1[i] ^= dynamax[i % 7]
        buffer_1[i + 1] ^= dynamax[(i - 7 * ((i + 1) // 7) + 1) % 7]
        buffer_1[i + 2] ^= dynamax[(i - 7 * ((i + 2) // 7) + 2) % 7]
        buffer_1[i + 3] ^= dynamax[(i - 7 * ((i + 3) // 7) + 3) % 7]
        buffer_1[i + 4] ^= dynamax[(i - 7 * ((i + 4) // 7) + 4) % 7]
        buffer_1[i + 5] ^= dynamax[(i - 7 * ((i + 5) // 7) + 5) % 7]

    except Exception as e:
        print(e)
        break
string = ''.join(chr(i) for i in buffer_1)

#Convert from base64 to utf-16
powershell = base64.b64decode(string).decode('utf-16')
print(powershell)
```
Output:
```shell
Len of parameter data:  19392
$dQRWGpP=83;$m83ytj3=101;$JZbPRdx=108;$2bGFs0n=99;$IB7a8ZE=116;$4JNB57M=45;$WdlS4IE=79;$7RCpZcf=98;$vqEpUU1=106;$9lW0iqg=71;$BmmmmZl=87;$yIaqt4f=109;$hD0mE1u=105;$v6toWZf=120;$3Mk19cu=49;$Ybe2ueL=43;$pOFj7MC=51;$G3WdcJX=0;$WtUReU3=8;$Cl0KEnn=23;$fmKyDnj=4;$BndBQNw=88;$TqzS5S5=41;$YnjQuXN=16;$YLUW40K=1;$qVWLerF=94;$zvAxZf5=12;$6GmjwOb=80;$KDIAD6V=114;$9GveMwq=111;$G7EUYfF=115;$A6dkVH0=78;$VJgdIv9=97;$UqZ8QWd=117;$xxoESSt=112;$zr8KNJC=102;$l20rjA9=110;$1OTzqiy=32;$6iWzL9I=40;$TKZvI17=36;$YuGQJOr=44;$u49DQDf=107;$Ai8VfwJ=123;$6W8EWAf=61;$WcMv5Ve=119;$SDR6Leb=121;$JX9l8Ad=46;$8TpJ1U6=67;$5zXgGI9=76;$BR44MnX=91;$SjKUbrN=93;$GMM0VAk=59;$9hKyK1w=48;$5CCRyVN=65;$FL9a7vL=100;$v3OZPNF=104;$OeRF5lQ=125;$hyeGZZS=84;$PKAOYmh=33;$QCZYyAR=([char]$dQRWGpP+[char]$m83ytj3+[char]$JZbPRdx+[char]$m83ytj3+[char]$2bGFs0n+[char]$IB7a8ZE+[char]$4JNB57M+[char]$WdlS4IE+[char]$7RCpZcf+[char]$vqEpUU1+[char]$m83ytj3+[char]$2bGFs0n+[char]$IB7a8ZE);$5sqiujS=([char]$9lW0iqg+[char]$m83ytj3+[char]$IB7a8ZE+[char]$4JNB57M+[char]$BmmmmZl+[char]$yIaqt4f+[char]$hD0mE1u+[char]$WdlS4IE+[char]$7RCpZcf+[char]$vqEpUU1+[char]$m83ytj3+[char]$2bGFs0n+[char]$IB7a8ZE);$GoU0UFd=([char]$9lW0iqg+[char]$m83ytj3+[char]$IB7a8ZE+[char]$4JNB57M+[char]$BmmmmZl+[char]$yIaqt4f+[char]$hD0mE1u+[char]$WdlS4IE+[char]$7RCpZcf+[char]$vqEpUU1+[char]$m83ytj3+[char]$2bGFs0n+[char]$IB7a8ZE);$WdrZONR=([char]$hD0mE1u+[char]$m83ytj3+[char]$v6toWZf);$KOEurzh=([char]$BmmmmZl+[char]$KDIAD6V+[char]$hD0mE1u+[char]$IB7a8ZE+[char]$m83ytj3+[char]$4JNB57M+[char]$WdlS4IE+[char]$UqZ8QWd+[char]$IB7a8ZE+[char]$xxoESSt+[char]$UqZ8QWd+[char]$IB7a8ZE);$id = [System.Diagnostics.Process]::GetCurrentProcess() | . $QCZYyAR -ExpandProperty ID
$dQRWGpQ = . $5sqiujS Win32_Process -Filter "ProcessId = '$id'"
$dQRWGpQ = . $GoU0UFd Win32_Process -Filter "ProcessId = '$($dQRWGpQ.ParentProcessId)'"

. $WdrZONR ([char]$zr8KNJC+[char]$UqZ8QWd+[char]$l20rjA9+[char]$2bGFs0n+[char]$IB7a8ZE+[char]$hD0mE1u+[char]$9GveMwq+[char]$l20rjA9+[char]$1OTzqiy+[char]$3Mk19cu+[char]$Ybe2ueL+[char]$3Mk19cu+[char]$6iWzL9I+[char]$TKZvI17+[char]$7RCpZcf+[char]$YuGQJOr+[char]$1OTzqiy+[char]$TKZvI17+[char]$u49DQDf+[char]$TqzS5S5+[char]$1OTzqiy+[char]$Ai8VfwJ+[char]$TKZvI17+[char]$l20rjA9+[char]$1OTzqiy+[char]$6W8EWAf+[char]$1OTzqiy+[char]$A6dkVH0+[char]$m83ytj3+[char]$WcMv5Ve+[char]$4JNB57M+[char]$WdlS4IE+[char]$7RCpZcf+[char]$vqEpUU1+[char]$m83ytj3+[char]$2bGFs0n+[char]$IB7a8ZE+[char]$1OTzqiy+[char]$dQRWGpP+[char]$SDR6Leb+[char]$G7EUYfF+[char]$IB7a8ZE+[char]$m83ytj3+[char]$yIaqt4f+[char]$JX9l8Ad+[char]$8TpJ1U6+[char]$9GveMwq+[char]$JZbPRdx+[char]$JZbPRdx+[char]$m83ytj3+[char]$2bGFs0n+[char]$IB7a8ZE+[char]$hD0mE1u+[char]$9GveMwq+[char]$l20rjA9+[char]$G7EUYfF+[char]$JX9l8Ad+[char]$9lW0iqg+[char]$m83ytj3+[char]$l20rjA9+[char]$m83ytj3+[char]$KDIAD6V+[char]$hD0mE1u+[char]$2bGFs0n+[char]$JX9l8Ad+[char]$5zXgGI9+[char]$hD0mE1u+[char]$G7EUYfF+[char]$IB7a8ZE+[char]$BR44MnX+[char]$dQRWGpP+[char]$SDR6Leb+[char]$G7EUYfF+[char]$IB7a8ZE+[char]$m83ytj3+[char]$yIaqt4f+[char]$JX9l8Ad+[char]$WdlS4IE+[char]$7RCpZcf+[char]$vqEpUU1+[char]$m83ytj3+[char]$2bGFs0n+[char]$IB7a8ZE+[char]$SjKUbrN+[char]$GMM0VAk+[char]$zr8KNJC+[char]$9GveMwq+[char]$KDIAD6V+[char]$1OTzqiy+[char]$6iWzL9I+[char]$TKZvI17+[char]$hD0mE1u+[char]$1OTzqiy+[char]$6W8EWAf+[char]$1OTzqiy+[char]$9hKyK1w+[char]$GMM0VAk+[char]$1OTzqiy+[char]$TKZvI17+[char]$hD0mE1u+[char]$1OTzqiy+[char]$4JNB57M+[char]$JZbPRdx+[char]$IB7a8ZE+[char]$1OTzqiy+[char]$TKZvI17+[char]$7RCpZcf+[char]$JX9l8Ad+[char]$8TpJ1U6+[char]$9GveMwq+[char]$UqZ8QWd+[char]$l20rjA9+[char]$IB7a8ZE+[char]$GMM0VAk+[char]$1OTzqiy+[char]$TKZvI17+[char]$hD0mE1u+[char]$Ybe2ueL+[char]$Ybe2ueL+[char]$TqzS5S5+[char]$1OTzqiy+[char]$Ai8VfwJ+[char]$TKZvI17+[char]$l20rjA9+[char]$JX9l8Ad+[char]$5CCRyVN+[char]$FL9a7vL+[char]$FL9a7vL+[char]$6iWzL9I+[char]$BR44MnX+[char]$2bGFs0n+[char]$v3OZPNF+[char]$VJgdIv9+[char]$KDIAD6V+[char]$SjKUbrN+[char]$6iWzL9I+[char]$TKZvI17+[char]$7RCpZcf+[char]$BR44MnX+[char]$TKZvI17+[char]$hD0mE1u+[char]$SjKUbrN+[char]$1OTzqiy+[char]$4JNB57M+[char]$7RCpZcf+[char]$v6toWZf+[char]$9GveMwq+[char]$KDIAD6V+[char]$1OTzqiy+[char]$TKZvI17+[char]$u49DQDf+[char]$BR44MnX+[char]$TKZvI17+[char]$hD0mE1u+[char]$SjKUbrN+[char]$TqzS5S5+[char]$TqzS5S5+[char]$OeRF5lQ+[char]$1OTzqiy+[char]$KDIAD6V+[char]$m83ytj3+[char]$IB7a8ZE+[char]$UqZ8QWd+[char]$KDIAD6V+[char]$l20rjA9+[char]$1OTzqiy+[char]$4JNB57M+[char]$vqEpUU1+[char]$9GveMwq+[char]$hD0mE1u+[char]$l20rjA9+[char]$1OTzqiy+[char]$TKZvI17+[char]$l20rjA9+[char]$JX9l8Ad+[char]$hyeGZZS+[char]$9GveMwq+[char]$5CCRyVN+[char]$KDIAD6V+[char]$KDIAD6V+[char]$VJgdIv9+[char]$SDR6Leb+[char]$6iWzL9I+[char]$TqzS5S5+[char]$GMM0VAk+[char]$OeRF5lQ)
$Wrm8EMP=(.(([char]$3Mk19cu+[char]$Ybe2ueL+[char]$3Mk19cu)) @($pOFj7MC,$G3WdcJX,$WtUReU3,$Cl0KEnn,$fmKyDnj,$BndBQNw,$TqzS5S5,$YnjQuXN,$YLUW40K,$qVWLerF,$YnjQuXN,$zvAxZf5) $dQRWGpQ.([char]$6GmjwOb+[char]$KDIAD6V+[char]$9GveMwq+[char]$2bGFs0n+[char]$m83ytj3+[char]$G7EUYfF+[char]$G7EUYfF+[char]$A6dkVH0+[char]$VJgdIv9+[char]$yIaqt4f+[char]$m83ytj3));
try {
&$Wrm8EMP @"
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⠖⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡤⢤⡀⠀⠀⠀⠀⢸⠀⢱⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠳⡀⠈⠢⡀⠀⠀⢀⠀⠈⡄⠀⠀⠀⠀⠀⠀⠀⠀⡔⠦⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡤⠊⡹⠀⠀⠘⢄⠀⠈⠲⢖⠈⠀⠀⠱⡀⠀⠀⠀⠀⠀⠀⠀⠙⣄⠈⠢⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡠⠖⠁⢠⠞⠀⠀⠀⠀⠘⡄⠀⠀⠀⠀⠀⠀⠀⢱⠀⠀⠀⠀⠀⠀⠀⠀⠈⡆⠀⠀⠉⠑⠢⢄⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⡠⠚⠁⠀⠀⠀⡇⠀⠀⠀⠀⠀⢀⠇⠀⡤⡀⠀⠀⠀⢀⣼⠀⠀⠀⠀⠀⠀⠀⠀⠀⡇⢠⣾⣿⣷⣶⣤⣄⣉⠑⣄⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⢀⠞⢁⣴⣾⣿⣿⡆⢇⠀⠀⠀⠀⠀⠸⡀⠀⠂⠿⢦⡰⠀⠀⠋⡄⠀⠀⠀⠀⠀⠀⠀⢰⠁⣿⣿⣿⣿⣿⣿⣿⣿⣷⣌⢆⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⡴⢁⣴⣿⣿⣿⣿⣿⣿⡘⡄⠀⠀⠀⠀⠀⠱⣔⠤⡀⠀⠀⠀⠀⠀⠈⡆⠀⠀⠀⠀⠀⠀⡜⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣮⢣⠀⠀⠀⠀⠀
⠀⠀⠀⡼⢠⣾⣿⣿⣿⣿⣿⣿⣿⣧⡘⢆⠀⠀⠀⠀⠀⢃⠑⢌⣦⠀⠩⠉⠀⡜⠀⠀⠀⠀⠀⠀⢠⠃⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣧⣣⡀⠀⠀⠀
⠀⠀⢰⢃⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣦⠱⡀⠀⠀⠀⢸⠀⠀⠓⠭⡭⠙⠋⠀⠀⠀⠀⠀⠀⠀⡜⢰⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⡱⡄⠀⠀
⠀⠀⡏⣼⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣇⢃⠀⠀⠀⢸⠀⠀⠀⠀⢰⠀⠀⠀⠀⠀⠀⠀⢀⠜⢁⣼⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⠘⣆⠀
⠀⢸⢱⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡘⣆⠀⠀⡆⠀⠀⠀⠀⠘⡄⠀⠀⠀⠀⡠⠖⣡⣾⠁⣸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣧⢸⠀
⠀⡏⣾⣿⣿⣿⣿⡿⡛⢟⢿⣿⣿⣿⣿⣿⣿⣧⡈⢦⣠⠃⠀⠀⠀⠀⠀⢱⣀⠤⠒⢉⣾⡉⠻⠋⠈⢘⢿⣿⣿⣿⣿⠿⣿⣿⠏⠉⠻⢿⣿⣿⣿⣿⡘⡆
⢰⡇⣿⣿⠟⠁⢸⣠⠂⡄⣃⠜⣿⣿⠿⠿⣿⣿⡿⠦⡎⠀⠀⠀⠀⠀⠒⠉⠉⠑⣴⣿⣿⣎⠁⠠⠂⠮⢔⣿⡿⠉⠁⠀⠹⡛⢀⣀⡠⠀⠙⢿⣿⣿⡇⡇
⠘⡇⠏⠀⠀⠀⡾⠤⡀⠑⠒⠈⠣⣀⣀⡀⠤⠋⢀⡜⣀⣠⣤⣀⠀⠀⠀⠀⠀⠀⠙⢿⡟⠉⡃⠈⢀⠴⣿⣿⣀⡀⠀⠀⠀⠈⡈⠊⠀⠀⠀⠀⠙⢿⡇⡇
⠀⠿⠀⠀⠀⠀⠈⠀⠉⠙⠓⢤⣀⠀⠁⣀⡠⢔⡿⠊⠀⠀⠀⠀⠙⢦⡀⠀⠐⠢⢄⡀⠁⡲⠃⠀⡜⠀⠹⠟⠻⣿⣰⡐⣄⠎⠀⠀⠀⠀⠀⠀⠀⠀⢣⡇
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠉⠉⠁⠀⡜⠀⠀⠀⠀⠀⠀⠀⠀⠱⡀⠀⠀⠀⠙⢦⣀⢀⡴⠁⠀⠀⠀⠀⠉⠁⢱⠈⢆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⢱⠀⠀⠀⠀⠈⢏⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⡇⠈⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡠⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡇⠀⠀⠀⠀⠀⠱⡄⠀⠀⠀⠀⠀⠀⠀⠀⡇⠀⢸⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡜⠀⢹⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⠀⠀⠀⠀⠀⠀⠘⣆⠀⠀⠀⠀⠀⠀⣰⠃⠀⠀⡇⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡾⠀⠀⠘⣆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⠁⠀⠀⠀⠀⠀⠀⠸⡄⠀⠀⠀⢀⡴⠁⠀⠀⢀⠇⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢧⠀⠀⠀⠘⢆⠀⠀⠀⠀⠀⠀⠀⠀⠀⡇⠀⠀⠀⠀⠀⠀⠀⠀⣧⣠⠤⠖⠋⠀⠀⠀⠀⡸⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠢⡀⠀⠀⠀⠳⢄⠀⠀⠀⠀⠀⠀⠀⢣⠀⠀⠀⠀⠀⠀⠀⠀⡏⠀⠀⠀⠀⠀⠀⢀⡴⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⡠⠊⠈⠁⠀⠀⠀⡔⠛⠲⣤⣀⣀⣀⠀⠈⢣⡀⠀⠀⠀⠀⠀⢸⠁⠀⠀⠀⢀⡠⢔⠝⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠐⢈⠤⠒⣀⠀⠀⠀⠀⣀⠟⠀⠀⠀⠑⠢⢄⡀⠀⠀⠈⡗⠂⠀⠀⠀⠙⢦⠤⠒⢊⡡⠚⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠆⠒⣒⡁⠬⠦⠒⠉⠀⠀⠀⠀⠀⠀⠀⠀⠈⠉⠒⢺⢠⠤⡀⢀⠤⡀⠠⠷⡊⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⠣⡀⡱⠧⡀⢰⠓⠤⡁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠁⠀⠈⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀

"@
}
catch {
        . $KOEurzh ([char]$6GmjwOb+[char]$hD0mE1u+[char]$u49DQDf+[char]$VJgdIv9+[char]$2bGFs0n+[char]$v3OZPNF+[char]$UqZ8QWd+[char]$1OTzqiy+[char]$l20rjA9+[char]$1OTzqiy+[char]$m83ytj3+[char]$G7EUYfF+[char]$IB7a8ZE+[char]$1OTzqiy+[char]$xxoESSt+[char]$VJgdIv9+[char]$G7EUYfF+[char]$1OTzqiy+[char]$FL9a7vL+[char]$hD0mE1u+[char]$G7EUYfF+[char]$xxoESSt+[char]$9GveMwq+[char]$l20rjA9+[char]$hD0mE1u+[char]$7RCpZcf+[char]$JZbPRdx+[char]$m83ytj3+[char]$1OTzqiy+[char]$m83ytj3+[char]$l20rjA9+[char]$1OTzqiy+[char]$FL9a7vL+[char]$SDR6Leb+[char]$l20rjA9+[char]$VJgdIv9+[char]$yIaqt4f+[char]$VJgdIv9+[char]$v6toWZf+[char]$1OTzqiy+[char]$PKAOYmh+[char]$PKAOYmh+[char]$PKAOYmh)
}
```

And there we have found our Charizard! And also a bunch of obfuscated variables and powershell code.

## Deobfuscating the powershell code

Let's write some more code to replace the variables with their actual values

```python
obfuscated_ps=powershell.replace('\x00', '').replace(';',';\n')
#Make the obfuscated code a little more readable and create a dictionary of variables for character translation
obf_char_list = obfuscated_ps.split('$QCZYyAR=')
obf_char_list = obf_char_list[0].split(';\n')
commands = obfuscated_ps

dict = {}
for i in obf_char_list:
    if i != '':
        dict[i.split('=')[0]] = i.split('=')[1]

#Convert all the variables to their respective values, except the "+" signs
for var in dict:
    commands = commands.replace("[char]"+var, chr(int(dict[var])))
    commands = commands.replace(var+",", str(int(dict[var]))+",").replace(","+var, ","+str(int(dict[var])))
commands=commands.replace('+++',"PLUS").replace("++","PLUS").replace('+','').replace('PLUS','+')

#Print result!
print("----- \n Decrypted command: \n-----")
print(commands)
print("----- \n End of command \n-----")
```
Output:
```shell
----- 
 Decrypted command: 
-----
$dQRWGpP=83; $m83ytj3=101;$JZbPRdx=108;$2bGFs0n=99;$IB7a8ZE=116;$4JNB57M=45;$WdlS4IE=79;$7RCpZcf=98;$vqEpUU1=106;$9lW0iqg=71;$BmmmmZl=87;$yIaqt4f=109;$hD0mE1u=105;$v6toWZf=120;$3Mk19cu=49;$Ybe2ueL=43;$pOFj7MC=51;$G3WdcJX=0;$WtUReU3=8;$Cl0KEnn=23;$fmKyDnj=4;$BndBQNw=88;$TqzS5S5=41;$YnjQuXN=16;$YLUW40K=1;$qVWLerF=94;$zvAxZf5=12;$6GmjwOb=80;$KDIAD6V=114;$9GveMwq=111;$G7EUYfF=115;$A6dkVH0=78;$VJgdIv9=97;$UqZ8QWd=117;$xxoESSt=112;$zr8KNJC=102;$l20rjA9=110;$1OTzqiy=32;$6iWzL9I=40;$TKZvI17=36;$YuGQJOr=44;$u49DQDf=107;$Ai8VfwJ=123;$6W8EWAf=61;$WcMv5Ve=119;$SDR6Leb=121;$JX9l8Ad=46;$8TpJ1U6=67;$5zXgGI9=76;$BR44MnX=91;$SjKUbrN=93;$GMM0VAk=59;$9hKyK1w=48;$5CCRyVN=65;$FL9a7vL=100;$v3OZPNF=104;$OeRF5lQ=125;$hyeGZZS=84;$PKAOYmh=33;
$QCZYyAR=(Select-Object);
$5sqiujS=(Get-WmiObject);
$GoU0UFd=(Get-WmiObject);
$WdrZONR=(iex);
$KOEurzh=(Write-Output);
$id = [System.Diagnostics.Process]::GetCurrentProcess() | . $QCZYyAR -ExpandProperty ID
$dQRWGpQ = . $5sqiujS Win32_Process -Filter "ProcessId = '$id'"
$dQRWGpQ = . $GoU0UFd Win32_Process -Filter "ProcessId = '$($dQRWGpQ.ParentProcessId)'"

. $WdrZONR (function 1+1($b, $k) {$n = New-Object System.Collections.Generic.List[System.Object];for ($i = 0; $i -lt $b.Count; $i++) {$n.Add([char]($b[$i] -bxor $k[$i]))} return -join $n.ToArray();})
$Wrm8EMP=(.((1+1)) @(51,0,8,23,4,88,41,16,1,94,16,12) $dQRWGpQ.(ProcessName));

try {
&$Wrm8EMP @"
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⠖⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡤⢤⡀⠀⠀⠀⠀⢸⠀⢱⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠳⡀⠈⠢⡀⠀⠀⢀⠀⠈⡄⠀⠀⠀⠀⠀⠀⠀⠀⡔⠦⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡤⠊⡹⠀⠀⠘⢄⠀⠈⠲⢖⠈⠀⠀⠱⡀⠀⠀⠀⠀⠀⠀⠀⠙⣄⠈⠢⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡠⠖⠁⢠⠞⠀⠀⠀⠀⠘⡄⠀⠀⠀⠀⠀⠀⠀⢱⠀⠀⠀⠀⠀⠀⠀⠀⠈⡆⠀⠀⠉⠑⠢⢄⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⡠⠚⠁⠀⠀⠀⡇⠀⠀⠀⠀⠀⢀⠇⠀⡤⡀⠀⠀⠀⢀⣼⠀⠀⠀⠀⠀⠀⠀⠀⠀⡇⢠⣾⣿⣷⣶⣤⣄⣉⠑⣄⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⢀⠞⢁⣴⣾⣿⣿⡆⢇⠀⠀⠀⠀⠀⠸⡀⠀⠂⠿⢦⡰⠀⠀⠋⡄⠀⠀⠀⠀⠀⠀⠀⢰⠁⣿⣿⣿⣿⣿⣿⣿⣿⣷⣌⢆⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⡴⢁⣴⣿⣿⣿⣿⣿⣿⡘⡄⠀⠀⠀⠀⠀⠱⣔⠤⡀⠀⠀⠀⠀⠀⠈⡆⠀⠀⠀⠀⠀⠀⡜⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣮⢣⠀⠀⠀⠀⠀
⠀⠀⠀⡼⢠⣾⣿⣿⣿⣿⣿⣿⣿⣧⡘⢆⠀⠀⠀⠀⠀⢃⠑⢌⣦⠀⠩⠉⠀⡜⠀⠀⠀⠀⠀⠀⢠⠃⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣧⣣⡀⠀⠀⠀
⠀⠀⢰⢃⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣦⠱⡀⠀⠀⠀⢸⠀⠀⠓⠭⡭⠙⠋⠀⠀⠀⠀⠀⠀⠀⡜⢰⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⡱⡄⠀⠀
⠀⠀⡏⣼⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣇⢃⠀⠀⠀⢸⠀⠀⠀⠀⢰⠀⠀⠀⠀⠀⠀⠀⢀⠜⢁⣼⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⠘⣆⠀
⠀⢸⢱⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡘⣆⠀⠀⡆⠀⠀⠀⠀⠘⡄⠀⠀⠀⠀⡠⠖⣡⣾⠁⣸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣧⢸⠀
⠀⡏⣾⣿⣿⣿⣿⡿⡛⢟⢿⣿⣿⣿⣿⣿⣿⣧⡈⢦⣠⠃⠀⠀⠀⠀⠀⢱⣀⠤⠒⢉⣾⡉⠻⠋⠈⢘⢿⣿⣿⣿⣿⠿⣿⣿⠏⠉⠻⢿⣿⣿⣿⣿⡘⡆
⢰⡇⣿⣿⠟⠁⢸⣠⠂⡄⣃⠜⣿⣿⠿⠿⣿⣿⡿⠦⡎⠀⠀⠀⠀⠀⠒⠉⠉⠑⣴⣿⣿⣎⠁⠠⠂⠮⢔⣿⡿⠉⠁⠀⠹⡛⢀⣀⡠⠀⠙⢿⣿⣿⡇⡇
⠘⡇⠏⠀⠀⠀⡾⠤⡀⠑⠒⠈⠣⣀⣀⡀⠤⠋⢀⡜⣀⣠⣤⣀⠀⠀⠀⠀⠀⠀⠙⢿⡟⠉⡃⠈⢀⠴⣿⣿⣀⡀⠀⠀⠀⠈⡈⠊⠀⠀⠀⠀⠙⢿⡇⡇
⠀⠿⠀⠀⠀⠀⠈⠀⠉⠙⠓⢤⣀⠀⠁⣀⡠⢔⡿⠊⠀⠀⠀⠀⠙⢦⡀⠀⠐⠢⢄⡀⠁⡲⠃⠀⡜⠀⠹⠟⠻⣿⣰⡐⣄⠎⠀⠀⠀⠀⠀⠀⠀⠀⢣⡇
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠉⠉⠁⠀⡜⠀⠀⠀⠀⠀⠀⠀⠀⠱⡀⠀⠀⠀⠙⢦⣀⢀⡴⠁⠀⠀⠀⠀⠉⠁⢱⠈⢆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⢱⠀⠀⠀⠀⠈⢏⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⡇⠈⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡠⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡇⠀⠀⠀⠀⠀⠱⡄⠀⠀⠀⠀⠀⠀⠀⠀⡇⠀⢸⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡜⠀⢹⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⠀⠀⠀⠀⠀⠀⠘⣆⠀⠀⠀⠀⠀⠀⣰⠃⠀⠀⡇⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡾⠀⠀⠘⣆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⠁⠀⠀⠀⠀⠀⠀⠸⡄⠀⠀⠀⢀⡴⠁⠀⠀⢀⠇⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢧⠀⠀⠀⠘⢆⠀⠀⠀⠀⠀⠀⠀⠀⠀⡇⠀⠀⠀⠀⠀⠀⠀⠀⣧⣠⠤⠖⠋⠀⠀⠀⠀⡸⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠢⡀⠀⠀⠀⠳⢄⠀⠀⠀⠀⠀⠀⠀⢣⠀⠀⠀⠀⠀⠀⠀⠀⡏⠀⠀⠀⠀⠀⠀⢀⡴⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⡠⠊⠈⠁⠀⠀⠀⡔⠛⠲⣤⣀⣀⣀⠀⠈⢣⡀⠀⠀⠀⠀⠀⢸⠁⠀⠀⠀⢀⡠⢔⠝⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠐⢈⠤⠒⣀⠀⠀⠀⠀⣀⠟⠀⠀⠀⠑⠢⢄⡀⠀⠀⠈⡗⠂⠀⠀⠀⠙⢦⠤⠒⢊⡡⠚⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠆⠒⣒⡁⠬⠦⠒⠉⠀⠀⠀⠀⠀⠀⠀⠀⠈⠉⠒⢺⢠⠤⡀⢀⠤⡀⠠⠷⡊⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⠣⡀⡱⠧⡀⢰⠓⠤⡁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠁⠀⠈⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀

"@
}
catch {
        . $KOEurzh (Pikachu n est pas disponible en dynamax !!!)
}
----- 
 End of command 
-----
```

It seems that we will get out Charizard if the $Wrm8EMP variable, which is the return value of the "1+1" function does not throw an error. Since it's also in a try{} block with ASCII art as an argument, then it most likely is a function.

#### The 1+1 function
```powershell
function 1+1($b, $k) {
    $n = New-Object System.Collections.Generic.List[System.Object]
    for ($i = 0; $i -lt $b.Count; $i++) {
        $n.Add([char]($b[$i] -bxor $k[$i]))
    }
    return -join $n.ToArray()
}
```

The function takes 2 arguments and xors each character and returns the result. $n=\$b\$k

#### $Wrm8EMP
```powershell
$Wrm8EMP=(.((1+1)) @(51,0,8,23,4,88,41,16,1,94,16,12) $dQRWGpQ.(ProcessName));
```
I don't know about all the powershell functions, so let's ask Chat-GPT to save some time


>The last variable, $dQRWGpQ, seems to be querying information about a process using WMI (Windows Management Instrumentation). Here's a breakdown of what it does:
> >   $id = [System.Diagnostics.Process]::GetCurrentProcess() | . $QCZYyAR -ExpandProperty ID: This line gets the current process ID using [System.Diagnostics.Process]::GetCurrentProcess(), then pipes it to Select-Object (stored in $QCZYyAR) to extract the ID property.
> >  
> >   $dQRWGpQ = . \$5sqiujS Win32_Process -Filter "ProcessId = '$id'": This line queries the Win32_Process WMI class using Get-WmiObject (stored in $5sqiujS) to get information about the process with the ID stored in $id.
> >   
>  >  $dQRWGpQ = . \$GoU0UFd Win32_Process -Filter "ProcessId = '$($dQRWGpQ.ParentProcessId)'": This line queries the Win32_Process WMI class again to get information about the parent process of the process obtained in the previous step ($dQRWGpQ). It uses the ParentProcessId property of $dQRWGpQ to filter the query.
>  >  
>In summary, $dQRWGpQ contains information about the parent process of the current process.

So, it looks like $Wrm8EMP is equal to the xor value of the name of the parent process and some hardcoded integers.

Now we know that $Wrm8EMP is supposed to print the ASCII art. There are quite a few "print" equivalent in powershell, but the one we've seen already in this code is "Write-Output". And it so happens that it's exactly the same length as the Process name that we are looking for...

Let's write a quick program to find what our hardcoded_values xor "Write-Output" would be equal to:

```python
#To un-XOR and find the name of the process
hardcoded_values = [51,0,8,23,4,88,41,16,1,94,16,12]
cmd = "Write-Output"
binary_hardcoded_values = []; sol = []; binary_cmd =[]
#Convert to binary
for e in hardcoded_values:
    binary_hardcoded_values.append(bin(e)[2:])
for i in range(len(cmd)):
    binary_cmd.append(bin(ord(cmd[i]))[2:])
#xor
for index in range(len(binary_cmd)):
    sol.append(chr(int(binary_cmd[index], 2) ^ int(binary_hardcoded_values[index], 2)))

#Join the hardcoded_values
sol = ''.join(sol)
print("Name of the parent process: ")
print(sol)
```
Output:
```shell
Name of the parent process: 
dracaufeu.ex
```

And there we have it! All that's left to do is to confirm

## Solution

```powershell
mv pikachu.exe dracaufeu.exe
./dracaufeu dynamax
```
![charizard](https://github.com/Maksence/write-ups/blob/main/reverse-tls-sec/images/charizard.png)

## Conclusion

This was a super interesting challenge, that uses real malware evasion/obfuscation techniques. I had not done much reverse before and discovered quite a few things along the way.
