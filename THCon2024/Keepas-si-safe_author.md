# Forensic: Keepas-si-safe:
(The pun only works if you speak french)
## Index
- [1. Challenge background](https://github.com/Maksence/write-ups/blob/main/THCon2024/Keepas-si-safe_author.md#chall-background)
- [2. WRITE-UP:](https://github.com/Maksence/write-ups/blob/main/THCon2024/Keepas-si-safe_author.md#write-up)
  - [2.1 Start](https://github.com/Maksence/write-ups/blob/main/THCon2024/Keepas-si-safe_author.md#21-start)
    - [Running processes](https://github.com/Maksence/write-ups/blob/main/THCon2024/Keepas-si-safe_author.md#running-processes)
  - [2.2 SOLVING USING THUNDERBIRD ONLY](https://github.com/Maksence/write-ups/blob/main/THCon2024/Keepas-si-safe_author.md#22-solving-using-thunderbird-only)
    - [2.2.1 Thunderbirdbird - Just looking at the strings](https://github.com/Maksence/write-ups/blob/main/THCon2024/Keepas-si-safe_author.md#221-thunderbirdbird---just-looking-at-the-strings)
    - [2.2.2 Thunderbird - If you know where to look](https://github.com/Maksence/write-ups/blob/main/THCon2024/Keepas-si-safe_author.md#222-thunderbird---if-you-know-where-to-look)
  - [2.3 SOLVING BY CARVING OUT THE PDF](https://github.com/Maksence/write-ups/blob/main/THCon2024/Keepas-si-safe_author.md#23-solving-by-carving-out-the-pdf)
    - [2.3.1 Filescan](https://github.com/Maksence/write-ups/blob/main/THCon2024/Keepas-si-safe_author.md#231-filescan)
      - [NB:](https://github.com/Maksence/write-ups/blob/main/THCon2024/Keepas-si-safe_author.md#nb)
    - [2.3.2 How was it ciphered ?](https://github.com/Maksence/write-ups/blob/main/THCon2024/Keepas-si-safe_author.md#232-how-was-it-ciphered---powershell-cli)
  - [2.4 Deciphering the pdf](https://github.com/Maksence/write-ups/blob/main/THCon2024/Keepas-si-safe_author.md#24-deciphering-the-pdf)
    - [2.4.1 Running the exploit](https://github.com/Maksence/write-ups/blob/main/THCon2024/Keepas-si-safe_author.md#241-running-the-exploit)
    - [2.4.2 Finding the right password](https://github.com/Maksence/write-ups/blob/main/THCon2024/Keepas-si-safe_author.md#242-finding-the-right-password)
- [3. Conclusion](https://github.com/Maksence/write-ups/blob/main/THCon2024/Keepas-si-safe_author.md#3-conclusion)
  - [TL;DR - key takeaways](https://github.com/Maksence/write-ups/blob/main/THCon2024/Keepas-si-safe_author.md#tldr---what-to-remember-for-future-challs)

### Chall Background:
So I wanted to create a forensics challenge for this event, and I stumbled upon an Ippsec
video where he breaks Keepass using **CVE-2023-32784**.
From the NIST website:

> In KeePass 2.x before 2.54, **it is possible to recover the cleartext master password** from a memory dump, even when a workspace is locked or no longer running. The memory dump can be a KeePass process dump, swap file (pagefile.sys), hibernation file (hiberfil.sys), or RAM dump of the entire system. The first character cannot be recovered. 

The main idea is that keepass left residual bits of strings in memory whenever you typed your master password, which you could recover by  searching for patterns in the memory itself. I thought it was an interesting vulnerability and started playing around with it.

I downloaded keepass on a windows vm, created a new Database and added a sub-password entry inside.

But something weird happened when I ran an xploit, I had bits of my master password  intertwined with the sub-password entry. Taking a closer look, I realized that although the CVE on the NIST website says that it “**is possible to recover the cleartext master password from a memory dump**”, what’s actually happening is you can recover **“any password last typed in the memory dump”.**

If I’d taken the time to thoroughly read the actual post from the original finder of the vuln [@vdohney](https://github.com/vdohney/keepass-password-dumper) , which is very well explained, it would have been clear from the start. 
Which is why I thought it would be fun to store the password to something else in the keepass db, and see if people realized that it was not the master password. :)

## WRITE-UP:
###     2.1 Start
So you are given a keepass .kdbx file, which is just the keepass standard for storing a
database of passwords, and the following description:
>We believe the bad guys got a hold of a memory dump on one of our machines. Looking through our logs, we also realized they were able to access this Database file. The person responsible for this machine says there is no way they could have gained access to his password manager - could you have a look ?

```shell
$ ls
adupont.dmp  Database.kdbx
```
Of course you could immediately look up something online such as “Keepass get master
password from .dmp” and you would most likely stumble on the CVE.

As expected many people tried to bf the master-password using the one you found with the CVE (we had a lot of tickets asking why it wasn’t working :’) so we ended up adding a hint to make it clearer that this was indeed not the master password.

#### Running processes
If you didn’t think of immediately looking for a CVE, then just taking a look at the running
processes 3 main ones should pop out 
```shell 
$ vol3 -f adupont.dmp windows.pslist

Volatility 3 Framework 2.5.2
Progress:  100.00		PDB scanning finished                        
PID	PPID	ImageFileName	Offset(V)	Threads	Handles	SessionId	Wow64	CreateTime	ExitTime

4	0	System	0x8616b040	107	-	N/A	False	2023-05-17 09:11:46.000000 	N/A
* 72	4	Registry	0x87c29640	4	-	N/A	False	2023-05-17 09:11:43.000000 	N/A
[...]
552	476	winlogon.exe	0x90bc4040	4	-	1	False	2023-05-17 09:11:48.000000 	N/A
* 704	552	fontdrvhost.ex	0x90bc3680	6	-	1	False	2023-05-17 09:11:49.000000 	N/A
* 3796	552	userinit.exe	0xa0657040	0	-	1	False	2023-05-17 09:12:10.000000 	2023-05-17 09:12:51.000000 
** 3832	3796	explorer.exe	0xa07cb040	54	-	1	False	2023-05-17 09:12:10.000000 	N/A
*** 5056	3832	SecurityHealth	0xab09d0c0	2	-	1	False	2023-05-17 09:12:39.000000 	N/A
*** 5248	3832	thunderbird.ex	0xab0a37c0	45	-	1	False	2023-05-17 09:12:42.000000 	N/A
**** 6008	5248	thunderbird.ex	0xad6d4840	15	-	1	False	2023-05-17 09:12:50.000000 	N/A
*** 5188	3832	msedge.exe	0xab0a3040	47	-	1	False	2023-05-17 09:12:41.000000 	N/A
[...]
**** 5140	5188	msedge.exe	0xa766c040	9	-	1	False	2023-05-17 09:13:23.000000 	N/A
*** 2896	3832	KeePass.exe	0x9d87b8c0	4	-	1	False	2023-05-17 09:13:27.000000 	N/A
*** 4208	3832	powershell.exe	0xa6fef040	14	-	1	False	2023-05-17 09:14:59.000000 	N/A
**** 888	4208	conhost.exe	0xa07e6040	6	-	1	False	2023-05-17 09:14:59.000000 	N/A
*** 5172	3832	OneDrive.exe	0xab0a5040	25	-	1	False	2023-05-17 09:12:40.000000 	N/A
* 904	552	dwm.exe	0x90ec2040	16	-	1	False	2023-05-17 09:11:50.000000 	N/A

```
*Thunderbird, Keepass, and powershell.*

The rest are all regular classic services, and hopefully you didn’t spend too much time looking at them (there was nothing to find in Edge).

Thunderbird is particularly interesting because, well, emails. If powershell is running then
maybe some commands were ran ? And the keepass process will come in handy later

There are actually two separate paths you could have taken to solve the chall, which both lead to the same outcome.
### 2.2 SOLVING USING THUNDERBIRD ONLY
Let’s take a closer look at thunderbird. Without looking for files in particular, you could just
dump the process and have a look at the strings. There are quite a few so we’ll try to filter on
some useful words.
#### 2.2.1 Thunderbirdbird - Just looking at the strings
First let's dump the process
```shell
$ vol3 -f adupont.dmp windows.memmap --pid 5248 --dump
```
If you tried to grep for “mail”, “gmail”, “Sent”, “Inbox”, then you would find many references to the adress adupont.rep@gmail.com
Then grepping the strings and looking at some lines before and after
```shell
$ strings pid.5248.dmp | grep @gmail.com -A 30 -B 30
[...]
Message-ID: <40c10fc0-b6fb-4765-a80b-17940bece79a@gmail.com>
Date: Wed, 17 May 2023 08:25:40 GMT +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Content-Language: en-US
To: fgalthier.repadmin@gmail.com
From: Antoine Dupont <adupont.rep@gmail.com>
Subject: Recovery file for password manager
This is a multi-part message in MIME format.
--------------XJLZoYn0bXsIJ4JsrDDa7k5Y
Content-Type: text/plain; charset=UTF-8; format=flowed
Content-Transfer-Encoding: 7bit
Hey Fabien,
Here is the recovery file for my keepass db. For good measure I've 
ciphered it using open ssl with aes cbc 256 and 2048 iterations. I'll 
come to your desk to tell you the password, which I'll store securely in 
the db.
Cheers
Antoine
--------------XJLZoYn0bXsIJ4JsrDDa7k5Y
Content-Type: application/pdf; name="savecipher.pdf"
Content-Disposition: attachment; filename="savecipher.pdf"
Content-Transfer-Encoding: base64
U2FsdGVkX1/JDDCaToEZSYAf+sRcFFcQaVGazRcrtiUf6ekqqw+YakTx7JieultS4vSf9XTQ
BRGVX6NXgYX7VZhBpg/xJNHvvdv7hR8z1i4Tjml06TGcYP7FeHKEk5/LcS43X9rF/XA/XwjD
f1E/d/VOnZBymg93rYm0NIeTIOVzuLp8nhjLmvu2A45XxdnP8UcoqKngS1yuprV05JVzmJiJ
kNWMjS9wj8lZYG7BGQxSSa13wikVCrSUD0nmR71TRSoddTkPz9dvodvc/VZsmoAUanlwj3TA
ZCwpx3GRoxTAjlXC75JgD8WmFMHkhjtKRROBGLd0Ay2sIDLZqfe70dot5iQiN8kxaus3kRbC
CuQJhIO8xi9lwxxjMnsVF3lcZ0InJKzWPoIjO0O+i7UyvDpyKJDZuXlUvEj2nNO1k4Gj3C2W
4c45tEwtrKDY11Wx2MmWmcCI7mxulj67B1Fowubl/jTtpIyozWT2wLCORjoVgbeTrWowxSAL
pX+umrbTz+N9JxalHHnBY4RWQjHisti9jjfvIvEMlGHlIztky0AzqmxBXUhba02vin7UaODR
NbHua0n34Sg8MasUySdgLAO9FZxlueMhk6NKwvQU3H79+QAW6qXMrRwZ/2Sej6VoBdTVCpIv
HiH4wwFVx/EBNTRFiuMJ0+a90s8XMM57p+N4BSeuu5BjXP2a/J50vMcUOzlYaLTjcEtzdjsb
c4Kp7MLEoHVXhpuTwDxgAoFLxEuAfUt7OXgjIMZHVYnwLuSJd/NWPQwg4olRdCuSj2g2XdqT
WP0MpvbFJ8tCGtQ+ylbj4iaNNhZACWmfk1b9rordA6mb+V/v/Jc8NAxVPJWcnYZiL1yo2H1W
uub54+Ccq6KKn+saRQ7g/C8MKHjUx/d+snejtgZ9zA9YX/ue4bGbouO/zmiInwl3x/hNnA+y
OBoR+mx+wCXKr3y/wiWsHS23ZqB1KG6KZrKnBPmAVu3EYRuB0djTMTIdgY08MOE/8awXNSdd
```

How wonderful! a pdf file base64 encoded that you can recover, and you are told exactly how it was ciphered!
And there even was a Re: to this email:
```shell
Subject: Re: Recovery file for password manager
Content-Language: en-US
From: Antoine Dupont <adupont.rep@gmail.com>
To: fgalthier.repadmin@gmail.com
[...]
I forgot to mention - my softwares are up to date as of today. 
Unless there's like a big cve or something we should be safe aha
```
Now you have a ciphered pdf, you know how it was ciphered, and there’s probably a CVE involved.

#### 2.2.2 Thunderbird - If you know where to look
Thundebird uses profile folders to store all the data for a given email profile.
http://kb.mozillazine.org/Profile_folder_-_Thunderbird
More specifically, it stores the sent emails in a data file called “Sent” and the received ones in “Inbox” in a sub-folder for the profile. With that in mind:
```shell
$ vol3 -f adupont.dmp windows.filescan > files.txt
$ cat files.txt | grep “Sent”
0xa6f04738	\Users\adupont\AppData\Roaming\Thunderbird\Profiles\sv9bcuck.default-release\Mail\pop.gmail.com\Sent	128
0xa6f04d20	\Users\adupont\AppData\Roaming\Thunderbird\Profiles\sv9bcuck.default-release\Mail\pop.gmail.com\Sent.msf	128
0xa6f07c60	\Users\adupont\AppData\Roaming\Thunderbird\Profiles\sv9bcuck.default-release\Mail\pop.gmail.com\Sent.msf	128
```
If you didn’t know that, you could still funnel your way to that file anyway by looking at all the Thunderbird files from the filescan (cat files.txt | grep “Thunderbird”), but that's much more tedious work.

This "Sent" file contains all the sent emails of the user, so you would then recover your pdf file as we did previously.

 *NB: recovering the gmail password*:
I know at least a team or two managed to find the password to the gmail account that was used. I thought that might happen but didn’t know how it was possible, so many thanks to jibe on discord who explained it to me:
> On peut dumper certains fichiers du profil Thunderbird (\Users\adupont\AppData\Roaming\Thunderbird\Profiles\sv9bcuck.default-release\logins.json et
\Users\adupont\AppData\Roaming\Thunderbird\Profiles\sv9bcuck.default-release\key4.db). On peut déchiffrer logins.json à partir des clés de key4.db, par exemple avec https://github.com/Iclevy/firepwd

For english speakers -> dump logins.json and key4db and then you can decipher logins.json using some other tools

At this point you didn’t need any more info. You could just skip to the deciphering of the pdf
## 2.3 SOLVING BY CARVING OUT THE PDF
### 2.3.1 Filescan
If you started looking for files out of the ordinary in ordinary places then you may have tried
to look at the files in the /Documents folder
```shell
$ vol3 -f adupont.dmp windows.filescan > files.txt
$ cat files.txt | grep Documents
[...]
0xa6f17a58	\Users\adupont\Documents\savecipher.pdf	128
```
“savecipher.pdf” ?? what could that be :’)
We can carve it out from the memory
```shell
$ vol3 -f adupont.dmp windows.dumpfiles --virtaddr 0xa6f17a58
```
But we can’t open it.
Taking a look at the file type you may have noticed that it was indeed ciphered (as the file
name would suggest), using openssl
```shell
$ file file.0xa6f17a58.0x9d8661b8.DataSectionObject.savecipher.pdf.dat 
file.0xa6f17a58.0x9d8661b8.DataSectionObject.savecipher.pdf.dat: openssl enc'd data with salted password
```
Now there are still multiple ways to use openssl and to cipher the file, so we’re missing some more info.

#### NB:
I know a team tried to bruteforce every single openssl cipher type (and may have succeeded?) but the simpler way was to ask yourself “how was it ciphered/what ciphered it” ?
### 2.3.2 How was it ciphered ? -> powershell cli
If you remember at the start we saw that there was a powershell process running at the time
of the dump., which is a subprocess of userinit.exe and explorer.exe -> so it most likely was started by the user.
Maybe some commands were ran ? But where to find them ?

A quick google search would give the answers
https://0xdf.gitlab.io/2018/11/08/powershell-history-file.html
>Windows stores commands in a .txt file called “ConsoleHost_history.txt” in AppData/Roaming.

Let’s go back to our filescan:
```shell
$ cat files.txt | grep "ConsoleHost_history"
0x8e6a1778	\Users\adupont\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt	128
```
Carve out the file and take a look inside
```shell
$ vol3 -f adupont.dmp windows.dumpfiles --virtaddr 0x8e6a1778
$ cat file.0x8e6a1778.0x9d9fc380.DataSectionObject.ConsoleHost_history.txt.dat 
.\tools\openssl.exe enc --aes-256-cbc --in .\save.pdf --out savecipher.pdf --iter 2048
rm .\save.pdf
rm .\save.pdf
cd .\Documents\
ls
cd .\Documents\
cat .\savecipher.pdf
ls
cd .\tools\
ls
cd ..
cat .\savecipher.pdf
cd ..
cd .\adupont\Documents\
ls
cat .\savecipher.pdf
cd .\tools\
ls
```

And now we know exactly how it was ciphered!

## 2.4 Deciphering the pdf
### 2.4.1 Running the exploit
Whichever path you took, at the end of the day you needed 3 elements:
- the savecipher.pdf file -> we have it
- how it was ciphered -> we know
- the key to the cipher -> ?

But we’re still missing the key with which it was ciphered. Most people had already figured out at this point that CVE-2023-32784 was to be used.
So let’s use it:

I used this exploit: https://github.com/dawnl3ss/CVE-2023-32784

We need to dump the keepass process memory

```shell
$ vol3 -f adupont.dmp windows.memmap --dump --pid 2896
```
Then running the exploit gives us a list of possible passwords
```shell
$ python keepass-dump-masterkey/poc.py pid.2896.dmp 
2024-05-08 23:12:53,700 [.] [main] Opened pid.2896.dmp
Possible password: ●ysuper*s4F3pwd78224DB
Possible password: ●ysuper*s4F3pwd78224DC
Possible password: ●%super*s4F3pwd78224DB
Possible password: ●%super*s4F3pwd78224DC
Possible password: ●'super*s4F3pwd78224DB
Possible password: ●'super*s4F3pwd78224DC
```
But we’re still missing the first character
### 2.4.2 Finding the right password
A few intended options at this point:
- If guessed that “mysuper*s4F3pwd…” seemed like a good candidate then
congrats you’ve just saved yourself a lot of time
- If you’re a heavy-approach kind of guy/gal, then you could bruteforce your way into
finding the right password.
Here’s a shell script I wrote to do that
```bash
#!/bin/bash

for char in {a..z} {A..Z} {0..9}
do
    result="${char}ysuper*s4F3pwd78224DB"
    echo "Trying:"$result
    cmd=$(openssl enc -d --aes-256-cbc -in file -out plzdecipher.pdf --iter 2048 --pass pass:$result 2>&1)
    if echo "$cmd" | grep -q "bad"; then
        continue
    else
        echo "Password found:"$result
	break
    fi
done
```
Run it:
```shell
$ chmod +x scriptfile
$ ./scriptfile 
Trying:aysuper*s4F3pwd78224DB
Trying:bysuper*s4F3pwd78224DB
Trying:cysuper*s4F3pwd78224DB
Trying:dysuper*s4F3pwd78224DB
Trying:eysuper*s4F3pwd78224DB
Trying:fysuper*s4F3pwd78224DB
Trying:gysuper*s4F3pwd78224DB
Trying:hysuper*s4F3pwd78224DB
Trying:iysuper*s4F3pwd78224DB
Trying:jysuper*s4F3pwd78224DB
Trying:kysuper*s4F3pwd78224DB
Trying:lysuper*s4F3pwd78224DB
Trying:mysuper*s4F3pwd78224DB
Password found:mysuper*s4F3pwd78224DB
```
We have the password, the file is unciphered 
Open it 

![emergency_sheet](https://github.com/Maksence/write-ups/blob/main/THCon2024/images/emergency_sheet.png)

And boom ! We have the master password (that’s a real sheet provided by keepass when creating a DB btw, I just wrote the password on it)

All that’s left is to enter the Database
```shell
$ kpcli 

KeePass CLI (kpcli) v4.0 is ready for operation.
Type 'help' for a description of available commands.
Type 'help <command>' for details on individual commands.

kpcli:/> open Database.kdbx 
Provide the master password: *************************
kpcli:/> cd Database/
kpcli:/Database> show -f flag 

 Path: /Database/
Title: flag
Uname: 
 Pass: THCON{p4ssw0rDS_4re_mY_favourite_things!}
  URL: 
Notes: 

kpcli:/Database> 
```


## 3. Conclusion
### TL;DR - what to remember for future challs:
- Actually read what a vulnerability does before spending hours trying to figure out why it’s not working
- Thunderbird stores emails data in profiles under ```C:\Users\<Windows username>\AppData\Roaming\Thunderbird\Profiles\<Profile name>\``` and the actual data of the Sent and Received emails are in cleartext “Sent” and “Inbox” data files
- Windows stores powershell info in ```$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt```
- You can recover a mail password from Thunderbird
- Finding a needle in a haystack is tough, luckily there were two needles in this challenge :’)
