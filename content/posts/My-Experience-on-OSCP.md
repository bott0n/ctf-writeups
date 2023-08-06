---
title: "My Experience on OSCP"
date: 2023-07-31T18:26:56+08:00
toc: true
draft: false
description: "A blog post about my experience on OSCP."
---

# Introduction

This is a blog post about my perosnal experience and sharing on OSCP Exam. I am currently a 21 y/o student. I started the OSCP labs during my second semester of my fourth year at university and passed the OSCP exam during the summer semester. I will share about my preparation and the things that I learned in this post. Please note that the content may not be suitable for all viewers, depending on the different backgrounds, knowledge, or situations.

# My Background

Before starting OSCP, I had two years of experience playing CTFs. Although I am not a highly skilled or experienced player and primarily focus on pwn challenges, I have a limited knowledge of cybersecurity and coding. This foundational knowledge has given me an rough understanding of how a server works, at least in the context of a simple web server, as well as basic usage of the Linux operating system.

Beside, I passed the CRTP in Oct. 2022, it has given me the elementary idea of Active Direcotry.

# Perparation

## Labs and exercises
I started the labs and exercises in Jan., the 3 month period is completed overlaied with my 2nd semester schedule. As this is my last semster in the university, I have a huge workload on academy stuffs (Final year project, assignments, quiz and exam, etc...). Therefore, I only played the labs and exercices for 1 month. I pwned around 39 machines and 80% or above progress on exercises in order to gain the 10 bonus point. To be honest, around 40% machines to be pwned are with the hints from discord server or forum. Mst of stucking are bacuase my enumeration is not enough, only a bit is because my lacking knowledege or guessy stuffs.

## Hackthebox
After the end of the labs, I turned to learn at hackthebox. At the beginning, I simply play with the active machine and watching ippsec video becuase I am frustrated on my various academy deadlines. I spent one machine per day on watching ippsec video or 0xdf blog writeup according to the TJnull's OSCP liked hackthebox list.

OSCP liked hackthebox: https://docs.google.com/spreadsheets/u/1/d/1dwSMIAPIam0PuRBkCiDI88pU3yzrqqHkDtBngUHNCw8/htmlview#

Untill a short break after the end of the semster. I decided to do these machines manually. I asked @Mystiz to buy me the hackthebox gift card (whcih is the prize of hkcertctf 2023 writeup competition) to become VIP to play the retired machine. I spent a month to play around on it and I realized my weekness is windows related machine and most of them are standalone machine. I moved to hackthebox active directory track. I didn't complete all of machines in the track but I still learn a lot about active directory.

## Days before the exam
In the days leading up to the exam, it is very important to ensure that all of your tools and scripts are properly prepared. It can be both avoidable and time-wasting to have to fix your tools in the exam environment. In view of that, I tested all tools and ensure all of them are worked properly and take a snapshot of the VM. Also, I even downloaded a brand new kali vmware as the backups VM. Since the preparation is finished, I am still seeking plenty of the oscp blogs, cheatsheet or hackthebox writeups in the internet for refreshing my knowledge or avoid any knowledge that I have missed.

# Exam
After finished the instruction of [Proctoring Tool Manual](https://help.offsec.com/hc/en-us/articles/360050299352). I started the exam. At first, I started the enumeration on all ip that I have received. Then I decieded to start with the AD set. In the first hour, I gained the administrator on the first machine and then stucking on the laterval movement. I moved my focus to other standalone machine. 

Luckily, I rooted 2 standlone machines in 30 minutues and spent a hour on the last machine but still cannot getting the inital access. I gained 40+10 points at that time and there is two path left to pass the exam: 

(1) Complete the AD machines set
(2) Root the last standalone machine

I turned back to AD set and started to check which steps or information that I missed. I felt extremtly lost and frustrated because I throught I was already tried everythings. 4 hours later, fortunately, I found a important information that I just ignored before. Finally, I compeleted the AD machines set after 30 minutes.

When submitted the flag of last AD machine, I knew I has already passed the exam with 80+10 points. I chilled out and took a 3 hour break for dinner, shower and taking a nap. Backing front of the computer, I didn't start to try the last machine. I spent a hour on recording every steps in details and taking every snapshots that I properly needed in the report.

I returned to the last machine and spent 4 hours on it. I still have no idea and 0 new progess on the inital access. (Please forgive me for not try harder on it) Finally, I ended the exam sessions in 12 hours and finished the report and uploaded it with 3 hours.

After 5 days, I recevied the OSCP certificate.

# Lessons I Learned
Through this experience, I learned some lessons to help improve my skills.

## Understand Every Command You Type
It's not necessary to read the source code of every command you use, but having a rough idea of why you are using a particular command, what it does, what services are involved, and the expected result. This approach helped me to understand the attack flows instead of just copying and pasting commands without knowing what was happening.

## Create Your Own Cheatsheet/Notes/Mindset Map
Whenever I learned a new tool, command, or trick, I added it to my own notes. This helped me to remember the different tools I had used and to use them again in similar situations. It also had a positive impact on my understanding of the enumeration or attack flow on various services or operating systems.

## Don't Be Afraid to Read Writeups or Seek Help
When I was working on machines in the OSCP labs or on HackTheBox, if I felt like I had tried every method I knew and wasn't making any progress, I would read writeups or seek for hints without hesitation. Sometimes, it maybe required a technique that I hadn't learned yet. It's better to learn from writeups directly instead of wasting a lot of time on guessing.
This article also mentioned it:

https://www.hackthebox.com/blog/It-is-Okay-to-Use-Writeups

<!--more-->
