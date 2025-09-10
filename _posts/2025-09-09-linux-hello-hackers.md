---
title: "[Linux Luminarium] - Hello Hackers"
date: 2025-09-09 17:00:00 +0700
categories: [Linux, Pwn.College]
tags: [linux, pwn.college, notes]
---

Bismillah, kali ini saya mau coba pelajari dan catat materi dari pwn.college, dojo **Linux Luminarium** module **Hello Hackers**

# 🐧 Module: Hello Hackers

## 📌 Deskripsi Module

Module ini adalah awal dari **Linux Luminarium** di [pwn.college](https://pwn.college).  
Tujuannya: mengenalkan **command line interface (CLI)**, apa itu **prompt**, dan gimana cara menjalankan command dasar.

Command line itu tempat kita bisa ngetik perintah untuk dijalankan sistem.  
Pas buka terminal, biasanya kita ketemu yang namanya **prompt**, contohnya:

```text
hacker@dojo:~$
```

Prompt ini punya arti:

- **hacker** → username user yang lagi login (default di pwn.college).
- **dojo** → nama mesin (hostname).
- **~** → posisi direktori saat ini (home directory).
- **$** → tanda user biasa (kalau root biasanya `#`).

Sederhananya, prompt ini kayak "alamat" + "status" kita sebelum jalanin command.
Setelah itu, terminal tinggal nunggu kita masukin perintah.

### Challenge 1 : Intro to Commands 🧟

Pada challenge ini kita diminta untuk menjalankan command pertama kita,
Caranya : ketik command lalu tekan `Enter`, maka command akan dijalankan

contoh

```bash
hacker@dojo:~$ whoami
hacker
hacker@dojo:~$
```

Untuk challenge ini, kita diminta menjalankan `hello` untuk mendapatkan Flag. Oh ya, perlu diingat command di linux itu case sensitive jadi kalo kita run `HELLO` maka itu adalah command yang berbeda.

```bash
hacker@dojo:~$ hello
Success! Here is your flag:
pwn.college{kLuAqWuYx-I8hWkv_Wo5FunqeUT.QX3YjM1wiNxYDOyEzW}
```

Boom! kita berhasil mendapatkan Flag-nya.
