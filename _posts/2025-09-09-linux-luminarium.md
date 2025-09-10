---
title: "[pwn.college] - Linux Luminarium"
date: 2025-09-09 17:00:00 +0700
categories: [Linux]
tags: [linux, pwn.college, notes]
---

Bismillah,

⚡ **Disclaimer:**  
Sebelumnya saya sudah pernah menyelesaikan dan mendapatkan badge **Linux Luminarium** dari [pwn.college](https://pwn.college).  
Namun waktu itu saya **tidak membuat catatan** sama sekali 😅.  
Kali ini saya memutuskan untuk **mengulang dari awal** sambil mencatat semua hal yang saya pelajari, supaya bisa jadi dokumentasi pribadi.

---

# 🐧 Module: Hello Hackers

## 📌 Deskripsi Module 1

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

---

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

---

### Challenge 2 : Intro to Arguments 🦾

Sekarang kita coba sesuatu yang sedikit lebih rumit: **command dengan arguments**.  
Arguments adalah data tambahan yang kita kasih ke command. Saat kita ngetik perintah lalu tekan `Enter`, shell akan memecah input kita menjadi **command** dan **arguments**.

- Kata pertama → command.
- Kata-kata setelahnya → arguments.

Contoh:

```bash
hacker@dojo:~$ echo Hello
Hello
hacker@dojo:~$
```

Pada contoh di atas command-nya adalah echo, dan argument-nya adalah Hello.
Command echo itu simpel → dia cuma mengulang (print) argument yang kita kasih ke terminal.

Untuk challenge ini, agar mendapatkan flag kita perlu menjalankan `hello` sebagai command dan `hackers` sebagai argument.

```bash
hacker@hello~intro-to-arguments:~$ hello hackers
Success! Here is your flag:
pwn.college{QmRWs0ue6W-EqxbFJNR6KnaMGGb.QX4YjM1wiNxYDOyEzW}
hacker@hello~intro-to-arguments:~$
```

Kita berhasil mendapatkan flag-nya.

---

### Challenge 3 : Command History 🎩

Kalau kita belajar Linux, kita bakal sering banget ngetik command. Kadang capek juga kalau harus ngetik ulang dari nol terus. Untungnya, shell punya fitur **command history** yang nyimpen semua command yang pernah kita jalanin.

Cara pakainya gampang:

- Tekan **panah atas (↑)** → buat lihat command sebelumnya.
- Tekan **panah bawah (↓)** → buat maju lagi ke command yang lebih baru.

Di challenge ini, flag akan **disuntikkan langsung ke dalam history** kita.  
Jadi tinggal buka terminal, tekan tombol panah atas, dan ambil flag yang udah ada di sana.

```bash
hacker@hello~command-history:~$ the flag is pwn.college{EAaCowH0UL2HehR98iJPGVmj1B3.0lNzEzNxwiNxYDOyEzW}
```

⚡ Note:  
Di challenge lain, history ini bakal berisi command yang udah kita ketik sendiri. Jadi kalau mau jalanin command mirip, kita nggak perlu ketik ulang → cukup scroll pake tombol panah.

---

---

# ⬇️ Next Module ⬇️

---

---

Lanjut lagi perjalanan kita di **Linux Luminarium**. Kali ini kita masuk ke module kedua yaitu _Pondering Paths_.  
Di sini kita bakal belajar dasar-dasar tentang **file paths di Linux**.

# 🐧 Module: Pondering Paths

## 📌 Deskripsi Module 2

Linux filesystem itu bentuknya kayak pohon 🌳.

- Paling atas ada **root directory** → ditulis dengan `/`.
- Di bawah root, ada banyak **directory** (folder) dan **file**.
- Untuk nyari file/direktori, kita pakai yang namanya **path**.

Ciri khas path di Linux:

- Path yang dimulai dari `/` berarti mulai dari root.
- Setiap “cabang” atau “folder” dipisahkan dengan `/`.

Contoh:  
`/home/hacker/file.txt` → artinya: dari root (`/`), masuk ke `home`, lalu `hacker`, lalu file `file.txt`.

---

### Challenges 1 : The Root 🫚
