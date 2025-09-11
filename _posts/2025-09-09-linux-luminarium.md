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

Konsep: **Absolute Path** → path yang dimulai dari root `/`.

Di Linux, semua filesystem itu start dari `/` alias **root directory**.  
Nah, di challenge ini ada sebuah program baru di root dengan nama `pwn`.  
Tugas kita simpel → jalanin aja program itu pakai **absolute path** (path lengkap dari root).

```bash
hacker@paths~the-root:~$ /pwn
BOOM!!!
Here is your flag:
pwn.college{kY9SZr5TpbOvYyMltSRxbi5gUBQ.QX4cTO0wiNxYDOyEzW}
```

---

### Challenge 2 : Program and Absolute Paths 🛣️

Kalau tadi kita jalanin program langsung dari root (`/pwn`), sekarang kita coba yang sedikit lebih panjang.  
Di dalam root (`/`) ada folder khusus buat challenge, namanya **`/challenge`**.  
Nah, di dalam folder itu ada program `run` yang harus kita eksekusi.

Karena kita diminta pakai **absolute path**, tinggal tulis aja path lengkapnya:

```bash
hacker@paths~program-and-absolute-paths:~$ /challenge/run
Correct!!!
/challenge/run is an absolute path! Here is your flag:
pwn.college{kyZRS7sOT8pVnMtvpmBlIAehzNt.QX1QTN0wiNxYDOyEzW}
hacker@paths~program-and-absolute-paths:~$
```

---

### Challenge 3 : Position Thy Self 🧭

📌 **Ilmu penting:**

- `cd` = change directory → buat pindah ke direktori tertentu.
- Prompt akan berubah sesuai direktori aktif.
- `~` di prompt artinya home directory user.

🛠️ **Contoh penggunaan:**

```bash
cd /some/path       # pindah ke direktori /some/path
cd ~                # balik ke home directory
cd ..               # naik 1 level ke parent directory
```

---

### Challenge 4 : Position Elsewhere 🌍

📌 **Ilmu penting:**

- Di Linux kita bisa **pindah direktori** pakai `cd` (**change directory**).
- Path yang kita kasih ke `cd` menentukan kita lagi “berdiri” di mana.
- Direktori aktif sekarang disebut **current working directory**.
- Prompt bakal ikut berubah sesuai lokasi kita.
- Tanda `~` di prompt itu shortcut buat **home directory**.

🛠️ **Command utama:**

```bash
cd /some/new/directory   # pindah ke direktori tertentu
pwd                      # cek lokasi sekarang
/challenge/run           # jalankan program setelah pindah
```

---

### Challenge 5 : Position Yet Elsewhere 🗂️

**Ilmu Penting**

- Kita bisa **pindah directory** di Linux pakai command `cd <path>`.
- `cd` akan mengubah **current working directory** dari shell kita.
- Di prompt, simbol `~` menunjukkan bahwa kita sedang ada di **home directory**.
- Kalau sudah pindah directory, kita bisa jalankan program dari lokasi baru sesuai instruksi challenge.

**Contoh Command**

```bash
# pindah ke direktori tertentu
cd /some/new/directory

# cek lokasi kita sekarang di prompt
hacker@dojo:/some/new/directory$
```

Jadi intinya di challenge ini, kita diminta untuk `cd` ke path tertentu dulu, baru jalankan program `/challenge/run` dari sana.
