---
title: "[Linux Luminarium] - Pondering Paths"
date: 2025-09-10 10:00:00 +0700
categories: [Linux]
tags: [linux, pwn.college, notes]
---

Bismillah,

Halo hackers! 👋  
Lanjut lagi perjalanan kita di **Linux Luminarium**. Kali ini kita masuk ke module kedua yaitu _Pondering Paths_.  
Di sini kita bakal belajar dasar-dasar tentang **file paths di Linux**.

# 🐧 Module: Pondering Paths

## 📌 Deskripsi Module

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

### Challenges 1 : The Root **/**
