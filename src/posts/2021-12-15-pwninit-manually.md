---
title: pwninitによるglibcとldの調整を手動でする
date: 2021-12-15
draft: false
---

CTFのpwn問では特定のバージョンのglibcが与えられることがあり、この場合glibcだけでなくリンカのバージョンも揃える必要がある。

Rust製の[pwninit](https://github.com/io12/pwninit)というツールがあり、`libc.so.6`と問題の`ELF`ファイルを用意すれば該当するバージョンの`deb`パッケージをダウンロードして[patchelf](https://github.com/NixOS/patchelf)でリンカなどの調整もしてくれる。

`pwninit`の挙動が気になったのでソースコードをざっと読みつつ、`deb`パッケージのダウンロード、`patchelf`による`libc.so.6`と`ld`の適用を手動で行った。

## 検証用の環境構築

```
$ docker run -it ubuntu:20.04 /bin/bash
# apt-get update
# apt-get upgrade
# apt-get install -y wget binutils xz-utils file
# cd ~
# mkdir workdir
# cd workdir
# pwd
/root/workdir
```

## picoCTF 'Chache Me Outside'

picoCTFの[Cache Me Outside](https://play.picoctf.org/practice/challenge/146?category=6&page=1)では問題のバイナリと同時に`libc.so.6`が渡される。

```
# wget https://mercury.picoctf.net/static/482492895851479e0da770f2892e2677/heapedit \
    https://mercury.picoctf.net/static/482492895851479e0da770f2892e2677/Makefile \
    https://mercury.picoctf.net/static/482492895851479e0da770f2892e2677/libc.so.6
# echo -n flag > flag.txt
# ls -l
total 2004
-rw-r--r-- 1 root root     114 Mar 16  2021 Makefile
-rw-r--r-- 1 root root       4 Dec 14 13:03 flag.txt
-rwxr-xr-x 1 root root    8760 Mar 16  2021 heapedit
-rwxr-xr-x 1 root root 2030544 Mar 15  2021 libc.so.6
```

```
# chmod +x ./heapedit ./libc.so.6
# file ./heapedit
./heapedit: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter ./ld-2.27.so, for GNU/Linux 3.2.0, BuildID[sha1]=6967c296c25feb50c480b4edb5c56c234bb30392, not stripped
# ./heapedit
Segmentation fault (core dumped)
```

```
# LD_TRACE_LOADED_OBJECTS=1 ./heapedit
    linux-vdso.so.1 (0x00007ffffdf60000)
    libc.so.6 => ./libc.so.6 (0x00007f6984d20000)
    /lib64/ld-linux-x86-64.so.2 (0x00007f6985113000)
```

```
# file ./libc.so.6 
./libc.so.6: ELF 64-bit LSB shared object, x86-64, version 1 (GNU/Linux), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=d3cf764b2f97ac3efe366ddd07ad902fb6928fd7, for GNU/Linux 3.2.0, stripped
```

```
# file /lib64/ld-linux-x86-64.so.2 
/lib64/ld-linux-x86-64.so.2: symbolic link to /lib/x86_64-linux-gnu/ld-2.31.so
# file /lib/x86_64-linux-gnu/ld-2.31.so 
/lib/x86_64-linux-gnu/ld-2.31.so: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, BuildID[sha1]=5374b5558386b815e69cc1838a6052cc9b4746f3, stripped
```

```
# apt-cache policy libc6
libc6:
  Installed: 2.31-0ubuntu9.2
  Candidate: 2.31-0ubuntu9.2
  Version table:
 *** 2.31-0ubuntu9.2 500
        500 http://archive.ubuntu.com/ubuntu focal-updates/main amd64 Packages
        100 /var/lib/dpkg/status
     2.31-0ubuntu9 500
        500 http://archive.ubuntu.com/ubuntu focal/main amd64 Packages
```

ライブラリは配布されたバイナリを参照しているが、一方で`ld`は`/lib64/ld-linux-x64-64.so.2`を参照している。そのため適切な`ld`を入手して変更する必要がある。


## バイナリを探す

`libc.so.6`を実行した際、一行目に表示されるのが`deb`パッケージのバージョンになる(今回では`2.27-3ubuntu1.2`)。パッケージの命名規約は[Debian Policy Manual](https://www.debian.org/doc/debian-policy/ch-controlfields.html#version)にある。

```
# ./libc.so.6
GNU C Library (Ubuntu GLIBC 2.27-3ubuntu1.2) stable release version 2.27.
Copyright (C) 2018 Free Software Foundation, Inc.
This is free software; see the source for copying conditions.
There is NO warranty; not even for MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE.
Compiled by GNU CC version 7.5.0.
libc ABIs: UNIQUE IFUNC
For bug reporting instructions, please see:
<https://bugs.launchpad.net/ubuntu/+source/glibc/+bugs>.
```

ダウンロードするために以下を入力。

```
# wget http://archive.ubuntu.com/ubuntu/pool/main/g/glibc/libc6_2.27-3ubuntu1.2_amd64.deb
```

`pwninit`では下記のURLを使っている。

```
# wget https://launchpad.net/ubuntu/+archive/primary/+files/libc6_2.27-3ubuntu1.2_amd64.deb
```

`dpkg -c`でパッケージの中身を見ると目的のファイルである`./lib/x86_64-linux-gnu/ld-2.27.so`が見つかる。

```
# dpkg -c libc6_2.27-3ubuntu1.2_amd64.deb | grep ld-2.27
-rwxr-xr-x root/root    170960 2020-06-04 17:25 ./lib/x86_64-linux-gnu/ld-2.27.so
lrwxrwxrwx root/root         0 2020-06-04 17:25 ./lib/x86_64-linux-gnu/ld-linux-x86-64.so.2 -> ld-2.27.so
lrwxrwxrwx root/root         0 2020-06-04 17:25 ./lib64/ld-linux-x86-64.so.2 -> /lib/x86_64-linux-gnu/ld-2.27.so
```

```
# ar -xv ./libc6_2.27-3ubuntu1.2_amd64.deb data.tar.xz
# tar -xvf ./data.tar.xz ./lib/x86_64-linux-gnu/ld-2.27.so
# mv ./lib/x86_64-linux-gnu/ld-2.27.so ./
# rm -rf ./lib ./data.tar.xz ./libc6_2.27-3ubuntu1.2_amd64.deb
# ls -l
total 2172
-rw-r--r-- 1 root root     114 Mar 16  2021 Makefile
-rw-r--r-- 1 root root       4 Dec 14 13:03 flag.txt
-rwxr-xr-x 1 root root    8760 Mar 16  2021 heapedit*
-rwxr-xr-x 1 root root  170960 Jun  4  2020 ld-2.27.so*
-rwxr-xr-x 1 root root 2030544 Mar 15  2021 libc.so.6*
```

これで`libc.so.6`と`ld-2.27.so`が揃った。

## patchelf

ソースコードをダウンロードしてビルドする。

```
# apt-get install -y gcc g++ build-essential autoconf cmake
# wget https://github.com/NixOS/patchelf/archive/refs/tags/0.14.3.tar.gz
# tar -zxvf 0.14.3.tar.gz
# cd patchelf-0.14.3
# ./bootstrap.sh
# ./configure
# make
# make install
# rm -rf 0.14.3.tar.gz patchelf-0.14.3/
# patchelf --version
patchelf 0.14.3
```

最後に`RPATH`とinterpreterを設定すれば問題のバイナリが動くようになる。

```
# cd /root/workdir
# patchelf --set-rpath /root/workdir/ --set-interpreter ./ld-2.27.so ./heapedit 
# LD_TRACE_LOADED_OBJECTS=1 ./heapedit 
        linux-vdso.so.1 (0x00007ffe6db84000)
        libc.so.6 => /root/workdir/libc.so.6 (0x00007fd480a74000)
        ./ld-2.27.so (0x00007fd480e65000)
# ./heapedit
You may edit one byte in the program.
Address: aaa
Value: t help you: this is a random string.
```

`pwninit`は他にもstripされている`libc.so.6`に[elfutils](https://sourceware.org/elfutils/)でデバッグ情報を付与したりと機能が豊富なので便利。

## 参考
- [io12/pwninit](https://github.com/io12/pwninit)
- [NixOS/patchelf](https://github.com/NixOS/patchelf)
- [An Introduction To Tcache Heap Exploits](https://featureenvy.com/blog/an-introduction-to-tcache-heap-exploits/)
- [Why does `ldd` and `(gdb) info sharedlibrary` show a different library base address?](https://reverseengineering.stackexchange.com/questions/6657/why-does-ldd-and-gdb-info-sharedlibrary-show-a-different-library-base-addr)
