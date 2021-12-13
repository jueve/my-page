---
title: pwnの問題で配布されたバイナリとリンカの整合性を取る
date: 2021-12-21
draft: true
---

CTFのpwn問を解こうとすると古いバージョンのglibcを使っていることがある。ELFのバイナリは実行時に`/usr/lib`