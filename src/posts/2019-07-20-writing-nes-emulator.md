---
title: ファミコンエミュレータを書こうとするも挫折しかけている話
date: 2019-07-20
draft: false
---

![dk on my emu](/img/2019-07-20-writing-nes-emulator/dk.gif "dk on my emu")

[リポジトリはここ](https://github.com/jueve/iris)

ファミコン(NES)エミュレータをScalaで書いている。音なしでごく一部のゲームが動くまで4ヶ月かかっている。
事前に低レイヤ関係の勉強もしたのでそれも含めれば8ヵ月ほどになる。本来こんなにかからないはず。

## 動機
「低レイヤを通じてプログラムや情報工学の基礎部分を知りたい」となったのがきっかけ。
さらに当時Scalaを勉強していて、Scalaを書く上でのノウハウと低レイヤの知識を同時に学ぶことができる成果物を求めてたどり着いたのがエミュレータだった。
すでにGitHub上にNESエミュレータのリポジトリが多数あることも実行の決め手となった。

## 事前勉強
2018年の11月上旬から2019年の3月上旬まで以下の本を読んだ。関係ないところを読み飛ばしたり、実技に挑戦するも挫折したりと達成度はいずれも中途半端。学習できた範囲はごくごく表面的なことだと思う。

### 内田公太, 上川大介 自作エミュレータで学ぶx86アーキテクチャ
x86アーキテクチャで32bitのCPUエミュレータを作ってみようという内容。ファミコンエミュレータでのCPU実装時にこの本で得た知見がかなり生かされた。コードがC言語で書かれている。少し触った程度で自信がなかったが、内容が比較的優しくてついていけた点も良かった。およそ200pとかなり短めだが説明が時折駆け足に感じた部分がある。3週間ほどで読了。

### Sarah L. Harris, David Money Harris他 ディジタル回路設計とコンピュータアーキテクチャ 第2版
10進数を2進数へ変換する内容から学習して簡単な論理回路を描き、最終的にFPGAを使ってMIPS32のアーキテクチャのCPUを実装する内容。コンピュータサイエンスのバックグラウンドがない自分でもどうにか読み進められた。ただ今回FPGAの学習は目標ではないので実装など関係ないところは飛ばした(主に4章と8章)。2ヵ月半。FPGAの実技など含めると半年以上かかると思う。

### 渡波郁 CPUの創りかた
上記の本を先に読んでしまったため、おさらいの感覚が強かった。TD4は作らず、1週間ほどで読了。2万円ほどでパーツが手に入るのと電子工作では単純な部類らしいのでいつかやりたい。

### Noam Nisan, Shimon Schocken他 コンピュータシステムの理論と実装
論理回路のNANDからNOT、AND、XORなどを作っていってCPUを完成させ、アセンブラとVM変換器を実装したらコンパイラとOSも作ろうという内容。12章のコンパイラで挫折した。11章の構文解析はまではどうにかなったがそこから自分が困っていることが具体的に分析できず本を閉じてしまった。挫折の時点で1ヵ月以上経過していた。


## 実装
3月の半ばからNESエミュレータの実装に入った。まずはNES研究室の`sample1.nes`でHello Worldを表示することを最初の目標に掲げた。

また、NESはハードの制約上画面描画などに限界があったりするのでゲームによってはカートリッジ側で基盤を拡張している。ドラクエのセーブ機能やゼルダの伝説で実現される上下方向のスクロールはその例で、このカートリッジの機能や構成はMapperと呼ばれている。

多くのゲームに対応するには多くのMapperを実装する必要があるがそんな気力はなく、任天堂の初期のゲームのみが動くMapper 0だけに対応している。今回の`sample1.nes`もこのMapperになる。

手順は以下の通り
1. 6502アセンブリの勉強
2. CPUの実装
3. メモリの実装
4. iNESヘッダ読み込みの実装
5. PPUのBackground処理を実装
6. GUIを実装
7. コントローラーを実装
8. `sample1.nes`のプログラムでHello Worldを表示する
9. CPUテストプログラムの`nestest.nes`を動かす
10. PPUのSprite処理を実装
11. スクロールしないゲームを動かす
12. スクロールするゲームを動かす

資料は以下の通り

### Nesdev Wiki
[Link](http://wiki.nesdev.com/w/index.php/Nesdev_Wiki)

NESの仕様を把握するために一番参考にしたページ。知りたいことはほとんどここで理解できた。

### NES研究室
[Link](http://hp.vector.co.jp/authors/VA042397/nes/index.html)

NESの仕様にざっくりと触れている。sample1.nesはこのサイトから取得。いきなりNesdev Wikiを読むよりもまずはここで概観を把握するといいと思う。

### 6502マシン語ゲームプログラミング
[Link](https://github.com/suzukiplan/mgp-fc)

6502のプログラミングとNESの仕様両方に触れたページ。NES研究室にはないPPUのOAMや画面のオーバースキャンなどの説明がある。ラスタースクロールについてはこちらの方がわかりやすかった。このリポジトリの作者はNESゲームを2本をアセンブリで書き上げていて、自分はエミュレータを書く際にそのソースコードをほんの少しだけ読んだりもしていた。

### Writing your own NES emulator - overview
[Link](https://yizhang82.dev/nes-emu-overview)

上記の実装の順番はここを参考にしている。ここの著者はC++で音以外を一週間半で書き上げている。

### Easy 6502
[Link](https://skilldrick.github.io/easy6502/)

CPUの実装で必要。アセンブリを記述しながらメモリやレジスタの値が確認できるのでアドレッシングモードの種類や分岐命令の挙動などがここで分かる。

### Instruction Reference
[Link](http://www.obelisk.me.uk/6502/reference.html)

6502の命令セット。各命令に作用するフラグの種類やサイクル数などの記述がある。

### 6502 Undocumented Opcodes
[Link](http://nesdev.com/undocumented_opcodes.txt)

6502の非公式命令セット。後述する`nestest.nes`は非公式命令の一部を実装しないとテストが通らないため必要。

### ファミコンエミュレータの創り方 - Hello, World!編 - - Qiita
[Link](https://qiita.com/bokuweb/items/1575337bef44ae82f4d3)

Background処理で参考になる。ここも概観を掴むのには良いなと思った。

## 苦戦

データの流れ方が分からないと実装のしようがないため、とにかくNesdev Wikiを読み漁った。実装する時間よりもドキュメントを読んでる時間の方がはるかに長かったように思う。

GitHubに上がっているエミュレータも何度も読んだ。JavaとGoで書かれたもので、どちらの言語も書いたことがなかったがNES側の仕様が分かっていると何がしたいのかがなんとなく分かることが興味深かった。

* [halfnes](https://github.com/andrew-hoffman/halfnes) Java製
* [nes](https://github.com/fogleman/nes) Go製

そして実装から2ヶ月後、`sample1.nes`でHello Worldが表示される。

![hello world](/img/2019-07-20-writing-nes-emulator/hello-world.png "hello world")

実は`sample1.nes`はCPUとPPUを適当に実装しても動いてしまう。そして両方ともおざなりにしてしまうと描画でバグが発生した際にどちらに原因があるのかを特定するのが本当につらい。

このため、まずはCPUを完成させることにした。Nesdev WikiのこのページからCPUのテストROMである`nestest.nes`を取得して動かす。

![nestest](/img/2019-07-20-writing-nes-emulator/nestest.png "nestest")

余談だが、CPUには割り込みのうち、NMIを実装しないとテストを選択するアイコン(上の画像左側にあるアスタリスクのマーク)が表示されない。そこに気づかなかったため1週間くらい進捗がなかった。

## 起動

ここまでくると画面描画の原因のほとんどはPPUだけになる。スプライト処理を実装するとゲーム上でスクロールがない「ドンキーコング」が起動する。

![dk with bug](/img/2019-07-20-writing-nes-emulator/dk-with-bug.png "dk with bug")

ROMの吸い出し機とカートリッジはAmazonで購入。吸い出しのアプリ起動にはWindowsが必要だった。

![rom](/img/2019-07-20-writing-nes-emulator/rom.jpg "rom")

そして画像のようにゲームが正常に描画された。

![dk without bug](/img/2019-07-20-writing-nes-emulator/dk-without-bug.png "dk without bug")

## 課題
ここまではまだどうにかなったがここから作業が止まる。課題は2つ。

1つ目がFPS。60必要なのだが、ドンキーコングが初めて動いた時点5しか出てなかった。不要な処理を省いたりして55くらいまで持ってくることはできたがまだ足りないので頑張る必要がある。そして全然安定しないので処理を軽くする必要がある。

2つ目がスクロール。下は横スクロール処理が必要な「スーパーマリオブラザーズ」。ゲーム起動直後になぜか勝手にスクロールする。

![mario with bug](/img/2019-07-20-writing-nes-emulator/super-mario-bros-with-bug.gif "mario with bug")

この2つをクリアすればどうにか最低限の要素は完成するけど、バグを探すのが大変すぎて正直つらい。