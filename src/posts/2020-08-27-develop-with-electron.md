---
title: Electornでアプリを作るために
date: 2020-08-27
---

Electronでアプリを作ろうとリリースまで2ヶ月近く、さんざん苦しんだ。同じ過ちを繰り返さまいとメモを残すことを決意。これはElectron + TypeScript + React + SQLite + Knex + webpackでアプリ制作に取り組んだときの記録。
[作ったもの](https://github.com/jueve/atcoder-review)

## Electron基本概念
* JavaScriptとHTML、そしてCSSでクロスプラットフォームのデスクトップアプリケーションが作れるフレームワーク
* Electronでできたアプリは2種類のプロセスから成る。アプリのエントリーポイントとなり、OSに近い存在である1つのmain processと、ブラウザのレンダリング部分を担う1つ以上のrenderer process
* プロセスの名称は違えどElectronのベースとなるChromiumがこのアーキテクチャを採用しているのでElectron自身もこのアーキテクチャを使っているらしい
* この2種類のプロセスを連携させるには、プロセス間で通信を取る(メッセージのやり取り)をする必要がある
* [Native Node Modules](https://nodejs.org/api/addons.html)が使える(`fs`とか)

## 環境構築
最初にして最高のハマりポイント。Reactを使うので構築が複雑そうだからと[Create React App](https://create-react-app.dev/)に手を伸ばしたくなるが[SSRのCreate React AppでNative Node Modulesは使えない](https://github.com/facebook/create-react-app/issues/3074)。これは結果的にmain processのほとんどを捨ててrenderer processだけでアプリを作る状況になる。

こうなるとmain process側で呼び出す[sqlite3](https://www.npmjs.com/package/sqlite3)が使用できなくなるため、別のテンプレートを探す必要がある。しかし英語で"Electron TypeScript React"などと検索すると、各々が考えた独自テンプレートが大量に引っかかって途方に暮れるので公式の[Boilerplates and CLIs](https://www.electronjs.org/docs/tutorial/boilerplates-and-clis)などから良さげなやつを引っ張ってくる。候補に挙がったのは3つで、最終的に使用したの1番目のelectron-webpackだった。

### 1. electron-webpack
- [GitHub](https://github.com/electron-userland/electron-webpack)
- [Documentation](https://webpack.electron.build/development)

プロジェクト構成がシンプルかつTypeScriptとReactのアドオンがあり、デフォルトでwebpackを使っている。必要機能が揃っていてこれが個人的にベスト。yarnを使うことが強く推奨されているので、addした後にnode_modules内を見てみると、あらかじめ.webpack.jsファイルがいくつか用意されておりユーザー側が必要な設定がほとんど無いのも良いところ。ビルドには後述するelectron-builderを使っている。これのおかげでNode Native Modulesとの依存関係も解決できる。

今回のようにSQLiteとKnexを使う際は`custom.webpack.js`で[externals](https://webpack.js.org/configuration/externals/)を指定しなければならないので追加の`.webpack.js`ファイルが必要。

```javascript
// custom.webpack.js
module.exports = {
  externals: {
    sqlite3: "commonjs sqlite3",
    knex: "commonjs knex",
  },
}
```

```json
// package.json
// どの`.webpack.js`ファイルを使うか知らせる必要がある
{
  ...,
  "electronWebpack": {
    "main": {
      "webpackConfig": "./custom.webpack.js"
    },
    "renderer": {
      "webpackConfig": "./custom.webpack.js"
    }
  },
}
```

### 2. Electron Forge
- [GitHub](https://github.com/electron-userland/electron-forge) 
- [Documentation](https://www.electronforge.io/)


一時期、というかビルドする直前までこれを使って開発していた。yarnで取り込んですぐに開発ができるので便利。これ単体でビルドができwebpackとTypeScriptのサポートがある。`.webpack.js`ファイルもmain process用とrenderer process用で分かれていて管理しやすく、localhost上でも上手く動いていたのに**Native Node Modulesと一緒にビルドすると実行ファイルにはなったけど動かない。**調べてみると[Electron ForgeがNative Node Modulesの依存解決をうまくできないみたいなissueが立っていて](https://github.com/electron-userland/electron-forge/issues/1224)諦めて1のelectron-webpackに乗り換えた。使っているユーザーが多いらしいが検索しても意外とそれらしいページがヒットせず苦しんだことや、ホットリロードが効かないことも影響している。

乗り換えた後で知ったが上記のissueの数年後に[解決策](https://github.com/electron-userland/electron-forge/issues/575)が出たよう。自分の手元で試していないので上手くいくかはわからない。

### 3. electron-react-boilerplate
- [GitHub](https://github.com/electron-react-boilerplate/electron-react-boilerplate)

Electron、React、Redux、 React Router、webpack、React Hot Loaderが全部乗った状態のテンプレートで、さらにelectron-builderを使って各OSごとでビルドできるようにしてくれている。しかしReduxを使う予定がなかったことに加え、ボイラープレートの名に恥じず(?)[package.jsonの記述量があまりにも膨大](https://github.com/electron-react-boilerplate/electron-react-boilerplate/blob/master/package.json)なことから断念。何かしらのバグが起きた時にこれらを全て解読して解決できる自信がなかった。

## ビルド
便宜上、開発の途中経過となる雑感を飛ばして先にこちらに言及する。

electron-webpackはビルドに[electron-builder](https://www.electron.build/)を採用している。使い方が意外とシンプルでOSごとに適用したいビルドの設定をpackage.jsonに記していけばいい。さらに`electron-builder install-app-deps`と叩けばsqlite3などNative Node Modulesの依存解決をしてくれる。これらのおかげでビルドの手間がかなり省けた。(electron-builderというよりも[electron-rebuild](https://www.electronjs.org/docs/tutorial/using-native-node-modules#installing-modules-and-rebuilding-for-electron)のおかげかもしれない)

余談だがアイコンの生成には[electron-icon-maker](https://www.npmjs.com/package/electron-icon-maker)が便利。windowsはビルドの際アイコンを用意してないと途中でエラー吐くので注意。macの場合はそもそもmac上でないと.dmgファイルを作ることができないみたいなやり取りをどこかのissueで見た。真偽不明。
## 開発途中の雑感 
まとまりがないので順不同に書く。

### process間の通信について
ElectronのAPIには

- main processのみで動くAPI
- renderer processのみで動くAPI
- main processとrenderer processの両方で動くAPI


の3種類がある。どのAPIがどれに対応しているかは[ドキュメント](https://www.electronjs.org/docs/api)を見れば分かるが使い方を理解するのに時間がかかった。例えばボタンをクリックすることで外部にHTTP/HTTPSリクエストを飛ばしてJSONを取得したいとする。このときリクエストを送るには[netモジュール](https://www.electronjs.org/docs/api/net)を使うが、netはmain process側のみで使用できるAPIなので、renderer process側のファイル(この例だとボタンが定義されている.jsxファイルや.tsxファイル)でnetをimportしても意味がない。

この場合は

1. 一度renderer process側からmain process側にメッセージを送る
2. main process側がメッセージを受け取る
3. main process側がnetモジュールを使ってリクエストを飛ばしてレスポンスを受け取った後、bodyをパースしてJSONオブジェクトに変換する
4. 今度はmain process側からrenderer process側に送り返してやる

という一連の流れが必要になる。

このさながらリクエスト/レスポンスのような体系がprocess間のやりとりの基本で、データベースのレコードの追加やログファイルへの書き込みといった処理を実装したいときはだいたいこれが関わってくる。

実装方法についてはrenderer process側で`ipcRenderer`、main process側で`ipcMain`を使う。コールバック関数を伴うので、DOMのevent linstenerのような感覚で実装できる。一度感覚を掴んでしまえば楽になるはず。async/awaitに特化したAPIもある。


```javascript
// renderer-process
// 1.ボタンをクリックしてメッセージを送信

import React, { useEffect } from "react";
import { ipcRenderer } from "electron";

function Component(): JSX.Element {
  const handleClick = () => {
    ipcRenderer.send("get-json");  // 1
  }

  useEffect(() => {
    ipcRenderer.on("succeeded", (event, res) => {
      console.log(res);
    });
  }, []);

  return(
    <button onClick={handleClick}>
      click
    </button>
  );
}
```

```javascript
// main-process
// 2. renderer-processからメッセージを受け取る
// 3. リクエストを投げてレスポンスを受け取る
// 4. renderer-processにメッセージを送り返す

import { ipcMain } from "electron";

ipcMain.on("get-json", (event) => { // 2
  const res = fetchSomethingAndParse(); // 3
  event.reply("succeeded", res); // 4
});
```

これは既にdeprecatedになっているのであまり関係ないが以前は2つのプロセスを媒介するのにremoteモジュールを使っていた。しかしElectronのメンバーによると[remoteオブジェクトはローカルのオブジェクトにアクセスするよりも10,000倍低速らしく](https://medium.com/@nornagon/electrons-remote-module-considered-harmful-70d69500f31)他にも問題点があるとのことで`ipcMain`と`ipcRenderer`の利用を呼びかけていた。

### HTTP/HTTPSリクエストを叩く
上記の例で軽く触れたがHTTP/HTTPSリクエストを叩きたいときはChromiumのネットワークライブラリを内部で使用しているnetを使ったほうが手間暇の意味で早いが、Promiseが返ってくるわけではないのでコールバック関数を書く必要があり面倒である。

HTTP/HTTPSリクエストを送りたいとなると[axios](https://github.com/axios/axios)が思い浮かんだので使ってみたがサーバー側でCORSが有効になっているためアクセスできなかった。これを回避するためにmain processでウィンドウを生成する際にwebPreferncesオブジェクトのwebSecurityプロパティをfalseにするという荒業があるが[セキュリティリスクの観点から推奨されていないので使うことはできない。](https://www.electronjs.org/docs/tutorial/security#5-do-not-disable-websecurity)結局やり方が分からずnetを使用するに至った。
