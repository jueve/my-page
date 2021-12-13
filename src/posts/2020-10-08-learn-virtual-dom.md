---
title: Snabbdomで学ぶ仮想DOMの仕組み
date: 2020-10-08
---

仮想DOMの勉強がしたくなったので[Snabbdom](https://github.com/snabbdom/snabbdom)v2.1.0のコードを読んだ。本記事はソースコード内容と仮想DOMのアルゴリズムについてまとめたものになる。

Snabbdomを選んだ理由は以下の2点。

- [仮想DOMのコア部分となるコードの量が少ない](https://github.com/snabbdom/snabbdom/blob/v2.1.0/README.md#features)
- [Vue.jsがSnabbdomのフォークを使っている](https://github.com/snabbdom/snabbdom/blob/v2.1.0/README.md#structuring-applications)

## 概要
Snabbdomの仮想DOMではHTMLの木構造をJavaScriptのオブジェクトで表現する。そして2つのオブジェクトにあるプロパティを比較しながら必要最低限のDOMのAPIを呼び出し、real DOM nodeの生成を行う。

**仮想DOM自身が速いというよりも、仮想DOMが最小限の回数でreal DOM nodeの更新をしてくれるため、コードを書く人間が闇雲にDOM APIを使ってreal DOM nodeを更新してしまうよりも相対的に速くなるという認識が正しいように思う。**

日本の仮想DOMに関する記事では、仮想DOMと区別するためにreal DOM nodeが「**実DOM**」と呼ばれたりする。本記事でもreal DOM nodeを示す際はこの言葉を使う。

## VNode
SnabbdomはTypeScriptで書かれていて、仮想DOMを表現する際`VNode`というinterfaceが使われている。

[snabbdom/src/package/vnode.ts](https://github.com/snabbdom/snabbdom/blob/v2.1.0/src/package/vnode.ts#L13-L20)

```typescript 
export interface VNode {
  sel: string | undefined
  data: VNodeData | undefined
  children: Array<VNode | string> | undefined
  elm: Node | undefined
  text: string | undefined
  key: Key | undefined
}
```

`VNode`のプロパティのうち、仮想DOMの差分検知アルゴリズムの理解に最低限必要なのは以下の5つ。

- `sel` ... 要素名が文字列として格納される。`<div>`タグなら`div`となる。
- `children` ... VNodeの子要素を`Array`で管理する。
- `elm` ... 実DOMが格納されている。
- `text` ... テキスト部分。`<p>sample</p>`の`sample`が相当する。
- `key` ... `<li>`要素など、一つの親の下に複数の同じ要素が並ぶときに指定する値。並び替え等が起こった時に必要になる。

### h関数
`VNode`を生成する手段の一つに`h`関数がある。これはHTMLの木構造をJavaScriptのオブジェクト上で表現するために使われる。

[snabbdom/src/package/h.ts](https://github.com/snabbdom/snabbdom/blob/v2.1.0/src/package/h.ts)

```html
<div>Hello World</div>
```

このHTMLを`h`関数を使って表現すると以下のようになる。

```typescript
import { h } from 'snabbdom/h';

h('div', 'Hello World');
```

`VNode`interfaceでは以下のように表現される。

```typescript
{
  sel: 'div', // 要素名
  data: {}, 
  children: undefined, // 子要素
  text: 'Hello World', // テキスト
  elm: undefined, // 実DOM
  key: undefined, // キー
}
```

またネストされた要素は以下のように表記できる。

```html
<!-- keyの表現は便宜的なもので実際の書き方はパーサーに依存する -->
<ul>
  <li key="1">1</li>  
  <li key="2">2</li>  
</ul>
```

```typescript
import { h } from 'snabbdom/h';

h('ul', [
  h('li', { key: 1 }, '1'),
  h('li', { key: 2 }, '2'),
]);
```

こちらも最終的に`VNode`interfaceで表すと以下のようになる。

```typescript
{
  sel: 'ul',
  data: {},
  elm: undefined,
  children: [
    {
      sel: 'li',
      data: {},
      elm: undefined,
      children: undefined,
      text: '1',
      key: '1',
    },
    {
      sel: 'li',
      data: {},
      elm: undefined,
      children: undefined,
      text: '2',
      key: '2',
    },
  ],
  text: undefined,
  key: undefined,
}
```

`h`の引数の型が異なるときがあるが、実際の定義でも複数をoverloadしている。

[snabbdom/src/package/h.ts](https://github.com/snabbdom/snabbdom/blob/v2.1.0/src/package/h.ts#L21-#L25)

```typescript
export function h (sel: string): VNode
export function h (sel: string, data: VNodeData | null): VNode
export function h (sel: string, children: VNodeChildren): VNode
export function h (sel: string, data: VNodeData | null, children: VNodeChildren): VNode
export function h (sel: any, b?: any, c?: any): VNode
```

### toVNode関数
`VNode`の生成には`toVNode`関数もある。これは実DOMを直接`VNode`に変換する関数になる。

[snabbdom/src/package/tovnode.ts](https://github.com/snabbdom/snabbdom/blob/v2.1.0/src/package/tovnode.ts)

```typescript
import { toVNode } from 'snabbdom/tovnode';

const div = document.createElement('div');
const p = document.createElement('p');
const text = document.createTextNode('Hello, World');

p.appendChild(text);
div.appendChild(p);

const vnode = toVNode(div);

// 以下のようなVNodeができる
// {
//   sel: 'div',
//   data: {},
//   elm: real DOM node,
//   children: [
//     {
//       sel: 'p',
//       data: {},
//       elm: real DOM node,
//       children: undefined,
//       text: 'Hello, World',
//       key: undefined,
//     },
//   ],
//   text: undefined,
//   key: undefined,
// }
```

## 差分反映を実行する関数
オブジェクトで表現した2つの木構造から差分を取り、実DOMに反映させるときは`init`関数が関わる。この`init`関数を一度呼び出して初期化した後、ポインタとして返る関数`patch`をさらに呼び出すことで差分の反映が可能になる。

[snabbdom/src/package/init.ts](https://github.com/snabbdom/snabbdom/blob/v2.1.0/src/package/init.ts#L48)

```typescript
// `init`関数の第一引数にはhooksに利用したいモジュールを配列で渡す。
// 空の配列を渡した場合、hooksが動かずに仮想DOMの差分検知アルゴリズムだけが動作する。
// 第二引数はオプションで、カスタムしたDOMのAPIを渡すことができる。
export function init (modules: Array<Partial<Module>>, domApi?: DOMAPI)
```

[snabbdom/src/package/init.ts](https://github.com/snabbdom/snabbdom/blob/v2.1.0/src/package/init.ts#L304)

```typescript
return function patch (oldVnode: VNode | Element, vnode: VNode): VNode
```

`patch`関数の戻り値の型は`VNode`である。戻り値自身が、差分反映後の実DOMの木構造をTypeScirptのinterfaceで表現していることになる。また`elm`プロパティの値には実DOMが格納されている。

```typescript
import { h } from 'snabbdom/h';
import { toVNode } from 'snabbdom/tovnode';
import { init } from 'snabbdom/init';

const patch = init([]);

const div = document.createElement('div');

const vnode1 = toVNode(div);
const vnode2 = h('p', 'Hello');
const vnode3 = h('p', 'World');

const temp = patch(vnode1, vnode2);
const result = patch(temp, vnode3);

// elmプロパティにアクセスすることで実DOMを確認することができる。
console.log(temp.elm.tagName); // 'P'
console.log(temp.elm.textContent); // 'Hello'

console.log(result.elm.tagName); // 'P'
console.log(result.elm.textContent); // 'World'

// `VNode`型を使った`result`の表現は以下のようになる
// {
//   sel: 'p',
//   data: {},
//   elm: real DOM node
//   children: undefined,
//   text: 'World',
//   key:  undefined
// }
```

`init`関数は200行ほどの実装で、その内部では上記の`patch`を含め、**`init`関数のスコープ内で**関数がいくつか定義されている。コードリーディングで深く関わってきたのは以下の6つだった。

- `addVNodes` ... 変更前のVNodeに無くて、変更後のVNodeにあるVNodeをDOM APIを利用して実DOMに追加する。
- `createElm` ... VNodeからDOM APIを利用して実DOMのNodeを生成する。
- `patch` ... 差分反映を行う際のエントリーポイントとなる関数。戻り値は`VNode`。
- `patchVNode` ... 同じ階層にある一つのVNode同士を比較してDOM APIを呼び出して実DOMに差分を反映する。
- `removeVNodes` ... 変更前のVNodeにあって、変更後のVNodeに無いVNodeをDOM APIを利用して実DOMから削除する。
- `updateChildren` ... 子要素の差分反映に利用される。`<li>`要素など、同じ親要素の下に同じ階層の子要素が複数ある場合に使われる。`key`プロパティが深く関わっている。

## 差分検知アルゴリズム
ここからは差分検知のアルゴリズムに触れたい。差分検知には**DFS(深さ優先探索)**が使われていて、子要素、孫要素…とできるだけノードを深く終端まで探っていき、その都度上記に挙げた関数のいずれかを実行する。

ここで変更前の`VNode`を`before`、変更後を`after`とする。差分検知アルゴリズムでは、`before`の`elm`プロパティ、つまり変更前の実DOMを一度`after`と[共有する](https://github.com/snabbdom/snabbdom/blob/v2.1.0/src/package/init.ts#L276)。

その後、**同じ階層のノード同士で**以下のような流れが繰り返される。

1. `before`と`after`のノード同士で`sel`プロパティや`children`プロパティなどを**JavaScriptのオブジェクトやプリミティブ値の単位で**比較する。つまり、この時点でDOM APIは呼び出していない。
2. `before`と`after`に何かしらの違いがある場合、共有した`elm`プロパティにDOM APIを適用して実DOMを更新する。

また、`before`には無いが`after`にはある要素、逆に`before`にはあったが`after`で無くなっている要素が存在する場合は、その要素の追加/削除があることを示している。

以下、プロフィールをイメージしたHTMLを使って流れを説明したい。

```html
<!-- 変更前 -->
<div>
  <p><a>Alice</a></p>
  <ul>
    <li>HTML</li>
    <li>CSS</li>
  </ul>
</div>

<!-- 変更後 -->
<!-- <a>内のテキストを変更 -->
<!-- <li>をひとつ追加 -->
<div>
  <p><a>Bob</a></p>
  <ul>
    <li>HTML</li>
    <li>CSS</li>
    <li>JavaScript</li>
  </ul>
</div>
```

これはSnabbdomで操作すると以下のようになる。

```typescript
import { init } from 'snabbdom/init';
import { h } from 'snabbdom/h';
import { toVNode } from 'snabbdom/tovnode';

const patch = init([]);

const div = toVnode(document.createElement('div'));

const vnode1 = h('div', [
  h('p', h('a', 'Alice')),
  h('ul', [
    h('li', 'HTML'), h('li', 'CSS')
  ]),
]);

const vnode2 = h('div', [
  h('p', h('a', 'Bob')),
  h('ul', [
    h('li', 'HTML'), h('li', 'CSS'), h('li', 'JavaScript')
  ]),
]);

const divToVNode1 = patch(div, vnode1);
const VNode1ToVNode2 = patch(divToVNode1, vnode2);
const elm1 = divToVNode1.elm;
const elm2 = VNode1ToVNode2.elm;

console.log(elm1.tagName); // 'DIV'

console.log(elm1.children[0].tagName); // 'P'
console.log(elm1.children[0].children[0].tagName); // 'A'
console.log(elm1.children[0].children[0].textContent); // 'Alice'

console.log(elm1.children[1].tagName); // 'UL'
console.log(elm1.children[1].children[0].tagName); // 'LI'
console.log(elm1.children[1].children[0].textContent); // 'HTML'
console.log(elm1.children[1].children[1].tagName); // LI
console.log(elm1.children[1].children[1].textContent); // 'CSS'

console.log(elm2.tagName); // 'DIV'

console.log(elm2.children[0].tagName); // 'P'
console.log(elm2.children[0].children[0].tagName); // 'A'
console.log(elm2.children[0].children[0].textContent); // 'Bob'

console.log(elm2.children[1].tagName); // 'UL'
console.log(elm2.children[1].children[0].tagName); // 'LI'
console.log(elm2.children[1].children[0].textContent); // 'HTML'
console.log(elm2.children[1].children[1].tagName); // 'LI'
console.log(elm2.children[1].children[1].textContent); // 'CSS'
console.log(elm2.children[1].children[2].tagName); // 'LI'
console.log(elm2.children[1].children[2].textContent); // 'JavaScript'
```

まずは木構造でいうと根の部分に当たる`vnode1`のdivと`vnode2`のdivを比べる。この2つの`sel`プロパティや`text`プロパティを比べても変更されている部分はない。ただ、`vnode1`と`vnode2`両方で`children`プロパティに要素があることが分かっているので下の階層に進む。


![ALT](/img/2020-10-08-learn-virtual-dom/vnode-step01.png "step 1")

次に`vnode1`と`vnode2`の直接の子要素にあるp要素を比べる。この2つも変更されている部分はない。そしてこちらも両方で子要素があることが分かっているので下の階層に進む。


![ALT](/img/2020-10-08-learn-virtual-dom/vnode-step02.png "step 2")

p要素の子要素であるa要素を比べる。`sel`プロパティは変更がないが、`text`プロパティが`'Alice'`から`'Bob'`に変更されている。このためDOM APIの`textContent`を呼び出して`elm`プロパティにある実DOMのtext node部分を`'Bob'`に更新する。


![ALT](/img/2020-10-08-learn-virtual-dom/vnode-step03.png "step 3")

左側のノードは終端まで見たので、今度はdivの子要素であるulに移る。変更が無いので、子要素を見る。


![ALT](/img/2020-10-08-learn-virtual-dom/vnode-step04.png "step 4")

li要素1つ目。変更はないので次に移る。


![ALT](/img/2020-10-08-learn-virtual-dom/vnode-step05.png "step 5")

li要素2つ目。変更はないので次に移る。


![ALT](/img/2020-10-08-learn-virtual-dom/vnode-step06.png "step 6")

li要素3つ目。`vnode1`の`children`プロパティには無い要素が`vnode2`にある。これは要素の追加を意味する。DOM APIの`createElement`や`createTextNode`でli要素を生成した後、`appendChild`で実DOMに反映する。


![ALT](/img/2020-10-08-learn-virtual-dom/vnode-step07.png "step 7")

これにより差分の反映が終了する。


![ALT](/img/2020-10-08-learn-virtual-dom/vnode-step08.png "step 8")


今回の例では、各子要素に対する直接の親要素が全て同じパターンだった。もし親要素が異なる場合、**Snabbdomは、新しい要素が生成されたと判断して新しい親要素以下の全てのノードをDOM APIを使って生成する。そして古いノードを子要素も含めて全て破棄する**。

この処理が働く箇所は2つある。

1. ノードを木構造で表現した時に根に相当する箇所
  上記の例でいうところの`div`要素が異なっていた時に該当する。この場合、差分検知アルゴリズムは働かない。
    - [ノード追加のコード](https://github.com/snabbdom/snabbdom/blob/v2.1.0/src/package/init.ts#L319)
    - [ノード削除のコード](https://github.com/snabbdom/snabbdom/blob/v2.1.0/src/package/init.ts#L321-L324)

2. 根以外の部分で親要素となっている箇所
  上記の例でいうところの`p`要素や`ul`要素が異なっていた時に該当する。差分検知アルゴリズムの中で発生する。
    - [ノード追加のコード](https://github.com/snabbdom/snabbdom/blob/v2.1.0/src/package/init.ts#L252-L253)
    - [ノード削除のコード](https://github.com/snabbdom/snabbdom/blob/v2.1.0/src/package/init.ts#L268)

## hooks
Snabbdomにはhooksもある。

### hooksの実行
hooksにはモジュール経由で使用できるものとDOM APIで実DOMを操作する際に使用するものがある。
また、hooksには実行タイミングみたいなものが定められている。

[公式ドキュメント内](https://github.com/snabbdom/snabbdom/tree/v2.1.0#overview)では10種類あるとのこと。

[snabbdom/src/package/hooks.ts](https://github.com/snabbdom/snabbdom/blob/v2.1.0/src/package/hooks.ts)では以下のように型定義されている。
```typescript
import { VNode } from './vnode'

export type PreHook = () => any
export type InitHook = (vNode: VNode) => any
export type CreateHook = (emptyVNode: VNode, vNode: VNode) => any
export type InsertHook = (vNode: VNode) => any
export type PrePatchHook = (oldVNode: VNode, vNode: VNode) => any
export type UpdateHook = (oldVNode: VNode, vNode: VNode) => any
export type PostPatchHook = (oldVNode: VNode, vNode: VNode) => any
export type DestroyHook = (vNode: VNode) => any
export type RemoveHook = (vNode: VNode, removeCallback: () => void) => any
export type PostHook = () => any

export interface Hooks {
  pre?: PreHook
  init?: InitHook
  create?: CreateHook
  insert?: InsertHook
  prepatch?: PrePatchHook
  update?: UpdateHook
  postpatch?: PostPatchHook
  destroy?: DestroyHook
  remove?: RemoveHook
  post?: PostHook
}

```

### モジュール
`init`関数で初期化を行う際、引数にモジュールを配列で渡すことでモジュールの選択ができるようになっている。例えばHTMLのclass属性に関する操作をしたい場合は`classModule`、style属性に関する操作をしたいときは`styleModule`を使って以下のように記述する。

```typescript
import { init } from 'snabbdom/init'
import { classModule } from 'snabbdom/modules/class'
import { styleModule } from 'snabbdom/modules/style'

const patch = init([
  classModule,
  styleModule,
]);
```

モジュールの種類は[`snabbdom/src/package/modules`](https://github.com/snabbdom/snabbdom/tree/v2.1.0/src/package/modules)で確認できる。

- `class.ts` ... HTMLタグのclassの切り替えができる。
- `eventlisteners.ts` ... DOM APIのイベントリスナに関係。クリックやキー入力に関するイベントの登録や削除ができる。
- `style.ts` ... HTMLタグに直接書かれたstyle属性を編集できる。
- `props.ts` ... DOM elementのプロパティをカスタムできる。
- `attributes.ts` ... DOM elementの属性が設定できる。
- `dataset.ts` ... DOM Elementの`data-*`グローバル属性の追加と削除を行う。

モジュールには`hero.ts`もあるが、これは正直役割が分からなかった。

`props.ts`にはプロパティの追加と変更はあっても削除は無い。これはDOM側でプロパティを削除できないためらしく、Snabbdomが意図的に実装していない。削除の可能性もあるなら`dataset.ts`を使うことが推奨されている。


## まとめ
SnabbdomではHTMLの木構造をTypeScriptのinterface(JavaScriptのオブジェクト)`VNode`で表現していた。変更前の`VNode`と変更後の`VNode`の差分を検知するアルゴリズムにはDFSが使われており、最小回数のDOM API呼び出しを行うことで高速な実DOMの更新を実現していた。

## 参考記事
- [仮想DOMの内部の動き](https://postd.cc/the-inner-workings-of-virtual-dom/)
