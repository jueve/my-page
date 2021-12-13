---
title: 仕様書から読み解くECMAScriptのnew
date: 2020-09-19
---

ECMAScriptの`new`演算子をECMAScript2020の仕様書から読み解く話。

確認することは以下の2点である。

* `new`が変数名として使えない理由
* `new`を使ったオブジェクトの生成はどのように働いているか

```javascript
var new; // Syntax Error
let new; // Syntax Error
var new = 1; // Syntax Error
let new = 1; // Syntax Error
const new = 1; // Syntax Error

var obj1 = { new: 1 }; // ok
let obj2 = {};
obj2.new = 1; // ok
obj2.new // ok
obj2["new"] // ok
```

```javascript
function Vehicle(plate, capacity) {
  this.plate = plate;
  this.capacity = capacity;
}

let car = new Vehicle("A-1234", 4);
```

`class`を使っていない古い書き方だが、実際のコードと仕様書を照らし合わせていく関係上こちらの表記のほうが分かりやすいので`class`を使わずに進める。

また、ES6で`new.target`も出てきたが今回これは対象外とする。

```javascript
// new.target
function User (name) {
  this.name = name;
  if (!new.target) {
    throw new Error(`Object 'User' must have a 'new' prefix.`);
  }
}

let Alice = new User("Alice"); // ok
let Bob = User("Bob"); // Uncaught Error
```

## 表記編
「`new`は予約語なので変数名には使えない」と技術書に書かれていたりする。まずはこれを確かめる。

### 事前知識(表記編)
ECMAScriptで書かれたソースコードのテキストはUnicodeのコードポイントとして扱われた後、

- トークン(token)
- 行終端(line termination)
- コメント(comments)
- 空白(white space)

の4つで構成された列に変換される。これら4つは**input element**と呼ばれ、テキストを左から右に読み取りながら次のinput elementが続く限り、できるだけ長い列に変換される。

この変換には[**lexical grammar**](https://www.ecma-international.org/ecma-262/#sec-lexical-and-regexp-grammars)という文法が使われる。ECMAScriptの仕様書にはいくつかの文法が定められているがlexical grammarはその1つ。lexical grammarはContext-Free Grammarで表記されていて`左辺::右辺`の形式を取る。例えば`InputElementDiv`は以下のように表す。

```
InputElementDiv::
  WhiteSpace
  LineTerminator
  Comment
  CommonToken
  DivPunctuator
  RightBracePunctuator
```

これは左辺`InputElementDiv`が

- `WhiteSpace`
- `LineTerminator`
- `Comment`
- `CommonToken`
- `DivPunctuator`
- `RightBracePunctuator`

の6種類から成ることを示している。

また、この6つはそれ自体が新たな左辺になる。このようにlexical grammarは終端まで再帰的に続いていく。

lexical grammarを使った解析の後は、tokenの列が構文的に正しいコンポーネントとなっているかを確かめるために[**syntactic grammar**](https://www.ecma-international.org/ecma-262/#sec-syntactic-grammar)が適用される。syntactic grammarもlexical grammar同様、ECMAScriptに定められている文法の1つ。表記は`左辺:右辺`となり、lexical grammarと比べて`:`の数が1個少なくなっている。

例えばリテラル表記は以下のように示される。

```
Literal:
  NullLiteral
  BooleanLiteral
  NumericLiteral
  StringLiteral
```

### tokenとしてのnew
さて、lexical grammarの中には識別子の名前を決めるため`IdentifierName`と呼ばれるtokenが存在する。

[IdentifierName](https://tc39.es/ecma262/#prod-IdentifierName)

```
IdentifierName::
  IdentifierStart
  IdentifierNameIdentifierPart
```

さらに`IdentifierName`のうち、`if`、`while`、`async`、`await`のように文法的に意味があるものは**keyword**と呼ばれる。そして多くのkeywordは**reserved word**にも分類される

上記のことは[Keywords and Reserved Words](https://www.ecma-international.org/ecma-262/#sec-keywords-and-reserved-words)で確認できる。
>A keyword is a token that matches IdentifierName, but also has a syntactic use; that is, it appears literally, in a fixed width font, in some syntactic production. The keywords of ECMAScript include if, while, async, await, and many others.

>A reserved word is an IdentifierName that cannot be used as an identifier. Many keywords are reserved words, but some are not, and some are reserved only in certain contexts. if and while are reserved words. await is reserved only inside async functions and modules. async is not reserved; it can be used as a variable name or statement label without restriction.


以上のことを(厳密ではないが)図にすると以下のようになる。

![ALT](/img/2020-09-19-ecmascript-new/category.png)

`new`は上の図のうち赤色の部分、つまりreserved wordに属する。lexical grammarの中でreserved wordは`ReservedWord`とされ以下のように表される。

[ReservedWord](https://tc39.es/ecma262/#prod-ReservedWord)

```
ReservedWord::one of
  await break case catch class const continue debugger default
    delete do else enum export extends false finally for function
    if import in instanceof new null return super switch this throw
    true try typeof var void while with yield
```

さらに仕様書には以下のように書かれている。
> A reserved word is an IdentifierName that cannot be used as an identifier.

> 予約語は識別子として使うことのできないIdentifierNameのことである。(拙訳)

ここでいうidentifier(識別子)はsyntactic grammarで登場する。

### 変数にnewが指定できない理由

変数名に`new`が使えない理由を見ていきたい。syntactic grammarの中では`var`を使った変数宣言に`VariableStatement`、`VariableDeclarationList`、`VariableDeclaration`が使われる。

[VariableStatement](https://www.ecma-international.org/ecma-262/#sec-variable-statement)

```
VariableStatement[Yield, Await]:
  varVariableDeclarationList[+In, ?Yield, ?Await] ;

VariableDeclarationList[In, Yield, Await]:
  VariableDeclaration[?In, ?Yield, ?Await]
  VariableDeclarationList[?In, ?Yield, ?Await] , VariableDeclaration[?In, ?Yield, ?Await]

VariableDeclaration[In, Yield, Await]:
  BindingIdentifier[?Yield, ?Await] Initializer[?In, ?Yield, ?Await]opt
  BindingPattern[?Yield, ?Await] Initializer[?In, ?Yield, ?Await]
```

一方、`let`と`const`を使った変数宣言には`LexicalDeclaration`、`LetOrConst`、`BindingList`、`LexicalBinding`が現れる。

[Let and Const Declarations](https://www.ecma-international.org/ecma-262/#sec-let-and-const-declarations)

```
LexicalDeclaration[In, Yield, Await]:
  LetOrConst BindingList[?In, ?Yield, ?Await];

LetOrConst:
  let
  const

BindingList[In, Yield, Await]:
  LexicalBinding[?In, ?Yield, ?Await]
  BindingList[?In, ?Yield, ?Await] , LexicalBinding[?In, ?Yield, ?Await]

LexicalBinding[In, Yield, Await]:
  BindingIdentifier[?Yield, ?Await] Initializer[?In, ?Yield, ?Await] opt
  BindingPattern[?Yield, ?Await] Initializer[?In, ?Yield, ?Await]
```

`[]`内に登場する`In`や`?Yield`、末尾にある`opt`については今回触れない。

上記を見比べてみると`var`を使った変数宣言、`let`または`const`を使った変数宣言には共通して内部で`BindingIdentifier`が使われている。

さらにこの`BindingIdentifier`を見てみると内部で`Identifier`が登場する。

[BindingIdentifier](https://www.ecma-international.org/ecma-262/#prod-BindingIdentifier)
```
BindingIdentifier[Yield, Await]:
  Identifier
  yield
  await
```

[Identifier](https://www.ecma-international.org/ecma-262/#prod-Identifier)
```
Identifier:
  IdentifierName but not ReservedWord
```

つまり、`Identifier`となれるのは`IdentifierName`のうち`ReservedWord`に属さないものである。以上のことから`new`は`Identifier`として使うことができないことが分かる。

```javascript
var new; // Syntax Error
let new; // Syntax Error
var new = 1; // Syntax Error
let new = 1; // Syntax Error
const new = 1; // Syntax Error
```

一方、オブジェクトをリテラルで表記したり、プロパティにアクセスする際のsyntactic grammarに`Identifier`は登場しない。
そのため以下のコードはエラーにならない。

```javascript
var obj1 = { new: 1 }; // ok
let obj2 = {};
obj2.new = 1; // ok
obj2.new // ok
obj2["new"] // ok
```

### tokenとしてのnewが許される表記
syntactic grammarで`new`の登場が許されるのものの一つに`MemberExpression`がある。

[MemberExpression](https://www.ecma-international.org/ecma-262/#prod-MemberExpression)

```
MemberExpression[Yield, Await]:
  PrimaryExpression[?Yield, ?Await]
  MemberExpression[?Yield, ?Await] [ Expression[+In, ?Yield, ?Await] ]
  MemberExpression[?Yield, ?Await] . IdentifierName
  MemberExpression[?Yield, ?Await] TemplateLiteral[?Yield, ?Await, +Tagged]
  SuperProperty[?Yield, ?Await]
  MetaProperty
  new MemberExpression[?Yield, ?Await] Arguments[?Yield, ?Await]
```

一番下に`new MemberExpression[?Yield, ?Await] Arguments[?Yield, ?Await]`という表記がある。これは冒頭に掲げたコードが該当する。

```javascript
let car = new Vehicle("A-1234", 4);
// '=' より右側の表記が 'new MemberExpression[?Yield, ?Await] Arguments[?Yield, ?Await]' に当てはまる
```

そして、これまでのsyntactic grammarとコードの関係を図に表すと以下のようになる(が、本来コードへたどり着くにはもう少しsyntactic grammarをたどる必要がある。例えば`Vehicle`はそれ自身が`MemberExpression`であるが、途中[`IdentifierReference`](https://www.ecma-international.org/ecma-262/#prod-IdentifierReference)にたどり着く)。

![tree](/img/2020-09-19-ecmascript-new/tree.png)

では`MemberExpression`のうち、`new MemberExpression[?Yield, ?Await] Arguments[?Yield, ?Await]`は実行時にどのような働きをしているのだろうか。

## ランタイム編

`new MemberExpression[?Yield, ?Await] Arguments[?Yield, ?Await]`の実行時の動きを見る前に仕様書におけるオブジェクトの振る舞いを見ておきたい。

### 事前知識(ランタイム編)

ECMAScriptにおけるオブジェクトの振る舞いを記述するために、仕様書では特定のアルゴリズムを記述した**internal method**と、オブジェクトの状態を記述した**internal slot**がある。両方とも仕様書の中でのみ扱われる。

internal slotとinternal methodを使った表記はECMAScriptのコードでオブジェクトを使ったときの書き方に似ている。

例えばあるオブジェクト`O`のinternal slot`[[Slot]]`を参照するときは以下のようになる。

```
O.[[Slot]]
```

また、`O`のinternal method`[[Method]]`を、引数`argument`と一緒に呼ぶ場合は以下のようになる。

```
O.[[Method]](argument)
````

internal slotとinternal methodを取り上げた理由は、ECMAScriptのオブジェクトには**共通して複数のinternal methodが実装されてなければならないと仕様書の中で定められている**からだ。ECMAScriptのオブジェクトは、このベースとなるinternal methodに加えて追加のinternal slotやinternal methodを実装することで様々なオブジェクトを表現している。

今回注目している`new`に関連するオブジェクトのうち、重要なものは以下。

* **function object** ... 必要なinternal methodに加え、追加で`[[Call]]`というinternal methodが定義されている。
* **constructor** ... function objectに更に追加で`[[Construct]]`というinternal methodが定義されている。

関係図を示すと以下の継承のような形になる。

![ALT](/img/2020-09-19-ecmascript-new/relation-between-objects.png)

`[[Call]]`は関数呼び出しの際に用いられる一方、`[[Construct]]`はオブジェクトの生成に用いられる。このため以降は`[[Construct]]`に焦点を当てる。

### [[Construct]]について

`[[Construct]]`の説明は以下のように書かれている。

[Table 7: Additional Essential Internal Methods of Function Objects](https://www.ecma-international.org/ecma-262/#table-6)

> Creates an object. Invoked via the new operator or a super call. The first argument to the internal method is a list containing the arguments of the constructor invocation or the super call. The second argument is the object to which the new operator was initially applied. Objects that implement this internal method are called constructors. A function object is not necessarily a constructor and such non-constructor function objects do not have a [[Construct]] internal method.

> オブジェクトを生成し、`new`演算子か`super`の宣言を経由して呼び出される。第一引数にconstructorの呼び出しの引数を含むリスト、または`super`を使った宣言の引数を含むリストを与える。第二引数には`new`演算子が最初に適用されたオブジェクトを与える。このinternal methodを実装したオブジェクトはconstructorと呼ばれる。function objectはconstructorである必要はなく、constructorではないfunction objectは[[Construct]]というinternal methodを持たない。(拙訳)

以上から分かることは

* `new`か`super`を使うことで新しいオブジェクトが生成できる
* `[[Construct]]`を実装したオブジェクトはconstructorと呼ばれる

である。

```javascript
function Vehicle(plate, capacity) {
  this.plate = plate;
  this.capacity = capacity;
}

// new演算子を使うことで新しいオブジェクトを生成している
let car = new Vehicle("A-1234", 4);
```

ここから`[[Construct]]`が具体的に使われている場面を見ていきたい。

### Runtime Semantics

ランタイム時に呼び出される意味論のことは[**runtime semantics**](https://www.ecma-international.org/ecma-262/#sec-runtime-semantics)と呼ばれる。runtime semanticsでは仕様書の中で定義された[**abstract operation**](https://www.ecma-international.org/ecma-262/#sec-algorithm-conventions-abstract-operations)と呼ばれるアルゴリズムを用いて疑似コードのような形で振る舞いが表現される。

余談だが、**internal methodとabstract operationは異なる**。前者はオブジェクトにおけるメソッドのような位置付けに対して、後者は仕様書内で使われるアルゴリズムを簡潔に表現するために書かれたものである。
表記も前者なら`[[Notation]]`の形で表現されるが後者は`Notation`と表現される。

話を戻し、先程のsyntactic grammarを見る。

```
new MemberExpression[?Yield, ?Await] Arguments[?Yield, ?Await]
```

このsyntactic grammarには以下のruntime semanticsが定義されている。

[12.3.5.1 Runtime Semantics: Evaluation](https://www.ecma-international.org/ecma-262/#sec-new-operator-runtime-semantics-evaluation)

```
12.3.5.1 Runtime Semantics: Evaluation

MemberExpression : new MemberExpression Arguments
  1. Return ? EvaluateNew(MemberExpression, Arguments).
```

実行されるのは`Return ? EvaluateNew(MemberExpression, Arguments)`になる。

ここに見知らぬ`Return`、`?`、`EvaluateNew`という3つのabstract operationが登場する。

`Return`は実際のECMAScriptのコードで扱う`return`とほぼ同じである。`?`は実行中に何かしらのエラーが出た時に即`Return`して中断するためのabstract operationである。残りの`EvaluateNew`に着目する。

[12.3.5.1.1 Runtime Semantics: EvaluateNew ( constructExpr , arguments )](https://www.ecma-international.org/ecma-262/#sec-evaluatenew)

```
12.3.5.1.1 Runtime Semantics: EvaluateNew ( constructExpr , arguments )

The abstract operation EvaluateNew with arguments constructExpr,
and arguments performs the following steps:

1. Assert: constructExpr is either a NewExpression or a MemberExpression.
2. Assert: arguments is either empty or an Arguments.
3. Let ref be the result of evaluating constructExpr.
4. Let constructor be ? GetValue(ref).
5. If arguments is empty, let argList be a new empty List.
6. Else,
  a. Let argList be ? ArgumentListEvaluation of arguments.
7. If IsConstructor(constructor) is false, throw a TypeError exception.
8. Return ? Construct(constructor, argList).
```

abstract operationの呼び出しが続いていくが、今度は8の`Return ? Construct(constructor, argList)`のうち、`Construct(constructor, argList)`に着目したい。

[7.3.14 Construct ( F [ , argumentsList [ , newTarget ] ] )](https://www.ecma-international.org/ecma-262/#sec-construct)

```
7.3.14 Construct (F [ , argumentsList [ , newTarget ] ])

The abstract operation Construct is used to call the [[Construct]] internal method of a function object. 
The operation is called with arguments F, and optionally argumentsList, and newTarget where F is the function object.
argumentsList and newTarget are the values to be passed as the corresponding arguments of the internal method.
If argumentsList is not present, a new empty List is used as its value.
If newTarget is not present, F is used as its value. This abstract operation performs the following steps:

1. If newTarget is not present, set newTarget to F.
2. If argumentsList is not present, set argumentsList to a new empty List.
3. Assert: IsConstructor(F) is true.
4. Assert: IsConstructor(newTarget) is true.
5. Return ? F.[[Construct]](argumentsList, newTarget).
```

5でようやく`[[Construct]]`が記述されているのが分かる。`F`というオブジェクトに定義されたinternal method`[[Construct]]`を２つの引数`(argumentsList, newTarget)`で呼び出してその戻り値を取得している。

まとめると、`new MemberExpression Arguments`の形で表記されたECMAScriptはランタイム時、`EvaluateNew`、`Construct`といったabstract operationを経由して、最終的には`F.[[Construct]]`というinternal methodを呼び出して新たにインスタンスとしてのオブジェクトを生成する。

ところで`F`というオブジェクトが`[[Construct]]`というinternal methodを持っているということは、**`F`はconstructorであり、function objectでもある**。

ではこの`F`はどこから来たのだろうか。

### constructorの取得

ここで一度、これまで登場したRuntime Semanticsを一部表記を省略して並べ、abstract operationの引数と変数の関係に注目したい。

```
MemberExpression: new MemberExpression Arguments
  1. Return ? EvaluateNew(MemberExpression, Arguments).


EvaluateNew( constructExpr , arguments )
  ...
  3. Let ref be the result of evaluating constructExpr.
  4. Let constructor be ? GetValue(ref).
  5. If arguments is empty, let argList be a new empty List.
  6. Else,
    a. Let argList be ? ArgumentListEvaluation of arguments.
  7. If IsConstructor(constructor) is false, throw a TypeError exception.
  8. Return ? Construct(constructor, argList).


Construct ( F [ , argumentsList [ , newTarget ] ] )
  1. If newTarget is not present, set newTarget to F.
  2. If argumentsList is not present, set argumentsList to a new empty List.
  ...
  5. Return ? F.[[Construct]](argumentsList, newTarget).


F.[[Construct]](argumentsList, newTarget)
```

`F`が初めて登場するのは`Construct`の第一引数としてである。

その`Construct`が呼び出される`EvaluateNew`では、4で変数`constructor`が`GetValue(ref)`というabstract operationの結果として格納されている。そしてこれが`Construct`の第一引数となっている。

![runtime 01](/img/2020-09-19-ecmascript-new/runtime01.png)

続いて、同じく`EvaluateNew`内で呼び出されているabstract operationの`GetValue(ref)`に注目する。引数`ref`は3にあるとおり、`constructExpr`の評価の結果とされている。

そしてこの`constructExpr`は`EvaluateNew`自身の第一引数であり、`MemberExpression`でもある。


![runtime 02](/img/2020-09-19-ecmascript-new/runtime02.png)

さらに今一度、表記編で扱った画像を確認したい。

![tree](/img/2020-09-19-ecmascript-new/tree.png)

以上から`ref`は`Vehicle`の評価の結果、つまり`function`で宣言した`Vehicle`の参照の結果を意味する。言い換えると、`EvaluateNew`内で生成される変数`constructor`の源は`Vehicle`にある。

```javascript
// 宣言時にconstructorになっている…?
function Vehicle(plate, capacity) {
  this.plate = plate;
  this.capacity = capacity;
}

let car = new Vehicle("A-1234", 4);
```

### constructorの生成


順番としては前後するが、`function`宣言時、どういったruntime semanticsが定義されているのかを見ていきたい。

表記の観点から言えば、上記のような宣言はlexical grammarにおける[`FunctionDeclaration`](https://www.ecma-international.org/ecma-262/#prod-FunctionDeclaration)になる。

そして`FunctionDeclaration`のruntime semanticsは以下の通りである。


[14.1.23 Runtime Semantics: InstantiateFunctionObject](https://www.ecma-international.org/ecma-262/#sec-function-definitions-runtime-semantics-instantiatefunctionobject)

```
With parameter scope.

FunctionDeclaration : function BindingIdentifier ( FormalParameters ) { FunctionBody }
  1. Let name be StringValue of BindingIdentifier.
  2. Let F be OrdinaryFunctionCreate(%Function.prototype%, FormalParameters, FunctionBody, non-lexical-this, scope).
  3. Perform MakeConstructor(F).
  4. Perform SetFunctionName(F, name).
  5. Set F.[[SourceText]] to the source text matched by FunctionDeclaration.
  6. Return F.
```

重要な部分は以下の2点である。

* 2でfunction objectを生成する(つまり、オブジェクトとして必要なinternal methodを追加して、さらに`[[Call]]`を実装している)
* 3でconstructorを生成する(つまり、2で作ったfunction objectにさらに`[[Construct]]`を実装している)

このように`function`宣言で定義された関数は**function objectでありconstructorでもある**。そして`new`を使ってインスタンスとして新たにオブジェクトを作るときはこのconstructorが参照される。


## まとめ

`new`についてまずは表記的な観点から見た。変数名として使えないのは`new`が`ReservedWord`してlexical grammarで定義されており、syntactic grammarで使うことが許されていないためであった。

次にランタイム時のオブジェクト生成に焦点を当て、仕様書内で定義されたinternal methodの`[[Construct]]`に着目した。`[[Construct]]`はconstructorと呼ばれるオブジェクトに定義されている新しいオブジェクトを生成するinternal methodだった。そのconstructorの正体はあらかじめ`function`宣言で定義された関数だった。
