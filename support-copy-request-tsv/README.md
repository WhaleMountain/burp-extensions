# Support Copy Request TSV

TSV形式でクリップボードにコピーできる下記拡張機能のサポート機能  
* [Burp-copy-request-tsv](https://github.com/toubaru/burp-copy-request-tsv)

パラメータもしくはヘッダーが多いリクエストを簡単に確認できるようになる。

### 機能

* Proxy の HTTP history にある全てのリクエストの比較を行う
* Proxy Listener でリアルタイムでリクエストの比較を行う
* Proxy の HTTP history で選択したリクエストの比較を行う

- 優先順
    1. **パラメータ数** が多いリクエスト
    1. **パラメータ数** が同等で **ヘッダー数** が多いリクエスト

※ パラメータもしくはヘッダーが少ないリクエストはグレーアウトされる

### 手動インストール

1. リポジトリをクローンします
1. 上部タブの Extender から Extensions を開きます
1. Add ボタンをクリックし、Extension Details の Extension type で Python を選択します
1. Select file でクローンしたリポジトリから **suport-copy-request-tsv.py** を選択し Next をクリックします
1. Error が表示されなければインストール成功です

### 使い方

1. Extender で **Support Copy Request TSV** にチェックを入れます
1. Target から比較を行うサイトを Scope に追加します (Scopeに追加されたサイトが比較対象です)

#### Proxy の HTTP history にある全てのリクエストの比較を行う

1. 追加された **Suport Copy Request TSV** タブを開きます
1. Check all Proxy HTTP history の **Check** ボタンをクリックします
1. Proxy タブの HTTP history で比較結果を確認できます
1. Clear all highlight and Comment の **Clear** ボタンをクリックすることで比較結果をリセットできます

※ ハイライトが**設定されている色**であり、コメントがあるリクエストは**全て**クリアされます

#### Proxy Listener でリアルタイムでリクエストの比較を行う

1. 追加された **Suport Copy Request TSV** タブを開きます
1. ProxyListener の **Start** ボタンをクリックします
1. リアルタイムに HTTP history で比較結果が確認できます
1. **Stop and Reset** ボタンをクリックすることで、ストップすることができます

※ 事前に取得済みのリクエストも対象に含める場合は事前に **Check** ボタンをクリックしてください。

#### Proxy の HTTP history で選択したリクエストの比較を行う

1. 追加された **Suport Copy Request TSV** タブを開きます
1. Proxy タブの HTTP history から比較したいリクエストを複数選択します
1. 右クリックでメニューを開き **Sup cprTSV (Check)** をクリックします
1. 選択されたリクエストの比較が行われます
1. メニューから **Sup cprTSV (Clear)** をクリックすることで比較結果をリセットできます

※ コメントに記載される番号は選択したリクエストの範囲からカウントされます  
※ ハイライトが**設定されている色**であり、コメントがあるリクエストは**全て**クリアされます

#### 特定のリクエストを対象外に設定する

1. 追加された **Suport Copy Request TSV** タブを開きます
1. **Ignore to URLs** に対象外にしたいリクエストの`Method`、`URL`を入力し**Add**をクリックします
1. 対象外のテーブルに追加されます
1. また、HTTP historyから対象外にしたリクエストを選択し、**Sup cprTSV (Ignore)** から追加も可能です

※ URLのスキーマは **http://** または **https://** のみ登録できます  
※ URLにはGETパラメータなどは含めません  
※ Burpを再起動すると対象外のテーブルもリセットされるため、適宜Jsonファイルに**Import**してください