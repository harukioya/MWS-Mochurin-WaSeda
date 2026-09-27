# 同梱サンプル termmines の来歴

## これは何か

`termmines` は、Ghidra の公式教材（GhidraClass）に含まれる端末版マインスイーパーです。
**マルウェアではありません。** 解析の練習用に公開されているゲームです。

置かれているディレクトリの名前が `Debugger` ですが、この教材ではデバッグ機能を使いません。
プログラムの起動もしません（サンプルを作るときも、演習を作るときも）。

## 元のソース

| 項目 | 内容 |
|---|---|
| URL | https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.4_build/GhidraDocs/GhidraClass/ExerciseFiles/Debugger/termmines.c |
| タグ / コミット | `Ghidra_12.1.4_build` / `8b6bbb857accdfa20dc5b2f5dea471178c2e9fbc` |
| SHA-256 | `a30710cc0ff4e1e8136ec2164c235e201a969672cf6f5a5aceea95d81d6e13d2` |
| ライセンス | Apache License 2.0（[LICENSE-Apache-2.0.txt](LICENSE-Apache-2.0.txt)、[NOTICE-Ghidra.txt](NOTICE-Ghidra.txt)） |
| 同梱の写し | [termmines.c](termmines.c)（無改変） |

### 監査の結果（開発側）

- インクルードは `stdlib.h`、`stdio.h`、`string.h`、`pthread.h`、`ncurses.h` だけ。
- ファイルの読み書き、外部コマンドの起動（`system` / `exec` 系）、通信、環境変数の読み取りはない。
- 端末（ncurses）上でゲームを進める処理と、隠しコマンド（コナミコマンド）で地雷を表示する処理がある。
- upstream の `Makefile` は使わない（`-O2` と `strip` を行うため、関数名が残らない）。

## 作り方（開発側だけが行う。利用者はビルド不要）

`python3 ghidra/sample/build_sample.py`（[build_sample.py](build_sample.py)）がすべてを行います。
アプリ本体と同じ部品で Docker を使うので、接続先がこの PC の Docker だと確かめられない
場合（`DOCKER_HOST` や docker context がリモートを指す場合など）は、何も送らずに止まります。
どちらのコンテナにもメモリ・CPU・PID 数の上限と全体の時間制限（各 20 分）を付け、
時間切れや Ctrl+C のときはコンテナを止めて消してから終わります。

1. `termmines.c` の SHA-256 を上の値と照合する。
2. 使い捨てのコンテナ（ベースイメージは処理イメージと同じ Ubuntu 24.04 の固定 digest、
   `--platform linux/amd64`、メモリ 2 GB・PID 512）で、パッケージを取得してから
   `gcc -O0 -o termmines termmines.c -lncurses -lpthread` を実行する。通信を使うのはこの段階だけ。
   このコンテナにはホストの書き込み可能な領域を渡さず（ソースを読み取り専用で渡すだけ）、
   成果物は標準出力の tar で受け取って、ホスト側で名前・種類・大きさを検査してから
   ホストの利用者として `0644` で書き出す。root で動くコンテナに書かせると、通常の
   Linux の Docker Engine では root 所有のファイルが残るため。
   strip はしない（関数名を設問に使うため）。デバッグ情報（`-g`）は付けない。
   できたプログラムは起動しない。
3. アプリの処理イメージ（Ghidra 12.1.4）で、`--network=none`・読み取り専用・権限を落とした
   コンテナの中で取り込みと自動解析を行い、開発者用の [tools/ExportGzf.java](tools/ExportGzf.java)
   で GZF に書き出す。このスクリプトは処理イメージには入れず、このときだけ読み取り専用で渡す。
4. GZF の SHA-256 を [sample.json](sample.json) に、使った部品の版を `toolchain.txt` に記録する。

同梱の GZF は Apple Silicon（linux/arm64 の処理イメージ）で解析しました。Ghidra 12.1.4 の
公式配布物には linux/arm64 用の逆コンパイラが含まれないため、逆コンパイラを使う一部の自動解析
（呼び出し規約の分析など）は行われていません。関数・命令・文字列・参照・外部関数の記録は
得られており、同梱サンプルから 3 種類の設問ができることを確かめています。
コンパイル結果（ELF）は作り直しても同じ SHA-256 になることを確かめました（再現可能）。

コンパイラ・ライブラリのパッケージの版は、実行した時点の Ubuntu 24.04 のものになります
（`toolchain.txt` に記録）。Ghidra の保存データには作成日時が入るため、作り直すと GZF の
ハッシュは変わります。作り直したら `sample.json` の値も更新されます。

## 記録

| 項目 | 値 |
|---|---|
| termmines.gzf の SHA-256 | `sample.json` の `sha256` |
| コンパイル結果（ELF）の SHA-256 | `sample.json` の `executableSha256`（GZF 内に Ghidra が保存した値と同じはず） |
| コンパイラ・パッケージの版 | `toolchain.txt` |
| 解析に使った Ghidra | 12.1.4（処理イメージ。`toolchain.txt` にイメージのタグ） |

## 配布の条件

- `termmines.c` は Apache 2.0。ライセンス全文と Ghidra の NOTICE を同じディレクトリに置き、
  ソース冒頭の表示を保持しています。
- `termmines.gzf` は、そのソースをコンパイルして Ghidra で解析した派生物です（変更の表示:
  「コンパイルし、Ghidra で解析して GZF として保存した」）。静的にリンクされた起動用
  オブジェクト（glibc、GCC）の条件は [../../THIRD_PARTY_NOTICES.md](../../THIRD_PARTY_NOTICES.md) にあります。
- 実データ、個人の GZF、過去の教材の実ログ、認証情報は含めていません。
