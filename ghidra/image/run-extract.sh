#!/bin/sh
# run-extract.sh — コンテナの固定エントリポイント。
#
# 引数は受け取らない。入力は /input/input.gzf（読み取り専用の bind mount）だけ。
# 標準出力には抽出スクリプトが書いた JSON だけを流す。Ghidra 自身の出力は
# 容量制限付きの /tmp に捨て、標準出力へ混ぜない。失敗時は、固定の理由符号を
# 1 行だけ標準エラーへ出す（呼び出し側はこの符号しか利用者に見せない）。
#
# 実行しないもの: 入力に含まれるスクリプト・拡張・設定。自動解析（-noanalysis）。
# プロジェクトへの保存（-readOnly）。任意のスクリプト（-postScript は固定名のみ）。
set -u
umask 077

if [ "$#" -ne 0 ]; then
  echo "MWS-REASON: bad-invocation" >&2
  exit 64
fi

IN=/input/input.gzf
WORK=/tmp/mws
OUT="$WORK/out/facts.json"
mkdir -p "$WORK/out" "$WORK/project" "$HOME" || { echo "MWS-REASON: workspace" >&2; exit 70; }

if [ ! -f "$IN" ] || [ -L "$IN" ]; then
  echo "MWS-REASON: input-missing" >&2
  exit 66
fi

# ユーザーの Ghidra 設定・スクリプトは継承しない（HOME は空の tmpfs）。
# ヒープは固定。コンテナのメモリ上限の内側に収める。
GHIDRA_HEADLESS_MAXMEM=2G
GHIDRA_HEADLESS_JAVA_OPTIONS="-XX:-UsePerfData -Djava.io.tmpdir=$WORK/jtmp"
export GHIDRA_HEADLESS_MAXMEM GHIDRA_HEADLESS_JAVA_OPTIONS
mkdir -p "$WORK/jtmp"

# Ghidra は GZF を開くとき、同じディレクトリにロックファイル（<名前>.lock）を
# 作る。入力の bind mount は読み取り専用のまま保ち、容量制限付きの /tmp へ
# 写したものを読ませる。ハッシュの照合は、元の読み取り専用の入力で行う。
COPY="$WORK/in/input.gzf"
mkdir -p "$WORK/in" && cp "$IN" "$COPY" || { echo "MWS-REASON: workspace-full" >&2; exit 70; }

"$GHIDRA_HOME/support/analyzeHeadless" "$WORK/project" mws_job \
  -import "$COPY" \
  -loader GzfLoader \
  -noanalysis \
  -readOnly \
  -deleteProject \
  -max-cpu 2 \
  -scriptPath /opt/mws/scripts \
  -postScript ExtractStaticFacts.java "$IN" "$OUT" \
  -log "$WORK/ghidra.log" \
  -scriptlog "$WORK/script.log" \
  >"$WORK/headless.out" 2>&1
rc=$?

reason() {
  # 既知の失敗だけを固定の符号へ写す。Ghidra の生の文言は外へ出さない。
  if grep -q "VersionException\|newer version\|older version" "$WORK/headless.out" "$WORK/ghidra.log" 2>/dev/null; then
    echo "version-unsupported"
  elif grep -q "LanguageNotFoundException\|Language not found" "$WORK/headless.out" "$WORK/ghidra.log" 2>/dev/null; then
    echo "language-unsupported"
  elif grep -q "not a Program" "$WORK/headless.out" "$WORK/ghidra.log" 2>/dev/null; then
    echo "not-program"
  elif grep -q "No load spec found\|Unable to load\|Loader .* not found\|Invalid loader" "$WORK/headless.out" "$WORK/ghidra.log" 2>/dev/null; then
    echo "not-gzf"
  elif grep -q "OutOfMemoryError" "$WORK/headless.out" "$WORK/ghidra.log" 2>/dev/null; then
    echo "out-of-memory"
  elif grep -q "No space left" "$WORK/headless.out" "$WORK/ghidra.log" 2>/dev/null; then
    echo "workspace-full"
  elif grep -q "ExtractStaticFacts" "$WORK/script.log" 2>/dev/null && grep -q "Exception" "$WORK/script.log" 2>/dev/null; then
    echo "script-failed"
  else
    echo "extract-failed"
  fi
}

# 成功は、Ghidra が正常終了し（rc=0）、かつ抽出結果が通常ファイルとして
# ある場合だけ。抽出後に Ghidra が異常終了した場合も、出力があるからと
# 成功にはしない（Python 側は終了コードで失敗を知る）。
if [ "$rc" -eq 0 ] && [ -f "$OUT" ] && [ ! -L "$OUT" ]; then
  if cat "$OUT"; then
    exit 0
  fi
  echo "MWS-REASON: extract-failed rc=$rc" >&2
  exit 3
fi

echo "MWS-REASON: $(reason) rc=$rc" >&2
# 開発者向けの診断。呼び出し側は MWS_GHIDRA_DEBUG=1 のときだけ手元の端末へ出す。
if [ -n "${MWS_DIAG:-}" ]; then
  tail -c 6000 "$WORK/headless.out" >&2 2>/dev/null
fi
exit 3
