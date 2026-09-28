# Ghidra 静的解析教材用の処理イメージ。
#
# 構築はアプリの「処理環境を準備する」（backend/ghidra_docker.py）が、ローカルの
# builder で行う。build context はこのディレクトリだけで、リポジトリ全体・
# .zip2learn-state/・入力 GZF・個人データは含めない。
#
# 固定しているもの（変えるときは backend/ghidra_docker.py の定数も同時に変える）:
#   * ベース: eclipse-temurin 21.0.12.1_1 JDK (Ubuntu 24.04 noble)、マルチアーキ index の digest
#   * Ghidra 12.1.4 公式配布 zip と、その SHA-256（公式リリースページ記載の値）
#   * 抽出スクリプトとエントリポイント（このディレクトリ内のファイル）
FROM eclipse-temurin:21.0.12.1_1-jdk-noble@sha256:d1eb0297924c2d5a37ba7042a59ae84a3487e086b077ac054019a423767d4311

# 公式リリース: https://github.com/NationalSecurityAgency/ghidra/releases/tag/Ghidra_12.1.4_build
ADD --checksum=sha256:ddac49f903da9d5bac833e5cc79395098b9c33cfd3279be5f31bd00387d2d4db \
    https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.1.4_build/ghidra_12.1.4_PUBLIC_20260921.zip \
    /opt/ghidra.zip

# 展開は JDK 同梱の jar で行う（版を固定できない追加パッケージを入れないため）。
# jar は実行属性を保たないので、起動に使うスクリプトとネイティブ部品だけに付け直す。
RUN set -eu; \
    cd /opt; \
    jar xf ghidra.zip; \
    rm ghidra.zip; \
    mv ghidra_12.1.4_PUBLIC /opt/ghidra; \
    chmod -R a+rX,go-w /opt/ghidra; \
    find /opt/ghidra/support -type f -exec chmod 0755 {} +; \
    find /opt/ghidra -path '*/os/linux_*' -type f -exec chmod 0755 {} +; \
    test -x /opt/ghidra/support/analyzeHeadless

# COPY --chmod は途中で作るディレクトリにも同じ属性を付ける（0444 だと中を参照できない）。
# ディレクトリは先に 0755 で作っておく。
RUN install -d -m 0755 /opt/zip2learn /opt/zip2learn/scripts /opt/zip2learn/bin
COPY --chmod=0444 ExtractStaticFacts.java /opt/zip2learn/scripts/ExtractStaticFacts.java
COPY --chmod=0555 run-extract.sh /opt/zip2learn/bin/run-extract.sh

ARG ZIP2LEARN_SCRIPT_SHA256=unset
ARG ZIP2LEARN_ENTRY_SHA256=unset
LABEL org.zip2learn.image-schema="1" \
      org.zip2learn.ghidra.version="12.1.4" \
      org.zip2learn.ghidra.zip-sha256="ddac49f903da9d5bac833e5cc79395098b9c33cfd3279be5f31bd00387d2d4db" \
      org.zip2learn.base="eclipse-temurin:21.0.12.1_1-jdk-noble@sha256:d1eb0297924c2d5a37ba7042a59ae84a3487e086b077ac054019a423767d4311" \
      org.zip2learn.script.sha256="${ZIP2LEARN_SCRIPT_SHA256}" \
      org.zip2learn.entry.sha256="${ZIP2LEARN_ENTRY_SHA256}"

ENV GHIDRA_HOME=/opt/ghidra \
    HOME=/tmp/zip2learn/home

# 実行時は呼び出し側が非 root の --user を必ず指定する。ここでも既定を非 root にしておく。
USER 65532:65532
ENTRYPOINT ["/opt/zip2learn/bin/run-extract.sh"]
