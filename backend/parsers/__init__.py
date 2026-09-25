"""parsers — ログ形式ごとの読み方と、その登録簿。

組み込みで登録するのは InfoTrace Mark II と Squid 形式のプロキシログの
二つだけ。任意の形式へ自動的に対応するわけではない。新しい形式に対応する
には、`Parser` を派生させたクラスを書き、`REGISTRY.register()` で登録する。
教材生成（explain.py）の変更は要らない。手順は docs の開発者ガイドを参照。
"""

from .base import (  # noqa: F401
    FACTS,
    KNOWN_KINDS,
    REQUIRED_ATTRIBUTES,
    ContractError,
    FactReading,
    FactText,
    InputSource,
    NormalizedEvent,
    Parser,
    clean_host_keys,
    source_of,
    validate_event,
)
from .registry import ParsedSources, ParserRegistry  # noqa: F401
from . import itm2, proxy

#: 既定の登録簿。サーバーと `explain.build_lesson()` はこれを使う。
REGISTRY = ParserRegistry([itm2.PARSER, proxy.PARSER])
