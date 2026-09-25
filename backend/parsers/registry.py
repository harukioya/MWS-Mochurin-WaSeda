"""parsers/registry.py — 登録済みパーサーの一覧と、入力ソースの解析。

教材生成へ渡る正規化イベントは、すべてここを通る。ここで守ることは四つ。

  1. 同じ ID の二重登録を拒否する（どちらが使われたかが分からなくなる）。
  2. 登録の順序で結果が変わらない。パーサーは常に ID 順に試し、イベントは
     （入力ソースの名前, パーサー ID, 行番号）の順に並べる。
  3. パーサーが返したものを検査する。契約に反した出力は、その入力ソースに
     ついて丸ごと捨て、理由を報告する。一部だけ使うと、どこまでが正しい
     記録なのかが分からなくなる。
  4. 指定された ID が未登録なら、黙って無視せず報告する。
  5. 自動判定（ID の指定が無いとき）には `AUTO_DETECT` のパーサーだけを
     使う。明示指定が要るパーサーが読めそうだったのに使わなかった入力
     ソースは `explicit_only` に残し、黙って落とさない。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, Mapping

import evidence

from .base import (
    ContractError,
    InputSource,
    NormalizedEvent,
    Parser,
    check_parser,
    detect_score,
    validate_event,
)


@dataclass
class ParsedSources:
    """解析の結果。教材生成が受け取るのはこれだけ。

    `store` は、この教材のための空の EvidenceStore。教材生成が、画面に出す
    行と相関に採用した行だけを登録する。
    """

    events: list[NormalizedEvent]
    parsers: dict[str, Parser]
    sources: list[str]
    #: 入力ソースの名前 -> 1 件以上のイベントを出したパーサーの ID
    recognized: dict[str, list[str]]
    unknown_parsers: list[str]
    failures: list[dict]
    store: evidence.EvidenceStore = field(default_factory=evidence.EvidenceStore)
    #: 入力ソースの名前 -> 読めそうだが明示指定が無いため使わなかったパーサーの ID
    explicit_only: dict[str, list[str]] = field(default_factory=dict)

    @property
    def unrecognized(self) -> list[str]:
        """どのパーサーも 1 件も読めなかった入力ソース。"""
        return [name for name in self.sources if not self.recognized.get(name)]

    def report(self) -> dict:
        """教材のメタデータへ残す形。本文や行の中身は含めない。"""
        used = sorted({e.parser_id for e in self.events})
        return {
            "parsers": used,
            "parserLabels": [self.parsers[i].label for i in used],
            "recognized": {k: list(v) for k, v in sorted(self.recognized.items()) if v},
            "unrecognized": self.unrecognized,
            "unknownParsers": list(self.unknown_parsers),
            "failures": [dict(f) for f in self.failures],
            "explicitOnly": {k: list(v) for k, v in sorted(self.explicit_only.items())},
        }


class ParserRegistry:
    """パーサーの登録簿。"""

    def __init__(self, parsers: Iterable[Parser] = ()) -> None:
        self._by_id: dict[str, Parser] = {}
        for parser in parsers:
            self.register(parser)

    def register(self, parser: Parser) -> None:
        check_parser(parser)
        if parser.id in self._by_id:
            raise ContractError(f"パーサー ID '{parser.id}' はすでに登録されています。")
        self._by_id[parser.id] = parser

    def unregister(self, parser_id: str) -> None:
        del self._by_id[parser_id]

    def get(self, parser_id: str) -> Parser | None:
        return self._by_id.get(parser_id)

    def ids(self) -> list[str]:
        return sorted(self._by_id)

    def label(self, parser_id: str) -> str:
        parser = self._by_id.get(parser_id)
        return parser.label if parser else parser_id

    def __contains__(self, parser_id: object) -> bool:
        return parser_id in self._by_id

    def resolve(self, parser_ids: Iterable[str] | None = None,
                ) -> tuple[list[Parser], list[str]]:
        """使うパーサーと、未登録の ID。

        `None` は「プロファイルが指定していない」＝登録済みのうち
        `AUTO_DETECT` のものを候補にして、各入力ソースで `detect()` に判定
        させる（自動判定）。明示指定が要るものは、ID で指定されたときだけ使う。
        """
        if parser_ids is None:
            return [self._by_id[i] for i in sorted(self._by_id)
                    if self._by_id[i].AUTO_DETECT], []
        wanted = sorted(set(parser_ids))
        known = [self._by_id[i] for i in wanted if i in self._by_id]
        unknown = [i for i in wanted if i not in self._by_id]
        return known, unknown

    def explicit_only(self, parser_ids: Iterable[str] | None = None) -> list[Parser]:
        """明示指定が要るのに、今回は指定されていないパーサー（ID 順）。"""
        chosen = set(parser_ids or ())
        return [self._by_id[i] for i in sorted(self._by_id)
                if not self._by_id[i].AUTO_DETECT and i not in chosen]

    def parse_sources(self, sources: Mapping[str, str],
                      parser_ids: Iterable[str] | None = None,
                      ) -> ParsedSources:
        """入力ソースを、候補のパーサーで読む。

        1 つの入力ソースを複数のパーサーが読んでもよい（1 本のログに複数の
        形式の行が混ざることがある）。各パーサーは自分の形式の行だけを
        イベントにする。
        """
        candidates, unknown = self.resolve(parser_ids)
        store = evidence.EvidenceStore()
        events: list[NormalizedEvent] = []
        recognized: dict[str, list[str]] = {}
        failures: list[dict] = []
        names = sorted(sources)
        for name in names:
            src = InputSource(name=name, text=sources[name])
            used: list[str] = []
            for parser in candidates:
                try:
                    if detect_score(parser.detect(src)) <= 0.0:
                        continue
                    got = parser.parse(src, store)
                    if not isinstance(got, list):
                        raise ContractError("parse() は list を返さなければなりません。")
                    for event in got:
                        validate_event(event, parser.id)
                except ContractError as exc:
                    # 理由はこちらの固定文だけにする。パーサーの例外文には
                    # ログの中身が入りうる。
                    failures.append({
                        "source": name, "parser": parser.id, "reason": "contract",
                        "detail": str(exc),
                    })
                    continue
                except Exception as exc:  # noqa: BLE001 - 1 つの不具合で全体を止めない
                    failures.append({
                        "source": name, "parser": parser.id, "reason": "error",
                        "detail": f"解析中に {type(exc).__name__} が起きました。",
                    })
                    continue
                if got:
                    used.append(parser.id)
                    events.extend(got)
            recognized[name] = used
        # どれにも読まれなかったソースについて、明示指定が要るパーサーなら
        # 読めたかを確かめる。使いはしないが、「形式が分からない」のではなく
        # 「指定すれば読めるが、内容だけでは断定しない」ことを伝えるため。
        explicit: dict[str, list[str]] = {}
        held_back = self.explicit_only(parser_ids)
        for name in names:
            if recognized.get(name) or not held_back:
                continue
            src = InputSource(name=name, text=sources[name])
            hits = []
            for parser in held_back:
                try:
                    if detect_score(parser.detect(src)) > 0.0:
                        hits.append(parser.id)
                except Exception:  # noqa: BLE001 - 報告のための確認で止めない
                    continue
            if hits:
                explicit[name] = hits
        return ParsedSources(
            events=events,
            parsers={p.id: p for p in candidates},
            sources=names,
            recognized=recognized,
            unknown_parsers=unknown,
            failures=failures,
            store=store,
            explicit_only=explicit,
        )
