"""evidence.py — ログ 1 行を「根拠」として扱える形に保つ。

教材が「なぜその答えなのか」を示せるかどうかは、解析の途中で出典を捨てて
いないかで決まる。以前の教材生成は行を読んで事象へ畳み込むだけで、
どのファイルの何行目から来たのかを落としていた。ここはその出典を組み立て、
決定的な識別子を付け、重複なく貯める役を持つ。

外へ出す文字列の扱い（原文は HTML として解釈せず、常にテキストとして扱う）:

  * 抜粋はログ全体ではなく 1 行、しかも上限まで。
  * 制御文字と双方向制御文字は、保存する時点で見える形に置き換える。画面側の
    `textContent` は HTML としての解釈は防ぐが、`U+202E` のような不可視の
    並べ替え文字までは戻せない。ZIP の中身は細工されている前提で扱う。
  * 出典の名前も同じく信頼しない。これも ZIP 由来の文字列である。
  * 保持するのは ZIP の中での論理パスだけで、手元の絶対パスは持たない。
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field

#: 1 件の抜粋に許す長さ。
#:
#: 「読める程度」ではなく「答えが含まれる程度」で決める。設問は引用した行を
#: 読んで答えるものなので、答えにあたる項目が切り落とされていたら設問自体が
#: 成り立たない。ITM2 の行は長く、`psPath` や `path` のような答えにあたる
#: 項目は行の後ろのほうに現れる。短く切ると、まさにその項目だけが落ちる。
#:
#: 典型的な行が収まる値にする。上限そのものは残す。まれに非常に長い行が
#: あり、無制限にすると画面にも保存にも響くため。
MAX_EXCERPT = 1000

#: 出典として表示する名前の長さ。これも ZIP 由来なので上限を置く。
MAX_NAME = 300

#: 証拠 ID の十六進部分の長さ。96 ビットあれば、1 演習に収まる程度の件数で
#: 偶然ぶつかることは考えなくてよい。
ID_HEX = 24

#: 並べ替え・上書き系の双方向制御文字と、C0/C1 制御文字（改行とタブを含む）。
#: `payroll<RLO>gnp.exe` が `payrollexe.png` に見える類を防ぐ。
#:
#: 改行とタブも対象にする。ZIP のメンバー名には改行を入れられるので、除いて
#: おくと出典の表示や読み上げラベルを複数行に割って紛らわしくできてしまう。
#: 抜粋は行ごとに切り出しているので本来 1 行だが、規則はここで揃える。
_UNSAFE = re.compile(
    r"[‪-‮⁦-⁩‎‏؜"
    r"\x00-\x1f\x7f-\x9f]"
)


def visible(text: str, limit: int = MAX_EXCERPT) -> str:
    """危ない文字を見える形へ置き換え、長さを切り詰める。

    消さずに `<U+XXXX>` として残すのは、そこに何かが仕込まれていたこと自体が
    調査上の手がかりだから。黙って落とすと、細工された名前が普通の名前に
    見えてしまう。
    """
    if not isinstance(text, str):
        text = str(text)
    out = _UNSAFE.sub(
        lambda m: f"<U+{ord(m.group()):04X}>", text
    )
    if len(out) > limit:
        out = out[:limit] + "…"
    return out


@dataclass(frozen=True)
class Source:
    """証拠がどこから来たか。ZIP の中での位置だけを持つ。

    `archive_path` は `case/evidence/logs.zip :: logs/ws02.log` のような
    論理パス。同じ `member` 名のログが別の内側 ZIP にあっても、ここが違うので
    取り違えない。手元のどこに ZIP が置かれているかは持たない。
    """

    archive_path: str
    member: str
    line: int          # 1 始まり。元ファイル上の位置。
    excerpt: str

    def as_json(self) -> dict:
        return {
            "archivePath": visible(self.archive_path, MAX_NAME),
            "member": visible(self.member, MAX_NAME),
            "line": self.line,
            "excerpt": visible(self.excerpt),
        }


def evidence_id(source: Source, kind: str = "") -> str:
    """出典から決定的な ID を作る。

    同じ ZIP・同じプロファイル・同じ実装からは毎回同じ値になる必要がある。
    Python の `hash()` はプロセスごとに変わるので使えない。並び順は材料に
    しないので、事象の順序が変わっても ID は動かない。

    区切りに NUL を挟むのは、`("ab", "c")` と `("a", "bc")` が同じ入力に
    ならないようにするため。パスワードなどの秘密は材料にしない。
    """
    digest = hashlib.sha256()
    for part in (source.archive_path, source.member, str(source.line),
                 source.excerpt, kind):
        digest.update(str(part).encode("utf-8"))
        digest.update(b"\x00")
    return "ev-" + digest.hexdigest()[:ID_HEX]


#: 証拠の確からしさ（observed / correlated / hypothesis の 3 段階）。
#: このフェーズで作るのは `observed` だけ。
#: ログにそう書いてあることしか主張しない。相関や推測を `observed` として
#: 貯めると、根拠の強さが区別できなくなる。
OBSERVED = "observed"


@dataclass
class EvidenceStore:
    """1 つの演習ぶんの証拠。同じ行を何度参照しても 1 件にまとめる。"""

    items: dict[str, dict] = field(default_factory=dict)

    def add(self, source: Source, kind: str, confidence: str = OBSERVED) -> str:
        """証拠を登録し、その ID を返す。すでにあれば足さない。"""
        ident = evidence_id(source, kind)
        if ident not in self.items:
            self.items[ident] = {
                "id": ident,
                "kind": kind,
                "source": source.as_json(),
                "confidence": confidence,
            }
        return ident

    def get(self, ident: str) -> dict | None:
        return self.items.get(ident)

    def as_json(self) -> dict:
        """レッスン JSON へ入れる形。ID 順で並べ、出力を決定的にする。"""
        return {k: self.items[k] for k in sorted(self.items)}


def pick_index(seed: str, count: int) -> int:
    """正解の位置を決める。seed から決まるので毎回同じ。

    常に同じ位置へ置くと、中身を読まなくても当てられてしまう。かといって
    乱数では再生成のたびに変わり、「同じ入力・同じ版からは同じ問題と順序を
    作る」という再現性を満たせない。
    """
    if count <= 0:
        return 0
    return int(hashlib.sha256(seed.encode("utf-8")).hexdigest()[:8], 16) % count
