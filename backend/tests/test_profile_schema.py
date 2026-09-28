"""Profile schema, external profile directories, and the public boundary.

A profile is data the product does not ship: it is added per site, at server
start, from a directory named in `DATASET_PROFILE_DIR`. So the loader is an
input boundary, and these tests treat it as one:

  * `year` is not part of the model; `edition` is an optional string;
  * a profile that cannot be read, or does not match the schema, is reported
    with a reason -- never silently skipped;
  * a duplicated id loads NO copy, so which rules applied never depends on
    file order;
  * a parser id the registry does not know is reported;
  * zero profiles is a normal state, and the app still works;
  * the public profile directory ships no profile at all.

NO REAL DATASET. Every profile here is invented.
"""

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import api  # noqa: E402
import dataset  # noqa: E402
import parsers  # noqa: E402


#: 公開版が標準で同梱するプロファイル（data/profiles/*.json）。今は 0 件。
#: 汎用のプロファイルを同梱すると決めたときにだけ、ここへ名前を足す。
#: 特定のデータセット向けのものは外部フォルダへ置く（docs の開発者ガイド）。
SHIPPED_PROFILES: set[str] = set()


def minimal(**over) -> dict:
    body = {
        "id": "sample-profile",
        "label": "Sample incident logs",
        "match": {"requiredPathPatterns": ["*/evidence/logs.zip"]},
    }
    body.update(over)
    return body


class DirCase(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()

    def put(self, name: str, body, raw: str | None = None) -> str:
        path = os.path.join(self.dir, name)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(raw if raw is not None else json.dumps(body, ensure_ascii=False))
        return path

    def load(self, *dirs):
        return dataset.load_catalog(list(dirs) or [self.dir])


class TestProfileModel(DirCase):

    def test_a_profile_without_year_loads(self):
        self.put("a.json", minimal())
        cat = self.load()
        self.assertEqual(cat.errors, [])
        profile = cat.get("sample-profile")
        self.assertIsNotNone(profile)
        self.assertEqual(profile.edition, "")
        self.assertEqual(profile.metadata, {})
        self.assertIsNone(profile.parsers, "parsers を書かなければ自動判定")
        self.assertEqual(profile.display_label, "Sample incident logs")
        self.assertFalse(hasattr(profile, "year"))

    def test_year_is_not_a_field_and_points_to_edition(self):
        """年度を特別扱いしない。書いてあれば黙って捨てず、edition を案内する。"""
        self.put("a.json", minimal(year=2022))
        cat = self.load()
        self.assertEqual(cat.profiles, [])
        self.assertEqual(len(cat.errors), 1)
        self.assertIn("edition", cat.errors[0].reason)

    def test_edition_is_free_text_and_optional(self):
        for edition in ("v1", "2026 春", "第 3 回", "Round-B"):
            with self.subTest(edition=edition):
                d = tempfile.mkdtemp()
                with open(os.path.join(d, "a.json"), "w", encoding="utf-8") as fh:
                    json.dump(minimal(edition=edition), fh, ensure_ascii=False)
                profile = dataset.load_catalog([d]).get("sample-profile")
                self.assertEqual(profile.edition, edition)
                self.assertEqual(profile.display_label, f"Sample incident logs（{edition}）")

    def test_metadata_is_optional_and_kept(self):
        self.put("a.json", minimal(metadata={"producer": "someone", "description": "x"}))
        profile = self.load().get("sample-profile")
        self.assertEqual(profile.metadata, {"producer": "someone", "description": "x"})

    def test_choices_are_ordered_by_order_then_label_then_id(self):
        self.put("a.json", minimal(id="zeta", label="Zeta", order=2))
        self.put("b.json", minimal(id="alpha", label="Alpha", order=5))
        self.put("c.json", minimal(id="mid-b", label="Mid"))
        self.put("d.json", minimal(id="mid-a", label="Mid"))
        ids = [c["id"] for c in self.load().choices()]
        self.assertEqual(ids, ["zeta", "alpha", "mid-a", "mid-b"])

    def test_the_api_accepts_exactly_the_ids_the_loader_accepts(self):
        self.assertEqual(api.Handler.PROFILE_ID.pattern, dataset.PROFILE_ID)


class TestInvalidProfilesAreReported(DirCase):
    """読めない・不正なプロファイルを、黙って無視しない。"""

    CASES = {
        "not-json.json": (None, "{ this is not json"),
        "not-object.json": (["a"], None),
        "no-id.json": ({k: v for k, v in minimal().items() if k != "id"}, None),
        "bad-id.json": (minimal(id="../escape"), None),
        "no-label.json": ({k: v for k, v in minimal().items() if k != "label"}, None),
        "unknown-key.json": (minimal(pasers=["itm2"]), None),
        "no-match.json": ({k: v for k, v in minimal().items() if k != "match"}, None),
        "empty-required.json": (minimal(match={"requiredPathPatterns": []}), None),
        "bad-pattern.json": (minimal(match={"requiredPathPatterns": [123]}), None),
        "bad-role.json": (minimal(roles={"villain": ["*"]}), None),
        "bad-metadata.json": (minimal(metadata={"k": 1}), None),
        "bad-order.json": (minimal(order="first"), None),
        "empty-parsers.json": (minimal(parsers=[]), None),
        "bad-unsupported.json": (minimal(unsupportedFormats=[{"label": "x"}]), None),
    }

    def test_each_invalid_profile_is_rejected_with_a_reason(self):
        for name, (body, raw) in self.CASES.items():
            self.put(name, body, raw)
        cat = self.load()
        self.assertEqual(cat.profiles, [], [p.id for p in cat.profiles])
        by_source = {e.source: e.reason for e in cat.errors}
        self.assertEqual(set(by_source), set(self.CASES))
        for name, reason in by_source.items():
            with self.subTest(file=name):
                self.assertTrue(reason)

    def test_a_valid_profile_next_to_broken_ones_still_loads(self):
        self.put("good.json", minimal())
        self.put("broken.json", None, "{")
        cat = self.load()
        self.assertEqual([p.id for p in cat.profiles], ["sample-profile"])
        self.assertEqual([e.source for e in cat.errors], ["broken.json"])

    def test_errors_do_not_quote_the_file_contents(self):
        """理由には項目名だけを書き、値や JSON の断片を引用しない。"""
        secret = "do-not-echo-this-value"
        self.put("a.json", minimal(metadata={"k": {"nested": secret}}))
        self.put("b.json", None, '{"id": "x", "label": "' + secret + '", ')
        blob = json.dumps(self.load().errors_json(), ensure_ascii=False)
        self.assertNotIn(secret, blob)

    def test_an_oversized_file_is_refused(self):
        body = minimal(metadata={"description": "x" * 400})
        self.put("big.json", None, json.dumps(body) + " " * dataset.MAX_PROFILE_BYTES)
        cat = self.load()
        self.assertEqual(cat.profiles, [])
        self.assertEqual(cat.errors[0].source, "big.json")

    def test_a_missing_external_directory_is_reported(self):
        missing = os.path.join(self.dir, "does-not-exist")
        cat = dataset.load_catalog([missing])
        self.assertEqual(cat.profiles, [])
        self.assertEqual(len(cat.errors), 1)


class TestDuplicateIds(DirCase):

    def test_duplicates_in_one_directory_load_no_copy(self):
        self.put("a.json", minimal(label="First"))
        self.put("b.json", minimal(label="Second"))
        cat = self.load()
        self.assertEqual(cat.profiles, [])
        self.assertEqual(len(cat.errors), 2)
        for err in cat.errors:
            self.assertIn("重複", err.reason)

    def test_duplicates_across_directories_load_no_copy(self):
        other = tempfile.mkdtemp()
        self.put("a.json", minimal())
        with open(os.path.join(other, "a.json"), "w", encoding="utf-8") as fh:
            json.dump(minimal(label="Other copy"), fh)
        cat = dataset.load_catalog([self.dir, other])
        self.assertEqual(cat.profiles, [])
        self.assertEqual(len(cat.errors), 2)

    def test_unrelated_profiles_survive_a_duplicate(self):
        self.put("a.json", minimal())
        self.put("b.json", minimal())
        self.put("c.json", minimal(id="fine"))
        self.assertEqual([p.id for p in self.load().profiles], ["fine"])


class TestUnknownParserIds(DirCase):
    """未知のパーサー ID は、読み込み時にも生成時にも報告する。"""

    def test_reported_at_load_and_in_the_dataset_view(self):
        self.put("a.json", minimal(parsers=["itm2", "no-such-format"]))
        profile = self.load().get("sample-profile")
        self.assertEqual(profile.unknown_parsers, ["no-such-format"])

        view = dataset.detect(["x/evidence/logs.zip"], profiles=[profile])
        self.assertEqual(view.profile.id, "sample-profile")
        self.assertTrue(any("no-such-format" in w for w in view.warnings), view.warnings)
        info = dataset.dataset_info(view)
        self.assertEqual(info["unknownParsers"], ["no-such-format"])
        self.assertEqual(info["parsers"], ["itm2"])

    def test_reported_by_the_registry_at_generation(self):
        parsed = parsers.REGISTRY.parse_sources({"a.log": "x\n"}, ["itm2", "no-such-format"])
        self.assertEqual(parsed.unknown_parsers, ["no-such-format"])


class TestExternalProfileDirectory(DirCase):
    """外部フォルダは起動時の設定（環境変数）からだけ受け取る。"""

    def tearDown(self):
        dataset.configure_profiles([])

    def test_profiles_from_the_environment_are_loaded(self):
        self.put("a.json", minimal())
        cat = api.configure_profiles_from_env({"DATASET_PROFILE_DIR": self.dir})
        self.assertEqual([p.id for p in cat.profiles], ["sample-profile"])
        self.assertIs(dataset.profile_catalog(), cat)
        view = dataset.detect(["case/evidence/logs.zip"])
        self.assertEqual(view.profile.id, "sample-profile")

    def test_several_directories_can_be_listed(self):
        other = tempfile.mkdtemp()
        self.put("a.json", minimal())
        with open(os.path.join(other, "b.json"), "w", encoding="utf-8") as fh:
            json.dump(minimal(id="second"), fh)
        cat = api.configure_profiles_from_env(
            {"DATASET_PROFILE_DIR": os.pathsep.join([self.dir, other])})
        self.assertEqual(sorted(p.id for p in cat.profiles), ["sample-profile", "second"])

    def test_the_app_starts_with_no_external_profiles(self):
        cat = api.configure_profiles_from_env({})
        self.assertEqual(cat.errors, [])
        # 公開版は標準のプロファイルを同梱しないので、0 件。
        self.assertEqual(cat.profiles, [])

    def test_no_http_route_can_name_a_profile_directory(self):
        """フォルダを受け取る経路は、起動時の環境変数だけ。"""
        for route in api.ROUTES:
            self.assertNotIn("profile", route.pattern.pattern.lower())
        import inspect

        for name in ("h_dataset", "h_generate", "_generate_with"):
            src = inspect.getsource(getattr(api.Handler, name))
            self.assertNotIn("configure_profiles", src)
            self.assertNotIn("PROFILE_DIR", src)


class TestZeroProfilesStillWork(unittest.TestCase):

    def test_detect_and_summarise_with_an_empty_catalog(self):
        view = dataset.detect(["a/b.log", "a/notes.md"], profiles=[])
        self.assertTrue(view.generic)
        body = dataset.summarise(view, [{"name": "a/b.log"}, {"name": "a/notes.md"}],
                                 catalog=dataset.ProfileCatalog())
        self.assertEqual(body["profiles"], [])
        self.assertEqual(body["profileErrors"], [])
        self.assertEqual(body["label"], dataset.GENERIC_LABEL)
        self.assertEqual(body["edition"], "")


class TestPublicBoundary(unittest.TestCase):
    """公開リポジトリが、特定のデータセットを前提にしないこと。"""

    def test_the_public_profile_directory_ships_only_the_allowlist(self):
        """標準のプロファイルフォルダには、許可したものしか置かない。

        特定のデータセット向けのプロファイルがここへ戻ると、公開版が黙って
        そのデータセットを「標準対応」として扱い始める。
        """
        shipped = {
            n for n in os.listdir(dataset.BUILTIN_PROFILE_DIR) if n.endswith(".json")
        }
        self.assertEqual(shipped, SHIPPED_PROFILES,
                         "data/profiles に許可されていないプロファイルがあります")

    def test_every_shipped_profile_loads_cleanly(self):
        cat = dataset.load_catalog([], include_builtin=True)
        self.assertEqual(cat.errors, [])


if __name__ == "__main__":
    unittest.main()
