// ExtractStaticFacts.java — GZF に保存済みの解析情報だけを JSON へ書き出す固定スクリプト。
//
// MWS Mochurin WaSeda の Ghidra 静的解析教材が使う。開発側で用意したもので、
// 利用者から差し替えさせない（イメージ内の読み取り専用ディレクトリに置く）。
//
// してよいこと:
//   * 読み込み済みの Program から、関数・命令・定義済み文字列・参照・外部関数を
//     列挙すること。
// してはいけないこと（このファイルに入れない）:
//   * 対象プログラムの起動、エミュレーション（P-code を含む）、デバッガ連携。
//   * Original File 等での元検体の復元・書き出し、メモリ内容の丸ごとの出力。
//   * 自動解析の開始、Program への書き込み、他スクリプトの呼び出し、外部
//     プログラムの起動。
//   * 入力に由来する文字列をコードとして評価すること。
//
// 出力は固定名の 1 ファイルだけ。上限で打ち切った場合は truncated に記録し、
// 完全な解析結果とは名乗らない。列挙順はアドレス順に固定して決定的にする。
//
//@category MWS
//@runtime Java

import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

import ghidra.app.script.GhidraScript;
import ghidra.framework.Application;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.data.StringDataInstance;
import ghidra.program.model.symbol.ExternalLocation;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.util.DefinedStringIterator;
import ghidra.program.util.GhidraProgramUtilities;

public class ExtractStaticFacts extends GhidraScript {

	static final String SCHEMA = "mws-ghidra-static/1";
	static final String SCRIPT_VERSION = "1.0.0";

	// 件数の上限。超えた分は出さず、truncated に記録する。
	static final int MAX_FUNCTIONS = 5000;
	static final int MAX_EXTERNALS = 2000;
	static final int MAX_STRINGS = 5000;
	static final int MAX_STRING_REFS = 10000;
	static final int MAX_CALLS = 20000;
	// 1 項目の文字数の上限。
	static final int MAX_NAME = 256;
	static final int MAX_STRING_VALUE = 512;
	static final int MAX_INSTRUCTION = 160;

	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		if (args.length != 2) {
			throw new IllegalArgumentException("expected <input.gzf> <output.json>");
		}
		Path input = Paths.get(args[0]);
		Path output = Paths.get(args[1]);
		Program program = currentProgram;
		if (program == null) {
			throw new IllegalStateException("no program");
		}

		Json j = new Json();
		j.beginObject();
		j.key("schemaVersion").value(SCHEMA);

		j.key("input").beginObject();
		j.key("sha256").value(sha256(input));
		j.key("bytes").value(Files.size(input));
		j.endObject();

		j.key("tool").beginObject();
		j.key("ghidraVersion").value(Application.getApplicationVersion());
		j.key("scriptVersion").value(SCRIPT_VERSION);
		j.endObject();

		j.key("program").beginObject();
		j.key("name").value(clip(program.getName(), MAX_NAME));
		j.key("languageId").value(program.getLanguageID().getIdAsString());
		j.key("compilerSpecId").value(
			program.getCompilerSpec().getCompilerSpecID().getIdAsString());
		j.key("executableFormat").value(clip(program.getExecutableFormat(), MAX_NAME));
		// 元の実行ファイルについて DB に保存されたハッシュ。入力 GZF のハッシュとは別物。
		j.key("storedExecutableSha256").value(clip(program.getExecutableSHA256(), 64));
		j.key("imageBase").value(addr(program.getImageBase()));
		j.key("analyzed").value(GhidraProgramUtilities.isAnalyzed(program));
		j.endObject();

		Listing listing = program.getListing();
		// 打ち切った項目の名前。同じ名前は一度だけ出す（受け取る側は重複を拒否する）。
		Set<String> truncated = new LinkedHashSet<>();

		// ---- 採用する関数と外部関数を、書き出す前に確定する ----
		// 上限で打ち切ったあとに、一覧に無い関数を参照元・呼び出し先・thunk の
		// 行き先として書くと、受け取る側の整合性検査で出力全体が拒否される。
		// 先に集合を決め、その外を指す記録は書かずに、打ち切りとして記録する。
		List<Function> functions = new ArrayList<>();
		FunctionIterator fit = program.getFunctionManager().getFunctions(true);
		while (fit.hasNext()) {
			monitor.checkCancelled();
			Function f = fit.next();
			if (functions.size() >= MAX_FUNCTIONS) {
				truncated.add("functions");
				break;
			}
			functions.add(f);
		}
		TreeMap<String, Function> allExternals = new TreeMap<>();
		FunctionIterator eit = program.getFunctionManager().getExternalFunctions();
		while (eit.hasNext()) {
			monitor.checkCancelled();
			Function f = eit.next();
			allExternals.put(sortKey(f.getEntryPoint()), f);
		}
		List<Function> externals = new ArrayList<>();
		for (Function f : allExternals.values()) {
			if (externals.size() >= MAX_EXTERNALS) {
				truncated.add("externals");
				break;
			}
			externals.add(f);
		}
		Set<String> emitted = new HashSet<>();
		for (Function f : functions) {
			emitted.add(functionId(f));
		}
		for (Function f : externals) {
			emitted.add(functionId(f));
		}
		// thunk の行き先。一覧にある行き先だけを持つ（呼び出しの resolvedTarget も同じ値を使う）。
		Map<String, String> thunkTargets = new HashMap<>();

		// ---- 関数（内部）----
		j.key("functions").beginArray();
		for (Function f : functions) {
			String fid = functionId(f);
			String target = null;
			if (f.isThunk()) {
				Function thunked = f.getThunkedFunction(true);
				if (thunked != null && emitted.contains(functionId(thunked))) {
					target = functionId(thunked);
					thunkTargets.put(fid, target);
				}
			}
			j.beginObject();
			j.key("id").value(fid);
			j.key("name").value(clip(f.getName(), MAX_NAME));
			j.key("entry").value(addr(f.getEntryPoint()));
			j.key("thunk").value(f.isThunk());
			j.key("thunkTarget").value(target);
			j.endObject();
		}
		j.endArray();

		// ---- 外部関数 ----
		j.key("externals").beginArray();
		for (Function f : externals) {
			ExternalLocation loc = f.getExternalLocation();
			j.beginObject();
			j.key("id").value(functionId(f));
			j.key("name").value(clip(f.getName(), MAX_NAME));
			j.key("library").value(loc == null ? null : clip(loc.getLibraryName(), MAX_NAME));
			j.key("address").value(addr(f.getEntryPoint()));
			j.endObject();
		}
		j.endArray();

		// ---- 定義済み文字列と、関数内の命令からの参照 ----
		j.key("strings").beginArray();
		List<String[]> stringRefs = new ArrayList<>();
		int nStrings = 0;
		for (Data data : DefinedStringIterator.forProgram(program)) {
			monitor.checkCancelled();
			if (nStrings >= MAX_STRINGS) {
				truncated.add("strings");
				break;
			}
			StringDataInstance sdi = StringDataInstance.getStringDataInstance(data);
			String value = sdi == null ? null : sdi.getStringValue();
			if (value == null) {
				continue;
			}
			String sid = "str:" + sortKey(data.getAddress());
			j.beginObject();
			j.key("id").value(sid);
			j.key("address").value(addr(data.getAddress()));
			// 長さは UTF-16 の単位（String.length()）。Python 側も同じ単位で照合する。
			j.key("length").value(value.length());
			j.key("value").value(clip(value, MAX_STRING_VALUE));
			j.key("clipped").value(value.length() > MAX_STRING_VALUE);
			j.endObject();
			nStrings++;

			ReferenceIterator rit = program.getReferenceManager().getReferencesTo(data.getAddress());
			while (rit.hasNext()) {
				Reference ref = rit.next();
				Address from = ref.getFromAddress();
				Instruction ins = listing.getInstructionAt(from);
				Function fn = program.getFunctionManager().getFunctionContaining(from);
				if (ins == null || fn == null) {
					continue;
				}
				if (!emitted.contains(functionId(fn))) {
					// 参照元の関数が一覧の外（関数の打ち切り）。書くと参照先の無い記録になる。
					truncated.add("stringRefs");
					continue;
				}
				if (stringRefs.size() >= MAX_STRING_REFS) {
					truncated.add("stringRefs");
					break;
				}
				stringRefs.add(new String[] {
					sortKey(from), functionId(fn), sid, clip(ins.toString(), MAX_INSTRUCTION),
					addr(from), ref.getReferenceType().getName()
				});
			}
		}
		j.endArray();
		stringRefs.sort((a, b) -> {
			int c = a[0].compareTo(b[0]);
			return c != 0 ? c : a[2].compareTo(b[2]);
		});
		j.key("stringRefs").beginArray();
		for (String[] r : stringRefs) {
			j.beginObject();
			j.key("from").value(r[4]);
			j.key("function").value(r[1]);
			j.key("string").value(r[2]);
			j.key("instruction").value(r[3]);
			j.key("refType").value(r[5]);
			j.endObject();
		}
		j.endArray();

		// ---- 呼び出し命令 ----
		// 一意に解決できた直接呼び出しだけを書き、間接・未解決は件数だけ数える。
		// 命令が存在することと、実行時に呼ばれたことは別であり、ここでは前者しか扱わない。
		// 呼び出し元・呼び出し先の両方が一覧にあるものだけを書く。
		j.key("calls").beginArray();
		int nCalls = 0;
		int indirect = 0;
		int unresolved = 0;
		outer:
		for (Function f : functions) {
			if (f.isThunk()) {
				continue;
			}
			InstructionIterator iit = listing.getInstructions(f.getBody(), true);
			while (iit.hasNext()) {
				monitor.checkCancelled();
				Instruction ins = iit.next();
				FlowType flow = ins.getFlowType();
				if (!flow.isCall()) {
					continue;
				}
				if (flow.isComputed()) {
					indirect++;
					continue;
				}
				Address[] flows = ins.getFlows();
				Function target = flows.length == 1
						? program.getFunctionManager().getFunctionAt(flows[0])
						: null;
				if (target == null) {
					unresolved++;
					continue;
				}
				String targetId = functionId(target);
				if (!emitted.contains(targetId)) {
					truncated.add("calls");
					continue;
				}
				if (nCalls >= MAX_CALLS) {
					truncated.add("calls");
					break outer;
				}
				j.beginObject();
				j.key("from").value(addr(ins.getAddress()));
				j.key("function").value(functionId(f));
				j.key("mnemonic").value(clip(ins.getMnemonicString(), 32));
				j.key("instruction").value(clip(ins.toString(), MAX_INSTRUCTION));
				j.key("target").value(targetId);
				j.key("targetAddress").value(addr(flows[0]));
				j.key("resolvedTarget").value(thunkTargets.get(targetId));
				j.endObject();
				nCalls++;
			}
		}
		j.endArray();
		j.key("callStats").beginObject();
		j.key("indirect").value(indirect);
		j.key("unresolved").value(unresolved);
		j.endObject();

		j.key("truncated").beginArray();
		for (String t : truncated) {
			j.value(t);
		}
		j.endArray();
		// 末尾の印。これが無い出力は途中で切れたものとして扱う。
		j.key("end").value("mws-ghidra-static-end");
		j.endObject();

		// 途中まで書かれたファイルを完成品と取り違えないよう、一時名で書いてから置き換える。
		Path tmp = output.resolveSibling(output.getFileName() + ".part");
		try (OutputStream os = Files.newOutputStream(tmp, StandardOpenOption.CREATE_NEW,
			StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS)) {
			os.write(j.toString().getBytes(StandardCharsets.UTF_8));
		}
		Files.move(tmp, output, StandardCopyOption.ATOMIC_MOVE);
	}

	// ---- helpers --------------------------------------------------------

	static String functionId(Function f) {
		return (f.isExternal() ? "ext:" : "fn:") + sortKey(f.getEntryPoint());
	}

	/** アドレス空間名とゼロ詰めの 16 進。辞書順がアドレス順と一致する。 */
	static String sortKey(Address a) {
		return a.getAddressSpace().getName() + ":" + String.format("%016x", a.getOffset());
	}

	static String addr(Address a) {
		return a == null ? null : sortKey(a);
	}

	/**
	 * max 単位（UTF-16 の単位。String.length() と同じ）までに切り詰める。
	 * サロゲートペアの途中では切らない（切ると壊れた文字が残る）。
	 */
	static String clip(String s, int max) {
		if (s == null) {
			return null;
		}
		if (s.length() <= max) {
			return s;
		}
		int end = max;
		if (end > 0 && Character.isHighSurrogate(s.charAt(end - 1))) {
			end--;
		}
		return s.substring(0, end);
	}

	static String sha256(Path p) throws Exception {
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		try (InputStream in = Files.newInputStream(p, LinkOption.NOFOLLOW_LINKS)) {
			byte[] buf = new byte[65536];
			int n;
			while ((n = in.read(buf)) > 0) {
				md.update(buf, 0, n);
			}
		}
		StringBuilder sb = new StringBuilder();
		for (byte b : md.digest()) {
			sb.append(String.format("%02x", b));
		}
		return sb.toString();
	}

	/** 依存を持たない最小の JSON 書き出し。値は必ずエスケープする。 */
	static final class Json {
		private final StringBuilder sb = new StringBuilder();
		private final List<Boolean> first = new ArrayList<>();
		private boolean afterKey = false;

		private void sep() {
			if (afterKey) {
				afterKey = false;
				return;
			}
			if (!first.isEmpty()) {
				int i = first.size() - 1;
				if (!first.get(i)) {
					sb.append(',');
				}
				first.set(i, false);
			}
		}

		Json beginObject() {
			sep();
			sb.append('{');
			first.add(true);
			return this;
		}

		Json endObject() {
			first.remove(first.size() - 1);
			sb.append('}');
			return this;
		}

		Json beginArray() {
			sep();
			sb.append('[');
			first.add(true);
			return this;
		}

		Json endArray() {
			first.remove(first.size() - 1);
			sb.append(']');
			return this;
		}

		Json key(String k) {
			sep();
			str(k);
			sb.append(':');
			afterKey = true;
			return this;
		}

		Json value(String v) {
			sep();
			if (v == null) {
				sb.append("null");
			}
			else {
				str(v);
			}
			return this;
		}

		Json value(long v) {
			sep();
			sb.append(v);
			return this;
		}

		Json value(boolean v) {
			sep();
			sb.append(v ? "true" : "false");
			return this;
		}

		private void str(String s) {
			sb.append('"');
			for (int i = 0; i < s.length(); i++) {
				char c = s.charAt(i);
				switch (c) {
					case '"':
						sb.append("\\\"");
						break;
					case '\\':
						sb.append("\\\\");
						break;
					default:
						if (c < 0x20 || c == 0x2028 || c == 0x2029 || Character.isSurrogate(c)) {
							sb.append(String.format("\\u%04x", (int) c));
						}
						else {
							sb.append(c);
						}
				}
			}
			sb.append('"');
		}

		@Override
		public String toString() {
			return sb.toString();
		}
	}

}
