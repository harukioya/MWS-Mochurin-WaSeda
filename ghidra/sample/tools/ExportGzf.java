// ExportGzf.java — 開発者用。解析済みの Program を GZF として書き出す。
//
// 同梱サンプル（termmines.gzf）を作り直すときだけ、build_sample.py が読み取り
// 専用でマウントして使う。アプリの処理イメージには入れず、利用者の入力に対して
// 使われることはない。書き出すのは Ghidra の解析データベース（GZF）だけで、
// 元の実行ファイルの書き出しや、対象の起動は行わない。
//
//@category Zip2Learn
//@runtime Java

import java.io.File;

import ghidra.app.script.GhidraScript;

public class ExportGzf extends GhidraScript {
	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		if (args.length != 1) {
			throw new IllegalArgumentException("expected <output.gzf>");
		}
		File out = new File(args[0]);
		if (out.exists()) {
			throw new IllegalStateException("output already exists");
		}
		// GzfExporter.export() と同じ処理。エクスポーターは失敗の理由を握りつぶして
		// false だけを返すので、直接呼んで例外をそのまま見えるようにする。
		// Headless はスクリプトをトランザクションの中で動かすが、開いたままでは
		// 保存用のロックを取れない。いったん確定して閉じ、保存後に開き直す。
		end(true);
		try {
			currentProgram.saveToPackedFile(out, monitor);
		}
		finally {
			start();
		}
	}
}
