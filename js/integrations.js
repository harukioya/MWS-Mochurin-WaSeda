// integrations.js — OPTIONAL, KEY-GATED cloud helpers. NOT on the default runtime path.
// =============================================================================
// These functions are OFF BY DEFAULT and are NEVER auto-called by the app.
// The lesson player runs entirely on the synthetic JSON in data/lessons/ and
// does not import or invoke anything here. A developer would have to wire these
// in deliberately AND supply their own API key at call time.
//
// HARD SAFETY (non-negotiable):
//   - Hash-lookup ONLY. These functions NEVER upload, submit, download, execute,
//     detonate, or reconstitute a sample. They pass a hash string and read a
//     report that a third-party sandbox already produced.
//   - No secrets in this file. Keys are passed in as arguments by the caller;
//     nothing is hardcoded, cached, or persisted here.
//   - With no key, each function logs a clear note and returns null — the app's
//     synthetic lessons remain the only data path.
// =============================================================================

/**
 * Fetch a behavior report for an already-known file hash and normalize it into
 * the lesson "stages" shape. HASH LOOKUP ONLY — never uploads a sample.
 *
 * @param {string} hash   - SHA-256 / SHA-1 / MD5 of a sample already in VT.
 * @param {string} apiKey - The caller's own VirusTotal API key. If absent, returns null.
 * @returns {Promise<Array|null>} normalized stages, or null when disabled/unavailable.
 *
 * HOW THIS WOULD WORK (documented, not on the default path):
 *   1. GET https://www.virustotal.com/api/v3/files/{hash}/behaviours
 *        headers: { 'x-apikey': apiKey }
 *      This reads an EXISTING behavior report keyed by hash. It sends only the
 *      hash — no file bytes ever leave the machine, so no sample is uploaded.
 *   2. The response groups events by sandbox. For each behavior event we would
 *      map it into the lesson event shape used everywhere else in the app:
 *          { type, detail, attck: { id, name } }
 *      Rough field mapping per VT behaviour report:
 *        - processes_created / command_executions  -> type: "process"
 *        - files_written / files_dropped           -> type: "file"
 *        - registry_keys_set                        -> type: "registry"
 *        - dns_lookups / ip_traffic / http_conversations -> type: "network"
 *        - modules_loaded / calls                   -> type: "api" / "import"
 *      The ATT&CK tag comes from the report's own mitre_attack_techniques[]
 *      entries ({ id, signature_description }) -> { id, name }, so the tag is
 *      ground-truth from the sandbox, not inferred by us.
 *   3. Group the normalized events into a small number of stages (surface,
 *      launch, recon, persistence, exfil) by ATT&CK tactic, matching the
 *      lesson schema in data/lessons/lesson-01.json.
 *
 * The body below is intentionally a stub: it never performs the network call in
 * this build. It only demonstrates the safe contract (key check + null return).
 */
export async function fetchTraceByHash(hash, apiKey) {
  if (!apiKey) {
    console.info(
      '[integrations] fetchTraceByHash is disabled: no API key supplied. ' +
        'This app runs on synthetic lessons only; returning null. ' +
        '(If enabled, this would read a VirusTotal behaviour report by hash — ' +
        'hash lookup only, never uploading any sample.)'
    );
    return null;
  }

  // --- Reference implementation, NOT executed in this build ------------------
  // Uncomment deliberately, at your own risk, with your own key. Hash lookup
  // only; this must never be changed into an upload/submit call.
  //
  // const url = `https://www.virustotal.com/api/v3/files/${encodeURIComponent(hash)}/behaviours`;
  // const res = await fetch(url, { headers: { 'x-apikey': apiKey } });
  // if (!res.ok) return null;
  // const report = await res.json();
  // return normalizeBehaviourReport(report);
  // ---------------------------------------------------------------------------

  console.info(
    '[integrations] fetchTraceByHash: live lookup is stubbed out in this build. ' +
      'Returning null so the app keeps using synthetic lessons only.'
  );
  return null;
}

/**
 * Turn a lesson's ground-truth events into a grounded multiple-choice quiz.
 * Without an LLM key, returns null (the app ships hand-authored quizzes).
 *
 * @param {Array}  events - lesson events: [{ type, detail, attck: { id, name } }]
 * @param {Object} opts   - { apiKey, model, ... } caller-supplied; no defaults with secrets.
 * @returns {Promise<Object|null>} a quiz { q, options, correct, explain } or null.
 *
 * HOW THIS WOULD WORK (documented, not on the default path):
 *   - The ANSWER KEY is derived from the data, never from the model. We pick the
 *     single most diagnostic ATT&CK-tagged event as the ground truth, and the
 *     `correct` index and `explain` are built from that event's attck.{id,name}
 *     and detail — so correctness cannot drift even if the model hallucinates.
 *   - The LLM is used ONLY to phrase a natural-language question stem and to
 *     generate plausible-but-wrong distractor option text. Its output is then
 *     validated: the correct option must restate the ground-truth event, and
 *     distractors must NOT match the true ATT&CK technique. If validation fails,
 *     return null rather than emit an ungrounded quiz.
 *   - opts.apiKey is the caller's LLM key, used transiently and never stored.
 */
export async function generateQuizFromEvents(events, opts) {
  const apiKey = opts && opts.apiKey;
  if (!apiKey) {
    console.info(
      '[integrations] generateQuizFromEvents is disabled: no LLM key supplied. ' +
        'The app uses hand-authored, ATT&CK-grounded quizzes; returning null.'
    );
    return null;
  }

  // --- Reference sketch, NOT executed in this build --------------------------
  // 1. groundTruth = pickMostDiagnostic(events);  // the attck-tagged event
  // 2. prompt the model ONLY for question wording + distractors (given groundTruth.detail).
  // 3. build quiz: correct answer = restatement of groundTruth; correct index fixed by us.
  // 4. validate distractors don't collide with groundTruth.attck; else return null.
  // ---------------------------------------------------------------------------

  console.info(
    '[integrations] generateQuizFromEvents: LLM generation is stubbed out in this build. ' +
      'Returning null so hand-authored quizzes remain the source of truth.'
  );
  return null;
}
