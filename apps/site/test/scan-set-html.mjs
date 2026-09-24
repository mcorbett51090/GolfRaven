/**
 * AT(7): finds every `set:html` USE in an `.astro` source file, in any
 * syntactic form — an expression (`set:html={EXPR}`, brace-matched so a
 * nested `{}` inside `EXPR` doesn't truncate the match), a string literal
 * (`set:html="…"` / `set:html='…'`), or a spread-embedded key
 * (`{...{ "set:html": EXPR }}`) — while ignoring the bare word appearing
 * in PROSE (a doc comment saying "the set:html directive" has no `=` or
 * `:` immediately following the token, so it's never mistaken for a use).
 *
 * Exported so both the real-source-tree assertion AND the
 * scratch-mutated-copy proof (that the detector actually catches each
 * form, not just that none happen to exist today) run the exact same
 * logic.
 */
export function findSetHtmlOccurrences(content) {
  const results = [];
  const token = "set:html";
  let searchFrom = 0;

  while (true) {
    const idx = content.indexOf(token, searchFrom);
    if (idx === -1) break;
    const before = idx > 0 ? content[idx - 1] : "";
    const afterToken = idx + token.length;

    let i = afterToken;
    while (i < content.length && /\s/.test(content[i])) i++;
    const nextChar = content[i];

    if (nextChar === "=") {
      let j = i + 1;
      while (j < content.length && /\s/.test(content[j])) j++;
      if (content[j] === "{") {
        let depth = 0;
        let k = j;
        for (; k < content.length; k++) {
          if (content[k] === "{") depth++;
          else if (content[k] === "}") {
            depth--;
            if (depth === 0) break;
          }
        }
        results.push({
          form: "expr",
          raw: content.slice(j + 1, k).trim(),
          full: content.slice(idx, k + 1),
        });
        searchFrom = k + 1;
        continue;
      }
      if (content[j] === '"' || content[j] === "'") {
        const quote = content[j];
        let k = j + 1;
        while (k < content.length && content[k] !== quote) k++;
        results.push({
          form: "string",
          raw: content.slice(j + 1, k),
          full: content.slice(idx, k + 1),
        });
        searchFrom = k + 1;
        continue;
      }
      // `set:html=` followed by neither `{` nor a quote — still a real
      // attribute use (e.g. a bare/unquoted value); record it generically
      // rather than silently skipping.
      results.push({ form: "other", raw: "", full: content.slice(idx, i + 40) });
      searchFrom = i + 1;
      continue;
    }

    if ((before === '"' || before === "'") && content[afterToken] === before) {
      // Object-KEY form, e.g. `"set:html": EXPR` (typically reached via a
      // spread: `{...{ "set:html": EXPR }}`) — the key is immediately
      // closed by the same quote it opened with, then a colon.
      let k = afterToken + 1;
      while (k < content.length && /\s/.test(content[k])) k++;
      if (content[k] === ":") {
        results.push({ form: "spread-key", raw: "set:html", full: content.slice(idx - 1, k + 1) });
        searchFrom = k + 1;
        continue;
      }
    }

    // Plain prose ("the set:html directive…") — not a use. Advance past
    // the token and keep scanning.
    searchFrom = afterToken;
  }

  return results;
}

/** True for the one sanctioned use: `set:html={ldScript}` (an EXPR form
 * whose expression is exactly the identifier `ldScript`). */
export function isSanctionedSetHtml(occurrence) {
  return occurrence.form === "expr" && occurrence.raw === "ldScript";
}
