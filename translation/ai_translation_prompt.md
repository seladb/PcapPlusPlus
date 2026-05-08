# AI Translation Sync Instructions

This document is the canonical instruction set for any AI agent (Claude, Codex, Gemini, GPT, or any other automated assistant) tasked with keeping the translated README files under `translation/` in sync with the authoritative English [`README.md`](../README.md) at the repository root.

Treat this file as a contract: follow every step, do not skip any verification, and do not deviate from the rules below.

## 1. Scope and Source of Truth

- **Single source of truth:** `/README.md` at the repository root (English) is the only canonical version. All files under `/translation/` are derivative translations of it.
- **Translated files in scope** (auto-discover; do not hard-code):
  - Any file matching `translation/README-*.md` (no other suffix patterns).
  - This file (`translation/ai_translation_prompt.md`) is itself **out of scope** — it is an instruction document, not a translation.
  - At the time of writing this includes:
    - `translation/README-zh-tw.md` — 正體中文 (Traditional Chinese)
    - `translation/README-kor.md` — 한국어 (Korean)
- For each discovered file, validate that it is a real translation by confirming **both**:
  1. The English `README.md` `Translations:` line links to it (or — for legacy files such as `README-kor.md` whose suffix doesn't match a standard locale code — that the file's own `Translations:` line and at least one sibling translation's `Translations:` line reference it consistently).
  2. The file contains a `Translations:` line that lists the same set of sibling files as the English source.
- If new `translation/README-*.md` files are added in the future, they automatically fall under this instruction and must be checked the same way. Adding a new translation requires updating the `Translations:` line in **every** existing README (English and all sibling translations) in the same change.

### 1.1 Mandatory "Synced using AI" caution

Every translated file under `translation/` (every `README-*.md`) **must** begin with a localized caution stating the file is maintained and synchronized using AI. This notice does **not** appear in the English `README.md` — it is intentionally only present in the translations.

- **Placement:** the notice is the **very first content** in the file, before the `<div align="center">` badges block, separated from the rest of the file by a blank line.
- **Format:** a single Markdown blockquote line beginning with `> ⚠️` (warning emoji), followed by a **bold** localized lead-in label (e.g. `**注意：**`, `**참고:**`, `**Note:**`), then plain prose that explicitly states the file is maintained / synchronized using AI and points readers at GitHub for corrections. The literal token `AI` must appear in the prose (uppercase Latin), but does not need to be inside the bold lead-in.
- **Language:** localized into the language of the file. The phrase that conveys "using AI" may be rendered in the target language (e.g. `AI 協助`, `AI를 사용하여`, `mediante IA`) as long as the meaning is preserved and the token `AI` remains uppercase Latin.
- **Update on every sync run:** if the notice is missing, malformed, or has drifted from the canonical wording in any sibling translation, restore it as part of Step 5.

Reference snippets (canonical at the time of writing — match tone, do not reword unless the existing translation already uses different phrasing):

```markdown
> ⚠️ **注意：** 本翻譯由 AI 協助維護與同步，可能與最新的英文版本存在差異。若您發現任何錯誤，歡迎開立 GitHub issue 或提交 PR。
```

```markdown
> ⚠️ **참고:** 이 번역은 AI를 사용하여 유지·동기화되며, 최신 영어 버전과 차이가 있을 수 있습니다. 부정확한 내용을 발견하시면 GitHub 이슈를 등록하거나 PR을 제출해 주세요.
```

For any future language without a reference snippet here, follow the same template: warning emoji + bold lead-in containing the localized "using AI" + one short sentence pointing readers at GitHub for corrections.

## 2. Trigger — When to Run This Procedure

Run the full sync procedure whenever **any** of the following is true:

1. The user asks to "update translations", "sync translations", "check translations", or anything semantically equivalent.
2. The English `README.md` has any uncommitted modification in the working tree, **or** has been modified in the current branch relative to the PR base branch (when running on a PR) or the repo's default branch (when no explicit base is given).
3. A new translated README is added under `translation/`, or any existing `translation/README-*.md` file is modified.
4. This contract file (`translation/ai_translation_prompt.md`) is modified — re-verify all translations under the new rules.
5. A periodic / scheduled translation audit is triggered.

If unsure whether a run is needed, run it. False positives are cheap; stale translations are not.

If `git` state is inconclusive (detached HEAD, no remote, fetch failure), fall back to comparing the working-tree `README.md` against each translation directly — never silently skip the run.

## 3. Required Workflow

Follow these steps **in order**. Do not skip steps even if you believe a translation is already up to date.

### Step 1 — Read the English source in full

1. Read `README.md` from the repository root, top to bottom, with no truncation.
2. Build an internal section-by-section outline of:
   - Title and badges block
   - Intro paragraphs
   - Translations link line (`Translations: ...`)
   - Table of Contents
   - Every `##` and `###` section, in order
   - Every numbered list item (especially in "Supported Network Protocols")
   - Every code block (verbatim — code must NOT be translated)
   - Every link, image, and shield URL
   - Footer / License section

### Step 2 — Enumerate all translated files

1. List every file matching `translation/README-*.md`.
2. For each translated file, record its target language (inferred from the filename suffix and the `Translations:` line).

### Step 3 — Diff each translation against English

For **each** translated file, perform a structural and semantic diff against the English source. The translation is considered **in sync** only if **all** of the following hold:

| Check | Requirement |
|-------|-------------|
| AI sync caution | The file begins with the mandatory "Synced using AI" notice described in Section 1.1, in the correct language and format, before the badges block. |
| Section structure | Every `##` / `###` heading in English has a corresponding heading in the translation, in the same order. |
| Table of Contents | TOC entries match the section headings present in the translated file, and every TOC anchor resolves to a heading **in the same file**. See "Anchor handling" below for the exact slug rules. |
| Numbered lists | Counts match exactly (e.g. the protocol list must have the same number of items, in the same order, with the same numbering). |
| Code blocks | Identifiers, type names, function names, namespaces, file paths, CLI commands, shell flags, library calls, and import statements are **identical** to English (untranslated). Fence info strings (` ```cpp `, ` ```shell `, ` ```text `) are also identical. Code **comments** and human-readable demo strings (e.g. `std::cerr << "..."` example output) MAY be translated, provided the choice is applied consistently across the file. Compiler diagnostics, tool output that the reader will literally see (e.g. `✓ Verification succeeded!`), and exact reproduction strings must remain in English. |
| External URLs | Every external URL (links to docs, GitHub, shields.io image URLs, badge destination URLs, image `src`) is **byte-identical** to English. |
| Internal Markdown anchors | Same-file anchors (`#section`) point to the **translated** heading slug, regenerated using GitHub's slug rules (see "Anchor handling" below). Anchors that point into other files (e.g. `../README.md#download`) keep the English slug. |
| HTML embeds | All raw HTML elements (`<div>`, `<picture>`, `<source>`, `<img>`, `<br>`, etc.) match English in element order, nesting, and non-prose attributes (`src`, `srcset`, `media`, `width`, `height`, `style`). The `alt` attribute MAY be translated (see "Badge alt text" below); all other attributes must be byte-identical. |
| Inline technical terms | Library names, protocol names (TCP, IPv4, DPDK, PF_RING, eBPF AF_XDP, JA3, etc.), product names, file names, and API names are kept in English / original casing. |
| Semantic content | Every paragraph in English has a corresponding translated paragraph conveying the same meaning. No content added, removed, or silently reordered. |
| Badges block | Every shields.io / badge image line in English has a corresponding line in the translation, in the same order, with byte-identical image URL and destination URL. Alt / label text inside the badge `[...]` may be localized (see "Badge alt text" below). |
| Markdown structure | Tables (column counts, alignment markers), blockquotes, emphasis (`*`/`_`), strong (`**`/`__`), horizontal rules (`---`), nested list indentation, and link reference definitions all match English structurally. |
| `Translations:` line | Lists the same set of languages as English, with the current language shown as plain text (not a link) and the others as relative links to the correct sibling files. |
| Trailing whitespace / final newline | File ends with a single trailing newline, matching repo style. |

If any check fails, the translation is **out of sync** and must be updated.

#### Anchor handling

GitHub renders Markdown anchors using the [github-slugger](https://github.com/Flet/github-slugger) algorithm. A translated heading produces a different slug than its English counterpart, so TOC anchors **must be regenerated per file**.

The algorithm, in order:

1. **Lowercase via `String.prototype.toLowerCase()`** — this lowercases ASCII Latin **and** accented Latin (so `É` → `é`). CJK, Hangul, Hiragana, Katakana, Cyrillic without case, etc. are preserved unchanged.
2. **Strip punctuation** — remove ASCII punctuation that has no semantic role in URLs, including: `` ` ``, `'`, `"`, `,`, `.`, `:`, `;`, `!`, `?`, `(`, `)`, `[`, `]`, `{`, `}`, `<`, `>`, `/`, `\`, `|`, `@`, `#`, `$`, `%`, `^`, `&`, `*`, `+`, `=`, `~`. **Keep** `-` and `_` and word characters. CJK / Hangul punctuation (`、`, `。`, `「」`, `（）`, etc.) is **also stripped** by github-slugger when it falls outside the kept-character set — when in doubt, drop it.
3. **Replace each whitespace character with a single `-`** — this is per-character, not per-run, so `A   B` (3 spaces) becomes `a---b` (3 hyphens). Existing `-` sequences are **not** collapsed.
4. **Duplicate suffix** — if the resulting slug already appears earlier in the same file, append `-1`, `-2`, ... in order of occurrence.
5. **No percent-encoding in the source** — write the raw Unicode (e.g. `#資料連接層-l2`); GitHub does the encoding at render time.

Worked examples:

| Heading | Slug |
|---------|------|
| `## Download` | `#download` |
| `## 下載` | `#下載` |
| `## 다운로드` | `#다운로드` |
| `### Homebrew` | `#homebrew` |
| `## DPDK And PF_RING Support` | `#dpdk-and-pf_ring-support` |
| `### 資料連接層 (L2)` | `#資料連接層-l2` |
| `## Q&A` | `#qa` |
| `## A & B` | `#a--b` (note the **double** hyphen — `&` is stripped, the two surrounding spaces each become `-`) |
| `## Café` | `#café` (`É` is lowercased; the diacritic is preserved) |

Anchors that target a heading in another file (`../README.md#feature-overview`) are external references and keep the **English** slug — do not localize them.

If a heading contains characters not covered by the table above (e.g. emoji, unusual punctuation), reproduce github-slugger's output rather than guessing — when uncertain, run it through the library or simplify the heading.

#### Badge alt text

Shields.io badges have the form `[![alt](image-url)](destination-url)`.

- `image-url` and `destination-url` must be byte-identical to English.
- The `alt` text inside `[...]` may be translated for accessibility (e.g. `[![GitHub 貢獻者](...)](...)`), provided the translation is consistent across the file and matches existing tone in that translated README.
- The same rule applies to `alt=` attributes on raw `<img>` tags.

### Step 4 — Report findings before editing

Before making any edits, produce a short report to the user containing, per translated file:

- ✅ in sync, or ❌ out of sync
- If out of sync: a bulleted list of concrete discrepancies (e.g. "missing section `## Benchmarks`", "protocol list has 54 items, English has 56", "code block on line 140 has been translated and must be reverted").

Do not begin editing until the user has seen this report — unless the user has explicitly pre-authorized autonomous updates in the same request.

### Step 5 — Update out-of-sync translations

When updating:

1. Edit only the translated files. **Never edit the English `README.md`** as part of a sync run.
2. Preserve the file's existing translation style, terminology, and tone. Read the surrounding paragraphs to match voice before introducing new translated text.
3. Translate **prose only**. Do **not** translate:
   - Inline code (anything inside `` ` ``).
   - Identifiers, type names, function names, file paths, CLI flags, shell commands, namespaces, import statements.
   - Fence info strings (the language tag right after ` ``` `).
   - Protocol names, library names, product names, brand names.
   - External URLs, badge image URLs, badge destination URLs, and any anchor that targets another file.
   - HTML attributes other than `alt` (see "HTML embeds" and "Badge alt text" in Step 3).
   - Verbatim tool output the reader will literally see (e.g. `✓ Verification succeeded!`).
4. **May** be translated — apply consistently across the file:
   - Prose, headings, list item text (the human-readable parts).
   - The `alt` text inside Markdown images / shields.io badges and the `alt=` attribute on raw `<img>` tags.
   - Same-file Markdown anchor slugs in the TOC, regenerated from the translated heading via the slug rules in Step 3.
   - Comments inside code blocks (`// ...`, `# ...`, `/* ... */`).
   - Human-readable demo string literals in code blocks (e.g. the message in `std::cerr << "Error opening the pcap file"`) — translate or keep, but do not mix within a single file.
5. Keep all Markdown structure identical to English: same heading levels, same list ordering and numbering, same table layouts, same blockquote usage, same horizontal rules, same emphasis/strong markers.
6. Update anchors in the Table of Contents so that they match the translated heading slugs in that file's language. Anchors that point into other files keep the English slug.
7. Maintain the `Translations:` line so the current file's language appears as plain text and all sibling languages appear as working relative links.
8. Do not introduce new sections, remove existing ones, or reorder them unless the English source did so first.

### Step 6 — Re-verify after editing

After edits, repeat Step 3 against the updated file. The run is complete only when every translated file passes every check.

### Step 7 — Summarize the diff to the user

Produce a final concise summary listing, per file:

- Whether it was already in sync or was updated.
- A one-line description of what changed (e.g. "added new `### Cryptographic key decoders` entry, refreshed protocol list 36–56").

## 4. Hard Rules (Do / Don't)

**Do:**

- Read the entire English `README.md` every run. Do not rely on memory or cached summaries.
- Auto-discover translation files via `translation/README-*.md` glob.
- Preserve all Markdown, HTML (`<picture>`, `<source>`, `<img>`, `<div>`), and badge syntax verbatim.
- Keep numbered list counts and ordering aligned with English.
- Match the tone and terminology already established in each translated file.

**Don't:**

- Don't translate code, identifiers, external URLs, protocol names, or brand names.
- Don't edit `README.md` as part of a translation sync.
- Don't add disclaimers, footers, or new sections that don't exist in English — **except** the mandatory "Synced using AI" caution required by Section 1.1, which is the only allowed translation-only addition and must appear at the top of every translated file.
- Don't reorder sections or list items.
- Don't change badge image URLs or destination URLs, and don't change cross-file anchor targets (e.g. links into the docs site or `../README.md`).
- Don't drop the `Translations:` line or break its sibling links.
- Don't silently fix typos or stylistic issues in English while doing a translation pass — raise them separately.
- Don't reuse English anchor slugs for same-file TOC links — regenerate them from the translated heading.

## 5. How to Invoke This Instruction

Any AI agent (Claude, Codex, Gemini, GPT, or other) can be pointed at this file and told:

> "Follow `translation/ai_translation_prompt.md` to verify and, if needed, update every file under `translation/` against the latest `README.md`."

The agent must then execute Sections 3.1 through 3.7 in order and produce the reports described in Steps 4 and 7.

## 6. Maintenance of This File

If the structure of `README.md` changes in a way that affects how translations should be verified (for example, a new top-level convention is added, or a new file pattern is introduced under `translation/`), update Sections 1 and 3 of this document **in the same change** so future agents see the new rules.
