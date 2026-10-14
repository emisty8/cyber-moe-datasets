# Splunk MCP dataset contracts

No production Splunk MCP schema or callable Splunk tool was provided/found in this
session. `configs/mcp/synthetic-splunk-v1.json` is an **original synthetic test-only**
contract. Its tool names are deliberately prefixed `fixture_`; compatibility with
the user's production MCP server is **unverified**. This code never calls an MCP
server or executes a tool request.

Supply the actual server's `tools/list` declarations as a reviewed local schema
pack conforming to `schemas/mcp_tool_pack.schema.json`: server ID, explicit version,
source URL, `synthetic: false`, exact names, descriptions, `inputSchema`, any known
`outputSchema`, and annotations. Do not rename tools or guess parameter names.
The pack adapter converts those names and JSON Schemas to the tokenizer's function
tool representation. The complete semantic pack has a canonical SHA256 identity.

Each canonical trace retains the server/version/hash reference, declared tool schemas,
assistant call IDs, names/arguments and matching tool results. Arguments must match
the declared schema; missing/orphan/duplicate results fail. Tool output validation
uses the declared output schema when supplied. This adapter currently supports
MCP text-content blocks containing JSON plus an explicit `isError` envelope.
Multimodal and `structuredContent`-only payloads need another reviewed adapter.
Errors are preserved as errors, never interpreted as empty successful evidence.

Non-synthetic gold answers require documented analyst approval. Review binding is
computed by `sample.review_binding()`: it covers user inputs and assistant tool
calls/results; when native event evidence is attached it binds those events and
the MCP schema hash as well. The exact answer string has its own hash. No automatic
source-grounded promotion is allowed for real MCP answers.

The synthetic pilot covers index discovery, sourcetype discovery, bounded search,
empty results, errors, failed/successful-login correlation and structured reporting.
Every synthetic answer keeps attack status unconfirmed. The source/provenance and
schema reference must agree on synthetic status. Schema changes invalidate traces
until revalidated; remote JSON Schema references are forbidden, so validators do
not fetch or execute untrusted schema content.

```powershell
uv run cyber-data validate-mcp data/fixtures/soc/mcp.jsonl --schema configs/mcp/synthetic-splunk-v1.json
```

Search semantics are an explicit pack policy, separate from a tool's generic JSON
argument schema. `search_policies` identifies the **actual** query argument,
observed field inventory and approved indexes/sourcetypes. The conservative SPL
generator supports an explicit index/sourcetype, positive epoch window of at most
24 hours, observed `fields`, and chronological sorting. Wildcards, subsearches,
macros, mutation commands and unrestricted pipes are outside this supported subset.
This is an offline constrained-query validator, not a full SPL parser or proof that
a query is semantically correct for a live deployment. The actual MCP server must
still enforce permissions, limits and read-only execution in the later application.

Tool calibration is rendered with the exact Qwen tokenizer and tool schema into
`content`, because the pinned MLX-FUN loader drops top-level tool schemas on its
chat path. The exporter requires a token-preserving round trip and refuses truncation.
LoRA exports preserve messages/tools, including matching results. Scenario and event
grouping isolate calibration, training, validation and evaluation.

## Production integration needed

Provide the actual schema snapshot/version and approved recorded traces with original
result envelopes, native source event references, source licensing and documented
answer review. Fixture names/results must not be mapped silently into production
names/results. Review index/field/time policies against actual schema and field
discovery. Until then the production tool/MCP contribution remains zero.
