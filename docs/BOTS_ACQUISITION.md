# BOTS v3 acquisition and native event export

Task B research is pinned to [Splunk's official repository at commit
5f556f8](https://github.com/splunk/botsv3/tree/5f556f8b4c4ce0bd7498e642fdb52801e89bee0f).
Only its small README/license were read; no archive was downloaded, no Splunk
software installed and no live search executed. Research hashes and availability
checks are in `data/manifests/bots_source_inspection.json`.

The published distribution is a **320.1 MB pre-indexed Splunk TGZ**, not JSONL.
The publisher's MD5 is `d7ccca99a01cff070dff3c139cdc10eb`. Its README links the
archive and prescribes placing its app under `$SPLUNK_HOME/etc/apps` and searching
`index=botsv3 earliest=0`. Archive acquisition and software installation require
separate user authorization. Do not unpack untrusted archives from this pipeline.

The repository carries CC0-1.0. The README's dedication refers to the software;
confirm the actual archive and any third-party notices before approving extracted
events or redistributing derivatives. `botsv3` remains **unapproved** in the source
registry. Do not treat download availability as redistribution or answer approval.

The source's historical environment was Splunk Enterprise **7.1.7**. Significant
listed add-ons include Microsoft Windows **4.8.4**, Microsoft Sysmon **8.0.0**, AWS
**4.5.0**, Stream **7.1.2**, CIM **4.11.0**, Cisco ASA **3.3.0**, Unix/Linux **5.2.4**,
Office 365 **1.0.0**, Microsoft Cloud Services **2.1.0**, Symantec Endpoint Protection
**2.3.0**, and Security Essentials **2.2.0**. Consult the pinned README's complete
required-software table for Code42, Azure, OSquery, GuardDuty and other dependencies.
These are historical parsing requirements, not instructions to install an old
Splunk version now. Different versions may extract different fields; record the
actual lab version and add-ons when exporting and reviewing evidence.

Relevant published sourcetypes include `wineventlog`,
`xmlwineventlog:microsoft-windows-sysmon/operational`, `stream:dns`, `stream:tcp`,
`stream:http`, `aws:cloudtrail`, `aws:cloudwatch:guardduty`, `linux_secure`,
`cisco:asa`, and Microsoft cloud sign-in/audit sources. Do not assume normalized
field names or that every event contains a desired extraction.

The official repository provides installation and event/source descriptions and
links a CTF scoreboard project. It does not supply an approved per-event SOC answer
file for this pipeline. Third-party writeups can inform questions but are not gold
labels or substitutes for the underlying exported evidence.

## Export only authorized, bounded investigations

Use an existing approved Splunk lab. Preserve the original export locally under
`data/local/bots/`. Choose a case time interval, host/scenario scope and fields
after inspecting the actual source. Include these native fields in every row:

`_time`, `index`, `sourcetype`, `host`, `source`, `_raw`, `_bkt`, `_cd`.

Include only extracted fields actually used by the investigation, such as the
observed event-code/account/process/DNS/CloudTrail fields. The pipeline does not
invent aliases or parse arbitrary raw Windows XML into new field names. `_bkt`
and `_cd` identify the original indexed event together; keep their exact values.
Exports that lack native identifiers must be recreated, not assigned row-number IDs.

An example **shape**, to be adapted to the actual case, is:

```spl
index=botsv3 earliest=<CASE_START_EPOCH> latest=<CASE_END_EPOCH> host="<OBSERVED_HOST>"
| table _time index sourcetype host source _raw _bkt _cd <OBSERVED_REQUIRED_FIELDS>
```

The placeholders are not executable SPL. Avoid aggregate-only results that lose
event locators, raw evidence or time context. Record the exact query and whether
the result set was complete. Do not mistake a result cap for all investigation events.

Supported acquisition mechanisms are Splunk Web result export, CLI CSV/JSON export,
or completed REST job results. Splunk's [CLI export documentation](https://help.splunk.com/en/splunk-enterprise/search/search-manual/9.4/export-search-results/export-data-using-the-cli)
defines `-preview`, `-maxout` and `-output`; its default output cap is 100 records.
For an authorized bounded query on an existing lab, the command shape is:

```sh
splunk search "<REVIEWED_BOUNDED_SEARCH>" -preview 0 -maxout 1000 -output csv > events.csv
```

Check the output count and partition the export if that cap is reached; do not
silently accept an incomplete investigation. Use authenticated lab procedures
without putting credentials in shell history, commands, manifests or Git.

For REST, use a completed search job's results with `output_mode=json`, or the
streaming endpoint applicable to the installed version. The [official REST export
guide](https://help.splunk.com/en/splunk-enterprise/search/search-manual/10.4/export-search-results/export-data-using-the-splunk-rest-api)
describes output formats. The [endpoint reference](https://help.splunk.com/en/splunk-enterprise/rest-api-reference/10.2/search-endpoints/search-endpoint-descriptions)
marks the old `search/jobs/export` endpoint deprecated; newer versions use its v2
counterpart. Do not copy an old endpoint blindly. Final result wrappers are
supported; preview rows and error/message-only rows are rejected as evidence.

## Checksum and source manifest

If archive acquisition is later authorized, verify its published MD5 and record a
local SHA256 before import. Independently hash the **exact exported bytes**:

```powershell
Get-FileHash -Algorithm SHA256 -LiteralPath data/local/bots/events.csv
```

Create the export manifest following `schemas/splunk_export_manifest.schema.json`.
Required metadata: source ID `botsv3`; source revision matching `configs/sources.yaml`;
dataset `botsv3`; official source URL; reviewed license; `synthetic: false`; format;
payload SHA256; exact field inventory; query; actual Splunk version; export time
with timezone; and the verified archive MD5. The value in a manifest is an operator
attestation; this pipeline does not claim to have verified an unavailable archive.

Native JSON rows, JSON arrays, `{"results": [...]}` and final REST JSONL
`{"preview": false, "result": {...}}` are supported. CSV headers must match the
declared field inventory. Timestamps must be string ISO-8601 with timezone or finite
epoch seconds. Multivalue extracted JSON fields are preserved. UTF-8 BOM/CRLF source
exports may be read; generated files always use UTF-8 without BOM and LF. Duplicate
JSON keys, conflicting native locators, missing metadata and malformed records fail.

Never commit real raw exports. Only explicitly synthetic event fixtures are allowed
under `data/fixtures/`. Actual candidate/review records and their raw evidence stay
in ignored `data/local/` or `outputs/` directories.
