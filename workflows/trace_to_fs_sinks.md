# Trace Routes to Filesystem Sinks (Generic)

See also: `tool-notes/IDA_MCP.md` for IDA MCP command cheatsheet and action snippets.

Goal: From dispatchers, walk down the call graph to where user‑controlled paths hit filesystem APIs.

Steps
1) From a dispatcher function:
   - Enumerate callees and classify: router→handler, handler→path utility, sink wrapper
2) Identify sinks
   - Confirm via imports: open/fopen/stat/access/SendFile‑like
3) Build a 2–3 hop path
   - Dispatcher → static handler → path builder → sink wrapper → import
4) Record controls on the path
   - Is there URL decoding, per‑segment validation, canonicalization (realpath), base prefix enforcement before the sink? If not, note the gap.
