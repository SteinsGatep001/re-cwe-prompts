# Trace Routes to Filesystem Sinks (Generic)

Goal: From route dispatchers, walk down the call graph to find where user-controlled paths hit filesystem APIs.

Steps (ida-pro-mcp)
1) From a dispatcher function address:
   - `get_callees(<dispatcher_addr>)` to list children
   - For each child, decide: router→handler, handler→path utility, or sink wrapper

2) Identify sinks
   - Use `list_imports` and scan for FS primitives: open, fopen, __xstat, stat, access, read/open wrappers.
   - Decompile suspected sink wrappers: `decompile_function(<addr>)` and confirm they lead to FS calls.

3) Build a 2–3 hop path
   - Dispatcher → static handler → path builder → FS sink wrapper → FS import
   - Record whether decoding, segment validation, realpath/prefix checks occur before the FS sink.

4) Mark sanitizers
   - Find URL-decoding utilities and per-segment validators (search strings like `%2e`, references to dot checks, or code rejecting control chars).
   - Confirm these are actually invoked on the path reaching the sink.

5) Capture gaps via comments
   - Where validation is missing or occurs after FS calls, add `set_comment` noting the gap and suggested preconditions.

