# Append-only change: add these two barrel exports to the end of src/tools/index.ts
# (existing exports are unchanged; no line numbers assumed since the module is new).
+export * from "./security/bug-bounty";
+export * from "./descriptions/bug-bounty";
