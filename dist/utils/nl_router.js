// extremely lightweight NL parser for common intents
export function parseNL(nl) {
    const s = (nl || "").toLowerCase();
    const pick = (arr) => arr.find(k => s.includes(k));
    const action = pick(["discover"]) ? "discover" :
        pick(["preview", "dry run"]) ? "preview_import" :
            pick(["import", "steal", "grab", "bring in"]) ? "import_tools" :
                pick(["update", "sync"]) ? "update_tools" :
                    pick(["remove", "delete", "drop"]) ? "remove_tools" :
                        pick(["list sources", "sources"]) ? "list_sources" :
                            pick(["list tools", "list local"]) ? "list_local" :
                                pick(["enable"]) ? "enable" :
                                    pick(["disable"]) ? "disable" :
                                        pick(["rename"]) ? "rename" :
                                            pick(["move"]) ? "move" :
                                                pick(["export"]) ? "export" :
                                                    pick(["deprecate"]) ? "deprecate" :
                                                        undefined;
    const params = { action };
    const prefix = s.match(/prefix\s+([a-z0-9_]+)/);
    if (prefix)
        params.prefix = prefix[1];
    const include = [...s.matchAll(/include\s+([a-z0-9_.*-]+)/g)].map(m => m[1]);
    if (include.length)
        params.include = include;
    const exclude = [...s.matchAll(/exclude\s+([a-z0-9_.*-]+)/g)].map(m => m[1]);
    if (exclude.length)
        params.exclude = exclude;
    if (s.includes("dry run") || s.includes("dry-run"))
        params.dry_run = true;
    if (s.includes("force"))
        params.force = true;
    const sourceUrls = [...s.matchAll(/https?:\/\/\S+/g)].map(m => m[0]);
    if (sourceUrls.length)
        params.sources = sourceUrls;
    const rename = s.match(/rename\s+([a-z0-9_.*-]+)\s+to\s+([a-z0-9_.*-]+)/);
    if (rename) {
        params.tool = rename[1];
        params.new_name = rename[2];
    }
    const enableM = s.match(/enable\s+([a-z0-9_.*-]+)/);
    if (enableM)
        params.tool = enableM[1];
    const disableM = s.match(/disable\s+([a-z0-9_.*-]+)/);
    if (disableM)
        params.tool = disableM[1];
    const moveM = s.match(/move\s+([a-z0-9_.*-]+)\s+to\s+([a-z0-9_./-]+)/);
    if (moveM) {
        params.tool = moveM[1];
        params.dest_dir = moveM[2];
    }
    const exportM = s.match(/export\s+([a-z0-9_.*-]+)\s+to\s+([a-z0-9_./:-]+)/);
    if (exportM) {
        params.tool = exportM[1];
        params.export_path = exportM[2];
    }
    return params;
}
