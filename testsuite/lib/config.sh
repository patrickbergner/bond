# Control-file emission.
#
# Every config this suite writes names outputPath and workPath explicitly, and
# config_new takes them as required arguments so that no case can forget. The
# reason is worth stating: the default for both is {{TOOL_DIR}}, and TOOL_DIR
# is the directory holding the binary – which here is the repository root. A
# config that leaves them out would quietly write containers into the checkout.
#
# Usage:
#
#   config_new "$out" "$work"
#   config_setting '"compressionLevel": 0'
#   config_target photos "$src" '"excludedDirectoryNames": ["thumbs"]'
#   config_write "$cfg"

CONFIG_SETTINGS=""
CONFIG_TARGETS=""
CONFIG_OUT=""
CONFIG_WORK=""

# json_string quotes a value for JSON. Paths in this suite are mixed-mode
# (C:/like/this) precisely so that there are no backslashes to escape, but a
# generator that only works while nobody uses a backslash is a trap for the
# next person.
json_string() {
    printf '"%s"' "$(printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g')"
}

config_new() {
    [ -n "${1:-}" ] || fail "config_new needs an output directory"
    [ -n "${2:-}" ] || fail "config_new needs a work directory"
    CONFIG_OUT="$1"
    CONFIG_WORK="$2"
    CONFIG_SETTINGS=""
    CONFIG_TARGETS=""
}

# config_setting adds one line to the global settings block, given as a raw
# JSON member so a case reads as the JSON it is producing.
config_setting() {
    CONFIG_SETTINGS="${CONFIG_SETTINGS}        $1,
"
}

# config_target adds a target: an id, a source path, and optionally the filter
# members that go beside the path.
config_target() {
    local id="$1" path="$2" filters="${3:-}" extra="${4:-}" source_json

    source_json="            { \"path\": $(json_string "$path")"
    if [ -n "$filters" ]; then
        source_json="${source_json}, $filters"
    fi
    source_json="${source_json} }"

    CONFIG_TARGETS="${CONFIG_TARGETS}        {
            \"id\": $(json_string "$id"),
${extra:+            $extra,
}            \"sources\": [
$source_json
            ]
        },
"
}

# config_target_multi adds a target with several sources, given as a ready
# JSON array body.
config_target_multi() {
    local id="$1" sources="$2" extra="${3:-}"
    CONFIG_TARGETS="${CONFIG_TARGETS}        {
            \"id\": $(json_string "$id"),
${extra:+            $extra,
}            \"sources\": [
$sources
            ]
        },
"
}

config_write() {
    local path="$1"
    [ -n "$CONFIG_TARGETS" ] || fail "config_write: no targets were added"
    mkdir -p "$(dirname "$path")"
    {
        printf '{\n'
        printf '    "targets": [\n'
        printf '%s' "$(strip_trailing_comma "$CONFIG_TARGETS")"
        printf '\n    ],\n'
        printf '    "settings": {\n'
        printf '%s' "$CONFIG_SETTINGS"
        printf '        "outputPath": %s,\n' "$(json_string "$CONFIG_OUT")"
        printf '        "workPath": %s\n' "$(json_string "$CONFIG_WORK")"
        printf '    }\n'
        printf '}\n'
    } >"$path"
}

# strip_trailing_comma removes the comma the last accumulated entry carries.
# Building JSON by concatenation is only tolerable because the alternative –
# depending on jq being installed – would make the suite refuse to run on a
# machine where BOND itself works fine.
strip_trailing_comma() {
    printf '%s' "$1" | sed '$ s/,$//'
}
