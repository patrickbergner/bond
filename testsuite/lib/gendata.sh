# Test-tree generation.
#
# The shape is deterministic and the bytes are not, and the split is
# deliberate. Shard counts and volume boundaries have to mean the same thing on
# every run or a damage test aimed "well inside the second volume" lands
# somewhere different each time – so names, sizes and the tree's structure come
# from a seeded $RANDOM. The contents come from /dev/urandom, so that no case
# can pass because the data happened to be predictable.
#
# Set BOND_TEST_SEED to reshape every tree in the suite. Nothing here is
# committed; it all lives under testsuite/tmp and goes away when a case passes.

# A line of prose to build compressible content from. Real text, because
# "aaaaaaaa" compresses in a way nothing an operator owns ever does.
GEN_CORPUS='Es ist ein kapitaler Fehler, eine Theorie aufzustellen, bevor man entsprechende Anhaltspunkte hat. Unbewußt beginnt man Fakten zu verdrehen, damit sie zu den Theorien passen, statt daß die Theorien zu den Fakten passen – Arthur Conan Doyle. '

seed_rng() {
    RANDOM="$1"
}

# rand_between prints a number in [lo, hi]. $RANDOM is 15 bits, so two draws
# are combined for the ranges this suite needs.
#
# The three assignments are three statements on purpose: bash expands every
# word of a `local` before it runs, so `local hi="$2" span=$(( hi - 1 ))` reads
# the caller's `hi`, not the one being declared on the same line.
rand_between() {
    local lo="$1" hi="$2"
    local span=$(( hi - lo + 1 ))
    local draw=$(( (RANDOM << 15 | RANDOM) % span ))
    printf '%s\n' "$(( lo + draw ))"
}

# gen_blob writes a file of exactly BYTES.
#
#   gen_blob PATH BYTES [random|text|mixed]
#
# random is incompressible, text compresses to almost nothing, and mixed is
# what a real backup mostly is: a bit of both.
gen_blob() {
    local path="$1" bytes="$2" kind="${3:-mixed}" half
    mkdir -p "$(dirname "$path")"
    case "$kind" in
        random)
            head -c "$bytes" /dev/urandom >"$path"
            ;;
        text)
            yes "$GEN_CORPUS" | head -c "$bytes" >"$path"
            ;;
        mixed)
            half=$(( bytes / 2 ))
            head -c "$half" /dev/urandom >"$path"
            yes "$GEN_CORPUS" | head -c $(( bytes - half )) >>"$path"
            ;;
        *)
            fail "gen_blob: unknown kind $kind"
            ;;
    esac
}

# gen_tree fills DIR with roughly SIZE_KB of files.
#
#   gen_tree DIR SIZE_KB [plain|awkward]
#
# plain is shaped like the thing people actually back up: documents, dated
# photo directories, and a few big opaque files. awkward adds the entries that
# break archivers, the same set internal/backup's fixture() covers – an empty
# file, non-ASCII names, a deep path, something incompressible and something
# that compresses to nothing – because a suite that only ever sees tidy input
# proves the tool works on input nobody has.
gen_tree() {
    local dir="$1" size_kb="$2" flavour="${3:-plain}"
    local remaining=$(( size_kb * 1024 ))
    local i n bytes day

    mkdir -p "$dir"

    # Documents: many small text files, the compressible half of the payload.
    n=$(rand_between 8 14)
    for i in $(seq 1 "$n"); do
        bytes=$(rand_between 400 9000)
        gen_blob "$dir/notes/note-$(printf '%02d' "$i").md" "$bytes" text
        remaining=$(( remaining - bytes ))
    done

    # Photos, in dated directories, incompressible.
    n=$(rand_between 3 6)
    for i in $(seq 1 "$n"); do
        day=$(printf '2026-%02d-%02d' "$(rand_between 1 12)" "$(rand_between 1 28)")
        bytes=$(rand_between 20000 120000)
        gen_blob "$dir/photos/$day/IMG_$(printf '%04d' "$(rand_between 1 9999)").jpg" "$bytes" random
        remaining=$(( remaining - bytes ))
    done

    # Whatever budget is left goes into a handful of larger opaque files, so a
    # case can ask for 10 MB and get 10 MB rather than a tree of the shape
    # above scaled to something absurd.
    if [ "$remaining" -gt 4096 ]; then
        n=$(rand_between 2 4)
        bytes=$(( remaining / n ))
        for i in $(seq 1 "$n"); do
            gen_blob "$dir/archive/volume-$(printf '%02d' "$i").bin" "$bytes" mixed
        done
    fi

    if [ "$flavour" = awkward ]; then
        gen_awkward "$dir"
    fi
}

# gen_awkward adds the entries that break archivers. Kept separate so a case
# can bolt them onto a tree of any size.
gen_awkward() {
    local dir="$1" deep

    : >"$dir/empty.txt"                                  # zero bytes
    printf 'x' >"$dir/one-byte.txt"                      # one byte
    mkdir -p "$dir/an empty directory"                   # no entries at all
    gen_blob "$dir/Grüße/Kapitel 1.txt" 60000 text       # umlauts, and a space
    gen_blob "$dir/ünïcödé and spaces.json" 3000 text    # more of both
    gen_blob "$dir/.hidden/config" 500 text              # a dotted directory

    # Deliberately absent: a directory whose name ends in a space. MSYS will
    # create one on Windows and the Win32 API will then refuse to open it, so
    # it tests the platform rather than BOND. It has a home in 94-bad-input,
    # where being unreadable is the point.

    # A path long enough to matter without depending on the platform's limit:
    # the Go tests already prove 611 characters work, this only proves the
    # binary passes such a path through unharmed.
    deep="$dir/deep"
    for _ in 1 2 3 4 5 6 7 8; do
        deep="$deep/a-directory-with-a-fairly-long-name"
    done
    gen_blob "$deep/leaf.bin" 2000 random
}

# gen_symlink makes a symbolic link, or returns non-zero if this machine will
# not make one. On Windows without developer mode, MSYS silently copies the
# file instead, which would turn a symlink test into a test of nothing – hence
# the check that what was made is actually a link.
gen_symlink() {
    local link="$1" target="$2"
    mkdir -p "$(dirname "$link")"
    ln -s "$target" "$link" 2>/dev/null || return 1
    [ -L "$link" ] || { rm -f "$link"; return 1; }
    return 0
}

# mutate_tree changes a tree the way a year changes one: some files grow, some
# are rewritten, some go away, some appear. Used by the over-the-year case so
# that each month's container genuinely holds something different.
mutate_tree() {
    local dir="$1" victim
    victim=$( ( cd "$dir" && find . -type f -name '*.md' ) | LC_ALL=C sort | head -n 1 )
    if [ -n "$victim" ]; then
        rm -f "$dir/${victim#./}"
    fi
    gen_blob "$dir/notes/added-$(rand_between 1000 9999).md" "$(rand_between 500 4000)" text
    victim=$( ( cd "$dir" && find . -type f -name '*.jpg' ) | LC_ALL=C sort | head -n 1 )
    if [ -n "$victim" ]; then
        gen_blob "$dir/${victim#./}" "$(rand_between 20000 60000)" random
    fi
}
