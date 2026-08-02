#!/bin/sh
# What Stratum v2 is made of. One cloc pass, bucketed, no cache.
#
# SCOPE IS v2 ONLY -- v1 at the repo root is the superseded prototype and is
# deliberately not counted. That was the old script's intent too; it is stated
# here rather than left implicit in a bare `cloc v2`.
#
# WHY BUCKETS AND NOT ONE NUMBER: the previous version printed a single
# unlabelled figure counting only C/headers/Rust/asm/TLA+ -- omitting ~48k
# lines of Markdown and the CMake/shell/Python build and CI machinery. An
# unlabelled total invites comparison against some other tool's total, and the
# difference then reads as lost code. That is not hypothetical: the sibling
# Thylacine script caused exactly that scare. A number that cannot say what it
# counted cannot be trusted when it moves.
#
# THE CACHE IS GONE. It was a 10-minute per-$PWD file in /tmp. It saved under a
# second on a command run by hand, and in exchange could hand back a figure it
# had not just measured -- which is how this script came to report a total that
# did not reconcile with a live count of the tree.
#
# Usage:
#   ./loc.sh          bucketed report
#   ./loc.sh -n       the authored total alone (for scripting)

set -u

# cloc matches --exclude-dir by BASENAME, so a bare `build` did NOT exclude
# build-asan / build-tsan / build-ubsan / build-werror / build-bench. Those are
# sanitizer and benchmark build trees whose generated sources were counted as
# ours, and whose contents vary with whatever was last configured.
EXCLUDE_DIRS='build,build-asan,build-tsan,build-ubsan,build-werror,build-bench,cmake-build-debug,cmake-build-release,CMakeFiles,.cache,node_modules'

command -v cloc >/dev/null 2>&1 || { echo "loc.sh: cloc not installed" >&2; exit 1; }

# Count the REPO's v2, not the current directory, so the answer does not depend
# on where you were standing when you asked.
root=$(git rev-parse --show-toplevel 2>/dev/null) || root=""
[ -n "$root" ] && cd "$root"
[ -d v2 ] || { echo "loc.sh: no v2/ here (run inside the stratum repo)" >&2; exit 1; }

raw=$(cloc v2 \
    --exclude-dir="$EXCLUDE_DIRS" \
    --not-match-d='(^|/)\.(git|idea|vscode)$' \
    --csv --quiet 2>/dev/null)

[ -n "$raw" ] || { echo "loc.sh: cloc produced no output" >&2; exit 1; }

printf '%s\n' "$raw" | awk -F',' -v mode="${1:-}" '
# cloc --csv columns: files,language,blank,comment,code
function commas(n,   s, out, len, i) {
    s = sprintf("%d", n); out = ""; len = length(s)
    for (i = 1; i <= len; i++) {
        out = out substr(s, i, 1)
        if ((len - i) % 3 == 0 && i < len) out = out ","
    }
    return out
}
$2 == "" || $2 == "language" || $2 == "SUM" { next }
{
    lang = $2; code = $5 + 0
    # Anything unrecognised lands in "other" rather than vanishing -- a silent
    # drop is precisely how the docs went uncounted before.
    if (lang == "C" || lang == "C/C++ Header" || lang == "C++" || \
        lang == "Rust" || lang == "Assembly" || lang == "Linker Script")
        { code_t += code }
    else if (lang == "TLA+")        { spec_t  += code }
    else if (lang == "Markdown")    { docs_t  += code }
    else if (lang == "diff")        { patch_t += code }
    else if (lang == "Bourne Shell" || lang == "Bourne Again Shell" || \
             lang == "Python" || lang == "Expect" || lang == "CMake" || \
             lang == "make")        { tool_t  += code }
    else                            { other_t += code; other_n[lang] = code }
}
END {
    total = code_t + spec_t + docs_t + patch_t + tool_t + other_t
    if (mode == "-n") { print total; exit }

    printf "  stratum v2  authored %s lines\n\n", commas(total)
    if (code_t)  printf "    code    %10s   C, headers, C++, Rust, asm\n", commas(code_t)
    if (docs_t)  printf "    docs    %10s   Markdown\n", commas(docs_t)
    if (spec_t)  printf "    specs   %10s   TLA+\n", commas(spec_t)
    if (tool_t)  printf "    tooling %10s   CMake, shell, Python, make\n", commas(tool_t)
    if (patch_t) printf "    patches %10s   patch series\n", commas(patch_t)
    if (other_t) {
        line = ""
        for (l in other_n) line = line (line == "" ? "" : ", ") l
        printf "    other   %10s   %s\n", commas(other_t), line
    }
}
'
