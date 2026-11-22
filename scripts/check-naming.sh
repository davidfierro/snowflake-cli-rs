#!/usr/bin/env bash
# Validates the naming rules of CONTRIBUTING.md ("Naming: branches, commits and PR titles").
# The `naming` workflow runs it on every pull request; run it yourself before pushing.
#
# Usage:
#   scripts/check-naming.sh branch <name>      a branch name, e.g. "$(git branch --show-current)"
#   scripts/check-naming.sh title <text>       a PR title or one commit subject
#   scripts/check-naming.sh commits <range>    every non-merge commit subject of a git range,
#                                              e.g. origin/main..HEAD
# Exits 0 when everything conforms, 1 with one `error:` line per violation, 2 on a usage error.
set -euo pipefail

TYPES='build|chore|ci|docs|feat|fix|perf|refactor|revert|style|test'
MAX_TITLE=100

title_re="^($TYPES)(\([a-z0-9]+(-[a-z0-9]+)*\))?!?: [^ ].*$"
branch_re="^($TYPES)/([A-Z]+-[0-9]+-)?[a-z0-9]+(-[a-z0-9]+)*$"
# release-plz names its own release PR branch (`release-plz-<timestamp>`).
bot_branch_re='^release-plz-'

usage() {
    sed -n '5,9p' "$0" | sed 's/^# \{0,1\}//' >&2
    exit 2
}

check_title() {
    local title=$1 what=$2
    if [[ ! $title =~ $title_re ]]; then
        echo "error: $what \"$title\" is not \"<type>[(scope)][!]: <summary>\" (types: ${TYPES//|/, })"
        return 1
    fi
    if [ "${#title}" -gt "$MAX_TITLE" ]; then
        echo "error: $what \"$title\" is ${#title} characters long; the limit is $MAX_TITLE"
        return 1
    fi
    if [[ $title == *. ]]; then
        echo "error: $what \"$title\" ends with a period"
        return 1
    fi
}

check_branch() {
    local branch=$1
    if [[ $branch =~ $bot_branch_re ]] || [[ $branch =~ $branch_re ]]; then
        return 0
    fi
    echo "error: branch \"$branch\" is not \"<type>/[<ISSUE-KEY>-]<kebab-case-slug>\" (types: ${TYPES//|/, })"
    return 1
}

check_commits() {
    local range=$1 subjects subject failed=0
    subjects=$(git log --no-merges --format=%s "$range")
    while IFS= read -r subject; do
        [ -n "$subject" ] || continue
        check_title "$subject" "commit subject" || failed=1
    done <<<"$subjects"
    return "$failed"
}

[ $# -eq 2 ] || usage
case $1 in
    branch) check_branch "$2" ;;
    title) check_title "$2" "title" ;;
    commits) check_commits "$2" ;;
    *) usage ;;
esac
