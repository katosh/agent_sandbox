#! /bin/bash --
# chaperon/handlers/sacctmgr.sh — Handle sacctmgr requests from sandbox
#
# Heavily restricted: only read-only queries that don't enumerate users or
# accounts are allowed.  All write operations (add, modify, delete, archive)
# are denied.
#
# Allowed:
#   sacctmgr show cluster     — cluster info
#   sacctmgr show qos         — QOS definitions
#   sacctmgr show tres        — trackable resources
#   sacctmgr show configuration — accounting config
#   sacctmgr --help/--version
#
# Denied:
#   sacctmgr show user/account/association — user/group enumeration
#   sacctmgr add/modify/delete/archive/dump/load — write operations

source "$(dirname "${BASH_SOURCE[0]}")/_handler_lib.sh"

handle_sacctmgr() {
    local project_dir="$1"
    local sandbox_exec="$2"

    local real_sacctmgr="${REAL_SACCTMGR:-/usr/bin/sacctmgr}"
    if [[ ! -x "$real_sacctmgr" ]]; then
        echo "chaperon: real sacctmgr not found at $real_sacctmgr" >&2
        return 1
    fi

    if [[ ${#REQ_ARGS[@]} -eq 0 ]]; then
        echo "chaperon: sacctmgr requires a subcommand" >&2
        return 1
    fi

    # Collect flags before the subcommand (sacctmgr puts flags first)
    local pre_flags=()
    local subcmd=""
    local subcmd_idx=0
    local i=0
    while (( i < ${#REQ_ARGS[@]} )); do
        local arg="${REQ_ARGS[$i]}"
        case "$arg" in
            --help|--version|--usage|-V)
                # Info flags — pass through directly
                local rc=0
                "$real_sacctmgr" "${REQ_ARGS[@]}" || rc=$?
                return "$rc"
                ;;
            -n|--noheader|-p|--parsable|-P|--parsable2|-r|--readonly|-v|--verbose|-Q|--quiet|--json|--yaml)
                pre_flags+=("$arg")
                ;;
            -*)
                echo "chaperon: denied unknown sacctmgr flag: $arg" >&2
                return 1
                ;;
            *)
                subcmd="$arg"
                subcmd_idx=$((i + 1))
                break
                ;;
        esac
        (( i++ )) || true
    done

    if [[ -z "$subcmd" ]]; then
        echo "chaperon: sacctmgr requires a subcommand (show)" >&2
        return 1
    fi

    # Only "show" (alias "list") is allowed
    case "$subcmd" in
        show|list)
            ;;
        add|create|modify|update|delete|remove|archive|dump|load|reconfigure)
            echo "chaperon: sacctmgr '$subcmd' is not allowed inside the sandbox" >&2
            return 1
            ;;
        *)
            echo "chaperon: sacctmgr '$subcmd' is not allowed inside the sandbox" >&2
            return 1
            ;;
    esac

    # Validate the show target
    if (( subcmd_idx >= ${#REQ_ARGS[@]} )); then
        echo "chaperon: sacctmgr show requires a target (cluster, qos, tres, configuration)" >&2
        return 1
    fi

    local target="${REQ_ARGS[$subcmd_idx]}"
    case "$target" in
        cluster|clusters)
            ;;
        qos)
            ;;
        tres)
            ;;
        configuration|config)
            ;;
        # Denied: user/group enumeration
        user|users|account|accounts|association|associations|coordinator|coordinators|event|events|problem|problems|reservation|reservations|runawayjobs|transaction|transactions|wckey|wckeys)
            echo "chaperon: sacctmgr show '$target' denied (user/group enumeration)" >&2
            return 1
            ;;
        *)
            echo "chaperon: sacctmgr show '$target' not allowed" >&2
            return 1
            ;;
    esac

    # Pass through remaining args after the target (format options, where clauses, etc.)
    local remaining_args=("${REQ_ARGS[@]:$subcmd_idx}")

    local rc=0
    "$real_sacctmgr" "${pre_flags[@]}" show "${remaining_args[@]}" || rc=$?
    return "$rc"
}
