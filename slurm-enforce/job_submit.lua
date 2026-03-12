-- job_submit.lua — Slurm job submit plugin enforcing sandbox on agent jobs
--
-- Place in /etc/slurm/job_submit.lua and enable with:
--   JobSubmitPlugins=lua   (in slurm.conf, then: scontrol reconfigure)
--
-- Every batch job is sandboxed unless _SANDBOX_BYPASS is set in the
-- job environment (typically injected by sbatch-token-wrapper.sh).
--
-- The token file is readable by normal users but protected from sandboxed
-- processes via eBPF LSM (denies read when PR_SET_NO_NEW_PRIVS is set).
-- See ADMIN_HARDENING.md §1.
--
-- Reads TOKEN_FILE and SANDBOX_EXEC from sandbox-wrapper.conf (single
-- source of truth shared with the sbatch/srun wrappers).

-- Parse sandbox-wrapper.conf (KEY="value" or KEY=value, ignoring comments)
local function read_conf(path)
    local conf = {}
    local f = io.open(path, "r")
    if not f then return conf end
    for line in f:lines() do
        local key, val = line:match("^(%w+)%s*=%s*\"(.-)\"")
        if not key then
            key, val = line:match("^(%w+)%s*=%s*(%S+)")
        end
        if key then conf[key] = val end
    end
    f:close()
    return conf
end

local conf = read_conf("/etc/slurm/sandbox-wrapper.conf")
local TOKEN_FILE = conf["TOKEN_FILE"] or "/etc/slurm/.sandbox-bypass-token"
local SANDBOX_EXEC = conf["SANDBOX_EXEC"] or "/app/sandbox/sandbox-exec.sh"

-- Read the bypass token once (re-read on each submission since Slurm
-- reloads the script each time).
local function read_token()
    local f = io.open(TOKEN_FILE, "r")
    if not f then return nil end
    local token = f:read("*l")
    f:close()
    return token and token:match("^%s*(.-)%s*$")  -- trim whitespace
end

function slurm_job_submit(job_desc, part_list, submit_uid)
    -- Only process batch jobs (sbatch). For srun, the sandbox is applied
    -- on the calling side by srun-sandbox.sh.
    if job_desc.script == nil then
        return slurm.SUCCESS
    end

    -- Check for bypass token (empty token = no bypass, to prevent
    -- misconfiguration where an empty file accidentally matches)
    local expected = read_token()
    if expected and expected ~= "" and job_desc.environment then
        local provided = job_desc.environment["_SANDBOX_BYPASS"]
        if provided == expected then
            slurm.log_info("job_submit/sandbox: uid %d bypass token valid", submit_uid)
            -- Clear the token from the job environment so it doesn't
            -- leak into the compute node. Use empty string because
            -- Slurm's Lua environment table does not support nil deletion.
            job_desc.environment["_SANDBOX_BYPASS"] = ""
            return slurm.SUCCESS
        end
    end

    -- No valid token — wrap the job script in sandbox-exec.sh.
    -- Preserve the shebang and any #SBATCH directives.
    local preamble = {}
    local body_lines = {}
    local in_preamble = true

    for line in job_desc.script:gmatch("[^\n]*") do
        if in_preamble then
            if line:match("^#!") or line:match("^#SBATCH") or line:match("^%s*$") then
                preamble[#preamble + 1] = line
            else
                in_preamble = false
                body_lines[#body_lines + 1] = line
            end
        else
            body_lines[#body_lines + 1] = line
        end
    end

    -- Use a heredoc to pass the job body to sandbox-exec.sh.
    -- This avoids Lua/shell quoting issues with single-quote escaping.
    --
    -- The delimiter includes the submit UID and a counter to prevent
    -- heredoc injection: if the user's script contains the delimiter
    -- string, it would terminate the heredoc early and execute code
    -- outside the sandbox. A per-submission unique delimiter makes
    -- this infeasible without knowing the exact string.
    local work_dir = job_desc.work_dir or "/tmp"
    local body = table.concat(body_lines, "\n")
    local delimiter = string.format("__SANDBOX_EOF_%d_%d__", submit_uid, os.time())
    -- Belt-and-suspenders: if the body somehow contains the delimiter, escape it
    body = body:gsub(delimiter, delimiter .. "_ESCAPED")
    local wrapper = string.format(
        "%s --project-dir %q -- bash <<'%s'\n%s\n%s",
        SANDBOX_EXEC, work_dir, delimiter, body, delimiter
    )

    job_desc.script = table.concat(preamble, "\n") .. "\n" .. wrapper .. "\n"

    slurm.log_info("job_submit/sandbox: wrapping job from uid %d in sandbox", submit_uid)
    return slurm.SUCCESS
end

function slurm_job_modify(job_desc, job_rec, part_list, modify_uid)
    return slurm.SUCCESS
end
