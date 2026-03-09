-- job_submit.lua — Slurm job submit plugin for sandbox-by-default
--
-- Place in /etc/slurm/job_submit.lua and enable with:
--   JobSubmitPlugins=lua   (in slurm.conf, then: scontrol reconfigure)
--
-- Every batch job is sandboxed unless the submitter provides a valid
-- bypass token via:   --export=_SANDBOX_BYPASS=<token>
--
-- The token file is readable by normal users but protected from sandboxed
-- processes via eBPF LSM (denies read when PR_SET_NO_NEW_PRIVS is set).
-- See ADMIN_HARDENING.md §1.

local TOKEN_FILE = "/etc/slurm/.sandbox-bypass-token"
local SANDBOX_EXEC = "/app/sandbox/sandbox-exec.sh"

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

    -- Check for bypass token
    local expected = read_token()
    if expected and job_desc.environment then
        local provided = job_desc.environment["_SANDBOX_BYPASS"]
        if provided == expected then
            slurm.log_info("job_submit/sandbox: uid %d provided valid bypass token", submit_uid)
            -- Clear the token from the job environment so it doesn't
            -- leak into the compute node.
            job_desc.environment["_SANDBOX_BYPASS"] = nil
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

    local work_dir = job_desc.work_dir or "/tmp"
    local wrapper = string.format(
        'exec %s --project-dir "%s" -- bash -c %s',
        SANDBOX_EXEC,
        work_dir,
        "'" .. table.concat(body_lines, "\n"):gsub("'", "'\\''") .. "'"
    )

    job_desc.script = table.concat(preamble, "\n") .. "\n" .. wrapper .. "\n"

    slurm.log_info("job_submit/sandbox: wrapping job from uid %d in sandbox", submit_uid)
    return slurm.SUCCESS
end

function slurm_job_modify(job_desc, job_rec, part_list, modify_uid)
    return slurm.SUCCESS
end
