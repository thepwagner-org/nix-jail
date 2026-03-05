//! HTML page renderers for the home subdomain.
//!
//! Each function returns a complete HTML document as a hyper response.
//! Dynamic data is substituted via simple string replacement into static
//! template constants — no templating engine required.

use crate::util::{error_response, full_body, BoxedBody};
use hyper::{Response, StatusCode};
use std::convert::Infallible;
use tracing::error;

// ---------------------------------------------------------------------------
// GET / — landing page with job list + submit form
// ---------------------------------------------------------------------------

pub async fn landing_page(daemon: &str) -> Result<Response<BoxedBody>, Infallible> {
    let jobs_json = match crate::api::fetch_jobs_json(daemon).await {
        Ok(j) => j,
        Err(e) => {
            error!(error = %e, "failed to fetch jobs for landing page");
            "[]".to_string()
        }
    };

    static HTML: &str = r###"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>nix-jail</title>
<style>
  *, *::before, *::after { box-sizing: border-box; }
  :root {
    --bg:       #000000;
    --surface:  #111116;
    --border:   #222228;
    --fg:       #c8c8d0;
    --muted:    #60606a;
    --purple:   #7c6af7;
    --green:    #5dbf5d;
    --red:      #d9534f;
    --font:     "SF Mono", "Cascadia Code", "Fira Code", ui-monospace, monospace;
  }
  html, body {
    margin: 0; padding: 0;
    background: var(--bg); color: var(--fg);
    font-family: var(--font); font-size: 13px; line-height: 1.6;
  }
  h1 { color: var(--purple); font-size: 1.1rem; margin: 0 0 1.5rem; letter-spacing: .05em; }
  h2 { font-size: .85rem; color: var(--muted); text-transform: uppercase;
       letter-spacing: .1em; margin: 0 0 .75rem; }
  a { color: var(--purple); text-decoration: none; }
  a:hover { text-decoration: underline; }

  .layout { max-width: 900px; margin: 0 auto; padding: 2rem 1.5rem; }

  /* job cards */
  .jobs { display: flex; flex-direction: column; gap: .5rem; margin-bottom: 2rem; }
  .job-card {
    background: var(--surface); border: 1px solid var(--border);
    border-radius: 4px; padding: .75rem 1rem;
    display: flex; align-items: center; gap: 1rem;
  }
  .job-card:hover { border-color: var(--purple); }
  @keyframes breathe {
    0%, 100% { box-shadow: 0 0 3px 1px var(--green); opacity: .85; }
    50%       { box-shadow: 0 0 8px 3px var(--green); opacity: 1; }
  }
  .job-dot { width: 8px; height: 8px; border-radius: 50%; flex-shrink: 0; }
  .job-dot.running   { background: var(--green); animation: breathe 2s ease-in-out infinite; }
  .job-dot.pending   { background: var(--muted); }
  .job-dot.completed { background: var(--green); }
  .job-dot.failed    { background: var(--red); }
  .job-meta { flex: 1; min-width: 0; }
  .job-id   { color: var(--purple); font-size: .8rem; }
  .job-desc { color: var(--muted); font-size: .8rem; white-space: nowrap;
              overflow: hidden; text-overflow: ellipsis; }
  .job-age  { color: var(--muted); font-size: .75rem; flex-shrink: 0; }
  .btn-log  {
    background: none; border: 1px solid var(--border); color: var(--fg);
    padding: .2rem .6rem; border-radius: 3px; cursor: pointer; font-family: var(--font);
    font-size: .75rem; text-decoration: none; display: inline-block;
  }
  .btn-log:hover { border-color: var(--purple); color: var(--purple); text-decoration: none; }
  .btn-retry-card {
    background: none; border: none; color: var(--muted);
    padding: .2rem .4rem; border-radius: 3px; cursor: pointer; font-family: var(--font);
    font-size: .8rem; line-height: 1; transition: color .15s;
  }
  .btn-retry-card:hover { color: var(--purple); }
  .btn-kill {
    background: none; border: none; color: var(--muted);
    padding: .2rem .4rem; border-radius: 3px; cursor: pointer; font-family: var(--font);
    font-size: .85rem; line-height: 1; transition: color .15s, background .15s;
  }
  .btn-kill:hover { color: #e05050; background: rgba(224, 80, 80, 0.1); }
  .empty { color: var(--muted); font-size: .85rem; margin: 0 0 2rem; }

  /* submit form */
  .form-section { margin-bottom: 2rem; }
  label { display: block; color: var(--muted); font-size: .75rem;
          text-transform: uppercase; letter-spacing: .08em; margin-bottom: .3rem; }
  textarea, input[type=text], select {
    width: 100%; background: var(--surface); border: 1px solid var(--border);
    color: var(--fg); font-family: var(--font); font-size: .85rem;
    padding: .5rem .75rem; border-radius: 3px; outline: none;
  }
  textarea:focus, input[type=text]:focus, select:focus { border-color: var(--purple); }
  textarea { resize: vertical; min-height: 120px; }
  select { cursor: pointer; appearance: none; background-image: none; }
  select option { background: var(--surface); }
  .form-row { display: flex; gap: .75rem; margin-top: .75rem; }
  .form-row input { flex: 1; }
  .preset-row { display: flex; align-items: center; gap: .75rem; margin-bottom: .75rem; }
  .preset-row select { flex: 1; }
  .preset-row label { margin: 0; white-space: nowrap; }
  button[type=submit] {
    background: var(--purple); color: #fff; border: none; padding: .5rem 1.2rem;
    border-radius: 3px; cursor: pointer; font-family: var(--font); font-size: .85rem;
    flex-shrink: 0;
  }
  button[type=submit]:hover { opacity: .85; }
  button[type=submit]:disabled { opacity: .4; cursor: default; }
  .field-row { display: flex; gap: .75rem; margin-top: .75rem; }
  .field-row > div { flex: 1; }
  .field-row input { width: 100%; }

  #submitted-link {
    display: none; margin-top: .75rem; font-size: .85rem; color: var(--muted);
  }
  #submitted-link.visible { display: block; }
  #submitted-link a { color: var(--purple); }
</style>
</head>
<body>
<div class="layout">
  <h1>nix-jail <span style="color:var(--muted);font-size:.75rem;font-weight:normal;letter-spacing:normal">v__VERSION__</span></h1>

  <section class="form-section">
    <h2>Run a job</h2>
    <div class="preset-row">
      <label for="preset">preset</label>
      <select id="preset" onchange="applyPreset(this.value)">
        <option value="">-- choose a preset --</option>
        <option value="opencode">opencode (profile)</option>
        <option value="opencode-nix-jail">opencode on nix-jail (clone + profile)</option>
        <option value="count">count 1&#x2192;10 (streaming demo)</option>
        <option value="httpbin">curl httpbin.org/get</option>
        <option value="httpbin-post">curl httpbin.org/post (JSON body)</option>
        <option value="clone-nix-jail">python3 http.server (clone demo)</option>
        <option value="python-server">python3 http.server (reverse proxy demo)</option>
        <option value="nginx-server">nginx static server (reverse proxy demo)</option>
      </select>
    </div>
    <label for="script">script <span style="color:var(--muted);font-size:.7rem">(leave blank when using a profile)</span></label>
    <textarea id="script" placeholder="#!/usr/bin/env bash&#10;curl -s https://example.com | head -5"></textarea>
    <div class="field-row">
      <div>
        <label for="packages">packages</label>
        <input id="packages" type="text" placeholder="curl jq git">
      </div>
      <div>
        <label for="hosts">allowed hosts</label>
        <input id="hosts" type="text" placeholder="example.com *.github.com">
      </div>
    </div>
    <div class="field-row">
      <div>
        <label for="repo">repo (git clone URL)</label>
        <input id="repo" type="text" placeholder="https://git.pwagner.net/pwagner/pwagner">
      </div>
      <div>
        <label for="path">path in repo</label>
        <input id="path" type="text" placeholder="projects/nix-jail">
      </div>
      <div>
        <label for="git-ref">git ref</label>
        <input id="git-ref" type="text" placeholder="main">
      </div>
    </div>
    <div class="field-row">
      <div>
        <label for="subdomain">subdomain (for reverse proxy)</label>
        <input id="subdomain" type="text" placeholder="my-server">
      </div>
      <div>
        <label for="service-port">service port</label>
        <input id="service-port" type="text" placeholder="8080">
      </div>
      <div>
        <label for="profile">profiles (space-separated)</label>
        <input id="profile" type="text" placeholder="opencode cargo">
      </div>
      <div style="display:flex;align-items:flex-end">
        <button type="submit" id="submit-btn" onclick="submitJob()">Run</button>
      </div>
    </div>
  </section>

  <div id="submitted-link"></div>

  <section>
    <h2>Jobs</h2>
    <div id="jobs-list"></div>
  </section>
</div>

<script>
const INITIAL_JOBS = __JOBS_JSON__;

function reltime(secs) {
  if (secs < 5)   return 'just now';
  if (secs < 60)  return secs + 's ago';
  if (secs < 3600) return Math.floor(secs/60) + 'm ago';
  return Math.floor(secs/3600) + 'h ago';
}

function statusDot(status) {
  return '<span class="job-dot ' + status + '"></span>';
}

function jobDesc(job) {
  const parts = [];
  if (job.packages && job.packages.length) parts.push(job.packages.join(' '));
  if (job.path) parts.push(job.path);
  if (job.repo) parts.push(job.repo.replace(/https?:\/\/[^@]*@?/, ''));
  return parts.join(' \u00b7 ') || '(script)';
}

function renderJobs(jobs) {
  const el = document.getElementById('jobs-list');
  if (!jobs || !jobs.length) {
    el.innerHTML = '<p class="empty">No jobs yet.</p>';
    return;
  }
  const now = Date.now() / 1000;
  el.innerHTML = jobs.map(j => {
    const age = reltime(Math.round(now - j.created_at));
    const desc = jobDesc(j);
    const subUrl = j.subdomain
      ? window.location.origin.replace('//home.', '//' + j.subdomain + '.')
      : null;
    const sub = subUrl
      ? '<a href="' + subUrl + '" target="_blank">' + j.subdomain + '</a> \u00b7 '
      : '';
    const retryTitle = j.script ? 'retry this job' : '';
    return '<div class="job-card">'
      + statusDot(j.status)
      + '<div class="job-meta">'
      + '<div class="job-id">' + j.job_id + '</div>'
      + '<div class="job-desc">' + sub + desc + '</div>'
      + '</div>'
      + '<span class="job-age">' + j.status + ' \u00b7 ' + age + '</span>'
      + '<a class="btn-log" href="/logs/' + j.job_id + '" target="_blank">logs</a>'
      + (j.script
        ? '<button class="btn-retry-card" onclick="retryJob(\'' + j.job_id + '\')" title="' + retryTitle + '">\u21ba</button>'
        : '')
      + (j.status === 'running'
        ? '<button class="btn-kill" onclick="killJob(\'' + j.job_id + '\')" title="kill job">&#x2715;</button>'
        : '')
      + '</div>';
  }).join('');
}

async function refreshJobs() {
  try {
    const r = await fetch('/api/jobs');
    const data = await r.json();
    renderJobs(data.jobs || []);
  } catch(e) { console.error('refresh failed', e); }
}

renderJobs(INITIAL_JOBS.jobs || []);
setInterval(refreshJobs, 3000);

const PRESETS = {
  'opencode': {
    script: '',
    packages: '',
    hosts: '',
    repo: '',
    path: '',
    gitRef: '',
    subdomain: 'opencode',
    servicePort: '3337',
    profile: 'opencode',
  },
  'opencode-nix-jail': {
    script: '',
    packages: '',
    hosts: '',
    repo: 'https://git.pwagner.net/pwagner/pwagner',
    path: 'projects/nix-jail',
    gitRef: '',
    subdomain: 'opencode',
    servicePort: '3337',
    profile: 'opencode cargo',
  },
  'clone-nix-jail': {
    script: '#!/usr/bin/env bash\necho "cloned workspace:"\nls /workspace\necho "serving /workspace on port 8080..."\npython3 -m http.server 8080 --directory /workspace',
    packages: 'bash python3',
    hosts: '',
    repo: 'https://git.pwagner.net/pwagner/pwagner',
    path: 'projects/nix-jail',
    gitRef: '',
    subdomain: 'demo',
    servicePort: '8080',
    profile: '',
  },
  'count': {
    script: '#!/usr/bin/env bash\nfor i in $(seq 1 10); do\n  echo "count: $i"\n  sleep 1\ndone',
    packages: 'bash coreutils',
    hosts: '',
    repo: '',
    path: '',
    gitRef: '',
    subdomain: '',
    servicePort: '',
    profile: '',
  },
  'httpbin': {
    script: '#!/usr/bin/env bash\ncurl -s https://httpbin.org/get | jq .',
    packages: 'bash curl jq',
    hosts: 'httpbin.org',
    repo: '',
    path: '',
    gitRef: '',
    subdomain: '',
    servicePort: '',
    profile: '',
  },
  'httpbin-post': {
    script: '#!/usr/bin/env bash\ncurl -s -X POST https://httpbin.org/post \\\n  -H "Content-Type: application/json" \\\n  -d \'{"hello":"nix-jail"}\' | jq .',
    packages: 'bash curl jq',
    hosts: 'httpbin.org',
    repo: '',
    path: '',
    gitRef: '',
    subdomain: '',
    servicePort: '',
    profile: '',
  },
  'python-server': {
    script: '#!/usr/bin/env bash\necho "serving on port 8080..."\npython3 -m http.server 8080 --directory /',
    packages: 'bash python3',
    hosts: '',
    repo: '',
    path: '',
    gitRef: '',
    subdomain: 'demo',
    servicePort: '8080',
    profile: '',
  },
  'nginx-server': {
    script: '#!/usr/bin/env bash\nmkdir -p /tmp/www\ncat > /tmp/www/index.html <<EOF\n<!DOCTYPE html><html><body>\n<h1>hello from nix-jail</h1>\n<p>served via nginx inside a sandbox</p>\n</body></html>\nEOF\nnginx -p /tmp -c /dev/stdin <<NGINX\nworker_processes 1;\nevents {}\nhttp {\n  server {\n    listen 8080;\n    root /tmp/www;\n  }\n}\nNGINX',
    packages: 'bash nginx',
    hosts: '',
    repo: '',
    path: '',
    gitRef: '',
    subdomain: 'demo',
    servicePort: '8080',
    profile: '',
  },
};

function applyPreset(name) {
  const p = PRESETS[name];
  if (!p) return;
  document.getElementById('script').value       = p.script;
  document.getElementById('packages').value     = p.packages;
  document.getElementById('hosts').value        = p.hosts;
  document.getElementById('repo').value         = p.repo || '';
  document.getElementById('path').value         = p.path || '';
  document.getElementById('git-ref').value      = p.gitRef || '';
  document.getElementById('subdomain').value    = p.subdomain;
  document.getElementById('service-port').value = p.servicePort;
  document.getElementById('profile').value      = p.profile;
}

async function killJob(jobId) {
  try {
    const r = await fetch('/api/jobs/' + jobId, { method: 'DELETE' });
    const data = await r.json();
    if (!r.ok) { alert('Error: ' + (data.error || r.statusText)); return; }
    refreshJobs();
  } catch(e) { alert('Kill failed: ' + e); }
}

async function retryJob(jobId) {
  try {
    const r = await fetch('/api/jobs/' + jobId + '/retry', { method: 'POST' });
    const data = await r.json();
    if (!r.ok) { alert('Error: ' + (data.error || r.statusText)); return; }
    window.open('/logs/' + data.job_id, '_blank');
    refreshJobs();
  } catch(e) { alert('Retry failed: ' + e); }
}

async function submitJob() {
  const script      = document.getElementById('script').value.trim();
  const packages    = document.getElementById('packages').value.trim().split(/\s+/).filter(Boolean);
  const hosts       = document.getElementById('hosts').value.trim().split(/\s+/).filter(Boolean);
  const repo        = document.getElementById('repo').value.trim();
  const path        = document.getElementById('path').value.trim();
  const gitRef      = document.getElementById('git-ref').value.trim();
  const subdomain   = document.getElementById('subdomain').value.trim();
  const servicePort = parseInt(document.getElementById('service-port').value.trim(), 10);
  const profiles    = document.getElementById('profile').value.trim().split(/\s+/).filter(Boolean);

  if (!script && !profiles.length && !repo) { alert('script, profiles, or repo is required'); return; }

  const btn = document.getElementById('submit-btn');
  btn.disabled = true;
  btn.textContent = 'Submitting...';

  const body = { script, packages };
  if (hosts.length) body.hosts = hosts;
  if (repo)         body.repo = repo;
  if (path)         body.path = path;
  if (gitRef)       body.git_ref = gitRef;
  if (subdomain)    body.subdomain = subdomain;
  if (servicePort)  body.service_port = servicePort;
  if (profiles.length) body.profiles = profiles;

  try {
    const r = await fetch('/api/jobs', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    const data = await r.json();
    if (!r.ok) {
      alert('Error: ' + (data.error || r.statusText));
      return;
    }
    const logUrl = '/logs/' + data.job_id;
    const link = document.getElementById('submitted-link');
    link.innerHTML = 'job submitted: <a href="' + logUrl + '" target="_blank">' + data.job_id + '</a>';
    link.classList.add('visible');
    refreshJobs();
  } catch(e) {
    alert('Submit failed: ' + e);
  } finally {
    btn.disabled = false;
    btn.textContent = 'Run';
  }
}
</script>
</body>
</html>
"###;

    let html = HTML
        .replace("__JOBS_JSON__", &format!(r#"{{"jobs":{jobs_json}}}"#))
        .replace("__VERSION__", env!("NIX_JAIL_VERSION"));

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(hyper::header::CONTENT_TYPE, "text/html; charset=utf-8")
        .body(full_body(html))
        .unwrap_or_else(|_| error_response(StatusCode::INTERNAL_SERVER_ERROR, "render failed")))
}

// ---------------------------------------------------------------------------
// GET /logs/{job_id} — dedicated log viewer page
// ---------------------------------------------------------------------------

pub async fn log_page(job_id: &str) -> Result<Response<BoxedBody>, Infallible> {
    // Basic validation: job IDs are ULIDs (26 uppercase base32 chars)
    if job_id.is_empty()
        || job_id.len() > 64
        || !job_id
            .chars()
            .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
    {
        return Ok(error_response(StatusCode::BAD_REQUEST, "invalid job id"));
    }

    static HTML: &str = r###"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>__JOB_ID__ — nix-jail logs</title>
<style>
  *, *::before, *::after { box-sizing: border-box; }
  :root {
    --bg:       #000000;
    --surface:  #111116;
    --border:   #222228;
    --fg:       #c8c8d0;
    --muted:    #60606a;
    --purple:   #7c6af7;
    --green:    #5dbf5d;
    --red:      #d9534f;
    --font:     "SF Mono", "Cascadia Code", "Fira Code", ui-monospace, monospace;
  }
  html, body {
    margin: 0; padding: 0; height: 100%;
    background: var(--bg); color: var(--fg);
    font-family: var(--font); font-size: 13px; line-height: 1.6;
  }
  a { color: var(--purple); text-decoration: none; }
  a:hover { text-decoration: underline; }

  .layout { display: flex; flex-direction: column; height: 100%; max-width: 1100px; margin: 0 auto; padding: 1.5rem; }

  .header { display: flex; align-items: baseline; gap: 1rem; margin-bottom: 1rem; flex-shrink: 0; }
  .header h1 { color: var(--purple); font-size: 1rem; margin: 0; letter-spacing: .05em; }
  .header .job-id { color: var(--fg); font-size: .9rem; }
  .header .back { color: var(--muted); font-size: .8rem; margin-left: auto; }

  .meta-bar {
    display: flex; align-items: center; gap: 1.5rem;
    background: var(--surface); border: 1px solid var(--border);
    border-radius: 4px; padding: .5rem .85rem;
    margin-bottom: .75rem; flex-shrink: 0; font-size: .8rem;
  }
  @keyframes breathe {
    0%, 100% { box-shadow: 0 0 3px 1px var(--green); opacity: .85; }
    50%       { box-shadow: 0 0 8px 3px var(--green); opacity: 1; }
  }
  .meta-bar .status-dot { width: 8px; height: 8px; border-radius: 50%; }
  .meta-bar .status-dot.running   { background: var(--green); animation: breathe 2s ease-in-out infinite; }
  .meta-bar .status-dot.pending   { background: var(--muted); }
  .meta-bar .status-dot.completed { background: var(--green); }
  .meta-bar .status-dot.failed    { background: var(--red); }
  .meta-bar .label { color: var(--muted); }
  .meta-bar .value { color: var(--fg); }
  .meta-bar .spacer { flex: 1; }
  .btn-kill {
    background: none; border: 1px solid var(--border); color: var(--muted);
    padding: .2rem .6rem; border-radius: 3px; cursor: pointer; font-family: var(--font);
    font-size: .75rem; transition: color .15s, border-color .15s;
  }
  .btn-kill:hover { color: #e05050; border-color: #e05050; }
  .btn-kill.hidden { display: none; }
  .btn-retry {
    background: none; border: 1px solid var(--border); color: var(--muted);
    padding: .2rem .6rem; border-radius: 3px; cursor: pointer; font-family: var(--font);
    font-size: .75rem; transition: color .15s, border-color .15s;
  }
  .btn-retry:hover { color: var(--purple); border-color: var(--purple); }
  .btn-retry:disabled { opacity: .4; cursor: default; }

  #log-body {
    flex: 1; overflow-y: auto;
    background: var(--surface); border: 1px solid var(--border);
    border-radius: 4px; padding: .85rem 1rem;
    white-space: pre-wrap; word-break: break-all; font-size: .8rem; line-height: 1.55;
  }
  .log-line { display: block; }
  .log-line.hidden { display: none; }
  .log-prefix {
    display: inline-block; font-size: .7rem; width: 5.5em;
    opacity: .5; user-select: none; flex-shrink: 0;
  }
  .log-stdout      { color: var(--fg); }
  .log-stderr      { color: #e09060; }
  .log-proxy-out   { color: #7ab8d4; }
  .log-proxy-err   { color: #a08060; }
  .log-system      { color: var(--muted); font-style: italic; }
  .log-exit-ok     { color: var(--green); }
  .log-exit-err    { color: var(--red); }

  /* filter toggles */
  .filters { display: flex; gap: .4rem; flex-wrap: wrap; align-items: center; }
  .filter-btn {
    background: none; border: 1px solid var(--border); color: var(--muted);
    padding: .1rem .45rem; border-radius: 3px; cursor: pointer;
    font-family: var(--font); font-size: .7rem; transition: all .15s;
  }
  .filter-btn.active { border-color: currentColor; opacity: 1; }
  .filter-btn.f-stdout     { color: var(--fg); }
  .filter-btn.f-stderr     { color: #e09060; }
  .filter-btn.f-proxy-out  { color: #7ab8d4; }
  .filter-btn.f-proxy-err  { color: #a08060; }
  .filter-btn.f-system     { color: var(--muted); }
  .filter-btn:not(.active) { opacity: .35; }
</style>
</head>
<body>
<div class="layout">
  <div class="header">
    <h1><a id="home-link" href="/" style="color:inherit;text-decoration:none">nix-jail</a></h1>
    <span class="job-id">__JOB_ID__</span>
    <a class="back" href="/">&#8592; all jobs</a>
  </div>

  <div class="meta-bar" id="meta-bar">
    <span class="status-dot" id="status-dot"></span>
    <span class="label">status</span><span class="value" id="status-val">loading...</span>
    <span class="label">runtime</span><span class="value" id="runtime-val">&#x2014;</span>
    <span class="spacer"></span>
    <div class="filters">
      <span class="label">filter</span>
      <button class="filter-btn f-stdout   active" data-src="stdout"       onclick="toggleFilter(this)">stdout</button>
      <button class="filter-btn f-stderr   active" data-src="stderr"       onclick="toggleFilter(this)">stderr</button>
      <button class="filter-btn f-proxy-out active" data-src="proxy_stdout" onclick="toggleFilter(this)">proxy</button>
      <button class="filter-btn f-proxy-err active" data-src="proxy_stderr" onclick="toggleFilter(this)">proxy:err</button>
      <button class="filter-btn f-system   active" data-src="system"       onclick="toggleFilter(this)">system</button>
    </div>
    <button class="btn-retry" id="retry-btn" onclick="retryJob()">retry</button>
    <button class="btn-kill hidden" id="kill-btn" onclick="killJob()">kill</button>
  </div>

  <div id="log-body"></div>
</div>

<script>
const JOB_ID = '__JOB_ID__';

// Point the nix-jail heading at the home subdomain
document.getElementById('home-link').href =
  window.location.protocol + '//' +
  window.location.hostname.replace(/^[^.]+\./, 'home.');

const visibleSources = new Set(['stdout','stderr','proxy_stdout','proxy_stderr','system']);

const SOURCE_CLASS = {
  stdout:       'log-stdout',
  stderr:       'log-stderr',
  proxy_stdout: 'log-proxy-out',
  proxy_stderr: 'log-proxy-err',
  system:       'log-system',
};
const SOURCE_LABEL = {
  stdout:       'out',
  stderr:       'err',
  proxy_stdout: 'prx',
  proxy_stderr: 'prx:e',
  system:       'sys',
};

function toggleFilter(btn) {
  const src = btn.dataset.src;
  if (visibleSources.has(src)) {
    visibleSources.delete(src);
    btn.classList.remove('active');
  } else {
    visibleSources.add(src);
    btn.classList.add('active');
  }
  document.querySelectorAll('#log-body .log-line[data-src]').forEach(el => {
    el.classList.toggle('hidden', !visibleSources.has(el.dataset.src));
  });
}

function appendLog(entry) {
  const body = document.getElementById('log-body');
  const line = document.createElement('span');
  line.className = 'log-line';

  if (entry.exit_code !== undefined) {
    line.classList.add(entry.exit_code === 0 ? 'log-exit-ok' : 'log-exit-err');
    line.textContent = '[exit ' + entry.exit_code + ']\n';
  } else {
    const src = entry.source || 'stdout';
    line.dataset.src = src;
    line.classList.add(SOURCE_CLASS[src] || 'log-stdout');
    if (!visibleSources.has(src)) line.classList.add('hidden');

    const prefix = document.createElement('span');
    prefix.className = 'log-prefix';
    prefix.textContent = (SOURCE_LABEL[src] || src) + ' ';
    line.appendChild(prefix);

    const text = document.createTextNode(entry.content);
    line.appendChild(text);
  }

  body.appendChild(line);
  body.scrollTop = body.scrollHeight;
}

function setStatus(status, runtimeSecs) {
  const dot = document.getElementById('status-dot');
  dot.className = 'status-dot ' + status;
  document.getElementById('status-val').textContent = status;
  const rt = document.getElementById('runtime-val');
  if (runtimeSecs > 0) {
    rt.textContent = runtimeSecs < 60
      ? runtimeSecs + 's'
      : Math.floor(runtimeSecs / 60) + 'm ' + (runtimeSecs % 60) + 's';
  }
  const killBtn = document.getElementById('kill-btn');
  if (status === 'running') {
    killBtn.classList.remove('hidden');
  } else {
    killBtn.classList.add('hidden');
  }
}

async function killJob() {
  if (!confirm('Send SIGTERM to job ' + JOB_ID + '?')) return;
  try {
    const r = await fetch('/api/jobs/' + JOB_ID, { method: 'DELETE' });
    const data = await r.json();
    if (!r.ok) alert('Error: ' + (data.error || r.statusText));
  } catch(e) { alert('Kill failed: ' + e); }
}

async function retryJob() {
  const btn = document.getElementById('retry-btn');
  btn.disabled = true;
  btn.textContent = '...';
  try {
    const r = await fetch('/api/jobs/' + JOB_ID + '/retry', { method: 'POST' });
    const data = await r.json();
    if (!r.ok) { alert('Error: ' + (data.error || r.statusText)); return; }
    window.location.href = '/logs/' + data.job_id;
  } catch(e) {
    alert('Retry failed: ' + e);
  } finally {
    btn.disabled = false;
    btn.textContent = 'retry';
  }
}

let metaInterval = null;
async function refreshMeta() {
  try {
    const r = await fetch('/api/jobs');
    const data = await r.json();
    const job = (data.jobs || []).find(j => j.job_id === JOB_ID);
    if (job) {
      setStatus(job.status, job.runtime_seconds);
      if (job.status !== 'running' && job.status !== 'pending') {
        clearInterval(metaInterval);
        metaInterval = null;
      }
    }
  } catch(e) {}
}
refreshMeta();
metaInterval = setInterval(refreshMeta, 2000);

const es = new EventSource('/api/jobs/' + JOB_ID + '/stream');

es.addEventListener('log', e => {
  appendLog(JSON.parse(e.data));
});

es.addEventListener('done', () => {
  es.close();
  refreshMeta();
});

es.onerror = () => { es.close(); };
</script>
</body>
</html>
"###;

    let html = HTML.replace("__JOB_ID__", job_id);

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(hyper::header::CONTENT_TYPE, "text/html; charset=utf-8")
        .body(full_body(html))
        .unwrap_or_else(|_| error_response(StatusCode::INTERNAL_SERVER_ERROR, "render failed")))
}
