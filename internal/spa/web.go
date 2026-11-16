package spa

import (
	"encoding/json"
	"net"
	"net/http"
	"time"
)

// StartWeb 启动管理网页: 当前规则 / 用户(可吊销) / 最近授权记录。
func StartWeb(addr string, srv *Server) error {
	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(indexHTML))
	})
	mux.HandleFunc("/api/rules", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, srv.Firewall.List())
	})
	mux.HandleFunc("/api/log", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, srv.Log.Recent())
	})
	mux.HandleFunc("/api/users", func(w http.ResponseWriter, r *http.Request) {
		type userView struct {
			ID      string `json:"id"`
			Revoked bool   `json:"revoked"`
		}
		var out []userView
		for _, u := range srv.Users.List() {
			out = append(out, userView{ID: u.ID, Revoked: u.Revoked})
		}
		writeJSON(w, out)
	})
	mux.HandleFunc("/api/users/revoke", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		id := r.URL.Query().Get("id")
		if err := srv.Users.Revoke(id); err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		srv.Log.Add(AuthEvent{Time: time.Now(), IP: clientIP(r), User: id, OK: true, Reason: "user revoked via web"})
		writeJSON(w, map[string]string{"status": "revoked", "id": id})
	})

	return http.ListenAndServe(addr, mux)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	json.NewEncoder(w).Encode(v)
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

const indexHTML = `<!doctype html>
<html lang="zh">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SPA Gateway</title>
<style>
  :root { --bg:#0f1420; --panel:#1a2233; --fg:#dbe4f0; --dim:#8b98ad; --ok:#4ade80; --bad:#f87171; --line:#2a3550; }
  * { box-sizing: border-box; }
  body { margin:0; padding:24px; background:var(--bg); color:var(--fg); font:14px/1.5 -apple-system, "PingFang SC", sans-serif; }
  h1 { font-size:20px; margin:0 0 4px; }
  h2 { font-size:15px; margin:24px 0 8px; color:var(--dim); text-transform:uppercase; letter-spacing:.05em; }
  .sub { color:var(--dim); font-size:12px; }
  table { width:100%; border-collapse:collapse; background:var(--panel); border-radius:8px; overflow:hidden; }
  th, td { padding:8px 12px; text-align:left; border-bottom:1px solid var(--line); }
  th { color:var(--dim); font-weight:600; font-size:12px; }
  tr:last-child td { border-bottom:none; }
  .ok { color:var(--ok); } .bad { color:var(--bad); }
  button { background:#3b82f6; color:#fff; border:0; border-radius:6px; padding:4px 12px; cursor:pointer; }
  button:disabled { background:var(--line); color:var(--dim); cursor:default; }
  code { background:var(--panel); padding:2px 6px; border-radius:4px; }
</style>
</head>
<body>
<h1>SPA Gateway</h1>
<div class="sub">单包授权服务 · 每 2 秒自动刷新</div>

<h2>当前放开的规则</h2>
<table><thead><tr><th>#</th><th>来源 IP</th><th>端口</th><th>用户</th><th>放开时间</th><th>到期时间</th><th>剩余</th></tr></thead>
<tbody id="rules"></tbody></table>

<h2>用户</h2>
<table><thead><tr><th>用户</th><th>状态</th><th>操作</th></tr></thead>
<tbody id="users"></tbody></table>

<h2>最近授权记录</h2>
<table><thead><tr><th>时间</th><th>来源 IP</th><th>用户</th><th>端口</th><th>结果</th><th>说明</th></tr></thead>
<tbody id="log"></tbody></table>

<script>
const fmt = t => new Date(t).toLocaleString();
async function refresh() {
  const [rules, users, log] = await Promise.all([
    fetch('/api/rules').then(r => r.json()),
    fetch('/api/users').then(r => r.json()),
    fetch('/api/log').then(r => r.json()),
  ]);
  document.getElementById('rules').innerHTML = (rules || []).map(r => {
    const left = Math.max(0, Math.round((new Date(r.expires_at) - Date.now()) / 1000));
    return '<tr><td>' + r.id + '</td><td><code>' + r.ip + '</code></td><td>' + r.port +
      '</td><td>' + r.user + '</td><td>' + fmt(r.opened_at) + '</td><td>' + fmt(r.expires_at) +
      '</td><td>' + left + 's</td></tr>';
  }).join('') || '<tr><td colspan="7" class="sub">（无）</td></tr>';
  document.getElementById('users').innerHTML = (users || []).map(u =>
    '<tr><td>' + u.id + '</td><td class="' + (u.revoked ? 'bad' : 'ok') + '">' +
    (u.revoked ? '已吊销' : '正常') + '</td><td>' +
    (u.revoked ? '' : '<button onclick="revoke(\'' + u.id + '\')">吊销</button>') +
    '</td></tr>').join('');
  document.getElementById('log').innerHTML = (log || []).map(e =>
    '<tr><td>' + fmt(e.time) + '</td><td><code>' + e.ip + '</code></td><td>' + (e.user || '-') +
    '</td><td>' + (e.port || '-') + '</td><td class="' + (e.ok ? 'ok' : 'bad') + '">' +
    (e.ok ? '通过' : '拒绝') + '</td><td>' + e.reason + '</td></tr>').join('') ||
    '<tr><td colspan="6" class="sub">（无）</td></tr>';
}
async function revoke(id) {
  if (!confirm('确定吊销用户 ' + id + ' ? 该用户的包将立即失效。')) return;
  await fetch('/api/users/revoke?id=' + encodeURIComponent(id), { method: 'POST' });
  refresh();
}
refresh();
setInterval(refresh, 2000);
</script>
</body>
</html>
`
