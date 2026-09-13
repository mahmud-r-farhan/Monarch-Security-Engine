/**
 * "Vulnerable Corp" — an intentionally misconfigured demo application used to exercise the engine.
 * Run:  npm run demo:target   (listens on :4000)
 * Then scan http://localhost:4000 from the dashboard or CLI.
 */
import express from 'express';

const app = express();
const PORT = Number(process.env.DEMO_PORT || 4000);

// Unsigned JWT with sensitive + privileged claims (alg=none)
const b64 = o => Buffer.from(JSON.stringify(o)).toString('base64url');
const NONE_JWT = `${b64({ alg: 'none', typ: 'JWT' })}.${b64({ sub: 42, role: 'admin', email: 'ceo@vulnerable.corp', iat: 1700000000 })}.`;
const HS_JWT = `${b64({ alg: 'HS256', typ: 'JWT' })}.${b64({ sub: 7, iat: 1700000000, exp: 1700000000 + 60 * 60 * 24 * 365 })}.c2lnbmF0dXJlLXBsYWNlaG9sZGVy`;

app.use((req, res, next) => {
  res.set('X-Powered-By', 'Express/4.21.2 PHP/7.4.3');
  res.set('Server', 'Apache/2.4.29 (Ubuntu)');
  // Reflect any Origin with credentials — classic CORS misconfiguration
  if (req.headers.origin) { res.set('Access-Control-Allow-Origin', req.headers.origin); res.set('Access-Control-Allow-Credentials', 'true'); }
  next();
});

const layout = (title, body) => `<!doctype html><html><head><meta charset="utf-8"><title>${title} · Vulnerable Corp</title>
<link rel="stylesheet" href="/style.css">
<script src="https://cdn.jsdelivr.net/npm/lodash@4.17.21/lodash.min.js"></script>
<script src="/app.js"></script></head>
<body><nav><a href="/">Home</a> · <a href="/login">Login</a> · <a href="/profile">Profile</a> · <a href="/contact">Contact</a> · <a href="/search?q=test">Search</a></nav>
<h1>${title}</h1>${body}
<img src="http://placehold.co/300x80?text=Insecure+Image" alt="mixed content">
<footer onclick="track()">© Vulnerable Corp</footer></body></html>`;

app.get('/', (req, res) => {
  res.cookie('sessionid', 'abc123def456ghi789', { httpOnly: false, secure: false });
  res.cookie('auth_token', NONE_JWT, { httpOnly: false, secure: false, sameSite: 'none' });
  res.cookie('prefs', 'theme=dark');
  res.send(layout('Welcome', `<p>The world's least secure intranet.</p>
<script>
  // token bootstrap
  const token = "${HS_JWT}";
  localStorage.setItem('auth_token', token);
  const params = new URLSearchParams(location.search);
  document.getElementById('banner')?.insertAdjacentHTML('beforeend', params.get('msg') || '');
</script><div id="banner"></div>`));
});

app.get('/login', (req, res) => res.send(layout('Login', `
<form method="GET" action="/do-login">
  <input name="username" placeholder="Username"><input type="password" name="password" placeholder="Password">
  <button>Sign in</button>
</form>`)));

app.get('/do-login', (req, res) => res.redirect('/profile'));

app.get('/profile', (req, res) => res.send(layout('Profile', `
<form method="POST" action="/profile/update">
  <input name="display_name" value="Alice"><input name="email" value="alice@vulnerable.corp">
  <button>Save</button>
</form>
<script>
  window.addEventListener('message', function (e) { document.body.innerHTML += e.data; });
</script>`)));

app.post('/profile/update', (req, res) => res.redirect('/profile'));
app.get('/contact', (req, res) => res.send(layout('Contact', `<form method="POST" action="/contact"><textarea name="message"></textarea><button>Send</button></form>`)));
app.post('/contact', (req, res) => res.send(layout('Thanks', '<p>Sent.</p>')));
app.get('/search', (req, res) => res.send(layout('Search', `<p>Results for: <span id="q"></span></p><script>document.getElementById('q').innerHTML = decodeURIComponent(location.search.slice(3));</script>`)));

app.get('/app.js', (_, res) => res.type('js').send(`
// production bundle
const API_KEY = "AKIAIOSFODNN7EXAMPLE";
const STRIPE = "sk_live_51H8xUvKZvKuVv3Q9aBcDeFgHiJkLmNoPq";
function track(){ fetch('/api/track', { headers: { Authorization: 'Bearer ${HS_JWT}' } }); }
function render(html){ document.getElementById('out').innerHTML = html + location.hash; }
eval("1+1");
//# sourceMappingURL=app.js.map
`));
app.get('/style.css', (_, res) => res.type('css').send('body{font-family:system-ui;max-width:720px;margin:40px auto;padding:0 20px}nav a{margin-right:8px}'));

// Exposed artefacts
app.get('/.env', (_, res) => res.type('text').send('DB_PASSWORD=hunter2\nJWT_SECRET=changeme\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n'));
app.get('/.git/HEAD', (_, res) => res.type('text').send('ref: refs/heads/main\n'));
app.get('/phpinfo.php', (_, res) => res.send('<html><body><h1>PHP Version 7.4.3</h1><p>phpinfo()</p></body></html>'));
app.get('/robots.txt', (_, res) => res.type('text').send('User-agent: *\nDisallow: /admin-backup/\nDisallow: /internal/\n'));
app.get('/admin', (_, res) => res.send('<html><body><h1>Admin Login</h1><form><input type="password" name="password"></form></body></html>'));
app.get('/api/track', (_, res) => res.json({ ok: true }));

app.listen(PORT, '0.0.0.0', () => console.log(`  🎯 Vulnerable Corp demo target → http://localhost:${PORT}  (intentionally insecure — scan me!)`));
