import http from 'http';

const server = http.createServer((req, res) => {
  // CORS headers
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'OPTIONS, GET, POST, PUT, PATCH, DELETE');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }

  res.setHeader('Content-Type', 'application/json');

  const url = new URL(req.url, `http://${req.headers.host}`);
  const path = url.pathname;

  let body = '';
  req.on('data', chunk => {
    body += chunk.toString();
  });

  req.on('end', () => {
    console.log(`[${req.method}] ${path}`, body ? body : '');

    if (path === '/api/login') {
      try {
        const payload = JSON.parse(body);
        if (payload.username === 'test' && payload.password === 'test') {
          res.writeHead(200);
          res.end(JSON.stringify({ ok: true, data: { token: "mock-token-12345" } }));
          return;
        }
      } catch(e) {}
      res.writeHead(401);
      res.end(JSON.stringify({ ok: false, error: "Invalid credentials" }));
      return;
    }

    if (path === '/api/server/status') {
      res.writeHead(200);
      res.end(JSON.stringify({
        ok: true,
        data: {
          version: "1.0.0-mock",
          uptime_seconds: 12345,
          active_users: 1,
          total_users: 2
        }
      }));
      return;
    }

    if (path === '/api/users') {
      res.writeHead(200);
      res.end(JSON.stringify({
        ok: true,
        data: [
          {
            access_key: "mock-client-1",
            name: "Test Client",
            limit_bytes: null,
            bytes_up: 1000,
            bytes_down: 5000,
            connections: 1,
            online: true,
            last_seen: Math.floor(Date.now() / 1000)
          },
          {
            access_key: "mock-offline-2",
            name: "Offline User",
            limit_bytes: 10737418240, // 10 GB
            bytes_up: 50000000,
            bytes_down: 150000000,
            connections: 0,
            online: false,
            last_seen: Math.floor(Date.now() / 1000) - 86400
          }
        ]
      }));
      return;
    }

    if (path === '/api/users/bulk') {
      res.writeHead(200);
      res.end(JSON.stringify({
        ok: true,
        data: [
          "mock-new-key-1",
          "mock-new-key-2"
        ]
      }));
      return;
    }

    if (path === '/api/router/rules') {
      res.writeHead(200);
      res.end(JSON.stringify({
        ok: true,
        data: [
          { action: "proxy", domain_suffix: ["google.com", "youtube.com"], ip_cidr: [] },
          { action: "block", domain_suffix: ["ads.example.com"], ip_cidr: [] },
          { action: "direct", domain_suffix: [], ip_cidr: ["192.168.1.0/24"] }
        ]
      }));
      return;
    }

    if (path === '/api/audit' || path === '/api/logs/audit') {
      res.writeHead(200);
      res.end(JSON.stringify({
        ok: true,
        data: [
          { timestamp: Math.floor(Date.now() / 1000), message: "Mock server started", message_ru: "Мок сервер запущен", success: true }
        ]
      }));
      return;
    }

    if (path === '/api/server/config') {
      res.writeHead(200);
      res.end(JSON.stringify({
        ok: true,
        data: {
          server: { bind: "0.0.0.0:53210" },
          api: { enabled: true, user: "test", port: 53210 },
          dns: { enabled: true, adblock: true }
        }
      }));
      return;
    }

    if (path === '/api/connections') {
      res.writeHead(200);
      res.end(JSON.stringify({
        ok: true,
        data: []
      }));
      return;
    }

    if (path === '/api/dns/config') {
      res.writeHead(200);
      res.end(JSON.stringify({
        ok: true,
        data: {
          enabled: true,
          doh_upstream: "https://cloudflare-dns.com/dns-query",
          adblock_urls: ["https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"],
          custom_domains: { "myrouter.lan": "192.168.1.1" }
        }
      }));
      return;
    }

    if (path === '/api/dns/queries') {
      res.writeHead(200);
      res.end(JSON.stringify({
        ok: true,
        data: [
          { timestamp: Math.floor(Date.now() / 1000), domain: "google.com", client_ip: "10.8.0.2", blocked: false },
          { timestamp: Math.floor(Date.now() / 1000) - 5, domain: "ads.example.com", client_ip: "10.8.0.3", blocked: true }
        ]
      }));
      return;
    }

    // Default 200 OK for anything else (e.g. POST /api/users, DELETE, etc.)
    res.writeHead(200);
    res.end(JSON.stringify({ ok: true, data: { success: true, message: "Mock response" } }));
  });
});

const PORT = 9090;
server.listen(PORT, () => {
  console.log(`\n🚀 Mock API server is running on http://localhost:${PORT}`);
  console.log(`👉 Login with:  username: test  |  password: test\n`);
});
