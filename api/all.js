const { createClient } = require('@libsql/client');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

const db = createClient({
  url: process.env.TURSO_URL,
  authToken: process.env.TURSO_TOKEN,
});

// ---------- 初始化数据库（自动建表 + 插入默认用户） ----------
async function initDB() {
  // 创建表（如果不存在）
  await db.execute(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      nickname TEXT DEFAULT '管理员',
      avatar TEXT DEFAULT '👤',
      settings TEXT DEFAULT '{}'
    )
  `);
  await db.execute(`
    CREATE TABLE IF NOT EXISTS records (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      scan_date TEXT NOT NULL,
      part_number TEXT NOT NULL,
      quantity INTEGER NOT NULL,
      mpn TEXT DEFAULT '',
      scan_time TEXT NOT NULL,
      FOREIGN KEY (user_id) REFERENCES users(id)
    )
  `);
  await db.execute(`
    CREATE TABLE IF NOT EXISTS locations (
      user_id INTEGER NOT NULL,
      part_number TEXT NOT NULL,
      location TEXT NOT NULL,
      PRIMARY KEY (user_id, part_number),
      FOREIGN KEY (user_id) REFERENCES users(id)
    )
  `);
  await db.execute(`
    CREATE TABLE IF NOT EXISTS messages (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      sender_name TEXT NOT NULL,
      content TEXT NOT NULL,
      created_at TEXT DEFAULT (datetime('now','localtime')),
      FOREIGN KEY (user_id) REFERENCES users(id)
    )
  `);

  // 插入默认用户（如果不存在）
  const existing = await db.execute('SELECT id FROM users WHERE username = ?', ['cangku']);
  if (existing.rows.length === 0) {
    const hash = bcrypt.hashSync('927521', 10);
    await db.execute('INSERT INTO users (username, password_hash, nickname) VALUES (?,?,?)', ['cangku', hash, '管理员']);
  }
}

// 首次请求时初始化
let initialized = false;

// ---------- 认证中间件 ----------
function auth(req) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith('Bearer ')) return null;
  try {
    return jwt.verify(header.split(' ')[1], process.env.JWT_SECRET);
  } catch { return null; }
}

// ---------- 解析请求体 ----------
function parseBody(req) {
  return new Promise((resolve) => {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', () => {
      try { resolve(JSON.parse(body)); } catch { resolve({}); }
    });
  });
}

// ---------- 主处理函数 ----------
module.exports = async (req, res) => {
  // 自动初始化
  if (!initialized) {
    await initDB();
    initialized = true;
  }

  // CORS 预检
  if (req.method === 'OPTIONS') {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    return res.status(204).end();
  }

  const url = new URL(req.url, `http://${req.headers.host}`);
  const path = url.pathname.replace('/api', '').replace(/^\/+|\/+$/g, '');
  const pathParts = path.split('/');

  // ========== 登录 ==========
  if (req.method === 'POST' && path === 'auth/login') {
    const { username, password } = await parseBody(req);
    const result = await db.execute('SELECT id, username, password_hash, nickname, avatar FROM users WHERE username = ?', [username]);
    if (result.rows.length === 0) return res.status(401).json({ error: '账号或密码错误' });
    const user = result.rows[0];
    const valid = bcrypt.compareSync(password, user.password_hash);
    if (!valid) return res.status(401).json({ error: '账号或密码错误' });
    const token = jwt.sign(
      { id: user.id, username: user.username, nickname: user.nickname },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );
    return res.json({ token, user: { id: user.id, nickname: user.nickname, avatar: user.avatar } });
  }

  // ========== 需要认证的接口 ==========
  const user = auth(req);
  if (!user) return res.status(401).json({ error: '未授权' });

  // ---------- 修改密码 ----------
  if (req.method === 'POST' && path === 'auth/change-password') {
    const { oldPwd, newPwd } = await parseBody(req);
    const row = await db.execute('SELECT password_hash FROM users WHERE id = ?', [user.id]);
    if (!bcrypt.compareSync(oldPwd, row.rows[0].password_hash)) return res.status(400).json({ error: '旧密码错误' });
    const hash = bcrypt.hashSync(newPwd, 10);
    await db.execute('UPDATE users SET password_hash = ? WHERE id = ?', [hash, user.id]);
    return res.json({ success: true });
  }

  // ---------- 用户信息 ----------
  if (path === 'user/profile') {
    if (req.method === 'GET') {
      const row = await db.execute('SELECT nickname, avatar FROM users WHERE id = ?', [user.id]);
      return res.json(row.rows[0]);
    }
    if (req.method === 'PUT') {
      const { nickname, avatar } = await parseBody(req);
      await db.execute('UPDATE users SET nickname = ?, avatar = ? WHERE id = ?', [nickname || user.nickname, avatar || '👤', user.id]);
      return res.json({ success: true });
    }
  }

  // ---------- 用户设置 ----------
  if (path === 'user/settings') {
    if (req.method === 'GET') {
      const row = await db.execute('SELECT settings FROM users WHERE id = ?', [user.id]);
      return res.json(JSON.parse(row.rows[0].settings || '{}'));
    }
    if (req.method === 'PUT') {
      const { settings } = await parseBody(req);
      await db.execute('UPDATE users SET settings = ? WHERE id = ?', [JSON.stringify(settings), user.id]);
      return res.json({ success: true });
    }
  }

  // ---------- 盘点记录 ----------
  if (path.startsWith('records')) {
    if (req.method === 'GET') {
      const date = url.searchParams.get('date');
      const rows = await db.execute(
        'SELECT id, scan_time AS time, part_number AS part, quantity AS qty, mpn FROM records WHERE user_id = ? AND scan_date = ? ORDER BY scan_time',
        [user.id, date]
      );
      return res.json(rows.rows);
    }
    if (req.method === 'POST') {
      const { part, qty, mpn, time } = await parseBody(req);
      const today = new Date().toISOString().split('T')[0];
      await db.execute(
        'INSERT INTO records (user_id, scan_date, part_number, quantity, mpn, scan_time) VALUES (?,?,?,?,?,?)',
        [user.id, today, part, qty, mpn || '', time]
      );
      return res.json({ success: true });
    }
    if (req.method === 'DELETE') {
      if (pathParts[1] === 'delete-day') {
        const date = url.searchParams.get('date');
        await db.execute('DELETE FROM records WHERE user_id = ? AND scan_date = ?', [user.id, date]);
      } else {
        const id = pathParts[1];
        if (id) await db.execute('DELETE FROM records WHERE id = ? AND user_id = ?', [id, user.id]);
      }
      return res.json({ success: true });
    }
  }

  // ---------- 储位管理 ----------
  if (path.startsWith('locations')) {
    if (req.method === 'GET') {
      const search = url.searchParams.get('search') || '';
      const rows = await db.execute(
        'SELECT part_number AS part, location FROM locations WHERE user_id = ?',
        [user.id]
      );
      let list = rows.rows;
      if (search) list = list.filter(item => item.part.endsWith(search));
      return res.json(list);
    }
    if (req.method === 'POST') {
      const { part, location } = await parseBody(req);
      await db.execute(
        'INSERT OR REPLACE INTO locations (user_id, part_number, location) VALUES (?,?,?)',
        [user.id, part, location]
      );
      return res.json({ success: true });
    }
    if (req.method === 'DELETE') {
      const part = pathParts[1];
      if (part) await db.execute('DELETE FROM locations WHERE user_id = ? AND part_number = ?', [user.id, part]);
      return res.json({ success: true });
    }
  }

  // ---------- 聊天消息 ----------
  if (path.startsWith('chat/messages')) {
    if (req.method === 'GET') {
      const since = parseInt(url.searchParams.get('since')) || 0;
      const rows = await db.execute(
        `SELECT id, sender_name AS sender, content AS text, created_at AS time 
         FROM messages 
         WHERE id > ? 
         ORDER BY id ASC 
         LIMIT 200`,
        [since]
      );
      return res.json(rows.rows);
    }
    if (req.method === 'POST') {
      const { content } = await parseBody(req);
      if (!content || content.trim().length === 0) return res.status(400).json({ error: '内容不能为空' });
      await db.execute(
        'INSERT INTO messages (user_id, sender_name, content) VALUES (?,?,?)',
        [user.id, user.nickname || user.username, content]
      );
      return res.json({ success: true });
    }
  }

  res.status(404).json({ error: 'Not Found' });
};
