// เว็บฝากไฟล์: แอดมินล็อกอินแล้วอัปโหลดไฟล์ได้ ไฟล์เก็บถาวรบนดิสก์ + จำรายการไฟล์ไว้
// ไม่ต้องติดตั้งแพ็กเกจเพิ่ม (Node 18+)
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// โหลด .env
try {
  for (const line of fs.readFileSync(path.join(__dirname, '.env'), 'utf8').split(/\r?\n/)) {
    const m = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*)\s*$/);
    if (m && !(m[1] in process.env)) process.env[m[1]] = m[2];
  }
} catch (_) {}

const PORT = process.env.PORT || 3000;
const ADMIN_KEY = process.env.ADMIN_KEY;
const SECRET = process.env.SESSION_SECRET;
if (!ADMIN_KEY || !SECRET) { console.error('ต้องตั้ง ADMIN_KEY และ SESSION_SECRET ใน .env'); process.exit(1); }

// ---------- ที่เก็บไฟล์ ----------
// ตั้ง DATA_DIR ให้ชี้ไปโฟลเดอร์ที่ "ถาวร" (เช่น Persistent Disk ของ Render = /var/data)
// ถ้าไม่ตั้ง จะเก็บในโฟลเดอร์ data ข้างโปรเจกต์ ซึ่งบนโฮสต์บางเจ้าจะถูกล้างทุกครั้งที่ deploy/รีสตาร์ท
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const FILES_DIR = path.join(DATA_DIR, 'files');
const INDEX_FILE = path.join(DATA_DIR, 'files.json');
const MAX_BYTES = (Number(process.env.MAX_UPLOAD_MB) || 200) * 1024 * 1024;
const MAYBE_EPHEMERAL = !!process.env.RENDER && !process.env.DATA_DIR; // รันบน Render แต่ไม่ได้ตั้ง DATA_DIR
fs.mkdirSync(FILES_DIR, { recursive: true });
for (const f of fs.readdirSync(FILES_DIR)) if (f.endsWith('.part')) fs.unlink(path.join(FILES_DIR, f), () => {}); // เก็บกวาดไฟล์ค้างจากอัปโหลดที่ขาดกลางทาง

let index = [];
try {
  const parsed = JSON.parse(fs.readFileSync(INDEX_FILE, 'utf8'));
  if (Array.isArray(parsed)) index = parsed;
} catch (e) {
  if (e.code !== 'ENOENT') {
    const backup = path.join(DATA_DIR, `files.corrupt-${Date.now()}.json`); // ไฟล์รายการเสีย: เก็บสำรองไว้ ไม่เขียนทับ
    try { fs.renameSync(INDEX_FILE, backup); console.error('files.json เสีย ย้ายไปเก็บที่', backup); } catch (_) {}
  }
}
const saveIndex = () => {
  const tmp = INDEX_FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(index, null, 2));
  fs.renameSync(tmp, INDEX_FILE); // เขียนไฟล์ชั่วคราวก่อนแล้วสลับ กันไฟล์พังตอนไฟดับ
};

// ---------- ล็อกอินแอดมิน ----------
const SESSION_MS = 12 * 60 * 60 * 1000;
const sign = (v) => crypto.createHmac('sha256', SECRET).update(v).digest('hex');
const safeEq = (a, b) => {
  const x = crypto.createHash('sha256').update(String(a)).digest();
  const y = crypto.createHash('sha256').update(String(b)).digest();
  return crypto.timingSafeEqual(x, y);
};
const makeToken = () => { const exp = String(Date.now() + SESSION_MS); return exp + '.' + sign(exp); };
const validToken = (t) => {
  if (!t) return false;
  const [exp, sig] = t.split('.');
  return !!sig && safeEq(sig, sign(exp)) && Number(exp) > Date.now();
};
const cookies = (req) => Object.fromEntries((req.headers.cookie || '').split(';').map(s => s.trim().split('=')).filter(a => a[0]).map(([k, ...v]) => [k, v.join('=')]));
const isAuthed = (req) => validToken(cookies(req).session);

// จำกัดการเดารหัส: ผิด 5 ครั้งใน 10 นาที ล็อก IP นั้น
const fails = new Map();
const blocked = (ip) => { const f = fails.get(ip); return f && f.n >= 5 && Date.now() - f.t < 600000; };
const addFail = (ip) => { const f = fails.get(ip); fails.set(ip, f && Date.now() - f.t < 600000 ? { n: f.n + 1, t: f.t } : { n: 1, t: Date.now() }); };

const json = (res, code, obj, headers = {}) => { res.writeHead(code, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', ...headers }); res.end(JSON.stringify(obj)); };
const sendFile = (res, file, type = 'text/html; charset=utf-8') => fs.readFile(file, (e, d) => {
  if (e) { res.writeHead(404); return res.end('Not found'); }
  res.writeHead(200, { 'Content-Type': type, 'Cache-Control': 'no-store' }); res.end(d);
});
const redirect = (res, to) => { res.writeHead(302, { Location: to }); res.end(); };

const ID_RE = /^[a-f0-9]{32}$/;
const cleanName = (s) => String(s || '').replace(/[\u0000-\u001f\u007f]/g, '').split(/[\\/]/).pop().trim().slice(0, 200);

// ---------- อัปโหลด (สตรีมลงดิสก์ ไม่โหลดทั้งไฟล์เข้าหน่วยความจำ) ----------
function handleUpload(req, res) {
  let name = '';
  try { name = cleanName(decodeURIComponent(req.headers['x-filename'] || '')); } catch (_) {}
  if (!name) return json(res, 400, { success: false, error: 'ไม่มีชื่อไฟล์' });
  const declared = Number(req.headers['content-length'] || 0);
  const limitMb = Math.round(MAX_BYTES / 1024 / 1024);
  if (declared > MAX_BYTES) {
    json(res, 413, { success: false, error: `ไฟล์ใหญ่เกิน ${limitMb} MB` }, { Connection: 'close' });
    return res.on('finish', () => req.destroy());
  }

  const id = crypto.randomBytes(16).toString('hex');
  const finalPath = path.join(FILES_DIR, id);
  const tmpPath = finalPath + '.part';
  const out = fs.createWriteStream(tmpPath, { flags: 'wx' });
  const hash = crypto.createHash('sha256');
  let size = 0, done = false;

  const abort = (code, msg) => {
    if (done) return; done = true;
    out.destroy(); fs.unlink(tmpPath, () => {});
    if (res.headersSent) return;
    json(res, code, { success: false, error: msg }, { Connection: 'close' });
    res.on('finish', () => req.destroy());
  };

  req.on('data', (chunk) => {
    if (done) return;
    size += chunk.length;
    if (size > MAX_BYTES) return abort(413, `ไฟล์ใหญ่เกิน ${limitMb} MB`);
    hash.update(chunk);
    if (!out.write(chunk)) { req.pause(); out.once('drain', () => req.resume()); }
  });
  req.on('close', () => { if (!req.complete) abort(499, 'การอัปโหลดถูกยกเลิก'); });
  req.on('error', () => abort(400, 'การอัปโหลดผิดพลาด'));
  out.on('error', (e) => { console.error(e); abort(500, 'เขียนไฟล์ลงดิสก์ไม่สำเร็จ'); });
  req.on('end', () => {
    if (done) return;
    out.end(() => {
      if (done) return;
      if (size === 0) return abort(400, 'ไฟล์ว่างเปล่า');
      done = true;
      fs.rename(tmpPath, finalPath, (err) => {
        if (err) { console.error(err); fs.unlink(tmpPath, () => {}); return json(res, 500, { success: false, error: 'บันทึกไฟล์ไม่สำเร็จ' }); }
        const item = {
          id, name, size,
          type: String(req.headers['x-filetype'] || '').slice(0, 100),
          sha256: hash.digest('hex'),
          uploadedAt: new Date().toISOString(),
        };
        index.push(item);
        try { saveIndex(); } catch (e) {
          console.error(e); index.pop(); fs.unlink(finalPath, () => {});
          return json(res, 500, { success: false, error: 'บันทึกรายการไฟล์ไม่สำเร็จ' });
        }
        json(res, 201, { success: true, file: item });
      });
    });
  });
}

http.createServer((req, res) => {
  const url = req.url.split('?')[0];
  const ip = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
  const secure = req.headers['x-forwarded-proto'] === 'https' ? '; Secure' : '';

  if (req.method === 'POST' && url === '/api/admin/login') {
    if (blocked(ip)) return json(res, 429, { success: false, error: 'ลองผิดหลายครั้งเกินไป กรุณารอ 10 นาที' });
    let body = '';
    req.on('data', c => { body += c; if (body.length > 2000) req.destroy(); });
    req.on('end', () => {
      let key = '';
      try { key = JSON.parse(body).key || ''; } catch (_) {}
      if (key && safeEq(key, ADMIN_KEY)) {
        fails.delete(ip);
        return json(res, 200, { success: true }, { 'Set-Cookie': `session=${makeToken()}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${SESSION_MS / 1000}${secure}` });
      }
      addFail(ip);
      json(res, 401, { success: false, error: 'คีย์ไม่ถูกต้อง' });
    });
    return;
  }
  if (req.method === 'POST' && url === '/api/admin/logout')
    return json(res, 200, { success: true }, { 'Set-Cookie': 'session=; HttpOnly; Path=/; Max-Age=0' });

  // ---------- ดาวน์โหลดผ่านลิงก์ (ใครมีลิงก์ก็โหลดได้ รหัสในลิงก์สุ่ม เดาไม่ได้) ----------
  if (req.method === 'GET' && url.startsWith('/f/')) {
    const id = url.slice(3);
    const item = ID_RE.test(id) && index.find(f => f.id === id);
    if (!item) { res.writeHead(404); return res.end('Not found'); }
    const file = path.join(FILES_DIR, id);
    return fs.stat(file, (e, st) => {
      if (e) { res.writeHead(404); return res.end('ไม่พบไฟล์นี้บนเซิร์ฟเวอร์'); }
      res.writeHead(200, {
        'Content-Type': 'application/octet-stream', // บังคับให้เป็นดาวน์โหลด ไม่ให้เบราว์เซอร์รันไฟล์ HTML/JS ที่อัปโหลดมา
        'Content-Disposition': `attachment; filename*=UTF-8''${encodeURIComponent(item.name)}`,
        'Content-Length': st.size,
        'X-Content-Type-Options': 'nosniff',
      });
      fs.createReadStream(file).on('error', () => res.destroy()).pipe(res);
    });
  }

  // ---------- API ไฟล์ (ต้องล็อกอินแอดมิน) ----------
  if (url === '/api/files' || url.startsWith('/api/files/')) {
    if (!isAuthed(req)) return json(res, 401, { success: false, error: 'กรุณาเข้าสู่ระบบ' });
    const id = url.startsWith('/api/files/') ? url.slice('/api/files/'.length) : null;

    if (req.method === 'GET' && !id) {
      const files = index.map(f => ({ ...f, missing: !fs.existsSync(path.join(FILES_DIR, f.id)) })); // missing = มีในรายการแต่ไฟล์จริงหาย
      return json(res, 200, { success: true, files, maxMb: Math.round(MAX_BYTES / 1024 / 1024), maybeEphemeral: MAYBE_EPHEMERAL });
    }
    if (req.method === 'POST' && !id) return handleUpload(req, res);

    if (req.method === 'DELETE' && id) {
      const i = ID_RE.test(id) ? index.findIndex(f => f.id === id) : -1;
      if (i < 0) return json(res, 404, { success: false, error: 'ไม่พบไฟล์' });
      const [removed] = index.splice(i, 1);
      try { saveIndex(); } catch (e) { console.error(e); index.splice(i, 0, removed); return json(res, 500, { success: false, error: 'บันทึกรายการไม่สำเร็จ' }); }
      fs.unlink(path.join(FILES_DIR, id), () => {});
      return json(res, 200, { success: true });
    }
    return json(res, 405, { success: false, error: 'ไม่รองรับคำสั่งนี้ (ไฟล์ที่ฝากแล้วแก้ไข/เขียนทับไม่ได้)' });
  }

  if (url === '/login' || url === '/login.html') return sendFile(res, path.join(__dirname, 'public', 'login.html'));
  if (url === '/') return isAuthed(req) ? sendFile(res, path.join(__dirname, 'private', 'admin.html')) : redirect(res, '/login');
  res.writeHead(404); res.end('Not found');
}).listen(PORT, () => console.log('เปิดที่ http://localhost:' + PORT + ' | เก็บข้อมูลที่ ' + DATA_DIR));
