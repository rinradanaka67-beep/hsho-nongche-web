// เว็บฝากไฟล์ — ไม่ต้องติดตั้งแพ็กเกจเพิ่ม (Node 18+)
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// ---- โหลด .env ----
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
const SITE_NAME = process.env.SITE_NAME || 'files';
const MAX_BYTES = (Number(process.env.MAX_MB) || 200) * 1024 * 1024;
const MAX_TOTAL = (Number(process.env.MAX_TOTAL_GB) || 5) * 1073741824;
const UPLOAD_DIR = process.env.UPLOAD_DIR || path.join(__dirname, 'uploads');
const DB_FILE = process.env.DB_FILE || path.join(__dirname, 'data.json');
fs.mkdirSync(UPLOAD_DIR, { recursive: true });
for (const f of fs.readdirSync(UPLOAD_DIR)) if (f.startsWith('.tmp-')) fs.unlink(path.join(UPLOAD_DIR, f), () => {});

// ---- ฐานข้อมูลไฟล์ (JSON) ----
let db = {};
try { db = JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); } catch (_) {}
const saveDb = () => fs.writeFileSync(DB_FILE, JSON.stringify(db));
const META_FILE = DB_FILE.replace(/\.json$/, '') + '.meta.json';
let meta = { folders: [], release: null };
try { meta = { ...meta, ...JSON.parse(fs.readFileSync(META_FILE, 'utf8')) }; } catch (_) {}
const saveMeta = () => fs.writeFileSync(META_FILE, JSON.stringify(meta));
const RELEASE_DIR = path.join(UPLOAD_DIR, '.release');
fs.mkdirSync(RELEASE_DIR, { recursive: true });
const normDir = (s) => String(s || '').split('/').map((p) => p.trim()).filter((p) => p && p !== '.' && p !== '..').map(cleanName).join('/');
const inDir = (d, p) => d === p || d.startsWith(p + '/');
const totalSize = () => Object.values(db).reduce((n, f) => n + f.size, 0);
const bySlug = (slug) => Object.entries(db).find(([, f]) => f.slug === slug);

const cleanName = (n) => (String(n).replace(/[\\/:*?"<>|\x00-\x1f]/g, '_').replace(/^\.+/, '_').slice(0, 150)) || 'file';
const RESERVED = /^(api(\/|$)|login(\/|$)|admin(\/|$)|f(\/|$)|update(\/|$))/;
const checkSlug = (slug, selfId) => {
  if (!slug) return null;
  if (slug.length > 100 || !/^[A-Za-z0-9._~-]+(\/[A-Za-z0-9._~-]+)*$/.test(slug)) return 'ชื่อลิงก์ใช้ได้เฉพาะ a-z 0-9 . _ - และ / (ห้ามเว้นวรรค/ภาษาไทย)';
  if (slug.split('/').some((p) => /^\.+$/.test(p))) return 'ชื่อลิงก์ไม่ถูกต้อง';
  if (RESERVED.test(slug)) return 'ชื่อลิงก์นี้ถูกใช้โดยระบบ';
  const o = bySlug(slug);
  if (o && o[0] !== selfId) return 'มีไฟล์ใช้ชื่อลิงก์นี้อยู่แล้ว';
  return null;
};
const INLINE = { '.png':'image/png','.jpg':'image/jpeg','.jpeg':'image/jpeg','.gif':'image/gif','.webp':'image/webp','.mp4':'video/mp4','.webm':'video/webm','.mp3':'audio/mpeg','.wav':'audio/wav','.pdf':'application/pdf','.txt':'text/plain; charset=utf-8','.json':'application/json; charset=utf-8' };

// ---- เซสชัน ----
const SESSION_MS = 12 * 60 * 60 * 1000;
const sign = (v) => crypto.createHmac('sha256', SECRET).update(v).digest('hex');
const safeEq = (a, b) => crypto.timingSafeEqual(crypto.createHash('sha256').update(String(a)).digest(), crypto.createHash('sha256').update(String(b)).digest());
const makeToken = () => { const exp = String(Date.now() + SESSION_MS); return exp + '.' + sign(exp); };
const validToken = (t) => { if (!t) return false; const [exp, sig] = t.split('.'); return !!sig && safeEq(sig, sign(exp)) && Number(exp) > Date.now(); };
const cookies = (req) => Object.fromEntries((req.headers.cookie || '').split(';').map(s => s.trim().split('=')).filter(a => a[0]).map(([k, ...v]) => [k, v.join('=')]));
const isAuthed = (req) => validToken(cookies(req).session);

const fails = new Map();
const blocked = (ip) => { const f = fails.get(ip); return f && f.n >= 5 && Date.now() - f.t < 600000; };
const addFail = (ip) => { const f = fails.get(ip); fails.set(ip, f && Date.now() - f.t < 600000 ? { n: f.n + 1, t: f.t } : { n: 1, t: Date.now() }); };

// ---- ตัวช่วย ----
const json = (res, code, obj, headers = {}) => { res.writeHead(code, { 'Content-Type': 'application/json', ...headers }); res.end(JSON.stringify(obj)); };
const esc = (v) => String(v).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const sendFile = (res, file) => fs.readFile(file, 'utf8', (e, d) => {
  if (e) { res.writeHead(404); return res.end('Not found'); }
  res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' }); res.end(d.replace(/\{\{SITE_NAME\}\}/g, esc(SITE_NAME)));
});
const redirect = (res, to) => { res.writeHead(302, { Location: to }); res.end(); };
const readBody = (req, cb) => { let b = ''; req.on('data', c => { b += c; if (b.length > 5000) req.destroy(); }); req.on('end', () => { try { cb(JSON.parse(b)); } catch (_) { cb({}); } }); };
const baseUrl = (req) => process.env.BASE_URL || ((req.headers['x-forwarded-proto'] || 'http') + '://' + req.headers.host);
const linkOf = (req, id) => { const f = db[id]; return baseUrl(req) + (f.slug ? '/' + f.slug : '/f/' + id + '/' + encodeURIComponent(f.name)); };

// รับไฟล์จาก body ลงไฟล์ชั่วคราวแบบสตรีม (ไม่กินแรม) แล้วเรียก done(tmpPath, size)
function receive(req, res, replacingSize, done) {
  const len = Number(req.headers['content-length'] || 0);
  const tooBig = () => json(res, 413, { error: 'ไฟล์ใหญ่เกิน ' + MAX_BYTES / 1048576 + ' MB' });
  if (len > MAX_BYTES) return tooBig();
  if (totalSize() - replacingSize + len > MAX_TOTAL) return json(res, 507, { error: 'พื้นที่เซิร์ฟเวอร์เต็ม' });
  const tmp = path.join(UPLOAD_DIR, '.tmp-' + crypto.randomBytes(8).toString('hex'));
  const out = fs.createWriteStream(tmp);
  let got = 0, dead = false;
  const kill = (fn) => { if (dead) return; dead = true; out.destroy(); fs.unlink(tmp, () => {}); fn(); };
  req.on('data', (c) => { got += c.length; if (got > MAX_BYTES) { kill(tooBig); req.destroy(); } });
  req.on('aborted', () => kill(() => {}));
  req.pipe(out);
  out.on('finish', () => { if (!dead) done(tmp, got); });
  out.on('error', () => kill(() => json(res, 500, { error: 'บันทึกไฟล์ไม่สำเร็จ' })));
}

// ---- ZIP แบบ store (ไม่บีบอัด) พร้อม zip64 ----
const CRC = (() => { const t = new Uint32Array(256); for (let n = 0; n < 256; n++) { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xEDB88320 ^ (c >>> 1) : c >>> 1; t[n] = c >>> 0; } return t; })();
const crcStream = (file) => new Promise((ok, no) => { let c = 0xFFFFFFFF; fs.createReadStream(file).on('data', (b) => { for (let i = 0; i < b.length; i++) c = CRC[(c ^ b[i]) & 255] ^ (c >>> 8); }).on('end', () => ok((c ^ 0xFFFFFFFF) >>> 0)).on('error', no); });
const LIM = Number(process.env.ZIP64_LIMIT) || 0xFFFFFFFF;   // ปรับได้เพื่อทดสอบ
const u16 = (n) => { const b = Buffer.alloc(2); b.writeUInt16LE(n); return b; };
const u32 = (n) => { const b = Buffer.alloc(4); b.writeUInt32LE(n); return b; };
const u64 = (n) => { const b = Buffer.alloc(8); b.writeBigUInt64LE(BigInt(n)); return b; };
function dosTime(ms) { const d = new Date(ms); return [((d.getHours() << 11) | (d.getMinutes() << 5) | (d.getSeconds() >> 1)) & 0xFFFF, (((d.getFullYear() - 1980) << 9) | ((d.getMonth() + 1) << 5) | d.getDate()) & 0xFFFF]; }
async function sendZip(res, entries, zipName) {   // entries: [{zipPath, file, size, crc, time}]
  let off = 0; const cd = [];
  const write = (b) => new Promise((ok) => { off += b.length; res.write(b) ? ok() : res.once('drain', ok); });
  res.writeHead(200, { 'Content-Type': 'application/zip', 'Content-Disposition': "attachment; filename*=UTF-8''" + encodeURIComponent(zipName), 'Cache-Control': 'no-cache' });
  let aborted = false; res.on('close', () => { aborted = true; });
  for (const e of entries) {
    if (aborted) return;
    const nm = Buffer.from(e.zipPath, 'utf8'), [t, d] = dosTime(e.time), big = e.size >= LIM, start = off;
    const lx = big ? Buffer.concat([u16(1), u16(16), u64(e.size), u64(e.size)]) : Buffer.alloc(0);
    await write(Buffer.concat([u32(0x04034b50), u16(big ? 45 : 20), u16(0x0800), u16(0), u16(t), u16(d), u32(e.crc), u32(big ? 0xFFFFFFFF : e.size), u32(big ? 0xFFFFFFFF : e.size), u16(nm.length), u16(lx.length), nm, lx]));
    await new Promise((ok) => { const rs = fs.createReadStream(e.file); rs.on('data', (c) => { off += c.length; if (!res.write(c)) { rs.pause(); res.once('drain', () => rs.resume()); } }); rs.on('end', ok); rs.on('error', ok); });
    cd.push({ nm, t, d, e, big, start });
  }
  if (aborted) return;
  const cdStart = off;
  for (const c of cd) {
    const bigOff = c.start >= LIM, ex = [];
    if (c.big) ex.push(u64(c.e.size), u64(c.e.size)); if (bigOff) ex.push(u64(c.start));
    const x = ex.length ? Buffer.concat([u16(1), u16(ex.reduce((n, b) => n + b.length, 0)), ...ex]) : Buffer.alloc(0);
    await write(Buffer.concat([u32(0x02014b50), u16(45), u16(c.big || bigOff ? 45 : 20), u16(0x0800), u16(0), u16(c.t), u16(c.d), u32(c.e.crc), u32(c.big ? 0xFFFFFFFF : c.e.size), u32(c.big ? 0xFFFFFFFF : c.e.size), u16(c.nm.length), u16(x.length), u16(0), u16(0), u16(0), u32(0), u32(bigOff ? 0xFFFFFFFF : c.start), c.nm, x]));
  }
  const cdSize = off - cdStart, n = cd.length, z64 = n >= 0xFFFF || cdStart >= LIM || cdSize >= LIM;
  if (z64) {
    const z64Off = off;
    await write(Buffer.concat([u32(0x06064b50), u64(44), u16(45), u16(45), u32(0), u32(0), u64(n), u64(n), u64(cdSize), u64(cdStart)]));
    await write(Buffer.concat([u32(0x07064b50), u32(0), u64(z64Off), u32(1)]));
  }
  await write(Buffer.concat([u32(0x06054b50), u16(0), u16(0), u16(z64 ? 0xFFFF : n), u16(z64 ? 0xFFFF : n), u32(z64 ? 0xFFFFFFFF : cdSize), u32(z64 ? 0xFFFFFFFF : cdStart), u16(0)]));
  res.end();
}

// ---- เผยแพร่อัปเดตเกม ----
const fileSig = () => crypto.createHash('sha1').update(Object.keys(db).sort().map((id) => [id, db[id].size, db[id].time, db[id].dir || '', db[id].name].join(':')).join('|')).digest('hex');
const nextVersion = (v) => { const p = String(v || '1.0.0').split('.').map(Number); p[p.length - 1]++; return p.join('.'); };
function releaseInfo() {
  const r = meta.release;
  if (!r || !r.mode) return { version: r ? r.version : null, published: false, current: { files: Object.keys(db).length, size: totalSize() } };
  return { version: r.version, mode: r.mode, files: r.files, size: r.size, time: r.time, upToDate: r.mode === 'zip' ? true : r.sig === fileSig(), current: { files: Object.keys(db).length, size: totalSize() }, published: true };
}
let publishing = false;
async function publishAuto(res) {
  const ids = Object.keys(db);
  if (!ids.length) return json(res, 400, { error: 'ยังไม่มีไฟล์ให้เผยแพร่' });
  if (publishing) return json(res, 409, { error: 'กำลังเผยแพร่อยู่ รอสักครู่' });
  publishing = true;
  try {
    const version = nextVersion(meta.release && meta.release.version);
    const dir = path.join(RELEASE_DIR, 'v' + version + '-' + Date.now());
    fs.mkdirSync(dir);
    const files = [];
    for (const id of ids) {
      const f = db[id], src = path.join(UPLOAD_DIR, id);
      try { fs.linkSync(src, path.join(dir, id)); } catch (_) { fs.copyFileSync(src, path.join(dir, id)); }
      files.push({ id, path: (f.dir ? f.dir + '/' : '') + f.name, size: f.size, time: f.time, crc: await crcStream(path.join(dir, id)) });
    }
    const old = meta.release && meta.release.dir;
    meta.release = { mode: 'auto', version, dir: path.basename(dir), files: files.length, size: files.reduce((n, f) => n + f.size, 0), time: Date.now(), sig: fileSig(), list: files };
    saveMeta();
    if (old) fs.rm(path.join(RELEASE_DIR, old), { recursive: true, force: true }, () => {});
    json(res, 200, releaseInfo());
  } catch (e) { console.error(e); json(res, 500, { error: 'เผยแพร่ไม่สำเร็จ' }); } finally { publishing = false; }
}
function publishZip(req, res) {
  const name = cleanName(req.url.includes('name=') ? new URLSearchParams(req.url.split('?')[1]).get('name') : 'update.zip');
  return receive(req, res, 0, (tmp, size) => {
    const dir = path.join(RELEASE_DIR, 'v-zip-' + Date.now());
    fs.mkdirSync(dir);
    fs.rename(tmp, path.join(dir, 'update.zip'), (e) => {
      if (e) return json(res, 500, { error: 'บันทึกไฟล์ไม่สำเร็จ' });
      let count = 0;
      try { const fd = fs.openSync(path.join(dir, 'update.zip'), 'r'), n = Math.min(size, 65557), b = Buffer.alloc(n); fs.readSync(fd, b, 0, n, size - n); fs.closeSync(fd); const i = b.lastIndexOf(Buffer.from([0x50, 0x4b, 5, 6])); if (i >= 0) count = b.readUInt16LE(i + 10); } catch (_) {}
      const old = meta.release && meta.release.dir, version = nextVersion(meta.release && meta.release.version);
      meta.release = { mode: 'zip', version, dir: path.basename(dir), files: count, size, time: Date.now(), zipName: name };
      saveMeta();
      if (old) fs.rm(path.join(RELEASE_DIR, old), { recursive: true, force: true }, () => {});
      json(res, 200, releaseInfo());
    });
  });
}
function publicRelease(req, res, url) {   // ให้ตัวเกม/ลันเชอร์ใช้ (ไม่ต้องล็อกอิน)
  const r = meta.release;
  if (!r || !r.mode) { res.writeHead(404, { 'Content-Type': 'application/json' }); return res.end('{"error":"ยังไม่มีเวอร์ชันที่เผยแพร่"}'); }
  const origin = baseUrl(req);
  if (url === '/update/version.json') return json(res, 200, { version: r.version, files: r.files, size: r.size, time: r.time, zip: origin + '/update/latest.zip' }, { 'Cache-Control': 'no-cache' });
  if (url === '/update/manifest.json') return json(res, 200, { version: r.version, time: r.time, zip: origin + '/update/latest.zip', files: (r.list || []).map((f) => ({ path: f.path, size: f.size, crc32: f.crc.toString(16).padStart(8, '0'), url: origin + '/update/f/' + f.id })) }, { 'Cache-Control': 'no-cache' });
  if (url === '/update/latest.zip') {
    if (r.mode === 'zip') { const p = path.join(RELEASE_DIR, r.dir, 'update.zip'); res.writeHead(200, { 'Content-Type': 'application/zip', 'Content-Length': r.size, 'Content-Disposition': "attachment; filename*=UTF-8''" + encodeURIComponent(r.zipName || 'update.zip'), 'Cache-Control': 'no-cache' }); return fs.createReadStream(p).on('error', () => res.end()).pipe(res); }
    return sendZip(res, r.list.map((f) => ({ zipPath: f.path, file: path.join(RELEASE_DIR, r.dir, f.id), size: f.size, crc: f.crc, time: f.time })), 'update-v' + r.version + '.zip');
  }
  const m = url.match(/^\/update\/f\/([\w-]+)$/), f = m && (r.list || []).find((x) => x.id === m[1]);
  if (f) { res.writeHead(200, { 'Content-Type': 'application/octet-stream', 'Content-Length': f.size, 'Content-Disposition': "attachment; filename*=UTF-8''" + encodeURIComponent(path.basename(f.path)), 'Cache-Control': 'no-cache' }); return fs.createReadStream(path.join(RELEASE_DIR, r.dir, f.id)).on('error', () => res.end()).pipe(res); }
  res.writeHead(404); res.end('Not found');
}

http.createServer((req, res) => {
  const url = req.url.split('?')[0];
  const query = new URLSearchParams(req.url.split('?')[1] || '');
  const ip = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
  const secure = req.headers['x-forwarded-proto'] === 'https' ? '; Secure' : '';
  let pathname = url; try { pathname = decodeURIComponent(url); } catch (_) {}

  // ---- ล็อกอิน / ออกจากระบบ ----
  if (req.method === 'POST' && url === '/api/admin/login') {
    if (blocked(ip)) return json(res, 429, { success: false, error: 'ลองผิดหลายครั้งเกินไป กรุณารอ 10 นาที' });
    return readBody(req, (b) => {
      if (b.key && safeEq(b.key, ADMIN_KEY)) {
        fails.delete(ip);
        return json(res, 200, { success: true }, { 'Set-Cookie': `session=${makeToken()}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${SESSION_MS / 1000}${secure}` });
      }
      addFail(ip);
      json(res, 401, { success: false, error: 'คีย์ไม่ถูกต้อง' });
    });
  }
  if (req.method === 'POST' && url === '/api/admin/logout')
    return json(res, 200, { success: true }, { 'Set-Cookie': 'session=; HttpOnly; Path=/; Max-Age=0' });

  if (req.method === 'GET' && url.startsWith('/update/')) return publicRelease(req, res, url);

  // ---- ลิงก์ดาวน์โหลดสาธารณะ: /ชื่อลิงก์ที่ตั้งเอง  หรือ  /f/<id>/<ชื่อไฟล์> ----
  if (req.method === 'GET' || req.method === 'HEAD') {
    let id = null;
    const custom = bySlug(pathname.replace(/^\/+/, ''));
    if (custom) id = custom[0];
    else { const m = url.match(/^\/f\/([\w-]+)(?:\/.*)?$/); if (m && db[m[1]]) id = m[1]; }
    if (id) {
      const f = db[id], inline = INLINE[path.extname(f.name).toLowerCase()];
      res.writeHead(200, {
        'Content-Type': inline || 'application/octet-stream',
        'Content-Length': f.size,
        'Content-Disposition': (inline ? 'inline' : 'attachment') + "; filename*=UTF-8''" + encodeURIComponent(f.name),
        'Last-Modified': new Date(f.time).toUTCString(),
        'Cache-Control': 'no-cache',   // อัปเดตไฟล์แล้วคนโหลดได้ของใหม่ทันที
        'X-Content-Type-Options': 'nosniff',
        'Content-Security-Policy': "default-src 'none'; sandbox",
      });
      if (req.method === 'HEAD') return res.end();
      return fs.createReadStream(path.join(UPLOAD_DIR, id)).on('error', () => res.end()).pipe(res);
    }
  }

  // ---- API ฝั่งแอดมิน (ต้องล็อกอิน) ----
  if (url.startsWith('/api/') && !isAuthed(req)) return json(res, 401, { error: 'ยังไม่ได้ล็อกอิน' });

  if (req.method === 'GET' && url === '/api/files')
    return json(res, 200, { base: baseUrl(req), folders: meta.folders, files: Object.keys(db).map(id => ({ id, ...db[id], dir: db[id].dir || '', link: linkOf(req, id) })).sort((a, b) => b.time - a.time) });

  // อัปโหลดไฟล์ใหม่ (ตั้งชื่อลิงก์เองได้ด้วย ?slug=)
  if (req.method === 'POST' && url === '/api/upload') {
    const slug = (query.get('slug') || '').trim().replace(/^\/+|\/+$/g, '');
    const err = checkSlug(slug, null);
    if (err) return json(res, 400, { error: err });
    const name = cleanName(query.get('name') || 'file');
    const dir = normDir(query.get('dir'));
    return receive(req, res, 0, (tmp, size) => {
      if (slug && bySlug(slug)) { fs.unlink(tmp, () => {}); return json(res, 400, { error: 'มีไฟล์ใช้ชื่อลิงก์นี้อยู่แล้ว' }); }
      const id = crypto.randomBytes(9).toString('base64url');
      fs.rename(tmp, path.join(UPLOAD_DIR, id), (e) => {
        if (e) return json(res, 500, { error: 'บันทึกไฟล์ไม่สำเร็จ' });
        db[id] = { name, size, time: Date.now(), ip, ...(dir ? { dir } : {}), ...(slug ? { slug } : {}) }; saveDb();
        json(res, 200, { success: true, id, link: linkOf(req, id) });
      });
    });
  }

  // อัปเดตไฟล์ (เปลี่ยนเนื้อหา ลิงก์เดิมยังใช้ได้)
  const rep = url.match(/^\/api\/files\/([\w-]+)\/replace$/);
  if (req.method === 'POST' && rep) {
    const id = rep[1];
    if (!db[id]) return json(res, 404, { error: 'ไม่พบไฟล์' });
    const name = query.get('name') ? cleanName(query.get('name')) : db[id].name;
    return receive(req, res, db[id].size, (tmp, size) => {
      if (!db[id]) { fs.unlink(tmp, () => {}); return json(res, 404, { error: 'ไฟล์ถูกลบไปแล้ว' }); }
      fs.rename(tmp, path.join(UPLOAD_DIR, id), (e) => {
        if (e) return json(res, 500, { error: 'บันทึกไฟล์ไม่สำเร็จ' });
        Object.assign(db[id], { name, size, time: Date.now() }); saveDb();
        json(res, 200, { success: true, id, link: linkOf(req, id) });
      });
    });
  }

  // แก้ไฟล์: ชื่อลิงก์ (slug ว่าง = ลิงก์อัตโนมัติ) / ชื่อไฟล์ / ย้ายโฟลเดอร์
  const pat = url.match(/^\/api\/files\/([\w-]+)$/);
  if (req.method === 'PATCH' && pat) {
    const id = pat[1];
    if (!db[id]) return json(res, 404, { error: 'ไม่พบไฟล์' });
    return readBody(req, (b) => {
      if ('slug' in b) {
        const slug = String(b.slug || '').trim().replace(/^\/+|\/+$/g, '');
        const err = checkSlug(slug, id);
        if (err) return json(res, 400, { error: err });
        if (slug) db[id].slug = slug; else delete db[id].slug;
      }
      if (b.name) db[id].name = cleanName(b.name);
      if ('dir' in b) { const d = normDir(b.dir); if (d) db[id].dir = d; else delete db[id].dir; }
      saveDb(); json(res, 200, { success: true, link: linkOf(req, id) });
    });
  }

  // ---- โฟลเดอร์ ----
  if (url === '/api/folders') {
    const p = normDir(query.get('path'));
    if (req.method === 'POST') {
      if (!p) return json(res, 400, { error: 'ชื่อโฟลเดอร์ไม่ถูกต้อง' });
      if (!meta.folders.includes(p)) { meta.folders.push(p); saveMeta(); }
      return json(res, 200, { success: true });
    }
    if (req.method === 'DELETE') {
      if (!p) return json(res, 400, { error: 'ไม่ระบุโฟลเดอร์' });
      for (const id of Object.keys(db)) if (inDir(db[id].dir || '', p)) { fs.unlink(path.join(UPLOAD_DIR, id), () => {}); delete db[id]; }
      meta.folders = meta.folders.filter((f) => !inDir(f, p)); saveDb(); saveMeta();
      return json(res, 200, { success: true });
    }
    if (req.method === 'PATCH') {   // เปลี่ยนชื่อ/ย้ายโฟลเดอร์ ?path=เดิม&to=ใหม่
      const to = normDir(query.get('to'));
      if (!p || !to) return json(res, 400, { error: 'ชื่อโฟลเดอร์ไม่ถูกต้อง' });
      if (inDir(to, p)) return json(res, 400, { error: 'ย้ายเข้าไปในตัวเองไม่ได้' });
      const mv = (d) => (inDir(d, p) ? to + d.slice(p.length) : d);
      for (const id of Object.keys(db)) if (inDir(db[id].dir || '', p)) db[id].dir = mv(db[id].dir);
      meta.folders = [...new Set([...meta.folders.map(mv), to])]; saveDb(); saveMeta();
      return json(res, 200, { success: true });
    }
  }

  // ---- เผยแพร่อัปเดตเกม ----
  if (url === '/api/release' && req.method === 'GET') return json(res, 200, releaseInfo());
  if (url === '/api/release' && req.method === 'PATCH')
    return readBody(req, (b) => {
      const v = String(b.version || '').replace(/^v/i, '').trim();
      if (!/^\d+(\.\d+){1,3}$/.test(v)) return json(res, 400, { error: 'เลขเวอร์ชันต้องเป็นแบบ 4.0.71' });
      meta.release = { ...(meta.release || { mode: 'auto', files: 0, size: 0, time: Date.now(), sig: '' }), version: v }; saveMeta();
      json(res, 200, releaseInfo());
    });
  if (url === '/api/release/publish' && req.method === 'POST') return publishAuto(res);
  if (url === '/api/release/zip' && req.method === 'POST') return publishZip(req, res);

  if (req.method === 'DELETE' && pat) {
    if (db[pat[1]]) { fs.unlink(path.join(UPLOAD_DIR, pat[1]), () => {}); delete db[pat[1]]; saveDb(); }
    return json(res, 200, { success: true });
  }

  // ---- หน้าเว็บ ----
  if (url === '/login' || url === '/login.html') return sendFile(res, path.join(__dirname, 'public', 'login.html'));
  if (url === '/') return redirect(res, '/admin');
  if (url === '/admin') return isAuthed(req) ? sendFile(res, path.join(__dirname, 'private', 'admin.html')) : redirect(res, '/login');
  res.writeHead(404); res.end('Not found');
}).listen(PORT, function () {
  this.requestTimeout = 0;   // ไม่ตัดอัปโหลดไฟล์ใหญ่
  this.headersTimeout = 60000;
  this.timeout = 0;
  console.log('เปิดที่ http://localhost:' + PORT);
});
