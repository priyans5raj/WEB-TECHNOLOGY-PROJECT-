'use strict';
/**
 * Smart Attendance Management System - HTTP server + REST API
 * Pure Node.js (no npm dependencies). Requires Node >= 22.5 for node:sqlite.
 */
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { db, checkPassword, hashPassword, createUser, today, ensureSeeded } = require('./db');

const PORT = Number(process.env.PORT) || 3000;
const SECRET = crypto.randomBytes(32);
const THRESHOLD = 75;                         // minimum attendance % required
const TOKEN_TTL = 8 * 60 * 60 * 1000;         // 8 hours
const PUBLIC_DIR = path.join(__dirname, 'public');

class HttpError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}

/* ------------------------------ auth tokens ------------------------------ */
function sign(payload) {
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const sig = crypto.createHmac('sha256', SECRET).update(body).digest('base64url');
  return `${body}.${sig}`;
}
function verify(token) {
  try {
    const [body, sig] = String(token || '').split('.');
    if (!body || !sig) return null;
    const expect = crypto.createHmac('sha256', SECRET).update(body).digest('base64url');
    const a = Buffer.from(sig), b = Buffer.from(expect);
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
    const p = JSON.parse(Buffer.from(body, 'base64url').toString());
    return p.exp > Date.now() ? p : null;
  } catch { return null; }
}

/* simple brute-force protection: 8 failed logins / 5 minutes / IP */
const failures = new Map();
function tooManyFailures(ip) {
  const f = failures.get(ip);
  return f && f.count >= 8 && Date.now() - f.first < 5 * 60 * 1000;
}
function noteFailure(ip) {
  const f = failures.get(ip);
  if (!f || Date.now() - f.first > 5 * 60 * 1000) failures.set(ip, { count: 1, first: Date.now() });
  else f.count++;
}

/* ------------------------------ validation ------------------------------ */
const isDate = s => /^\d{4}-\d{2}-\d{2}$/.test(s || '') && !isNaN(new Date(s + 'T00:00:00'));
const clean = (v, max = 100) => String(v ?? '').trim().slice(0, max);
const pct = (att, total) => (total ? Math.round((att * 1000) / total) / 10 : null);

function need(cond, msg, status = 400) { if (!cond) throw new HttpError(status, msg); }

function studentInput(b, partial = false) {
  const s = {
    roll_no: clean(b.roll_no, 30), name: clean(b.name, 80), email: clean(b.email, 100),
    phone: clean(b.phone, 20), department: clean(b.department, 20).toUpperCase(),
    year: Number(b.year), section: clean(b.section, 5).toUpperCase()
  };
  need(s.roll_no, 'Roll number is required');
  need(s.name, 'Name is required');
  need(s.department, 'Department is required');
  need(Number.isInteger(s.year) && s.year >= 1 && s.year <= 4, 'Year must be between 1 and 4');
  need(!s.email || /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(s.email), 'Email address is not valid');
  need(!s.phone || /^[0-9+\-\s]{7,15}$/.test(s.phone), 'Phone number is not valid');
  return s;
}

/* ------------------------------ query helpers ------------------------------ */
function studentOf(user) {
  return db.prepare('SELECT * FROM students WHERE user_id = ?').get(user.id);
}

/** Attendance statistics for students x subjects (subjects chosen by department+year). */
function percentageMatrix({ department, year, subject_id, from, to, student_id }) {
  const sw = [], sp = [];
  if (department) { sw.push('s.department = ?'); sp.push(department.toUpperCase()); }
  if (year) { sw.push('s.year = ?'); sp.push(Number(year)); }
  if (student_id) { sw.push('s.id = ?'); sp.push(Number(student_id)); }
  const students = db.prepare(`SELECT s.* FROM students s ${sw.length ? 'WHERE ' + sw.join(' AND ') : ''} ORDER BY s.roll_no`).all(...sp);

  const subjWhere = [], subjParams = [];
  if (subject_id) { subjWhere.push('id = ?'); subjParams.push(Number(subject_id)); }
  const subjects = db.prepare(`SELECT id, code, name, department, year FROM subjects ${subjWhere.length ? 'WHERE ' + subjWhere.join(' AND ') : ''} ORDER BY code`).all(...subjParams);

  const dw = [], dp = [];
  if (from) { dw.push('a.date >= ?'); dp.push(from); }
  if (to) { dw.push('a.date <= ?'); dp.push(to); }
  const stats = db.prepare(`
    SELECT a.student_id, a.subject_id, COUNT(*) total,
           SUM(CASE WHEN a.status IN ('P','L') THEN 1 ELSE 0 END) attended,
           SUM(CASE WHEN a.status = 'L' THEN 1 ELSE 0 END) late
    FROM attendance a ${dw.length ? 'WHERE ' + dw.join(' AND ') : ''}
    GROUP BY a.student_id, a.subject_id`).all(...dp);
  const map = new Map(stats.map(r => [`${r.student_id}:${r.subject_id}`, r]));

  const rows = students.map(st => {
    const mine = subjects.filter(su => su.department === st.department && su.year === st.year);
    let tot = 0, att = 0;
    const per = {};
    mine.forEach(su => {
      const r = map.get(`${st.id}:${su.id}`) || { total: 0, attended: 0, late: 0 };
      per[su.id] = { total: r.total, attended: r.attended, late: r.late, percent: pct(r.attended, r.total) };
      tot += r.total; att += r.attended;
    });
    return {
      student: { id: st.id, roll_no: st.roll_no, name: st.name, department: st.department, year: st.year, section: st.section },
      subjects: per, total: tot, attended: att, percent: pct(att, tot),
      status: tot === 0 ? 'No data' : pct(att, tot) >= THRESHOLD ? 'OK' : 'Shortage'
    };
  }).filter(r => Object.keys(r.subjects).length > 0);
  return { threshold: THRESHOLD, subjects, rows };
}

/* ------------------------------ route table ------------------------------ */
const routes = [];
const route = (method, pattern, roles, handler) => {
  const keys = [];
  const re = new RegExp('^' + pattern.replace(/:([a-z_]+)/g, (_, k) => (keys.push(k), '([^/]+)')) + '$');
  routes.push({ method, re, keys, roles, handler });
};
const STAFF = ['admin', 'faculty'];
const ANY = ['admin', 'faculty', 'student'];

/* ---- auth ---- */
route('POST', '/api/login', null, ({ body, ip }) => {
  need(!tooManyFailures(ip), 'Too many failed attempts. Try again in a few minutes.', 429);
  const username = clean(body.username, 50), password = String(body.password || '');
  const u = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
  if (!u || !checkPassword(password, u.password_hash, u.salt)) { noteFailure(ip); throw new HttpError(401, 'Invalid username or password'); }
  failures.delete(ip);
  const user = { id: u.id, name: u.name, role: u.role, username: u.username };
  return { token: sign({ ...user, exp: Date.now() + TOKEN_TTL }), user };
});

route('GET', '/api/me', ANY, ({ user }) => ({ user }));

route('POST', '/api/password', ANY, ({ user, body }) => {
  const u = db.prepare('SELECT * FROM users WHERE id = ?').get(user.id);
  need(checkPassword(String(body.old_password || ''), u.password_hash, u.salt), 'Current password is incorrect', 403);
  const np = String(body.new_password || '');
  need(np.length >= 6, 'New password must be at least 6 characters');
  const { hash, salt } = hashPassword(np);
  db.prepare('UPDATE users SET password_hash=?, salt=? WHERE id=?').run(hash, salt, user.id);
  return { ok: true };
});

/* ---- subjects ---- */
route('GET', '/api/subjects', ANY, ({ user }) => {
  let sql = `SELECT sub.*, u.name faculty_name FROM subjects sub LEFT JOIN users u ON u.id = sub.faculty_id`;
  const p = [];
  if (user.role === 'student') {
    const st = studentOf(user);
    sql += ' WHERE sub.department = ? AND sub.year = ?'; p.push(st.department, st.year);
  }
  return db.prepare(sql + ' ORDER BY sub.code').all(...p);
});

route('POST', '/api/subjects', ['admin'], ({ body }) => {
  const s = { code: clean(body.code, 20).toUpperCase(), name: clean(body.name, 100), department: clean(body.department, 20).toUpperCase(), year: Number(body.year), faculty_id: body.faculty_id ? Number(body.faculty_id) : null };
  need(s.code && s.name && s.department, 'Code, name and department are required');
  need(Number.isInteger(s.year) && s.year >= 1 && s.year <= 4, 'Year must be between 1 and 4');
  need(!db.prepare('SELECT 1 FROM subjects WHERE code = ?').get(s.code), 'Subject code already exists', 409);
  if (s.faculty_id) need(db.prepare("SELECT 1 FROM users WHERE id=? AND role='faculty'").get(s.faculty_id), 'Faculty not found');
  const r = db.prepare('INSERT INTO subjects (code,name,department,year,faculty_id) VALUES (?,?,?,?,?)').run(s.code, s.name, s.department, s.year, s.faculty_id);
  return { id: Number(r.lastInsertRowid), ...s };
});

route('DELETE', '/api/subjects/:id', ['admin'], ({ params }) => {
  const r = db.prepare('DELETE FROM subjects WHERE id = ?').run(Number(params.id));
  need(r.changes, 'Subject not found', 404);
  return { ok: true };
});

route('GET', '/api/faculty', STAFF, () => db.prepare("SELECT id, name, username FROM users WHERE role='faculty' ORDER BY name").all());

/* ---- students (registration) ---- */
route('GET', '/api/students', STAFF, ({ query }) => {
  const w = [], p = [];
  if (query.q) { w.push('(name LIKE ? OR roll_no LIKE ?)'); p.push(`%${query.q}%`, `%${query.q}%`); }
  if (query.department) { w.push('department = ?'); p.push(query.department.toUpperCase()); }
  if (query.year) { w.push('year = ?'); p.push(Number(query.year)); }
  return db.prepare(`SELECT id, roll_no, name, email, phone, department, year, section FROM students ${w.length ? 'WHERE ' + w.join(' AND ') : ''} ORDER BY roll_no`).all(...p);
});

route('POST', '/api/students', STAFF, ({ body }) => {
  const s = studentInput(body);
  need(!db.prepare('SELECT 1 FROM students WHERE roll_no = ?').get(s.roll_no), 'A student with this roll number already exists', 409);
  const username = s.roll_no.toLowerCase();
  need(!db.prepare('SELECT 1 FROM users WHERE username = ?').get(username), 'Login name already taken', 409);
  db.exec('BEGIN');
  try {
    const uid = createUser(username, s.roll_no, 'student', s.name);   // default password = roll number
    const r = db.prepare('INSERT INTO students (roll_no,name,email,phone,department,year,section,user_id) VALUES (?,?,?,?,?,?,?,?)')
      .run(s.roll_no, s.name, s.email, s.phone, s.department, s.year, s.section, uid);
    db.exec('COMMIT');
    return { id: Number(r.lastInsertRowid), ...s, login: { username, password: s.roll_no } };
  } catch (e) { db.exec('ROLLBACK'); throw e; }
});

route('PUT', '/api/students/:id', STAFF, ({ params, body }) => {
  const s = studentInput(body);
  const cur = db.prepare('SELECT * FROM students WHERE id = ?').get(Number(params.id));
  need(cur, 'Student not found', 404);
  const dup = db.prepare('SELECT id FROM students WHERE roll_no = ? AND id <> ?').get(s.roll_no, cur.id);
  need(!dup, 'A student with this roll number already exists', 409);
  db.prepare('UPDATE students SET roll_no=?,name=?,email=?,phone=?,department=?,year=?,section=? WHERE id=?')
    .run(s.roll_no, s.name, s.email, s.phone, s.department, s.year, s.section, cur.id);
  if (cur.user_id) db.prepare('UPDATE users SET name=? WHERE id=?').run(s.name, cur.user_id);
  return { id: cur.id, ...s };
});

route('DELETE', '/api/students/:id', ['admin'], ({ params }) => {
  const cur = db.prepare('SELECT * FROM students WHERE id = ?').get(Number(params.id));
  need(cur, 'Student not found', 404);
  db.exec('BEGIN');
  db.prepare('DELETE FROM students WHERE id = ?').run(cur.id);
  if (cur.user_id) db.prepare('DELETE FROM users WHERE id = ?').run(cur.user_id);
  db.exec('COMMIT');
  return { ok: true };
});

/* ---- attendance entry ---- */
function subjectForStaff(user, subjectId) {
  const sub = db.prepare('SELECT * FROM subjects WHERE id = ?').get(Number(subjectId));
  need(sub, 'Subject not found', 404);
  need(user.role === 'admin' || sub.faculty_id === user.id, 'You can only mark attendance for your own subjects', 403);
  return sub;
}

route('GET', '/api/attendance/sheet', STAFF, ({ user, query }) => {
  const sub = subjectForStaff(user, query.subject_id);
  need(isDate(query.date), 'A valid date (YYYY-MM-DD) is required');
  const rows = db.prepare(`
    SELECT s.id student_id, s.roll_no, s.name, s.section, a.status
    FROM students s LEFT JOIN attendance a ON a.student_id = s.id AND a.subject_id = ? AND a.date = ?
    WHERE s.department = ? AND s.year = ? ORDER BY s.roll_no`).all(sub.id, query.date, sub.department, sub.year);
  return { subject: sub, date: query.date, already_marked: rows.some(r => r.status), students: rows };
});

route('POST', '/api/attendance', STAFF, ({ user, body }) => {
  const sub = subjectForStaff(user, body.subject_id);
  need(isDate(body.date), 'A valid date (YYYY-MM-DD) is required');
  need(body.date <= today(), 'Attendance cannot be marked for a future date');
  need(Array.isArray(body.records) && body.records.length, 'No attendance records supplied');
  const valid = new Set(db.prepare('SELECT id FROM students WHERE department = ? AND year = ?').all(sub.department, sub.year).map(r => r.id));
  const up = db.prepare(`INSERT INTO attendance (student_id,subject_id,date,status,marked_by) VALUES (?,?,?,?,?)
    ON CONFLICT(student_id,subject_id,date) DO UPDATE SET status = excluded.status, marked_by = excluded.marked_by`);
  db.exec('BEGIN');
  try {
    for (const r of body.records) {
      need(valid.has(Number(r.student_id)), `Student ${r.student_id} does not belong to this subject`);
      need(['P', 'A', 'L'].includes(r.status), 'Status must be P, A or L');
      up.run(Number(r.student_id), sub.id, body.date, r.status, user.id);
    }
    db.exec('COMMIT');
  } catch (e) { db.exec('ROLLBACK'); throw e; }
  return { ok: true, saved: body.records.length };
});

/* ---- reports ---- */
route('GET', '/api/reports/percentage', STAFF, ({ query }) => {
  need(!query.from || isDate(query.from), 'Invalid "from" date');
  need(!query.to || isDate(query.to), 'Invalid "to" date');
  const result = percentageMatrix(query);
  if (query.below) result.rows = result.rows.filter(r => r.percent !== null && r.percent < Number(query.below));
  return result;
});

route('GET', '/api/reports/datewise', STAFF, ({ query }) => {
  need(!query.from || isDate(query.from), 'Invalid "from" date');
  need(!query.to || isDate(query.to), 'Invalid "to" date');
  const w = [], p = [];
  if (query.from) { w.push('a.date >= ?'); p.push(query.from); }
  if (query.to) { w.push('a.date <= ?'); p.push(query.to); }
  if (query.subject_id) { w.push('a.subject_id = ?'); p.push(Number(query.subject_id)); }
  if (query.department) { w.push('s.department = ?'); p.push(query.department.toUpperCase()); }
  const rows = db.prepare(`
    SELECT a.date, sub.id subject_id, sub.code, sub.name subject, COUNT(*) total,
           SUM(a.status = 'P') present, SUM(a.status = 'L') late, SUM(a.status = 'A') absent
    FROM attendance a JOIN subjects sub ON sub.id = a.subject_id JOIN students s ON s.id = a.student_id
    ${w.length ? 'WHERE ' + w.join(' AND ') : ''}
    GROUP BY a.date, sub.id ORDER BY a.date DESC, sub.code`).all(...p)
    .map(r => ({ ...r, percent: pct(r.present + r.late, r.total) }));
  return { rows };
});

route('GET', '/api/reports/datewise/detail', STAFF, ({ query }) => {
  need(isDate(query.date), 'A valid date is required');
  const sub = db.prepare('SELECT * FROM subjects WHERE id = ?').get(Number(query.subject_id));
  need(sub, 'Subject not found', 404);
  const students = db.prepare(`SELECT s.roll_no, s.name, a.status FROM attendance a JOIN students s ON s.id = a.student_id
    WHERE a.subject_id = ? AND a.date = ? ORDER BY s.roll_no`).all(sub.id, query.date);
  return { subject: sub, date: query.date, students };
});

function studentReport(id) {
  const st = db.prepare('SELECT id, roll_no, name, email, phone, department, year, section FROM students WHERE id = ?').get(Number(id));
  need(st, 'Student not found', 404);
  const m = percentageMatrix({ student_id: st.id });
  const row = m.rows[0] || { subjects: {}, total: 0, attended: 0, percent: null, status: 'No data' };
  const subjects = m.subjects.filter(s => row.subjects[s.id]).map(s => {
    const x = row.subjects[s.id];
    const need75 = x.percent !== null && x.percent < THRESHOLD ? Math.ceil((THRESHOLD / 100 * x.total - x.attended) / (1 - THRESHOLD / 100)) : 0;
    const canMiss = x.percent !== null && x.percent >= THRESHOLD ? Math.floor(x.attended / (THRESHOLD / 100) - x.total) : 0;
    return { ...s, ...x, classes_needed: need75, can_miss: canMiss };
  });
  const history = db.prepare(`SELECT a.date, sub.code, sub.name subject, a.status FROM attendance a JOIN subjects sub ON sub.id = a.subject_id
    WHERE a.student_id = ? ORDER BY a.date DESC, sub.code LIMIT 60`).all(st.id);
  const trend = db.prepare(`SELECT date, COUNT(*) total, SUM(status IN ('P','L')) attended FROM attendance WHERE student_id = ?
    GROUP BY date ORDER BY date DESC LIMIT 14`).all(st.id).reverse().map(r => ({ date: r.date, percent: pct(r.attended, r.total) }));
  return { student: st, threshold: THRESHOLD, overall: { total: row.total, attended: row.attended, percent: row.percent, status: row.status }, subjects, history, trend };
}

route('GET', '/api/reports/student/me', ['student'], ({ user }) => {
  const st = studentOf(user);
  need(st, 'Student profile not found', 404);
  return studentReport(st.id);
});
route('GET', '/api/reports/student/:id', STAFF, ({ params }) => studentReport(params.id));

/* ---- dashboard ---- */
route('GET', '/api/dashboard', STAFF, () => {
  const totals = {
    students: db.prepare('SELECT COUNT(*) c FROM students').get().c,
    subjects: db.prepare('SELECT COUNT(*) c FROM subjects').get().c,
    faculty: db.prepare("SELECT COUNT(*) c FROM users WHERE role='faculty'").get().c,
    records: db.prepare('SELECT COUNT(*) c FROM attendance').get().c
  };
  const latest = db.prepare('SELECT MAX(date) d FROM attendance').get().d;
  const latestRow = latest ? db.prepare(`SELECT COUNT(*) total, SUM(status='P') p, SUM(status='L') l, SUM(status='A') a FROM attendance WHERE date = ?`).get(latest) : null;
  const trend = db.prepare(`SELECT date, COUNT(*) total, SUM(status IN ('P','L')) att FROM attendance GROUP BY date ORDER BY date DESC LIMIT 14`).all()
    .reverse().map(r => ({ date: r.date, percent: pct(r.att, r.total) }));
  const bySubject = db.prepare(`SELECT sub.code, sub.name, COUNT(*) total, SUM(a.status IN ('P','L')) att FROM attendance a JOIN subjects sub ON sub.id = a.subject_id
    GROUP BY sub.id ORDER BY sub.code`).all().map(r => ({ code: r.code, name: r.name, percent: pct(r.att, r.total) }));
  const split = db.prepare(`SELECT SUM(status='P') p, SUM(status='L') l, SUM(status='A') a FROM attendance`).get();
  const all = percentageMatrix({}).rows.filter(r => r.percent !== null);
  const low = all.filter(r => r.percent < THRESHOLD).sort((a, b) => a.percent - b.percent);
  const overall = pct(all.reduce((s, r) => s + r.attended, 0), all.reduce((s, r) => s + r.total, 0));
  return {
    threshold: THRESHOLD, totals, overall, latest_date: latest,
    latest: latestRow && { total: latestRow.total, present: latestRow.p, late: latestRow.l, absent: latestRow.a, percent: pct(latestRow.p + latestRow.l, latestRow.total) },
    trend, by_subject: bySubject, split: { present: split.p || 0, late: split.l || 0, absent: split.a || 0 },
    low_count: low.length, low: low.slice(0, 8).map(r => ({ id: r.student.id, roll_no: r.student.roll_no, name: r.student.name, percent: r.percent }))
  };
});

/* ------------------------------ HTTP plumbing ------------------------------ */
const MIME = { '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.json': 'application/json', '.svg': 'image/svg+xml', '.png': 'image/png', '.ico': 'image/x-icon' };

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = []; let size = 0;
    req.on('data', c => { size += c.length; if (size > 1e6) { reject(new HttpError(413, 'Request too large')); req.destroy(); } else chunks.push(c); });
    req.on('end', () => {
      if (!chunks.length) return resolve({});
      try { resolve(JSON.parse(Buffer.concat(chunks).toString())); } catch { reject(new HttpError(400, 'Invalid JSON body')); }
    });
    req.on('error', reject);
  });
}

function send(res, status, data, headers = {}) {
  const body = typeof data === 'string' || Buffer.isBuffer(data) ? data : JSON.stringify(data);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'X-Content-Type-Options': 'nosniff', 'Cache-Control': 'no-store', ...headers
  });
  res.end(body);
}

async function handleApi(req, res, url) {
  const r = routes.find(x => x.method === req.method && x.re.test(url.pathname));
  if (!r) {
    if (routes.some(x => x.re.test(url.pathname))) throw new HttpError(405, 'Method not allowed');
    throw new HttpError(404, 'API endpoint not found');
  }
  const m = url.pathname.match(r.re);
  const params = Object.fromEntries(r.keys.map((k, i) => [k, decodeURIComponent(m[i + 1])]));
  let user = null;
  if (r.roles) {
    const h = req.headers.authorization || '';
    user = verify(h.startsWith('Bearer ') ? h.slice(7) : '');
    need(user, 'Please log in', 401);
    need(r.roles.includes(user.role), 'You do not have permission to do that', 403);
  }
  const body = ['POST', 'PUT', 'PATCH'].includes(req.method) ? await readBody(req) : {};
  const out = await r.handler({ req, user, params, query: Object.fromEntries(url.searchParams), body, ip: req.socket.remoteAddress });
  send(res, 200, out);
}

function serveStatic(req, res, url) {
  let p = decodeURIComponent(url.pathname);
  if (p === '/') p = '/index.html';
  const file = path.normalize(path.join(PUBLIC_DIR, p));
  if (!file.startsWith(PUBLIC_DIR + path.sep)) return send(res, 403, 'Forbidden', { 'Content-Type': 'text/plain' });
  fs.readFile(file, (err, buf) => {
    if (err) return send(res, 404, 'Not found', { 'Content-Type': 'text/plain' });
    send(res, 200, buf, { 'Content-Type': MIME[path.extname(file)] || 'application/octet-stream', 'Cache-Control': 'no-cache' });
  });
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://localhost');
  try {
    if (url.pathname.startsWith('/api/')) await handleApi(req, res, url);
    else if (req.method === 'GET' || req.method === 'HEAD') serveStatic(req, res, url);
    else throw new HttpError(405, 'Method not allowed');
  } catch (e) {
    if (!(e instanceof HttpError)) console.error(e);
    const status = e instanceof HttpError ? e.status : 500;
    send(res, status, { error: e instanceof HttpError ? e.message : 'Internal server error' });
  }
});

if (require.main === module) {
  if (ensureSeeded()) console.log('Demo data created (admin / admin123, faculty1 / faculty123).');
  server.listen(PORT, () => console.log(`Smart Attendance Management System running at http://localhost:${PORT}`));
}
module.exports = { server };
