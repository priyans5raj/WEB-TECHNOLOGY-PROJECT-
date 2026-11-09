'use strict';
/**
 * Database layer - SQLite via the built-in node:sqlite module (Node >= 22.5).
 * No external packages are needed.
 */
const path = require('node:path');
const fs = require('node:fs');
const crypto = require('node:crypto');
const { DatabaseSync } = require('node:sqlite');

const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
fs.mkdirSync(DATA_DIR, { recursive: true });
const DB_FILE = process.env.DB_FILE || path.join(DATA_DIR, 'attendance.db');
const db = new DatabaseSync(DB_FILE);

db.exec(`
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  username      TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  salt          TEXT NOT NULL,
  role          TEXT NOT NULL CHECK (role IN ('admin','faculty','student')),
  name          TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS students (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  roll_no    TEXT NOT NULL UNIQUE,
  name       TEXT NOT NULL,
  email      TEXT,
  phone      TEXT,
  department TEXT NOT NULL,
  year       INTEGER NOT NULL CHECK (year BETWEEN 1 AND 4),
  section    TEXT,
  user_id    INTEGER REFERENCES users(id) ON DELETE SET NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS subjects (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  code       TEXT NOT NULL UNIQUE,
  name       TEXT NOT NULL,
  department TEXT NOT NULL,
  year       INTEGER NOT NULL CHECK (year BETWEEN 1 AND 4),
  faculty_id INTEGER REFERENCES users(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS attendance (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  student_id INTEGER NOT NULL REFERENCES students(id) ON DELETE CASCADE,
  subject_id INTEGER NOT NULL REFERENCES subjects(id) ON DELETE CASCADE,
  date       TEXT NOT NULL,
  status     TEXT NOT NULL CHECK (status IN ('P','A','L')),
  marked_by  INTEGER REFERENCES users(id) ON DELETE SET NULL,
  UNIQUE (student_id, subject_id, date)
);
CREATE INDEX IF NOT EXISTS idx_att_date    ON attendance(date);
CREATE INDEX IF NOT EXISTS idx_att_subject ON attendance(subject_id, date);
CREATE INDEX IF NOT EXISTS idx_att_student ON attendance(student_id);
`);

/* ---------- password helpers ---------- */
function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return { hash, salt };
}
function checkPassword(password, hash, salt) {
  const a = Buffer.from(hash, 'hex');
  const b = crypto.scryptSync(password, salt, 64);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
function createUser(username, password, role, name) {
  const { hash, salt } = hashPassword(password);
  const r = db.prepare('INSERT INTO users (username,password_hash,salt,role,name) VALUES (?,?,?,?,?)')
    .run(username, hash, salt, role, name);
  return Number(r.lastInsertRowid);
}

/* ---------- date helpers ---------- */
function ymd(d) {
  const p = n => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}`;
}
const today = () => ymd(new Date());

/* ---------- demo data ---------- */
function seed() {
  const NAMES = [
    'Aarav Reddy', 'Ananya Sharma', 'Bhavya Nair', 'Charan Teja', 'Deepika Rao', 'Eshwar Goud',
    'Farhan Ali', 'Gayathri Devi', 'Harsha Vardhan', 'Ishita Gupta', 'Jashwanth Kumar', 'Keerthi Suresh',
    'Lokesh Babu', 'Meghana Iyer', 'Nikhil Varma', 'Om Prakash', 'Pranavi Reddy', 'Rahul Verma',
    'Sneha Patel', 'Tarun Chowdary', 'Uday Kiran', 'Varsha Menon', 'Yashwanth Rao', 'Zoya Khan',
    'Abhinav Singh', 'Divya Teja', 'Manoj Kumar', 'Navya Sri', 'Sai Kiran', 'Tejaswini Rao'
  ];
  const adminId = createUser('admin', 'admin123', 'admin', 'System Administrator');
  const f1 = createUser('faculty1', 'faculty123', 'faculty', 'Mr. Bura Vijay Kumar');
  const f2 = createUser('faculty2', 'faculty123', 'faculty', 'Dr. Anitha Rao');
  const f3 = createUser('faculty3', 'faculty123', 'faculty', 'Prof. Ramesh Babu');

  const subj = db.prepare('INSERT INTO subjects (code,name,department,year,faculty_id) VALUES (?,?,?,?,?)');
  const S = [
    ['CS301', 'Web Technologies and Mobile Programming', 'CSE', 3, f1],
    ['CS302', 'Database Management Systems', 'CSE', 3, f2],
    ['CS303', 'Operating Systems', 'CSE', 3, f3],
    ['CS304', 'Computer Networks', 'CSE', 3, f2],
    ['CS305', 'Machine Learning', 'CSE', 3, f1],
    ['IT201', 'Data Structures', 'IT', 2, f3],
    ['IT202', 'Object Oriented Programming', 'IT', 2, f1]
  ];
  const subjectIds = S.map(s => Number(subj.run(...s).lastInsertRowid));

  const stu = db.prepare('INSERT INTO students (roll_no,name,email,phone,department,year,section,user_id) VALUES (?,?,?,?,?,?,?,?)');
  const students = [];
  NAMES.forEach((name, i) => {
    const cse = i < 22;
    const roll = (cse ? '2311CS01' : '2411IT02') + String(i + 1).padStart(2, '0');
    const uid = createUser(roll.toLowerCase(), roll, 'student', name);
    const email = name.toLowerCase().replace(/[^a-z]+/g, '.') + '@example.edu';
    const phone = '98' + String(48000000 + i * 7919).padStart(8, '0');
    const id = Number(stu.run(roll, name, email, phone, cse ? 'CSE' : 'IT', cse ? 3 : 2, i % 2 ? 'B' : 'A', uid).lastInsertRowid);
    students.push({ id, cse, idx: i });
  });

  // deterministic pseudo-random generator so the demo data is reproducible
  let seedVal = 20260101;
  const rnd = () => (seedVal = (seedVal * 1664525 + 1013904223) % 4294967296) / 4294967296;
  // attendance "habit" of every student (probability of being present)
  const habit = students.map((s, i) => (i % 7 === 3 ? 0.55 + rnd() * 0.12 : 0.80 + rnd() * 0.18));

  const att = db.prepare('INSERT OR IGNORE INTO attendance (student_id,subject_id,date,status,marked_by) VALUES (?,?,?,?,?)');
  db.exec('BEGIN');
  const end = new Date();
  for (let back = 0; back < 42; back++) {
    const d = new Date(end); d.setDate(end.getDate() - back);
    if (d.getDay() === 0 || d.getDay() === 6) continue;     // no classes at weekends
    const date = ymd(d);
    S.forEach((s, si) => {
      if (rnd() < 0.18) return;                              // subject had no class that day
      students.filter(x => (x.cse ? 'CSE' : 'IT') === s[2]).forEach(x => {
        const r = rnd();
        const status = r < habit[x.idx] ? (rnd() < 0.06 ? 'L' : 'P') : 'A';
        att.run(x.id, subjectIds[si], date, status, s[4]);
      });
    });
  }
  db.exec('COMMIT');
  return { adminId };
}

function ensureSeeded(force = false) {
  const n = db.prepare('SELECT COUNT(*) c FROM users').get().c;
  if (force) {
    db.exec('DELETE FROM attendance; DELETE FROM students; DELETE FROM subjects; DELETE FROM users; DELETE FROM sqlite_sequence;');
  } else if (n > 0) return false;
  seed();
  return true;
}

module.exports = { db, hashPassword, checkPassword, createUser, today, ymd, ensureSeeded };

if (require.main === module) {
  const forced = process.argv.includes('--reseed');
  console.log(ensureSeeded(forced) ? 'Demo data created.' : 'Database already has data (use --reseed to rebuild).');
}
