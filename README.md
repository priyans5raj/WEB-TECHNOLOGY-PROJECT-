# Smart Attendance Management System

A full-stack web application for **student registration, attendance entry, attendance percentage, date-wise reports and dashboards**.
Built with HTML5, CSS3, vanilla JavaScript, Node.js and SQLite - **no npm packages to install**.

## Requirements
* Node.js **22.5 or newer** (download from https://nodejs.org). The built-in `node:sqlite` module is used for the database.

## Run
```bash
cd smart-attendance
npm start
```
Open **http://localhost:3000** in a browser (works on a phone on the same Wi-Fi via `http://<your-PC-IP>:3000`).
On first start the database is created and filled with demo data (30 students, 7 subjects, about 6 weeks of attendance).

| Role    | Username      | Password     |
|---------|---------------|--------------|
| Admin   | `admin`       | `admin123`   |
| Faculty | `faculty1`    | `faculty123` |
| Student | `2311cs0101`  | `2311CS0101` |

Student logins are created automatically on registration (username = roll number in lower case, password = roll number).
Change `PORT` with `PORT=8080 npm start` (Windows PowerShell: `$env:PORT=8080; npm start`).
To rebuild the demo data from scratch: `npm run seed` (this erases all existing records).

## Features
| Module | What it does |
|---|---|
| Login & roles | Admin, Faculty and Student accounts, salted scrypt password hashes, signed expiring tokens, login rate-limit |
| Student registration | Add / edit / search / delete students, automatic student login |
| Subjects | Subject master with department, year and assigned faculty |
| Attendance entry | Pick subject + date, mark Present / Late / Absent for the whole class in one screen, re-save to correct |
| Attendance percentage | Student x subject matrix, overall %, 75 % shortage flag, date-range filter, CSV export, print |
| Date-wise report | Per-day, per-subject present / late / absent counts with drill-down to the student list |
| Dashboards | Admin/faculty: KPIs, 14-day trend, subject-wise bars, status split, lowest-attendance list. Student: own % per subject with "classes you can miss / must attend" guidance |

Attendance % = (Present + Late) / Total classes x 100. Minimum required attendance is 75 % (`THRESHOLD` in `server.js`).

## Project structure
```
server.js          HTTP server, REST API, authentication, reports
db.js              SQLite schema, password hashing, demo data
public/            index.html, style.css, app.js  (single-page front end)
tests/api.test.js  automated API tests  (npm test)
data/              SQLite database file (created automatically)
```

## REST API (summary)
`POST /api/login` - `GET /api/me` - `POST /api/password` - `GET|POST /api/subjects` - `DELETE /api/subjects/:id` -
`GET|POST /api/students` - `PUT|DELETE /api/students/:id` - `GET /api/attendance/sheet` - `POST /api/attendance` -
`GET /api/reports/percentage` - `GET /api/reports/datewise` - `GET /api/reports/datewise/detail` -
`GET /api/reports/student/:id|me` - `GET /api/dashboard`

## Tests
`npm test` runs 10 automated tests (authentication, role access, validation, attendance maths, report consistency, path-traversal protection, response times).
