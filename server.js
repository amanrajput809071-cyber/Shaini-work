import express from "express";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import Database from "better-sqlite3";
import path from "path";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const app = express();
const PORT = process.env.PORT || 3000;

const JWT_SECRET =
  process.env.JWT_SECRET || "SHAINI_WORK_CHANGE_THIS_SECRET";

const db = new Database(
  process.env.DB_FILE || path.join(__dirname, "shaini.db")
);

db.pragma("journal_mode=WAL");

/* =========================
   DATABASE TABLES
========================= */

db.exec(`
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  phone TEXT UNIQUE NOT NULL,
  role TEXT NOT NULL DEFAULT 'member',
  status TEXT NOT NULL DEFAULT 'active',
  earning INTEGER NOT NULL DEFAULT 0,
  portals INTEGER NOT NULL DEFAULT 0,
  customers INTEGER NOT NULL DEFAULT 0,
  paid INTEGER NOT NULL DEFAULT 0,
  pending INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS portals(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  url TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS activities(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  activity TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'Completed',
  amount INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
`);

/* =========================
   CREATE ADMIN
========================= */

if (!db.prepare(
  "SELECT id FROM users WHERE username='admin'"
).get()) {

  const hash = bcrypt.hashSync(
    process.env.ADMIN_PASSWORD || "ChangeMe123!",
    12
  );

  db.prepare(`
    INSERT INTO users
    (name, username, password_hash, phone, role)
    VALUES (?, ?, ?, ?, ?)
  `).run(
    "SHAINI Admin",
    "admin",
    hash,
    "0000000000",
    "admin"
  );
}

/* =========================
   CREATE 5 DEFAULT PORTALS
========================= */

if (db.prepare("SELECT COUNT(*) AS c FROM portals").get().c === 0) {

  const insert = db.prepare(
    "INSERT INTO portals(name,url) VALUES(?,?)"
  );

  for (let i = 1; i <= 5; i++) {
    insert.run(
      "Portal " + i,
      "https://example.com/portal" + i
    );
  }
}

/* =========================
   MIDDLEWARE
========================= */

app.use(express.json());

app.use(
  express.static(path.join(__dirname, "public"))
);

/* =========================
   AUTHENTICATION
========================= */

function auth(req, res, next) {

  const header = req.headers.authorization || "";

  if (!header.startsWith("Bearer ")) {
    return res.status(401).json({
      error: "Login required"
    });
  }

  try {

    req.user = jwt.verify(
      header.slice(7),
      JWT_SECRET
    );

    next();

  } catch {

    return res.status(401).json({
      error: "Session expired"
    });

  }
}

/* =========================
   ADMIN CHECK
========================= */

function admin(req, res, next) {

  if (req.user.role !== "admin") {

    return res.status(403).json({
      error: "Admin only"
    });

  }

  next();
}

/* =========================
   TOKEN
========================= */

function createToken(user) {

  return jwt.sign(
    {
      id: user.id,
      role: user.role
    },
    JWT_SECRET,
    {
      expiresIn: "12h"
    }
  );
}

/* =========================
   WORKER REGISTER
========================= */

app.post("/api/register", (req, res) => {

  const {
    name,
    phone,
    username,
    password
  } = req.body || {};

  if (!name || !phone || !username || !password) {

    return res.status(400).json({
      error:
        "Name, mobile number, username and password are required"
    });

  }

  if (!/^[6-9]\d{9}$/.test(String(phone))) {

    return res.status(400).json({
      error:
        "Enter a valid 10-digit Indian mobile number"
    });

  }

  if (String(password).length < 6) {

    return res.status(400).json({
      error:
        "Password must be at least 6 characters"
    });

  }

  if (
    String(username).trim().toLowerCase() === "admin"
  ) {

    return res.status(400).json({
      error: "This username is reserved"
    });

  }

  try {

    const hash = bcrypt.hashSync(
      String(password),
      12
    );

    const result = db.prepare(`
      INSERT INTO users
      (name, username, password_hash, phone)
      VALUES (?, ?, ?, ?)
    `).run(
      String(name).trim(),
      String(username).trim(),
      hash,
      String(phone)
    );

    res.json({
      ok: true,
      id: result.lastInsertRowid,
      message: "Account created successfully"
    });

  } catch {

    res.status(400).json({
      error:
        "Mobile number or username already registered"
    });

  }

});

/* =========================
   LOGIN
========================= */

app.post("/api/login", (req, res) => {

  const {
    username,
    password
  } = req.body || {};

  const user = db.prepare(`
    SELECT *
    FROM users
    WHERE username = ?
    AND status = 'active'
  `).get(
    String(username || "").trim()
  );

  if (
    !user ||
    !bcrypt.compareSync(
      String(password || ""),
      user.password_hash
    )
  ) {

    return res.status(401).json({
      error:
        "Username or password is incorrect"
    });

  }

  res.json({
    token: createToken(user),

    user: {
      id: user.id,
      name: user.name,
      username: user.username,
      role: user.role
    }
  });

});

/* =========================
   WORKER DASHBOARD
========================= */

app.get("/api/me", auth, (req, res) => {

  const user = db.prepare(`
    SELECT
      id,
      name,
      username,
      phone,
      role,
      status,
      earning,
      portals,
      customers,
      paid,
      pending
    FROM users
    WHERE id = ?
  `).get(req.user.id);

  if (!user) {

    return res.status(404).json({
      error: "User not found"
    });

  }

  const portals = db.prepare(`
    SELECT id, name, url
    FROM portals
    ORDER BY id
  `).all();

  const activities = db.prepare(`
    SELECT
      activity,
      status,
      amount,
      created_at
    FROM activities
    WHERE user_id = ?
    ORDER BY id DESC
    LIMIT 50
  `).all(req.user.id);

  res.json({
    user,
    portals,
    activities
  });

});

/* =========================
   ADMIN - USERS
========================= */

app.get(
  "/api/admin/users",
  auth,
  admin,
  (req, res) => {

    const users = db.prepare(`
      SELECT
        id,
        name,
        username,
        phone,
        status,
        earning,
        portals,
        customers,
        paid,
        pending,
        created_at
      FROM users
      WHERE role = 'member'
      ORDER BY id DESC
    `).all();

    res.json(users);

  }
);

/* =========================
   ADMIN - CREATE USER
========================= */

app.post(
  "/api/admin/users",
  auth,
  admin,
  (req, res) => {

    const {
      name,
      phone,
      username,
      password
    } = req.body || {};

    if (
      !name ||
      !phone ||
      !username ||
      !password
    ) {

      return res.status(400).json({
        error: "All fields required"
      });

    }

    try {

      const hash = bcrypt.hashSync(
        String(password),
        12
      );

      const result = db.prepare(`
        INSERT INTO users
        (name, username, password_hash, phone)
        VALUES (?, ?, ?, ?)
      `).run(
        String(name).trim(),
        String(username).trim(),
        hash,
        String(phone)
      );

      res.json({
        ok: true,
        id: result.lastInsertRowid
      });

    } catch {

      res.status(400).json({
        error:
          "Username or mobile already exists"
      });

    }

  }
);

/* =========================
   ADMIN - UPDATE USER
========================= */

app.patch(
  "/api/admin/users/:id",
  auth,
  admin,
  (req, res) => {

    const id = Number(req.params.id);

    const body = req.body || {};

    const allowed = [
      "name",
      "phone",
      "status",
      "earning",
      "portals",
      "customers",
      "paid",
      "pending"
    ];

    const fields = [];
    const values = [];

    for (const key of allowed) {

      if (body[key] !== undefined) {

        fields.push(key + "=?");

        if (
          ["name", "phone", "status"]
            .includes(key)
        ) {

          values.push(
            String(body[key])
          );

        } else {

          values.push(
            Math.max(
              0,
              Number(body[key]) || 0
            )
          );

        }

      }

    }

    if (!fields.length) {

      return res.status(400).json({
        error: "No changes"
      });

    }

    values.push(id);

    db.prepare(`
      UPDATE users
      SET ${fields.join(",")}
      WHERE id=?
      AND role='member'
    `).run(...values);

    res.json({
      ok: true
    });

  }
);

/* =========================
   ADMIN - ACTIVITIES
========================= */

app.post(
  "/api/admin/activity",
  auth,
  admin,
  (req, res) => {

    const {
      user_id,
      activity,
      status = "Completed",
      amount = 0
    } = req.body || {};

    if (!user_id || !activity) {

      return res.status(400).json({
        error:
          "User and activity required"
      });

    }

    db.prepare(`
      INSERT INTO activities
      (user_id, activity, status, amount)
      VALUES (?, ?, ?, ?)
    `).run(
      Number(user_id),
      String(activity),
      String(status),
      Math.max(
        0,
        Number(amount) || 0
      )
    );

    res.json({
      ok: true
    });

  }
);

/* =========================
   ADMIN - GET PORTALS
========================= */

app.get(
  "/api/admin/portals",
  auth,
  admin,
  (req, res) => {

    const portals = db.prepare(`
      SELECT id, name, url
      FROM portals
      ORDER BY id
    `).all();

    res.json(portals);

  }
);

/* =========================
   ADMIN - UPDATE PORTAL
========================= */

app.patch(
  "/api/admin/portals/:id",
  auth,
  admin,
  (req, res) => {

    const id = Number(req.params.id);

    const {
      name,
      url
    } = req.body || {};

    if (!name || !url) {

      return res.status(400).json({
        error:
          "Portal name and link are required"
      });

    }

    if (
      !/^https?:\/\//i.test(
        String(url).trim()
      )
    ) {

      return res.status(400).json({
        error:
          "Portal link must start with http:// or https://"
      });

    }

    const result = db.prepare(`
      UPDATE portals
      SET name=?, url=?
      WHERE id=?
    `).run(
      String(name).trim(),
      String(url).trim(),
      id
    );

    if (result.changes === 0) {

      return res.status(404).json({
        error: "Portal not found"
      });

    }

    res.json({
      ok: true,
      message:
        "Portal link saved successfully"
    });

  }
);

/* =========================
   MAIN WEBSITE
========================= */

app.get("/", (req, res) => {

  res.sendFile(
    path.join(
      __dirname,
      "public",
      "index.html"
    )
  );

});

/* =========================
   START SERVER
========================= */

app.listen(PORT, () => {

  console.log(
    "SHAINI WORK running on port " + PORT
  );

});
