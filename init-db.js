const fs = require("fs");
const path = require("path");
const { DEFAULT_DB_FILE, openDatabase } = require("./db");

async function initializeDatabase() {
  const analysisDir = path.dirname(DEFAULT_DB_FILE);
  fs.mkdirSync(analysisDir, { recursive: true });

  if (fs.existsSync(DEFAULT_DB_FILE)) {
    fs.unlinkSync(DEFAULT_DB_FILE);
  }

  const db = openDatabase(DEFAULT_DB_FILE);

  await db.run(`
    CREATE TABLE users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT NOT NULL UNIQUE,
      password TEXT NOT NULL,
      role TEXT NOT NULL,
      display_name TEXT NOT NULL
    )
  `);

  await db.run(`
    CREATE TABLE sessions (
      id TEXT PRIMARY KEY,
      user_id INTEGER NOT NULL,
      csrf_token TEXT NOT NULL,
      created_at TEXT NOT NULL,
      FOREIGN KEY(user_id) REFERENCES users(id)
    )
  `);

  await db.run(`
    CREATE TABLE notes (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      owner_id INTEGER NOT NULL,
      title TEXT NOT NULL,
      body TEXT NOT NULL,
      pinned INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL,
      FOREIGN KEY(owner_id) REFERENCES users(id)
    )
  `);

  await db.run(`
    CREATE TABLE settings (
      user_id INTEGER PRIMARY KEY,
      status_message TEXT NOT NULL,
      theme TEXT NOT NULL,
      email_opt_in INTEGER NOT NULL DEFAULT 1,
      FOREIGN KEY(user_id) REFERENCES users(id)
    )
  `);

  await db.run(
    "INSERT INTO users (username, password, role, display_name) VALUES (?, ?, ?, ?), (?, ?, ?, ?), (?, ?, ?, ?)",
    [
      "admin",
      "admin123",
      "admin",
      "Administrator",
      "alice",
      "wonderland",
      "student",
      "Alice Analyst",
      "bob",
      "builder",
      "student",
      "Bob Builder"
    ]
  );

  await db.run(
    "INSERT INTO settings (user_id, status_message, theme, email_opt_in) VALUES (?, ?, ?, ?), (?, ?, ?, ?), (?, ?, ?, ?)",
    [
      1,
      "I review every note before class.",
      "classic",
      1,
      2,
      "Looking for trust boundary examples.",
      "ocean",
      1,
      3,
      "Need help with the admin checklist.",
      "forest",
      0
    ]
  );

  await db.run(
    "INSERT INTO notes (owner_id, title, body, pinned, created_at) VALUES (?, ?, ?, ?, ?), (?, ?, ?, ?, ?), (?, ?, ?, ?, ?), (?, ?, ?, ?, ?)",
    [
      1,
      "Instructor checklist",
      "Review the settings flow before publishing the lab.",
      1,
      "2026-04-10T10:00:00.000Z",
      2,
      "DOM reminder",
      "Never trust browser-rendered HTML from note content.",
      0,
      "2026-04-10T11:00:00.000Z",
      2,
      "Study idea",
      "<strong>Reflection prompt:</strong> where does the browser interpret data as code?",
      0,
      "2026-04-11T09:15:00.000Z",
      3,
      "Lab question",
      "Can a normal user reach /admin if the client hides the link?",
      0,
      "2026-04-11T09:20:00.000Z"
    ]
  );

  await db.close();

  console.log(`Initialized SQLite database at ${DEFAULT_DB_FILE}`);
}

initializeDatabase().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});