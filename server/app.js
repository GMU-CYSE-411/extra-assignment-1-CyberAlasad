const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const express = require("express");
const cookieParser = require("cookie-parser");
const { DEFAULT_DB_FILE, openDatabase } = require("../db");

const PUBLIC_FILES = new Set([
  "index.html",
  "login.html",
  "notes.html",
  "settings.html",
  "admin.html"
]);

function sendPublicFile(response, fileName) {
  if (!PUBLIC_FILES.has(fileName)) {
    response.status(404).send("Not found");
    return;
  }

  response.sendFile(path.join(__dirname, "..", "public", fileName));
}

function createSessionId() {
  const randomText = crypto.randomBytes(32).toString("hex");
  return `SESSION-${randomText}`;
}

function cleanString(value, maxLength) {
  const text = String(value || "");

  if (text.length > maxLength) {
    return null;
  }

  return text;
}

function parseBool(value) {
  if (value === true || value === "true" || value === "1" || value === 1) {
    return 1;
  }

  return 0;
}

async function createApp() {
  if (!fs.existsSync(DEFAULT_DB_FILE)) {
    throw new Error(
      `Database file not found at ${DEFAULT_DB_FILE}. Run "npm run init-db" first.`
    );
  }

  const db = openDatabase(DEFAULT_DB_FILE);
  const app = express();

  app.use(express.json());
  app.use(express.urlencoded({ extended: false }));
  app.use(cookieParser());
  app.use("/css", express.static(path.join(__dirname, "..", "public", "css")));
  app.use("/js", express.static(path.join(__dirname, "..", "public", "js")));

  app.use((request, response, next) => {
    if (
      request.method === "GET" ||
      request.method === "HEAD" ||
      request.method === "OPTIONS"
    ) {
      next();
      return;
    }

    const origin = request.get("origin");

    if (!origin) {
      next();
      return;
    }

    const correctOrigin = `${request.protocol}://${request.get("host")}`;

    if (origin !== correctOrigin) {
      response.status(403).json({ error: "Invalid origin." });
      return;
    }

    next();
  });

  app.use(async (request, response, next) => {
    const sessionId = request.cookies.sid;

    if (!sessionId) {
      request.currentUser = null;
      next();
      return;
    }

    const row = await db.get(
      `
        SELECT
          sessions.id AS session_id,
          users.id AS id,
          users.username AS username,
          users.role AS role,
          users.display_name AS display_name
        FROM sessions
        JOIN users ON users.id = sessions.user_id
        WHERE sessions.id = ?
      `,
      [sessionId]
    );

    if (!row) {
      request.currentUser = null;
      next();
      return;
    }

    request.currentUser = {
      sessionId: row.session_id,
      id: row.id,
      username: row.username,
      role: row.role,
      displayName: row.display_name
    };

    next();
  });

  function requireAuth(request, response, next) {
    if (!request.currentUser) {
      response.status(401).json({ error: "Authentication required." });
      return;
    }

    next();
  }

  function requireAdmin(request, response, next) {
    if (!request.currentUser) {
      response.status(401).json({ error: "Authentication required." });
      return;
    }

    if (request.currentUser.role !== "admin") {
      response.status(403).json({ error: "Admin access required." });
      return;
    }

    next();
  }

  app.get("/", (_request, response) => {
    sendPublicFile(response, "index.html");
  });

  app.get("/login", (_request, response) => {
    sendPublicFile(response, "login.html");
  });

  app.get("/notes", (_request, response) => {
    sendPublicFile(response, "notes.html");
  });

  app.get("/settings", (_request, response) => {
    sendPublicFile(response, "settings.html");
  });

  app.get("/admin", (_request, response) => {
    sendPublicFile(response, "admin.html");
  });

  app.get("/api/me", (request, response) => {
    response.json({ user: request.currentUser });
  });

  app.post("/api/login", async (request, response) => {
    const username = cleanString(request.body.username, 80);
    const password = cleanString(request.body.password, 200);

    if (username === null || password === null) {
      response.status(400).json({ error: "Invalid username or password." });
      return;
    }

    const user = await db.get(
      `
        SELECT id, username, role, display_name
        FROM users
        WHERE username = ? AND password = ?
      `,
      [username, password]
    );

    if (!user) {
      response.status(401).json({ error: "Invalid username or password." });
      return;
    }

    if (request.cookies.sid) {
      await db.run("DELETE FROM sessions WHERE id = ?", [request.cookies.sid]);
    }

    const sessionId = createSessionId();

    await db.run(
      "INSERT INTO sessions (id, user_id, created_at) VALUES (?, ?, ?)",
      [sessionId, user.id, new Date().toISOString()]
    );

    response.cookie("sid", sessionId, {
      path: "/",
      httpOnly: true,
      sameSite: "lax",
      secure: process.env.NODE_ENV === "production"
    });

    response.json({
      ok: true,
      user: {
        id: user.id,
        username: user.username,
        role: user.role,
        displayName: user.display_name
      }
    });
  });

  app.post("/api/logout", async (request, response) => {
    if (request.cookies.sid) {
      await db.run("DELETE FROM sessions WHERE id = ?", [request.cookies.sid]);
    }

    response.clearCookie("sid", {
      path: "/",
      sameSite: "lax",
      secure: process.env.NODE_ENV === "production"
    });

    response.json({ ok: true });
  });

  app.get("/api/notes", requireAuth, async (request, response) => {
    const search = cleanString(request.query.search, 200);

    if (search === null) {
      response.status(400).json({ error: "Invalid search." });
      return;
    }

    const notes = await db.all(
      `
        SELECT
          notes.id,
          notes.owner_id AS ownerId,
          users.username AS ownerUsername,
          notes.title,
          notes.body,
          notes.pinned,
          notes.created_at AS createdAt
        FROM notes
        JOIN users ON users.id = notes.owner_id
        WHERE notes.owner_id = ?
          AND (notes.title LIKE ? OR notes.body LIKE ?)
        ORDER BY notes.pinned DESC, notes.id DESC
      `,
      [request.currentUser.id, `%${search}%`, `%${search}%`]
    );

    response.json({ notes });
  });

  app.post("/api/notes", requireAuth, async (request, response) => {
    const title = cleanString(request.body.title, 120);
    const body = cleanString(request.body.body, 5000);
    const pinned = parseBool(request.body.pinned);

    if (title === null || body === null) {
      response.status(400).json({ error: "Invalid note content." });
      return;
    }

    const result = await db.run(
      `
        INSERT INTO notes
          (owner_id, title, body, pinned, created_at)
        VALUES (?, ?, ?, ?, ?)
      `,
      [request.currentUser.id, title, body, pinned, new Date().toISOString()]
    );

    response.status(201).json({
      ok: true,
      noteId: result.lastID
    });
  });

  app.get("/api/settings", requireAuth, async (request, response) => {
    const settings = await db.get(
      `
        SELECT
          users.id AS userId,
          users.username,
          users.role,
          users.display_name AS displayName,
          settings.status_message AS statusMessage,
          settings.theme,
          settings.email_opt_in AS emailOptIn
        FROM settings
        JOIN users ON users.id = settings.user_id
        WHERE settings.user_id = ?
      `,
      [request.currentUser.id]
    );

    response.json({ settings });
  });

  app.post("/api/settings", requireAuth, async (request, response) => {
    const displayName = cleanString(request.body.displayName, 80);
    const statusMessage = cleanString(request.body.statusMessage, 280);
    const theme = cleanString(request.body.theme || "classic", 40);
    const emailOptIn = parseBool(request.body.emailOptIn);

    if (displayName === null || statusMessage === null || theme === null) {
      response.status(400).json({ error: "Invalid settings content." });
      return;
    }

    if (theme !== "classic" && theme !== "light" && theme !== "dark") {
      response.status(400).json({ error: "Invalid theme." });
      return;
    }

    await db.run(
      "UPDATE users SET display_name = ? WHERE id = ?",
      [displayName, request.currentUser.id]
    );

    await db.run(
      `
        UPDATE settings
        SET status_message = ?, theme = ?, email_opt_in = ?
        WHERE user_id = ?
      `,
      [statusMessage, theme, emailOptIn, request.currentUser.id]
    );

    response.json({ ok: true });
  });

  app.get("/api/settings/toggle-email", requireAuth, async (_request, response) => {
    response.status(405).json({ error: "Use POST instead." });
  });

  app.post("/api/settings/toggle-email", requireAuth, async (request, response) => {
    const enabled = parseBool(request.body.enabled);

    await db.run(
      "UPDATE settings SET email_opt_in = ? WHERE user_id = ?",
      [enabled, request.currentUser.id]
    );

    response.json({
      ok: true,
      userId: request.currentUser.id,
      emailOptIn: enabled
    });
  });

  app.get("/api/admin/users", requireAdmin, async (_request, response) => {
    const users = await db.all(`
      SELECT
        users.id,
        users.username,
        users.role,
        users.display_name AS displayName,
        COUNT(notes.id) AS noteCount
      FROM users
      LEFT JOIN notes ON notes.owner_id = users.id
      GROUP BY users.id, users.username, users.role, users.display_name
      ORDER BY users.id
    `);

    response.json({ users });
  });

  return app;
}

module.exports = {
  createApp
};