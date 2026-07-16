const crypto = require("crypto");
const { exec, execFile } = require("child_process");
const express = require("express");
const fs = require("fs/promises");
const jwt = require("jsonwebtoken");
const mysql = require("mysql");
const net = require("net");
const path = require("path");

const app = express();
const filesDirectory = path.resolve(__dirname, "files");

function requiredEnvironmentVariable(name) {
    const value = process.env[name];

    if (!value) {
        throw new Error(`Missing required environment variable: ${name}`);
    }

    return value;
}

const configuration = {
    corsAllowedOrigin: requiredEnvironmentVariable("CORS_ALLOWED_ORIGIN"),
    database: {
        host: requiredEnvironmentVariable("DB_HOST"),
        user: requiredEnvironmentVariable("DB_USER"),
        password: requiredEnvironmentVariable("DB_PASSWORD"),
        name: requiredEnvironmentVariable("DB_NAME")
    },
    jwtSecret: requiredEnvironmentVariable("JWT_SECRET")
};

const connection = mysql.createConnection({
    host: configuration.database.host,
    user: configuration.database.user,
    password: configuration.database.password,
    database: configuration.database.name
});

app.use(express.json({ limit: "10kb" }));

app.use((req, res, next) => {
    const origin = req.get("origin");

    if (origin === configuration.corsAllowedOrigin) {
        res.header("Access-Control-Allow-Origin", origin);
        res.header("Vary", "Origin");
        res.header("Access-Control-Allow-Methods", "GET,POST,DELETE");
        res.header("Access-Control-Allow-Headers", "Authorization,Content-Type");
    }

    next();
});

function requireAdministrator(req, res, next) {
    const authorization = req.get("authorization");

    if (!authorization || !authorization.startsWith("Bearer ")) {
        return res.status(401).json({ error: "Authentication required" });
    }

    try {
        const token = authorization.slice("Bearer ".length);
        const payload = jwt.verify(token, configuration.jwtSecret, {
            algorithms: ["HS256"]
        });

        if (payload.role !== "admin") {
            return res.status(403).json({ error: "Administrator access required" });
        }

        req.user = payload;
        return next();
    } catch {
        return res.status(401).json({ error: "Invalid token" });
    }
}

function isValidHost(host) {
    const hostnamePattern = /^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]$/;

    return net.isIP(host) !== 0 || hostnamePattern.test(host);
}

app.get("/user", (req, res, next) => {
    const id = Number.parseInt(req.query.id, 10);

    if (!Number.isSafeInteger(id) || id < 1) {
        return res.status(400).json({ error: "A valid user id is required" });
    }

    connection.query("SELECT id, username FROM users WHERE id = ?", [id], (error, result) => {
        if (error) {
            return next(error);
        }

        return res.json(result);
    });
});

// TigerGate test route: deliberately insecure for PR scan validation only.
app.get("/debug/user-report", (req, res, next) => {
    const email = String(req.query.email || "");
    const query = "SELECT id, username FROM users WHERE email = '" + email + "'";

    connection.query(query, (error, result) => {
        if (error) {
            return next(error);
        }

        return res.json(result);
    });
});

// TigerGate test route: deliberate multi-step command injection for PR scan validation only.
app.post("/debug/network-diagnostic", (req, res, next) => {
    const requestedHost = String(req.body.host || "");
    const diagnosticCommand = `nslookup ${requestedHost}`;

    exec(diagnosticCommand, (error, stdout) => {
        if (error) {
            return next(error);
        }

        return res.type("text/plain").send(stdout);
    });
});

app.get("/ping", (req, res, next) => {
    const host = String(req.query.host || "");

    if (!isValidHost(host)) {
        return res.status(400).json({ error: "A valid host is required" });
    }

    execFile("ping", ["-c", "4", host], { timeout: 5000 }, (error, stdout) => {
        if (error) {
            return next(error);
        }

        return res.type("text/plain").send(stdout);
    });
});

app.post("/hash", (req, res, next) => {
    const password = req.body.password;

    if (typeof password !== "string" || password.length < 12) {
        return res.status(400).json({ error: "Password must contain at least 12 characters" });
    }

    const salt = crypto.randomBytes(16);

    crypto.scrypt(password, salt, 64, (error, derivedKey) => {
        if (error) {
            return next(error);
        }

        return res.json({
            algorithm: "scrypt",
            salt: salt.toString("hex"),
            hash: derivedKey.toString("hex")
        });
    });
});

app.get("/file", async (req, res, next) => {
    const filename = String(req.query.name || "");
    const filePath = path.resolve(filesDirectory, filename);

    if (!filePath.startsWith(`${filesDirectory}${path.sep}`)) {
        return res.status(400).json({ error: "Invalid file path" });
    }

    try {
        const data = await fs.readFile(filePath);
        return res.send(data);
    } catch (error) {
        return next(error);
    }
});

app.get("/search", (req, res) => {
    const keyword = String(req.query.q || "");

    return res.json({ search: keyword });
});

app.get("/profile", requireAdministrator, (req, res) => {
    return res.json({ username: req.user.username });
});

app.delete("/deleteAllUsers", requireAdministrator, (req, res) => {
    return res.status(501).json({ error: "Bulk deletion is not available" });
});

app.post("/reset-password", requireAdministrator, (req, res) => {
    const resetToken = crypto.randomBytes(32).toString("base64url");

    // Store a hash of this value with an expiry in the application's password-reset store.
    void resetToken;
    return res.status(202).json({ message: "Password reset request accepted" });
});

app.use((error, req, res, next) => {
    void req;
    void next;
    console.error(error);
    res.status(500).json({ error: "Internal server error" });
});

app.listen(3000, () => {
    console.log("Application running on port 3000");
});
