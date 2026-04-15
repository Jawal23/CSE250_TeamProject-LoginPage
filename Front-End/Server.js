// ============================================================
// CSE250 - Team Project: Admin Login System with RBAC
// Team: Jawal, Yug, Kamya
// File: Server.js
//
// ROUTES IN THIS FILE:
//   POST /register    — new user signup (password is hashed with bcrypt)
//   POST /login       — login (bcrypt compares password to stored hash)
//   GET  /users       — fetch all users with roles (SuperAdmin/Admin)
//   POST /changerole  — update a user's role (SuperAdmin only)
//   GET  /version     — fetch Node.js + MariaDB version (SuperAdmin only)
//   GET  /test        — check if server is running
//
//   ── Phase 8 routes ──
//   GET  /stats       — returns total users, count per role, total permissions
//   POST /sendmessage — Viewer or Admin sends a message
//   GET  /inbox       — fetches inbox messages based on role
//   POST /reply       — Admin or SuperAdmin replies to a message
//
//   ── Phase 7 — Password Reset routes ──
//   POST /forgotpassword — checks if username or email exists in users table
//   POST /resetpassword  — hashes new password with bcrypt and updates DB
// ============================================================

const express = require("express");
const mysql   = require("mysql2");
const bcrypt  = require("bcrypt");       // ← Phase 7 (7o): added for password hashing
const path    = require("path");

const app = express();

app.use(express.json());
app.use(express.static(path.join(__dirname)));

// ── How many rounds bcrypt uses to scramble the password ──
// 10 is the standard — secure but not too slow.
// Higher = more secure but slower. Don't go above 12 for a local project.
const SALT_ROUNDS = 10;


// ============================================================
// Connect to MariaDB
// ============================================================
const db = mysql.createConnection({
    host:     process.env.DB_HOST     || "localhost",
    user:     process.env.DB_USER     || "root",
    password: process.env.DB_PASSWORD || "cse250",
    database: process.env.DB_NAME     || "admin_login_system",
    port:     process.env.DB_PORT     || 3306,
});

db.connect(function (err) {
    if (err) {
        console.log("Could not connect to MariaDB:", err.message);
        return;
    }
    console.log("Connected to MariaDB successfully!");
});


// ============================================================
// Route 1: POST /register
//
// CHANGE from before:
//   Old: stored the password directly as plain text
//   New: bcrypt.hash() scrambles the password first, THEN we
//        store the scrambled version (the hash) in the database.
//        The real password is never saved anywhere.
// ============================================================
app.post("/register", function (req, res) {

    const username    = req.body.username;
    const password    = req.body.password;
    const actual_name = req.body.actual_name;
    const email       = req.body.email;

    if (!username || !password || !actual_name || !email) {
        return res.json({ success: false, message: "All fields are required." });
    }

    // Check if username is already taken
    const checkQuery = "SELECT * FROM users WHERE username = ?";
    db.query(checkQuery, [username], function (err, results) {

        if (err) return res.json({ success: false, message: "Database error: " + err.message });

        if (results.length > 0) {
            return res.json({ success: false, message: "Username already taken. Try another one." });
        }

        // ── bcrypt: hash the password before saving ──────────────
        // bcrypt.hash(password, SALT_ROUNDS, callback)
        //   - Takes the plain text password the user typed
        //   - Scrambles it into a long random-looking string
        //   - Calls our function with the result (hashedPassword)
        // We then save hashedPassword into the database instead
        // of the real password. Even if someone steals the DB,
        // they cannot figure out what the original password was.
        bcrypt.hash(password, SALT_ROUNDS, function (err2, hashedPassword) {

            if (err2) return res.json({ success: false, message: "Could not hash password: " + err2.message });

            // Save the hashed password — NOT the original
            const insertQuery = "INSERT INTO users (actual_name, username, password_hash, email, is_active) VALUES (?, ?, ?, ?, 1)";
            db.query(insertQuery, [actual_name, username, hashedPassword, email], function (err3, result) {

                if (err3) return res.json({ success: false, message: "Could not save user: " + err3.message });

                const newUserId = result.insertId;
                const roleQuery = "INSERT INTO user_roles (user_id, role_id) VALUES (?, 3)";
                db.query(roleQuery, [newUserId], function (err4) {

                    if (err4) return res.json({ success: false, message: "User created but could not assign role: " + err4.message });

                    res.json({ success: true, message: "Account created successfully! You can now login." });
                });
            });
        });
    });
});


// ============================================================
// Route 2: POST /login
//
// CHANGE from before:
//   Old: searched the DB with WHERE password_hash = ? (plain text match)
//   New: we search by username only, then use bcrypt.compare() to
//        check if the typed password matches the stored hash.
//
//        bcrypt.compare() does NOT decrypt the hash.
//        It re-scrambles the typed password the same way and checks
//        if the result matches. It returns true or false.
// ============================================================
app.post("/login", function (req, res) {

    const username = req.body.username;
    const password = req.body.password;

    if (!username || !password) {
        return res.json({ success: false, message: "Please enter both username and password." });
    }

    // ── Step 1: Find the user by username only ───────────────
    // We do NOT put the password in this query anymore.
    // We find the user first, then check the password separately.
    const loginQuery = "SELECT * FROM users WHERE username = ? AND is_active = 1";
    db.query(loginQuery, [username], function (err, results) {

        if (err) return res.json({ success: false, message: "Database error: " + err.message });

        // Username not found — show generic message (don't say which field is wrong)
        if (results.length === 0) {
            return res.json({ success: false, message: "Username or Password is incorrect. Please try again." });
        }

        const user = results[0];

        // ── Step 2: Compare the typed password to the stored hash ──
        // bcrypt.compare(typedPassword, storedHash, callback)
        //   - typedPassword: what the user typed in the login form
        //   - storedHash:    the scrambled string stored in our DB
        //   - isMatch:       true if they match, false if not
        bcrypt.compare(password, user.password_hash, function (err2, isMatch) {

            if (err2) return res.json({ success: false, message: "Error checking password: " + err2.message });

            // Password is wrong
            if (!isMatch) {
                return res.json({ success: false, message: "Username or Password is incorrect. Please try again." });
            }

            // ── Password is correct — now fetch role ──────────────
            const roleQuery = `
                SELECT roles.role_id, roles.role_name
                FROM user_roles
                         JOIN roles ON user_roles.role_id = roles.role_id
                WHERE user_roles.user_id = ?
            `;
            db.query(roleQuery, [user.user_id], function (err3, roleResults) {

                if (err3) return res.json({ success: false, message: "Login ok but could not fetch role: " + err3.message });

                const roleName = roleResults.length > 0 ? roleResults[0].role_name : "Viewer";
                const roleId   = roleResults.length > 0 ? roleResults[0].role_id   : 3;

                // Fetch permissions for this role
                const permissionsQuery = `
                    SELECT permissions.permission_name
                    FROM role_permissions
                             JOIN permissions ON role_permissions.permission_id = permissions.permission_id
                    WHERE role_permissions.role_id = ?
                `;
                db.query(permissionsQuery, [roleId], function (err4, permissionResults) {

                    if (err4) return res.json({ success: false, message: "Login ok but could not fetch permissions: " + err4.message });

                    const permissionsList = permissionResults.map(function (row) {
                        return row.permission_name;
                    });

                    res.json({
                        success: true,
                        message: "Login successful!",
                        user: {
                            user_id:     user.user_id,
                            actual_name: user.actual_name,
                            username:    user.username,
                            email:       user.email,
                            role:        roleName,
                            permissions: permissionsList,
                        }
                    });
                });
            });
        });
    });
});


// ============================================================
// Route 3: GET /users
// Returns all users with their assigned role name
// ============================================================
app.get("/users", function (req, res) {

    const query = `
        SELECT
            users.user_id,
            users.actual_name,
            users.username,
            users.email,
            roles.role_name
        FROM users
                 LEFT JOIN user_roles ON users.user_id    = user_roles.user_id
                 LEFT JOIN roles      ON user_roles.role_id = roles.role_id
        ORDER BY users.created_at DESC
    `;

    db.query(query, function (err, results) {
        if (err) return res.json({ success: false, message: "Could not fetch users: " + err.message });
        res.json({ success: true, users: results });
    });
});


// ============================================================
// Route 4: POST /changerole
// Updates a user's role — called by SuperAdmin dashboard
// Body: { user_id: 5, role_id: 2 }
// ============================================================
app.post("/changerole", function (req, res) {

    const userId = req.body.user_id;
    const roleId = req.body.role_id;

    if (!userId || !roleId) {
        return res.json({ success: false, message: "user_id and role_id are required." });
    }

    const checkQuery = "SELECT * FROM user_roles WHERE user_id = ?";
    db.query(checkQuery, [userId], function (err, results) {

        if (err) return res.json({ success: false, message: "Database error: " + err.message });

        if (results.length > 0) {
            const updateQuery = "UPDATE user_roles SET role_id = ? WHERE user_id = ?";
            db.query(updateQuery, [roleId, userId], function (err2) {
                if (err2) return res.json({ success: false, message: "Could not update role: " + err2.message });
                res.json({ success: true, message: "Role updated successfully." });
            });
        } else {
            const insertQuery = "INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)";
            db.query(insertQuery, [userId, roleId], function (err2) {
                if (err2) return res.json({ success: false, message: "Could not assign role: " + err2.message });
                res.json({ success: true, message: "Role assigned successfully." });
            });
        }
    });
});


// ============================================================
// Route 5: GET /version
// ============================================================
app.get("/version", function (req, res) {

    const nodeVersion     = process.version;
    const minNodeVersion  = "16.0.0";
    const minMariaVersion = "10.5.0";

    db.query("SELECT VERSION() AS db_version", function (err, results) {

        if (err) return res.json({ success: false, message: "Could not fetch MariaDB version: " + err.message });

        const mariaVersion = results[0].db_version;

        function isBelowMinimum(current, minimum) {
            var cleanCurrent = current.replace("v", "").split("-")[0];
            var curr = cleanCurrent.split(".").map(Number);
            var min  = minimum.split(".").map(Number);
            for (var i = 0; i < 3; i++) {
                if (curr[i] > min[i]) return false;
                if (curr[i] < min[i]) return true;
            }
            return false;
        }

        res.json({
            success: true,
            node: {
                version:    nodeVersion,
                minimum:    "v" + minNodeVersion,
                hasWarning: isBelowMinimum(nodeVersion, minNodeVersion),
            },
            mariadb: {
                version:    mariaVersion,
                minimum:    minMariaVersion,
                hasWarning: isBelowMinimum(mariaVersion, minMariaVersion),
            }
        });
    });
});


// ============================================================
// Route 6: GET /test
// ============================================================
app.get("/test", function (req, res) {
    res.json({ message: "Server is running! MariaDB connection is active." });
});


// ============================================================
// ── PHASE 8 ROUTES ──────────────────────────────────────────
// ============================================================


// ============================================================
// Route 7: GET /stats
// ============================================================
app.get("/stats", function (req, res) {

    const totalUsersQuery       = "SELECT COUNT(*) AS total FROM users";
    const totalPermissionsQuery = "SELECT COUNT(*) AS total FROM permissions";
    const roleCountQuery        = `
        SELECT roles.role_name, COUNT(user_roles.user_id) AS count
        FROM roles
                 LEFT JOIN user_roles ON roles.role_id = user_roles.role_id
        GROUP BY roles.role_name
    `;

    db.query(totalUsersQuery, function (err1, userResults) {
        if (err1) return res.json({ success: false, message: "Could not count users: " + err1.message });

        db.query(roleCountQuery, function (err2, roleResults) {
            if (err2) return res.json({ success: false, message: "Could not count roles: " + err2.message });

            db.query(totalPermissionsQuery, function (err3, permResults) {
                if (err3) return res.json({ success: false, message: "Could not count permissions: " + err3.message });

                res.json({
                    success:          true,
                    totalUsers:       userResults[0].total,
                    totalPermissions: permResults[0].total,
                    roleCounts:       roleResults,
                });
            });
        });
    });
});


// ============================================================
// Route 8: POST /sendmessage
// ============================================================
app.post("/sendmessage", function (req, res) {

    const sender_id    = req.body.sender_id;
    const sender_role  = req.body.sender_role;
    const target_role  = req.body.target_role;
    const subject      = req.body.subject;
    const message_body = req.body.message_body;

    if (!sender_id || !sender_role || !target_role || !subject || !message_body) {
        return res.json({ success: false, message: "All fields are required." });
    }

    if (sender_role !== "Viewer" && sender_role !== "Admin") {
        return res.json({ success: false, message: "Only Viewers and Admins can send messages." });
    }

    const insertQuery = `
        INSERT INTO messages (sender_id, sender_role, target_role, subject, message_body)
        VALUES (?, ?, ?, ?, ?)
    `;

    db.query(insertQuery, [sender_id, sender_role, target_role, subject, message_body], function (err) {
        if (err) return res.json({ success: false, message: "Could not send message: " + err.message });
        res.json({ success: true, message: "Message sent successfully." });
    });
});


// ============================================================
// Route 9: GET /inbox
// ============================================================
app.get("/inbox", function (req, res) {

    const role    = req.query.role;
    const user_id = req.query.user_id;

    var inboxQuery  = "";
    var queryParams = [];

    if (role === "Viewer") {
        if (!user_id) return res.json({ success: false, message: "user_id is required for Viewer inbox." });
        inboxQuery = `
            SELECT messages.*, users.actual_name AS sender_name
            FROM messages
                     JOIN users ON messages.sender_id = users.user_id
            WHERE messages.sender_id = ?
            ORDER BY messages.sent_at DESC
        `;
        queryParams = [user_id];

    } else if (role === "Admin") {
        inboxQuery = `
            SELECT messages.*, users.actual_name AS sender_name
            FROM messages
                     JOIN users ON messages.sender_id = users.user_id
            WHERE messages.target_role = 'Admin'
            ORDER BY messages.sent_at DESC
        `;

    } else if (role === "SuperAdmin") {
        inboxQuery = `
            SELECT messages.*, users.actual_name AS sender_name
            FROM messages
                     JOIN users ON messages.sender_id = users.user_id
            ORDER BY messages.sent_at DESC
        `;

    } else {
        return res.json({ success: false, message: "Invalid role." });
    }

    db.query(inboxQuery, queryParams, function (err, results) {
        if (err) return res.json({ success: false, message: "Could not fetch inbox: " + err.message });
        res.json({ success: true, messages: results });
    });
});


// ============================================================
// Route 10: POST /reply
// ============================================================
app.post("/reply", function (req, res) {

    const message_id = req.body.message_id;
    const reply      = req.body.reply;
    const replied_by = req.body.replied_by;

    if (!message_id || !reply || !replied_by) {
        return res.json({ success: false, message: "message_id, reply, and replied_by are required." });
    }

    const updateQuery = `
        UPDATE messages
        SET reply      = ?,
            replied_by = ?,
            is_read    = 1
        WHERE message_id = ?
    `;

    db.query(updateQuery, [reply, replied_by, message_id], function (err, result) {
        if (err) return res.json({ success: false, message: "Could not save reply: " + err.message });

        if (result.affectedRows === 0) {
            return res.json({ success: false, message: "Message not found." });
        }

        res.json({ success: true, message: "Reply saved successfully." });
    });
});


// ============================================================
// ── PHASE 7 — PASSWORD RESET ROUTES ─────────────────────────
// ============================================================


// ============================================================
// Route 11: POST /forgotpassword
//
// What it does:
//   The user types their username OR email on the forgot-password page.
//   We search the database to see if any account matches.
//   If yes  → { success: true }  — account found, let them set a new password
//   If no   → { success: false } — no account with that username or email
//
// NOTE: This route does NOT change anything in the database.
//       It only checks if the account exists.
// ============================================================
app.post("/forgotpassword", function (req, res) {

    // The user can type either their username OR their email
    var identifier = req.body.identifier;

    if (!identifier) {
        return res.json({ success: false, message: "Please enter your username or email." });
    }

    // Search the users table — check both username and email columns
    var findQuery = "SELECT user_id FROM users WHERE username = ? OR email = ?";
    db.query(findQuery, [identifier, identifier], function (err, results) {

        if (err) return res.json({ success: false, message: "Database error: " + err.message });

        if (results.length === 0) {
            // No account found with that username or email
            return res.json({ success: false, message: "No account found with that username or email." });
        }

        // Account found — tell the frontend to show the new password form (Step 2)
        res.json({ success: true, message: "Account found." });
    });
});


// ============================================================
// Route 12: POST /resetpassword
//
// What it does:
//   The user has passed Step 1 (account found) and now submits a new password.
//   We receive: identifier (username or email) + newPassword
//   Steps:
//     1. Hash the new password using bcrypt (same way /register does it)
//     2. UPDATE the users table — set password_hash to the new hash
//        WHERE username = identifier OR email = identifier
//     3. Return { success: true } on success
// ============================================================
app.post("/resetpassword", function (req, res) {

    var identifier   = req.body.identifier;    // the username or email the user typed in Step 1
    var newPassword  = req.body.newPassword;   // the new password they want to set

    if (!identifier || !newPassword) {
        return res.json({ success: false, message: "Identifier and new password are required." });
    }

    // Hash the new password before saving — same as /register
    bcrypt.hash(newPassword, SALT_ROUNDS, function (err, hashedPassword) {

        if (err) return res.json({ success: false, message: "Could not hash password: " + err.message });

        // Update the password_hash column for the matching account
        var updateQuery = "UPDATE users SET password_hash = ? WHERE username = ? OR email = ?";
        db.query(updateQuery, [hashedPassword, identifier, identifier], function (err2, result) {

            if (err2) return res.json({ success: false, message: "Could not update password: " + err2.message });

            if (result.affectedRows === 0) {
                // Safety check — no rows were updated (account disappeared between Step 1 and Step 2)
                return res.json({ success: false, message: "Account not found. Please try again." });
            }

            res.json({ success: true, message: "Password reset successfully! You can now login with your new password." });
        });
    });
});


// ============================================================
// Start the server
// ============================================================
app.listen(3000, function () {
    console.log("Server is running at http://localhost:3000");
    console.log("Open http://localhost:3000/login.html to use the app");
});