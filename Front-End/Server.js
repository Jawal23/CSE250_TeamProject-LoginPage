// ============================================================
// CSE250 - Team Project: Admin Login System with RBAC
// Team: Jawal, Yug, Kamya
// File: Server.js
//
// ROUTES IN THIS FILE:
//   POST /register    — new user signup
//   POST /login       — login, returns role + permissions
//   GET  /users       — fetch all users with roles (SuperAdmin/Admin)
//   POST /changerole  — update a user's role (SuperAdmin only)
//   GET  /version     — fetch Node.js + MariaDB version (SuperAdmin only)
//   GET  /test        — check if server is running
//
//   ── Phase 8 routes (new) ──
//   GET  /stats       — returns total users, count per role, total permissions
//   POST /sendmessage — Viewer or Admin sends a message
//   GET  /inbox       — fetches inbox messages based on role
//   POST /reply       — Admin or SuperAdmin replies to a message
// ============================================================

const express = require("express");
const mysql   = require("mysql2");
const path    = require("path");

const app = express();

app.use(express.json());
app.use(express.static(path.join(__dirname)));


// ============================================================
// Connect to MariaDB
// ============================================================
const db = mysql.createConnection({
    host:     "localhost",
    user:     "root",
    password: "cse250",
    database: "admin_login_system",
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
// Saves a new user into the users table with Viewer role
// ============================================================
app.post("/register", function (req, res) {

    const username    = req.body.username;
    const password    = req.body.password;
    const actual_name = req.body.actual_name;
    const email       = req.body.email;

    if (!username || !password || !actual_name || !email) {
        return res.json({ success: false, message: "All fields are required." });
    }

    const checkQuery = "SELECT * FROM users WHERE username = ?";
    db.query(checkQuery, [username], function (err, results) {

        if (err) return res.json({ success: false, message: "Database error: " + err.message });

        if (results.length > 0) {
            return res.json({ success: false, message: "Username already taken. Try another one." });
        }

        const insertQuery = "INSERT INTO users (actual_name, username, password_hash, email, is_active) VALUES (?, ?, ?, ?, 1)";
        db.query(insertQuery, [actual_name, username, password, email], function (err2, result) {

            if (err2) return res.json({ success: false, message: "Could not save user: " + err2.message });

            const newUserId = result.insertId;
            const roleQuery = "INSERT INTO user_roles (user_id, role_id) VALUES (?, 3)";
            db.query(roleQuery, [newUserId], function (err3) {

                if (err3) return res.json({ success: false, message: "User created but could not assign role: " + err3.message });

                res.json({ success: true, message: "Account created successfully! You can now login." });
            });
        });
    });
});


// ============================================================
// Route 2: POST /login
// Checks username + password, returns role + permissions
// ============================================================
app.post("/login", function (req, res) {

    const username = req.body.username;
    const password = req.body.password;

    if (!username || !password) {
        return res.json({ success: false, message: "Please enter both username and password." });
    }

    const loginQuery = "SELECT * FROM users WHERE username = ? AND password_hash = ? AND is_active = 1";
    db.query(loginQuery, [username, password], function (err, results) {

        if (err) return res.json({ success: false, message: "Database error: " + err.message });

        if (results.length === 0) {
            return res.json({ success: false, message: "Wrong username or password. Please try again." });
        }

        const user = results[0];

        const roleQuery = `
            SELECT roles.role_id, roles.role_name
            FROM user_roles
                     JOIN roles ON user_roles.role_id = roles.role_id
            WHERE user_roles.user_id = ?
        `;
        db.query(roleQuery, [user.user_id], function (err2, roleResults) {

            if (err2) return res.json({ success: false, message: "Login ok but could not fetch role: " + err2.message });

            const roleName = roleResults.length > 0 ? roleResults[0].role_name : "Viewer";
            const roleId   = roleResults.length > 0 ? roleResults[0].role_id   : 3;

            const permissionsQuery = `
                SELECT permissions.permission_name
                FROM role_permissions
                         JOIN permissions ON role_permissions.permission_id = permissions.permission_id
                WHERE role_permissions.role_id = ?
            `;
            db.query(permissionsQuery, [roleId], function (err3, permissionResults) {

                if (err3) return res.json({ success: false, message: "Login ok but could not fetch permissions: " + err3.message });

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
//
// What it does:
//   - Gets the Node.js version directly from Node itself
//   - Runs SELECT VERSION() in MariaDB to get the DB version
//   - Sends both back as JSON
//   - Also checks if versions meet the minimum required
//
// Minimum versions we defined for this project:
//   Node.js  → 16.0.0
//   MariaDB  → 10.5.0
// ============================================================
app.get("/version", function (req, res) {

    const nodeVersion = process.version;

    const minNodeVersion  = "16.0.0";
    const minMariaVersion = "10.5.0";

    db.query("SELECT VERSION() AS db_version", function (err, results) {

        if (err) {
            return res.json({ success: false, message: "Could not fetch MariaDB version: " + err.message });
        }

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

        const nodeWarning  = isBelowMinimum(nodeVersion,  minNodeVersion);
        const mariaWarning = isBelowMinimum(mariaVersion, minMariaVersion);

        res.json({
            success: true,
            node: {
                version:    nodeVersion,
                minimum:    "v" + minNodeVersion,
                hasWarning: nodeWarning,
            },
            mariadb: {
                version:    mariaVersion,
                minimum:    minMariaVersion,
                hasWarning: mariaWarning,
            }
        });
    });
});


// ============================================================
// Route 6: GET /test
// Open http://localhost:3000/test to confirm server is running
// ============================================================
app.get("/test", function (req, res) {
    res.json({ message: "Server is running! MariaDB connection is active." });
});


// ============================================================
// ── PHASE 8 ROUTES ──────────────────────────────────────────
// ============================================================


// ============================================================
// Route 7: GET /stats
//
// What it does:
//   Returns a summary of the system for the dashboard:
//   - Total number of users in the system
//   - How many users have each role (SuperAdmin / Admin / Viewer)
//   - Total number of permissions defined in the system
//
// Who uses it:
//   - SuperAdmin sees everything
//   - Admin sees only the total user count (we filter on the frontend)
//
// Example response:
//   {
//     success: true,
//     totalUsers: 12,
//     totalPermissions: 7,
//     roleCounts: [
//       { role_name: "SuperAdmin", count: 1 },
//       { role_name: "Admin",      count: 3 },
//       { role_name: "Viewer",     count: 8 }
//     ]
//   }
// ============================================================
app.get("/stats", function (req, res) {

    // Query 1: Count total users
    const totalUsersQuery = "SELECT COUNT(*) AS total FROM users";

    // Query 2: Count how many users have each role
    const roleCountQuery = `
        SELECT roles.role_name, COUNT(user_roles.user_id) AS count
        FROM roles
        LEFT JOIN user_roles ON roles.role_id = user_roles.role_id
        GROUP BY roles.role_name
    `;

    // Query 3: Count total permissions
    const totalPermissionsQuery = "SELECT COUNT(*) AS total FROM permissions";

    // Run query 1 first
    db.query(totalUsersQuery, function (err1, userResults) {
        if (err1) return res.json({ success: false, message: "Could not count users: " + err1.message });

        // Run query 2 next
        db.query(roleCountQuery, function (err2, roleResults) {
            if (err2) return res.json({ success: false, message: "Could not count roles: " + err2.message });

            // Run query 3 last
            db.query(totalPermissionsQuery, function (err3, permResults) {
                if (err3) return res.json({ success: false, message: "Could not count permissions: " + err3.message });

                // Send everything back together
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
//
// What it does:
//   Saves a new message into the messages table in MariaDB.
//
// Who calls it:
//   - Viewer sends a support request → target is Admin
//   - Admin escalates an issue       → target is SuperAdmin
//
// What the frontend sends in the request body:
//   {
//     sender_id:    5,               ← the logged-in user's ID
//     sender_role:  "Viewer",        ← "Viewer" or "Admin"
//     target_role:  "Admin",         ← "Admin" or "SuperAdmin"
//     subject:      "Login Issue",   ← short title
//     message_body: "I cannot..."    ← the actual message text
//   }
// ============================================================
app.post("/sendmessage", function (req, res) {

    const sender_id   = req.body.sender_id;
    const sender_role = req.body.sender_role;
    const target_role = req.body.target_role;
    const subject     = req.body.subject;
    const message_body = req.body.message_body;

    // Make sure all fields were provided
    if (!sender_id || !sender_role || !target_role || !subject || !message_body) {
        return res.json({ success: false, message: "All fields are required." });
    }

    // Only Viewers and Admins are allowed to send messages
    if (sender_role !== "Viewer" && sender_role !== "Admin") {
        return res.json({ success: false, message: "Only Viewers and Admins can send messages." });
    }

    // Insert the message into the database
    const insertQuery = `
        INSERT INTO messages (sender_id, sender_role, target_role, subject, message_body)
        VALUES (?, ?, ?, ?, ?)
    `;

    db.query(insertQuery, [sender_id, sender_role, target_role, subject, message_body], function (err, result) {
        if (err) return res.json({ success: false, message: "Could not send message: " + err.message });

        res.json({ success: true, message: "Message sent successfully." });
    });
});


// ============================================================
// Route 9: GET /inbox
//
// What it does:
//   Fetches messages from the database based on who is asking.
//
// Who gets what:
//   - Viewer    → sees only their OWN sent messages + replies
//                 (so they can check if admin replied to them)
//   - Admin     → sees all messages sent TO Admin
//                 (i.e., Viewer support requests)
//   - SuperAdmin → sees ALL messages in the system
//                 (both Viewer requests and Admin escalations)
//
// How the frontend calls this route:
//   /inbox?role=Viewer&user_id=5
//   /inbox?role=Admin
//   /inbox?role=SuperAdmin
//
// The result also includes the sender's actual name (from the users table)
// so the inbox can show "From: John" instead of just "From: user_id 5"
// ============================================================
app.get("/inbox", function (req, res) {

    const role    = req.query.role;
    const user_id = req.query.user_id;

    var inboxQuery = "";
    var queryParams = [];

    if (role === "Viewer") {
        // Viewer: fetch only messages they personally sent
        if (!user_id) {
            return res.json({ success: false, message: "user_id is required for Viewer inbox." });
        }
        inboxQuery = `
            SELECT messages.*, users.actual_name AS sender_name
            FROM messages
            JOIN users ON messages.sender_id = users.user_id
            WHERE messages.sender_id = ?
            ORDER BY messages.sent_at DESC
        `;
        queryParams = [user_id];

    } else if (role === "Admin") {
        // Admin: fetch all messages where the target is Admin
        inboxQuery = `
            SELECT messages.*, users.actual_name AS sender_name
            FROM messages
            JOIN users ON messages.sender_id = users.user_id
            WHERE messages.target_role = 'Admin'
            ORDER BY messages.sent_at DESC
        `;

    } else if (role === "SuperAdmin") {
        // SuperAdmin: fetch ALL messages in the system
        inboxQuery = `
            SELECT messages.*, users.actual_name AS sender_name
            FROM messages
            JOIN users ON messages.sender_id = users.user_id
            ORDER BY messages.sent_at DESC
        `;

    } else {
        return res.json({ success: false, message: "Invalid role. Use Viewer, Admin, or SuperAdmin." });
    }

    db.query(inboxQuery, queryParams, function (err, results) {
        if (err) return res.json({ success: false, message: "Could not fetch inbox: " + err.message });

        res.json({ success: true, messages: results });
    });
});


// ============================================================
// Route 10: POST /reply
//
// What it does:
//   Saves a reply to an existing message.
//   Updates the row in the messages table with the reply text.
//
// Who calls it:
//   - Admin replies to a Viewer's support request
//   - SuperAdmin replies to a Viewer request or an Admin escalation
//
// What the frontend sends:
//   {
//     message_id:  3,                 ← which message to reply to
//     reply:       "We fixed it!",    ← the reply text
//     replied_by:  2                  ← user_id of whoever is replying
//   }
// ============================================================
app.post("/reply", function (req, res) {

    const message_id = req.body.message_id;
    const reply      = req.body.reply;
    const replied_by = req.body.replied_by;

    // Make sure all fields were provided
    if (!message_id || !reply || !replied_by) {
        return res.json({ success: false, message: "message_id, reply, and replied_by are required." });
    }

    // Update the message row with the reply
    // We also set is_read = 1 so the sender knows it was seen and answered
    const updateQuery = `
        UPDATE messages
        SET reply      = ?,
            replied_by = ?,
            is_read    = 1
        WHERE message_id = ?
    `;

    db.query(updateQuery, [reply, replied_by, message_id], function (err, result) {
        if (err) return res.json({ success: false, message: "Could not save reply: " + err.message });

        // result.affectedRows tells us if any row was actually updated
        if (result.affectedRows === 0) {
            return res.json({ success: false, message: "Message not found. Nothing was updated." });
        }

        res.json({ success: true, message: "Reply saved successfully." });
    });
});


// ============================================================
// Start the server
// ============================================================
app.listen(3000, function () {
    console.log("Server is running at http://localhost:3000");
    console.log("Open http://localhost:3000/login.html to use the app");
});