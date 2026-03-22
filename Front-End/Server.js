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
//   GET  /test        — check if server is running
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

    // Check if username already exists
    const checkQuery = "SELECT * FROM users WHERE username = ?";
    db.query(checkQuery, [username], function (err, results) {

        if (err) return res.json({ success: false, message: "Database error: " + err.message });

        if (results.length > 0) {
            return res.json({ success: false, message: "Username already taken. Try another one." });
        }

        // Insert new user
        const insertQuery = "INSERT INTO users (actual_name, username, password_hash, email, is_active) VALUES (?, ?, ?, ?, 1)";
        db.query(insertQuery, [actual_name, username, password, email], function (err2, result) {

            if (err2) return res.json({ success: false, message: "Could not save user: " + err2.message });

            // Assign Viewer role (role_id = 3) by default
            const newUserId   = result.insertId;
            const roleQuery   = "INSERT INTO user_roles (user_id, role_id) VALUES (?, 3)";
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

    // Step A: Check credentials
    const loginQuery = "SELECT * FROM users WHERE username = ? AND password_hash = ? AND is_active = 1";
    db.query(loginQuery, [username, password], function (err, results) {

        if (err) return res.json({ success: false, message: "Database error: " + err.message });

        if (results.length === 0) {
            return res.json({ success: false, message: "Wrong username or password. Please try again." });
        }

        const user = results[0];

        // Step B: Fetch the user's role
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

            // Step C: Fetch permissions for this role
            const permissionsQuery = `
                SELECT permissions.permission_name 
                FROM role_permissions 
                JOIN permissions ON role_permissions.permission_id = permissions.permission_id 
                WHERE role_permissions.role_id = ?
            `;
            db.query(permissionsQuery, [roleId], function (err3, permissionResults) {

                if (err3) return res.json({ success: false, message: "Login ok but could not fetch permissions: " + err3.message });

                // Convert to a simple array of names
                const permissionsList = permissionResults.map(function (row) {
                    return row.permission_name;
                });

                // Step D: Send everything back
                res.json({
                    success: true,
                    message: "Login successful!",
                    user: {
                        user_id:     user.user_id,
                        actual_name: user.actual_name,
                        username:    user.username,
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
// Used by SuperAdmin and Admin dashboards
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
        LEFT JOIN user_roles  ON users.user_id   = user_roles.user_id
        LEFT JOIN roles       ON user_roles.role_id = roles.role_id
        ORDER BY users.created_at DESC
    `;

    db.query(query, function (err, results) {

        if (err) return res.json({ success: false, message: "Could not fetch users: " + err.message });

        res.json({ success: true, users: results });
    });
});


// ============================================================
// Route 4: POST /changerole
// Updates a user's role in user_roles table
// Only SuperAdmin should call this (enforced on frontend)
// Body: { user_id: 5, role_id: 2 }
// ============================================================
app.post("/changerole", function (req, res) {

    const userId = req.body.user_id;
    const roleId = req.body.role_id;

    if (!userId || !roleId) {
        return res.json({ success: false, message: "user_id and role_id are required." });
    }

    // Update the role in user_roles table
    // If the user already has a role, update it. If not, insert a new row.
    const checkQuery = "SELECT * FROM user_roles WHERE user_id = ?";
    db.query(checkQuery, [userId], function (err, results) {

        if (err) return res.json({ success: false, message: "Database error: " + err.message });

        if (results.length > 0) {
            // User already has a role — update it
            const updateQuery = "UPDATE user_roles SET role_id = ? WHERE user_id = ?";
            db.query(updateQuery, [roleId, userId], function (err2) {
                if (err2) return res.json({ success: false, message: "Could not update role: " + err2.message });
                res.json({ success: true, message: "Role updated successfully." });
            });
        } else {
            // No role yet — insert new row
            const insertQuery = "INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)";
            db.query(insertQuery, [userId, roleId], function (err2) {
                if (err2) return res.json({ success: false, message: "Could not assign role: " + err2.message });
                res.json({ success: true, message: "Role assigned successfully." });
            });
        }
    });
});


// ============================================================
// Route 5: GET /test
// Open http://localhost:3000/test to confirm server is running
// ============================================================
app.get("/test", function (req, res) {
    res.json({ message: "Server is running! MariaDB connection is active." });
});


// ============================================================
// Start the server
// ============================================================
app.listen(3000, function () {
    console.log("Server is running at http://localhost:3000");
    console.log("Open http://localhost:3000/login.html to use the app");
});