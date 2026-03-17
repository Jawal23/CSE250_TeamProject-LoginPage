// ============================================================
// CSE250 - Team Project: Admin Login System with RBAC
// Team: Jawal, Yug, Kamya
// File: Server.js
// What this file does:
//   - Connects Node.js to our MariaDB database
//   - Handles /register (new user signup)
//   - Handles /login (check username + password + returns role AND permissions)
//   - Runs a local server on port 3000
// ============================================================

// Step 1: Import the packages we installed
const express = require("express");
const mysql = require("mysql2");
const path = require("path");

// Step 2: Create the Express app (this is our server)
const app = express();

// This line lets our server read JSON data sent from the frontend
app.use(express.json());

// This line lets our server serve HTML files from the same folder
app.use(express.static(path.join(__dirname)));


// ============================================================
// Step 3: Connect to MariaDB
// ============================================================
const db = mysql.createConnection({
    host: "localhost",                  // MariaDB is running on your own computer
    user: "root",                       // Your MariaDB username (usually 'root')
    password: "cse250",                 // Your MariaDB password
    database: "admin_login_system",     // The name of the database you created
});

// Try to connect and show a message
db.connect(function (err) {
    if (err) {
        console.log("Could not connect to MariaDB:", err.message);
        return;
    }
    console.log("Connected to MariaDB successfully!");
});


// ============================================================
// Route 1: /register
// What it does: Saves a new user into the 'users' table
// ============================================================
app.post("/register", function (req, res) {

    const username = req.body.username;
    const password = req.body.password;
    const actual_name = req.body.actual_name;
    const email = req.body.email;

    // Basic check — make sure nothing is empty
    if (!username || !password || !actual_name || !email) {
        return res.json({ success: false, message: "All fields are required." });
    }

    // Check if username already exists in the database
    const checkQuery = "SELECT * FROM users WHERE username = ?";
    db.query(checkQuery, [username], function (err, results) {

        if (err) {
            return res.json({ success: false, message: "Database error: " + err.message });
        }

        // If username already taken, stop here
        if (results.length > 0) {
            return res.json({ success: false, message: "Username already taken. Try another one." });
        }

        // Username is free — insert the new user
        const insertQuery = "INSERT INTO users (actual_name, username, password_hash, email, is_active) VALUES (?, ?, ?, ?, 1)";
        db.query(insertQuery, [actual_name, username, password, email], function (err2, result) {

            if (err2) {
                return res.json({ success: false, message: "Could not save user: " + err2.message });
            }

            // User saved! Now assign them the default role (Viewer = role_id 3)
            const newUserId = result.insertId;
            const roleQuery = "INSERT INTO user_roles (user_id, role_id) VALUES (?, 3)";
            db.query(roleQuery, [newUserId], function (err3) {

                if (err3) {
                    return res.json({ success: false, message: "User created but could not assign role: " + err3.message });
                }

                res.json({ success: true, message: "Account created successfully! You can now login." });
            });
        });
    });
});


// ============================================================
// Route 2: /login
// What it does: Checks username + password, returns user's role AND permissions
//
// WHAT CHANGED FROM BEFORE:
//   Before: only fetched the role name after login
//   Now:    also fetches the list of permissions for that role
//           and returns everything together in one response
// ============================================================
app.post("/login", function (req, res) {

    const username = req.body.username;
    const password = req.body.password;

    // Basic check
    if (!username || !password) {
        return res.json({ success: false, message: "Please enter both username and password." });
    }

    // Step A: Check if username + password match in the database
    const loginQuery = "SELECT * FROM users WHERE username = ? AND password_hash = ? AND is_active = 1";
    db.query(loginQuery, [username, password], function (err, results) {

        if (err) {
            return res.json({ success: false, message: "Database error: " + err.message });
        }

        // If no match found — wrong credentials
        if (results.length === 0) {
            return res.json({ success: false, message: "Wrong username or password. Please try again." });
        }

        const user = results[0];

        // Step B: Fetch this user's role from user_roles + roles tables
        const roleQuery = `
            SELECT roles.role_id, roles.role_name 
            FROM user_roles 
            JOIN roles ON user_roles.role_id = roles.role_id 
            WHERE user_roles.user_id = ?
        `;
        db.query(roleQuery, [user.user_id], function (err2, roleResults) {

            if (err2) {
                return res.json({ success: false, message: "Login ok but could not fetch role: " + err2.message });
            }

            // Default to Viewer if no role found
            const roleName = roleResults.length > 0 ? roleResults[0].role_name : "Viewer";
            const roleId = roleResults.length > 0 ? roleResults[0].role_id : 3;

            // Step C: Fetch all permissions linked to this role
            // This is the NEW part we added for Phase 3
            const permissionsQuery = `
                SELECT permissions.permission_name 
                FROM role_permissions 
                JOIN permissions ON role_permissions.permission_id = permissions.permission_id 
                WHERE role_permissions.role_id = ?
            `;
            db.query(permissionsQuery, [roleId], function (err3, permissionResults) {

                if (err3) {
                    return res.json({ success: false, message: "Login ok but could not fetch permissions: " + err3.message });
                }

                // Convert the results into a simple array of permission names
                // Example: ["view_dashboard", "view_users", "edit_users"]
                const permissionsList = permissionResults.map(function (row) {
                    return row.permission_name;
                });

                // Step D: Send everything back to the frontend in one response
                res.json({
                    success: true,
                    message: "Login successful!",
                    user: {
                        user_id: user.user_id,
                        actual_name: user.actual_name,
                        username: user.username,
                        role: roleName,
                        permissions: permissionsList,
                        // Example of what the frontend will receive:
                        // role: "SuperAdmin"
                        // permissions: ["view_dashboard", "view_users", "edit_users", "view_reports", "edit_roles", "view_system_info", "full_access"]
                    }
                });
            });
        });
    });
});


// ============================================================
// Route 3: /test (just to confirm server is working)
// Open http://localhost:3000/test in your browser to check
// ============================================================
app.get("/test", function (req, res) {
    res.json({ message: "Server is running! MariaDB connection is active." });
});


// ============================================================
// Start the server on port 3000
// ============================================================
app.listen(3000, function () {
    console.log("Server is running at http://localhost:3000");
    console.log("Test it by opening http://localhost:3000/test in your browser");
});