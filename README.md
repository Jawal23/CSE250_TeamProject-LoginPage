# CSE250 — Admin Login System with RBAC

> **Course:** CSE250 Database Management Systems | **Semester:** Winter 2026  
> **University:** Ahmedabad University (SEAS) | **Faculty:** Susanta Tewari  
> **Team:** Yug · Jawal · Kamya

---

## What is this project?

This project is a **Role-Based Access Control (RBAC) Login System** built as part of our CSE250 DBMS course. The idea is simple — users can register themselves, log in, and based on their assigned role (SuperAdmin, Admin, or Viewer), they will see a different dashboard with different permissions.

Everything runs **locally** using **IntelliJ** as the IDE. This is not a hosted/live project.

---

## Tech Stack

| Layer      | Technology          |
|------------|---------------------|
| Database   | MariaDB             |
| Backend    | Java                |
| Frontend   | HTML + CSS          |
| IDE        | IntelliJ (JetBrains)|
| Version Control | GitHub         |

---

## Database Structure (5 Tables)

| Table             | Purpose                                              |
|-------------------|------------------------------------------------------|
| `users`           | Stores registered users (username, password hash, etc.) |
| `roles`           | Stores roles: SuperAdmin, Admin, Viewer              |
| `permissions`     | Stores individual permission names                   |
| `role_permissions`| Links which permissions belong to which role         |
| `user_roles`      | Links which role is assigned to which user           |

---

## Current Progress

### Phase 1 — Project Planning & Database Design
On schedule

### Phase 2 — Backend: Java Server & MariaDB Connection

### Phase 3 — RBAC: Roles & Permissions Logic

### Phase 4 — Frontend: Web Pages (HTML + CSS)

### Phase 5 — Version Check Feature

### Phase 6 — Testing & Final Polish

---

## Note

This is just an overview about the project and detailed information about it can be obtained from the Project Wiki

### The Project Wiki contains
- Project Details
- Database Design
- Project Phases

---
