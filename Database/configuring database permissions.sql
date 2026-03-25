INSERT INTO roles (role_name, description) VALUES
                                               ('SuperAdmin', 'Has all permissions automatically - full system control'),
                                               ('Admin', 'Can manage users and view reports'),
                                               ('Viewer', 'Can only view data, no editing allowed');

INSERT INTO permissions (permission_name, description) VALUES
                                                           ('view_dashboard', 'Can view the main dashboard'),
                                                           ('view_users', 'Can view list of all users'),
                                                           ('edit_users', 'Can create/edit/delete users'),
                                                           ('view_reports', 'Can view reports'),
                                                           ('edit_roles', 'Can assign/change user roles'),
                                                           ('view_system_info', 'Can view system version information'),
                                                           ('full_access', 'Complete system access - only for SuperAdmin');

INSERT INTO role_permissions (role_id, permission_id)
SELECT 1, permission_id FROM permissions;

INSERT INTO role_permissions (role_id, permission_id) VALUES
                                                          (2, 1),
                                                          (2, 2),
                                                          (2, 3),
                                                          (2, 4);

INSERT INTO role_permissions (role_id, permission_id) VALUES
                                                          (3, 1),
                                                          (3, 2);

SELECT * FROM roles;
SELECT * FROM permissions;

SELECT r.role_name, p.permission_name
FROM role_permissions rp
         JOIN roles r ON rp.role_id = r.role_id
         JOIN permissions p ON rp.permission_id = p.permission_id
ORDER BY r.role_name;
