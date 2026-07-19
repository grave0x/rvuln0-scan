/// Built-in wordlist of common API and web paths.
pub const WORDLIST: &[&str] = &[
    // Admin / management
    "admin", "admin/", "admin/login", "admin/dashboard", "admin/config", "admin/settings",
    "administrator", "admin.php", "wp-admin",
    // API endpoints
    "api", "api/", "api/v1", "api/v2", "api/v3", "api/users", "api/login", "api/auth",
    "api/health", "api/status", "api/config", "api/admin", "api/metrics",
    "graphql", "graphiql", "swagger", "swagger.json", "api-docs", "openapi.json",
    // Config / secrets
    ".env", ".env.example", ".git/config", ".gitignore", ".git/HEAD", ".htaccess",
    "robots.txt", "sitemap.xml", "crossdomain.xml", "security.txt",
    "config.json", "config.yaml", "config.yml", "settings.json", "settings.py",
    // Debug / info
    "debug", "info", "status", "health", "healthz", "metrics", "version",
    "phpinfo.php", "info.php", "test.php", "server-status",
    // Common paths
    "login", "logout", "register", "signup", "forgot", "reset",
    "index.html", "index.php", "index.htm", "default.aspx",
    "static/", "assets/", "public/", "uploads/", "downloads/",
    "backup", "backups/", "dump", "export", "import",
    // Source control
    ".svn/", ".DS_Store", "CVS/", "Thumbs.db",
    // Web shells / malware patterns
    "shell.php", "cmd.php", "eval.php", "c99.php", "r57.php",
    // Cloud / hosting
    "aws", "aws.json", ".aws/", "credentials",
    // Cache / storage
    "cache/", "logs/", "log/", "error_log", "debug_log",
];
