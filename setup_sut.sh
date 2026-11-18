#!/usr/bin/env bash
# Automated Step 4 Setup for WP-SecOps Research SUTs (wp1 - wp10)
# Run this on the VPS in the same directory as docker-compose.yml.

set -euo pipefail

ADMIN_PASS="WpSecOpsLab!2026"
ADMIN_EMAIL="lab@wpsecops.local"

wait_for_wp() {
  local port="$1"
  local max_tries=30
  local i=1
  while [ "$i" -le "$max_tries" ]; do
    if curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:${port}/wp-admin/install.php" | grep -qE "^(200|302)$"; then
      return 0
    fi
    sleep 2
    i=$((i + 1))
  done
  return 1
}

install_wp() {
  local idx="$1"
  local port="$2"
  local admin_user="$3"

  local page
  page=$(curl -sL "http://127.0.0.1:${port}/wp-admin/install.php")
  if echo "$page" | grep -qiE "Already Installed|Sudah Terpasang"; then
    echo "  [wp${idx}] WordPress already installed on port ${port}."
    return 0
  fi

  echo "  [wp${idx}] Running WordPress install wizard on port ${port} (user: ${admin_user})..."
  curl -sS -o /dev/null -X POST "http://127.0.0.1:${port}/wp-admin/install.php?step=2" \
    --data-urlencode "weblog_title=WP-SecOps Target wp${idx}" \
    --data-urlencode "user_name=${admin_user}" \
    --data-urlencode "admin_password=${ADMIN_PASS}" \
    --data-urlencode "admin_password2=${ADMIN_PASS}" \
    --data-urlencode "pw_weak=1" \
    --data-urlencode "admin_email=${ADMIN_EMAIL}" \
    --data-urlencode "blog_public=1" \
    --data-urlencode "Submit=Install WordPress"
}

install_plugin_zip() {
  local svc="$1"
  local slug="$2"
  local ver="$3"
  local url="https://downloads.wordpress.org/plugin/${slug}.${ver}.zip"

  echo "  [${svc}] Installing & activating plugin ${slug} v${ver}..."
  docker compose exec -T "$svc" bash -c "
    set -e
    curl -fsSL '${url}' -o /tmp/${slug}.zip
    php -r '\$z = new ZipArchive(); if (\$z->open(\"/tmp/${slug}.zip\") === TRUE) { \$z->extractTo(\"/var/www/html/wp-content/plugins/\"); \$z->close(); } else { exit(1); }'
    rm -f /tmp/${slug}.zip
    chown -R www-data:www-data /var/www/html/wp-content/plugins/${slug}
    php -r '
      require \"/var/www/html/wp-load.php\";
      require_once \"/var/www/html/wp-admin/includes/plugin.php\";
      \$slug = \"${slug}\";
      foreach (get_plugins(\"/\" . \$slug) as \$file => \$data) {
        \$path = \$slug . \"/\" . \$file;
        if (!is_plugin_active(\$path)) {
          \$res = activate_plugin(\$path);
          if (is_wp_error(\$res)) { fwrite(STDERR, \$res->get_error_message() . \"\n\"); exit(1); }
        }
      }
    '
  " || echo "  [${svc}] WARNING: Failed to install/activate ${slug}.${ver}.zip (skipping)"
}

configure_scenario() {
  local idx="$1"
  local svc="wp${idx}"

  case "$idx" in
    1)
      # Grup A: WP 4.6 - vulnerable/outdated plugin + readme.html intact
      install_plugin_zip "$svc" "contact-form-7" "5.1.6"
      install_plugin_zip "$svc" "wp-file-manager" "6.0"
      ;;
    2)
      # Grup A: WP 4.9 - directory listing enabled + user 'admin' (set during install)
      echo "  [${svc}] Enabling directory listing on wp-content/uploads..."
      docker compose exec -T "$svc" bash -c "
        mkdir -p /var/www/html/wp-content/uploads
        echo 'Options +Indexes' > /var/www/html/wp-content/uploads/.htaccess
        chown -R www-data:www-data /var/www/html/wp-content/uploads
      "
      ;;
    3)
      # Grup A: WP 5.0 - dummy backup file wp-config.php.bak
      echo "  [${svc}] Creating dummy wp-config.php.bak..."
      docker compose exec -T "$svc" bash -c "
        cp /var/www/html/wp-config.php /var/www/html/wp-config.php.bak
        chown www-data:www-data /var/www/html/wp-config.php.bak
      "
      ;;
    4)
      # Grup B: WP 5.4 - 2 outdated popular plugins
      install_plugin_zip "$svc" "contact-form-7" "5.3.2"
      install_plugin_zip "$svc" "classic-editor" "1.5"
      ;;
    5)
      # Grup B: WP 5.8 - xmlrpc.php & REST API users open (WP default)
      echo "  [${svc}] Keeping xmlrpc.php and REST API users open (default)."
      ;;
    6)
      # Grup B: WP 6.0 - mixed active plugins + default theme
      install_plugin_zip "$svc" "contact-form-7" "5.6.4"
      ;;
    7)
      # Grup B: WP 6.2 - partially hardened (remove readme.html & license.txt)
      echo "  [${svc}] Removing readme.html and license.txt..."
      docker compose exec -T "$svc" rm -f /var/www/html/readme.html /var/www/html/license.txt
      ;;
    8)
      # Grup C: WP 6.4 - standard modern baseline
      echo "  [${svc}] Keeping standard modern baseline."
      ;;
    9)
      # Grup C: WP 6.5 - security headers added
      echo "  [${svc}] Enabling mod_headers and adding security headers..."
      docker compose exec -T "$svc" bash -c "
        a2enmod headers >/dev/null 2>&1 || true
        cat <<'EOF' > /var/www/html/.htaccess
<IfModule mod_headers.c>
  Header always set X-Content-Type-Options \"nosniff\"
  Header always set X-Frame-Options \"SAMEORIGIN\"
  Header always set Referrer-Policy \"strict-origin-when-cross-origin\"
  Header always set Permissions-Policy \"geolocation=(), microphone=(), camera=()\"
</IfModule>
EOF
        chown www-data:www-data /var/www/html/.htaccess
        apache2ctl graceful >/dev/null 2>&1 || true
      "
      ;;
    10)
      # Grup C: Latest - hardened baseline (control)
      echo "  [${svc}] Applying hardened baseline..."
      docker compose exec -T "$svc" bash -c "
        rm -f /var/www/html/readme.html /var/www/html/license.txt
        a2enmod headers >/dev/null 2>&1 || true
        cat <<'EOF' > /var/www/html/.htaccess
Options -Indexes

<Files \"xmlrpc.php\">
  Require all denied
</Files>

<FilesMatch \"^(\\.|wp-config\\.php|readme\\.html|license\\.txt)\">
  Require all denied
</FilesMatch>

<IfModule mod_headers.c>
  Header always set X-Content-Type-Options \"nosniff\"
  Header always set X-Frame-Options \"SAMEORIGIN\"
  Header always set Referrer-Policy \"strict-origin-when-cross-origin\"
  Header always set Content-Security-Policy \"default-src 'self' 'unsafe-inline' 'unsafe-eval' data:\"
  Header always set Permissions-Policy \"geolocation=(), microphone=(), camera=()\"
</IfModule>
EOF
        chown www-data:www-data /var/www/html/.htaccess
        if ! grep -q \"DISALLOW_FILE_EDIT\" /var/www/html/wp-config.php; then
          sed -i \"/That's all, stop editing/i define('DISALLOW_FILE_EDIT', true);\" /var/www/html/wp-config.php
        fi
        apache2ctl graceful >/dev/null 2>&1 || true
      "
      ;;
  esac
}

echo "=== WP-SecOps SUT Automated Setup ==="
running_services=$(docker compose ps --services --filter "status=running" 2>/dev/null || true)

for idx in $(seq 1 10); do
  svc="wp${idx}"
  port=$((8080 + idx))

  if ! echo "$running_services" | grep -qx "$svc"; then
    echo "[${svc}] Not running, skipping."
    continue
  fi

  echo "[${svc}] Waiting for HTTP on port ${port}..."
  if ! wait_for_wp "$port"; then
    echo "[${svc}] ERROR: Timed out waiting for port ${port}."
    continue
  fi

  if [ "$idx" -eq 2 ]; then
    admin_user="admin"
  else
    admin_user="wpsecadmin"
  fi

  install_wp "$idx" "$port" "$admin_user"
  configure_scenario "$idx"
done

echo ""
echo "=== Done! ==="
echo "Admin password for all installed targets: ${ADMIN_PASS}"
echo "wp2 username: admin | all other targets: wpsecadmin"
