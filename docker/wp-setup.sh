#!/bin/sh
set -e

echo "[*] Waiting for WordPress files..."
until [ -f /var/www/html/wp-includes/version.php ]; do
    sleep 1
done

echo "[*] Waiting for database..."
MAX_TRIES=10
TRIES=0
until wp db check --quiet 2>/dev/null; do
    TRIES=$((TRIES + 1))
    if [ "$TRIES" -ge "$MAX_TRIES" ]; then
        echo "[!] DB check failed after ${MAX_TRIES} attempts, proceeding anyway (DB likely ready via healthcheck)..."
        break
    fi
    sleep 1
done

if wp core is-installed 2>/dev/null; then
    echo "[+] WordPress already installed"
else
    echo "[*] Installing WordPress..."
    wp core install \
        --url="http://localhost:${WP_PORT:-8777}" \
        --title="Exploit Lab" \
        --admin_user=admin \
        --admin_password=admin \
        --admin_email=admin@lab.local \
        --skip-email
fi

for ROLE in subscriber contributor author editor; do
    echo "[*] Creating ${ROLE} user..."
    wp user create "${ROLE}" "${ROLE}@lab.local" \
        --user_pass="${ROLE}" \
        --role="${ROLE}" 2>/dev/null || true
done

PLUGIN_SLUG="${PLUGIN_SLUG:-}"
if [ -d "/var/www/html/wp-content/plugins/${PLUGIN_SLUG}" ]; then
    echo "[+] Plugin '${PLUGIN_SLUG}' already present"
else
    if [ -d "/mnt/plugin-src" ]; then
        echo "[*] Copying plugin from mounted source..."
        cp -r /mnt/plugin-src "/var/www/html/wp-content/plugins/${PLUGIN_SLUG}"
    fi
fi

PLUGIN_DIR="/var/www/html/wp-content/plugins/${PLUGIN_SLUG}"
if [ -n "${PLUGIN_SLUG}" ] && [ -d "${PLUGIN_DIR}" ]; then
    echo "[*] Patching PHP 8 compatibility (curly brace array access)..."
    find "${PLUGIN_DIR}" -name '*.php' -exec \
        sed -i 's/\(\$[a-zA-Z_][a-zA-Z0-9_]*\){\([0-9]\+\)}/\1[\2]/g' {} +
fi

if [ -n "${PLUGIN_SLUG}" ]; then
    echo "[*] Activating plugin: ${PLUGIN_SLUG}"
    ACTIVATE_OUTPUT=$(wp plugin activate "${PLUGIN_SLUG}" 2>&1) || true
    echo "${ACTIVATE_OUTPUT}"
    if echo "${ACTIVATE_OUTPUT}" | grep -q "Success"; then
        echo "[+] Plugin activated successfully"
    else
        echo "[!] Plugin activation may have failed — check output above"
    fi
fi

echo "[*] Flushing rewrite rules..."
wp rewrite flush 2>/dev/null || true

echo "[+] WordPress setup complete!"
echo "[+] Admin:       admin / admin"
echo "[+] Roles:       subscriber / contributor / author / editor (user=pass)"
echo "[+] URL:         http://localhost:${WP_PORT:-8777}"
