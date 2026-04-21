#!/bin/bash
#
# End-to-end smoke test for the *built Docker image*. This is the test that
# gates every push to Docker Hub — if any step fails, don't push.
#
# Flow mirrors what a real user does:
#   1. Pull / use the image
#   2. Start a container with just /config and the Docker socket mounted
#   3. Hit /health from outside → expect 200
#   4. Hit / with no session → expect 303 to /setup
#   5. GET /setup → expect the setup form
#   6. POST /setup with admin creds → expect 303 to /
#   7. GET / with the session cookie → expect 200, dashboard renders
#   8. GET /settings → expect 200, settings page
#   9. Save settings → expect 303 back
#  10. Logout → session gone → expect 303 to /login
#  11. Restart container → session is gone (in-memory only) but admin persists
#  12. Hit / → expect 303 to /login (NOT /setup — admin still in DB)

set -e
cd "$(dirname "$0")/.."

IMAGE="${IMAGE:-tehrobot/patch-pulse:local-smoke}"
PORT=38921
NAME="patchpulse-smoke-$$"
TMP=$(mktemp -d)
trap 'docker rm -f "$NAME" >/dev/null 2>&1 || true; rm -rf "$TMP"' EXIT

echo "==> Building image (as $IMAGE)..."
docker build --target runtime -t "$IMAGE" -q . | head -1

echo "==> Starting container (name=$NAME port=$PORT config=$TMP)..."
docker run -d --name "$NAME" \
    -v "$TMP:/config" \
    -v /var/run/docker.sock:/var/run/docker.sock:ro \
    -p "127.0.0.1:$PORT:8921" \
    "$IMAGE" >/dev/null
echo "  waiting for /health..."
for i in 1 2 3 4 5 6 7 8 9 10; do
    CODE=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$PORT/health" || true)
    [ "$CODE" = "200" ] && break
    sleep 1
done
if [ "$CODE" != "200" ]; then
    echo "FAIL: /health never returned 200 within 10s (last=$CODE)"
    docker logs "$NAME" 2>&1 | head -40
    exit 1
fi

pass() { echo "  ✓ $1"; }
fail() { echo "  ✗ $1"; docker logs "$NAME" 2>&1 | tail -20; exit 1; }

echo "==> 1. /health (public, must work pre-admin)"
CODE=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$PORT/health")
[ "$CODE" = "200" ] && pass "/health → 200" || fail "/health → $CODE"

echo "==> 2. / with no admin → 303 to /setup"
LOC=$(curl -s -o /dev/null -w '%{redirect_url}' "http://127.0.0.1:$PORT/")
[[ "$LOC" == *"/setup" ]] && pass "/ → /setup" || fail "/ → $LOC (expected /setup)"

echo "==> 3. /setup form loads"
BODY=$(curl -s "http://127.0.0.1:$PORT/setup")
echo "$BODY" | grep -q 'Welcome to PatchPulse' && pass "/setup shows wizard" || fail "/setup missing wizard heading"

echo "==> 4. POST /setup creates admin + auto-logs in"
COOKIE="$TMP/cookie.txt"
LOC=$(curl -s -c "$COOKIE" -o /dev/null -w '%{redirect_url}' \
    -d 'username=admin&password=testpass1&confirm=testpass1' \
    "http://127.0.0.1:$PORT/setup")
[[ "$LOC" == *"/" && "$LOC" != *"/setup" && "$LOC" != *"/login" ]] \
    && pass "POST /setup → $LOC" || fail "POST /setup → $LOC"

echo "==> 5. Dashboard renders with session"
BODY=$(curl -s -b "$COOKIE" "http://127.0.0.1:$PORT/")
echo "$BODY" | grep -q '<h1>Containers</h1>' && pass "dashboard has Containers heading" || fail "dashboard missing heading"

echo "==> 6. Settings page loads"
BODY=$(curl -s -b "$COOKIE" "http://127.0.0.1:$PORT/settings")
echo "$BODY" | grep -q '<legend>Polling</legend>' && pass "settings has Polling fieldset" || fail "settings missing fieldset"

echo "==> 7. POST /settings persists"
LOC=$(curl -s -b "$COOKIE" -o /dev/null -w '%{redirect_url}' \
    -d 'poll_cadence_hours=12&github_token=test&apprise_urls=ntfy%3A%2F%2Ft&notify_on_new_cve=on' \
    "http://127.0.0.1:$PORT/settings")
[[ "$LOC" == *"saved=1" ]] && pass "settings save → $LOC" || fail "settings save → $LOC"

echo "==> 7b. /container/unknown returns 404 (detail page wired)"
CODE=$(curl -s -b "$COOKIE" -o /dev/null -w '%{http_code}' "http://127.0.0.1:$PORT/container/unknown-id")
[ "$CODE" = "404" ] && pass "/container/unknown → 404" || fail "/container/unknown → $CODE (expected 404)"

echo "==> 7c. POST /check triggers poll + redirects to /?checked=1"
LOC=$(curl -s -b "$COOKIE" -o /dev/null -w '%{redirect_url}' -X POST "http://127.0.0.1:$PORT/check")
[[ "$LOC" == *"/?checked=1" ]] && pass "/check → $LOC" || fail "/check → $LOC (expected /?checked=1)"

echo "==> 7d. Force check button renders on dashboard"
BODY=$(curl -s -b "$COOKIE" "http://127.0.0.1:$PORT/")
echo "$BODY" | grep -q 'Force check now' && pass "dashboard has Force check button" || fail "dashboard missing Force check button"

echo "==> 7e. POST /container/.../update returns 403 when update action is disabled"
CODE=$(curl -s -b "$COOKIE" -o /dev/null -w '%{http_code}' -X POST "http://127.0.0.1:$PORT/container/any-id/update")
[ "$CODE" = "403" ] && pass "/container/any-id/update → 403 (disabled)" || fail "/container/any-id/update → $CODE (expected 403)"

echo "==> 7f. GET /ignored renders (authenticated)"
BODY=$(curl -s -b "$COOKIE" "http://127.0.0.1:$PORT/ignored")
echo "$BODY" | grep -q '>Ignored containers<' && pass "/ignored renders" || fail "/ignored missing heading"

echo "==> 7h. GET /export/cves.csv returns CSV (header row present, even with no scans)"
HDR=$(curl -s -b "$COOKIE" -D - -o "$TMP/cves.csv" "http://127.0.0.1:$PORT/export/cves.csv" | tr -d '\r')
echo "$HDR" | grep -qi '^Content-Type: text/csv' && pass "/export/cves.csv Content-Type is text/csv" || fail "/export/cves.csv missing Content-Type"
echo "$HDR" | grep -qi '^Content-Disposition: attachment' && pass "/export/cves.csv is download" || fail "/export/cves.csv not an attachment"
head -1 "$TMP/cves.csv" | grep -q 'container_name,image,tag,compose_project,cve_id' && pass "CSV has header row" || fail "CSV header missing"

echo "==> 7i. Export CVEs button renders on dashboard"
BODY=$(curl -s -b "$COOKIE" "http://127.0.0.1:$PORT/")
echo "$BODY" | grep -q 'Export CVEs' && pass "dashboard has Export CVEs link" || fail "dashboard missing Export CVEs link"

echo "==> 7g. POST /container/unknown/ignore redirects back to detail page"
LOC=$(curl -s -b "$COOKIE" -o /dev/null -w '%{redirect_url}' -X POST "http://127.0.0.1:$PORT/container/unknown-id/ignore")
[[ "$LOC" == *"/container/unknown-id" ]] && pass "/container/unknown/ignore → $LOC" || fail "/container/unknown/ignore → $LOC"

echo "==> 8. Logout clears session"
curl -s -b "$COOKIE" -c "$COOKIE" -o /dev/null -X POST "http://127.0.0.1:$PORT/logout"

echo "==> 9. / without session, admin exists → 303 to /login (not /setup)"
LOC=$(curl -s -o /dev/null -w '%{redirect_url}' "http://127.0.0.1:$PORT/")
[[ "$LOC" == *"/login" ]] && pass "/ → /login" || fail "/ → $LOC (expected /login)"

echo "==> 10. Restart the container; /health comes back + admin still in DB"
docker restart "$NAME" >/dev/null
for i in 1 2 3 4 5 6 7 8 9 10; do
    CODE=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$PORT/health" || true)
    [ "$CODE" = "200" ] && break
    sleep 1
done
[ "$CODE" = "200" ] && pass "/health post-restart → 200" || fail "/health post-restart → $CODE"
LOC=$(curl -s -o /dev/null -w '%{redirect_url}' "http://127.0.0.1:$PORT/")
[[ "$LOC" == *"/login" ]] && pass "/ post-restart → /login (admin persisted)" || fail "/ post-restart → $LOC"

echo
echo "==> ALL CHECKS PASSED"
