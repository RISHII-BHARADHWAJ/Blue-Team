#!/bin/sh
# Unit-level guard contract checks; run inside the PHP web container.
set -eu

valid=$(php -r 'session_start(); $_SESSION["csrf_token"]="known"; $_SERVER["HTTP_X_CSRF_TOKEN"]="known"; require "includes/soar/SoarCsrf.php"; SoarCsrf::enforce(["actor"=>"analyst"]); echo "allowed";')
[ "$valid" = "allowed" ] || { echo "Valid session token was rejected" >&2; exit 1; }

invalid=$(php -r 'session_start(); $_SESSION["csrf_token"]="known"; $_SERVER["HTTP_X_CSRF_TOKEN"]="wrong"; require "includes/soar/SoarCsrf.php"; SoarCsrf::enforce(["actor"=>"analyst"]); echo "allowed";')
case "$invalid" in
  *csrf_verification_failed*) ;;
  *) echo "Invalid session token was accepted" >&2; exit 1 ;;
esac

missing=$(php -r 'session_start(); $_SESSION["csrf_token"]="known"; require "includes/soar/SoarCsrf.php"; SoarCsrf::enforce(["actor"=>"analyst"]); echo "allowed";')
case "$missing" in
  *csrf_verification_failed*) ;;
  *) echo "Missing session token was accepted" >&2; exit 1 ;;
esac

automation=$(php -r 'require "includes/soar/SoarCsrf.php"; SoarCsrf::enforce(["actor"=>"api_automation","auth_method"=>"bearer"]); echo "allowed";')
[ "$automation" = "allowed" ] || { echo "Verified API automation was rejected" >&2; exit 1; }

spoofed=$(php -r 'session_start(); $_SESSION["csrf_token"]="known"; require "includes/soar/SoarCsrf.php"; SoarCsrf::enforce(["actor"=>"api_automation","auth_method"=>"session"]); echo "allowed";')
case "$spoofed" in
  *csrf_verification_failed*) ;;
  *) echo "Session username spoof bypassed CSRF" >&2; exit 1 ;;
esac

unknown=$(php -r 'session_start(); require "includes/soar/SoarCsrf.php"; SoarCsrf::enforce(["actor"=>"api_automation"]); echo "allowed";')
case "$unknown" in
  *csrf_verification_failed*) ;;
  *) echo "Missing auth provenance bypassed CSRF" >&2; exit 1 ;;
esac

echo "SOAR CSRF guard checks passed"
