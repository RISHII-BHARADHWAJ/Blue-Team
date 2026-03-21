<?php
echo "ADMIN_HASH=" . password_hash("ChangeMe123!", PASSWORD_ARGON2ID) . "\n";
echo "ANALYST_HASH=" . password_hash("kali", PASSWORD_ARGON2ID) . "\n";
?>
