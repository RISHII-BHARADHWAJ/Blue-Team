<?php
include 'includes/config.php';
$sql = file_get_contents('database.sql');
try {
    $pdo->exec($sql);
    echo "Database Reset Successful";
} catch (PDOException $e) {
    echo "Failed: " . $e->getMessage();
}
?>
