<?php
declare(strict_types=1);
if (PHP_SAPI !== 'cli' || getenv('SOAR_INTEGRATION_TEST') !== '1' || getenv('DB_HOST') !== 'db') {
    fwrite(STDERR, "Refusing to run outside disposable Compose CI.\n"); exit(2);
}
require_once __DIR__ . '/../includes/db.php';
require_once __DIR__ . '/../includes/soar/IncidentManager.php';
require_once __DIR__ . '/../includes/soar/CaseNoteService.php';
function noteCheck(bool $ok, string $label): void {
    if (!$ok) throw new RuntimeException('FAIL: ' . $label);
    echo "PASS: $label\n";
}
$pdo->beginTransaction();
try {
    $stmt = $pdo->prepare("INSERT INTO users (username, password, role) VALUES (?, ?, 'user')");
    $username = 'notes-ci-' . bin2hex(random_bytes(6));
    $stmt->execute([$username, password_hash(bin2hex(random_bytes(16)), PASSWORD_DEFAULT)]);
    $authorId = (int)$pdo->lastInsertId();
    $incident = (new IncidentManager($pdo))->createIncident(['title'=>'Case-note integration fixture', 'severity'=>'INFO']);
    $id = (int)$incident['id'];
    $service = new CaseNoteService($pdo);
    $text = "Original <script>alert(1)</script>\nSecond line: café";
    $result = $service->add($id, $authorId, $text);
    $notes = $service->list($id);
    noteCheck($notes['total'] === 1 && $notes['notes'][0]['note_text'] === $text, 'note text preserved exactly');
    noteCheck((int)$notes['notes'][0]['author_id'] === $authorId && $notes['notes'][0]['author'] === $username, 'note linked to verified account');
    $stmt = $pdo->prepare("SELECT details FROM incident_timeline WHERE incident_id = ? AND event_type = 'NOTE_ADDED'");
    $stmt->execute([$id]);
    noteCheck(json_decode($stmt->fetchColumn(), true)['note_id'] === $result['id'], 'timeline references saved note');
    $stmt = $pdo->prepare("SELECT details FROM audit_log WHERE action = 'add_case_note' AND target = ?");
    $stmt->execute(['incident:' . $id]);
    noteCheck(json_decode($stmt->fetchColumn(), true)['author_id'] === $authorId, 'audit records author and note reference');
    foreach (['', '   ', str_repeat('a', 10001)] as $invalid) {
        $rejected = false;
        try { $service->add($id, $authorId, $invalid); } catch (LengthException $e) { $rejected = true; }
        noteCheck($rejected, 'blank or oversized note rejected');
    }
    $rejected = false;
    try { $service->add($id, 0, 'Do not impersonate user 1'); } catch (DomainException $e) { $rejected = true; }
    noteCheck($rejected && $service->list($id)['total'] === 1 && $pdo->inTransaction(), 'unknown author leaves no partial note and keeps outer transaction');
    $rejected = false;
    try { $service->add(0, $authorId, 'Missing case'); } catch (OutOfBoundsException $e) { $rejected = true; }
    noteCheck($rejected, 'missing incident rejected');
    for ($i=0; $i<25; $i++) $service->add($id, $authorId, 'Pagination note ' . $i);
    $last = $service->list($id, 999);
    noteCheck($last['page'] === 2 && count($last['notes']) === 1, 'notes paginated with bounded page');
    $stmt = $pdo->prepare('SELECT status FROM incidents WHERE id = ?'); $stmt->execute([$id]);
    noteCheck($stmt->fetchColumn() === 'NEW', 'adding notes does not change incident state');
    require_once __DIR__ . '/../includes/soar/playbooks/ActionRegistry.php';
    $action = new AddIncidentNoteAction($pdo);
    $missingActor = $action->execute(['note'=>'Automated note'], ['incident'=>['id'=>$id]], false);
    noteCheck($missingActor->status === 'FAILED', 'playbook cannot impersonate hardcoded user 1');
    $dry = $action->execute(['note'=>'Preview note'], ['incident'=>['id'=>$id]], true);
    noteCheck($dry->status === 'SUCCESS' && $service->list($id)['total'] === 26, 'dry-run note does not persist');
    $saved = $action->execute(['note'=>'Attributed playbook note'], ['incident'=>['id'=>$id], 'analyst'=>['id'=>$authorId]], false);
    noteCheck($saved->status === 'SUCCESS' && $service->list($id)['total'] === 27, 'playbook records note using verified execution actor');
    $pdo->rollBack();
    echo "Case note integration passed; all fixtures rolled back.\n";
} catch (Throwable $e) {
    if ($pdo->inTransaction()) $pdo->rollBack();
    fwrite(STDERR, $e->getMessage() . "\n"); exit(1);
}
