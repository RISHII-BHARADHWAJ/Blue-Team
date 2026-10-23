<?php
declare(strict_types=1);
if (PHP_SAPI !== 'cli' || getenv('SOAR_INTEGRATION_TEST') !== '1' || getenv('DB_HOST') !== 'db') exit(2);
require_once __DIR__.'/../includes/db.php';
require_once __DIR__.'/../includes/soar/IncidentManager.php';
function timelineCheck(bool $ok, string $message): void {
    if (!$ok) throw new RuntimeException('FAIL: '.$message);
    echo "PASS: $message\n";
}
$pdo->beginTransaction();
try {
    $name = 'timeline-ci-'.bin2hex(random_bytes(6));
    $repo = new IncidentRepository($pdo);
    $real = $repo->create(['incident_number'=>$name.'-real', 'title'=>$name]);
    $sim = $repo->create(['incident_number'=>$name.'-sim', 'title'=>$name, 'is_simulated'=>true]);
    $empty = $repo->create(['incident_number'=>$name.'-empty', 'title'=>$name]);
    $timeline = new IncidentTimeline($pdo);
    $ids = [];
    for ($n=0; $n<27; $n++) {
        $ids[] = $timeline->addEvent($real, 'NOTE_ADDED', 'ANALYST', 'reader 100%_!', 'entry '.$n, ['private'=>'DETAIL_ONLY_SENTINEL']);
    }
    $system = $timeline->addEvent($real, 'STATUS_CHANGE', 'SYSTEM', 'engine', 'changed 100%_!');
    $playbook = $timeline->addEvent($real, 'PLAYBOOK_STEP', 'PLAYBOOK', 'worker', 'entry 27');
    $simEvent = $timeline->addEvent($sim, 'NOTE_ADDED', 'ANALYST', 'reader 100%_!', 'simulation history');
    $pdo->prepare("UPDATE incident_timeline SET created_at='2020-01-01 00:00:00' WHERE incident_id IN (?,?)")->execute([$real, $sim]);
    // A smaller ID with a later timestamp must still sort first by time.
    $pdo->prepare("UPDATE incident_timeline SET created_at='2020-01-02 00:00:00' WHERE id=?")->execute([$ids[0]]);
    $all = array_merge(array_slice($ids,1), [$system,$playbook,$ids[0]]);
    $first = $timeline->search($real, ['sort'=>'oldest']);
    $second = $timeline->search($real, ['sort'=>'oldest'], PHP_INT_MAX);
    $got = array_map('intval', array_column(array_merge($first['rows'], $second['rows']), 'id'));
    timelineCheck($got === $all && $first['total'] === 29 && count($first['rows']) === 25 && $second['page'] === 2, 'bounded adjacent pages preserve timestamp and ID order, with high pages clamped');
    $newest = $timeline->search($real);
    timelineCheck(array_map('intval',array_column($newest['rows'],'id')) === array_slice(array_reverse($all),0,25), 'newest order reverses timestamp and ID ties');
    timelineCheck(!array_key_exists('details',$newest['rows'][0]), 'raw structured details are not selected');
    $matches = $timeline->search($real, ['q'=>'100%_!', 'event_type'=>'NOTE_ADDED', 'actor_type'=>'ANALYST']);
    timelineCheck($matches['total'] === 27, 'actor substring, event type and actor type filters intersect');
    $matches = $timeline->search($real, ['q'=>'changed 100%_!']);
    timelineCheck($matches['total'] === 1 && (int)$matches['rows'][0]['id'] === $system, 'summary search treats percent, underscore and escape character literally');
    timelineCheck($timeline->search($real, ['actor_type'=>'PLAYBOOK'])['total'] === 1, 'playbook actor filter works');
    timelineCheck($timeline->search($real, ['event_type'=>'STATUS_CHANGE', 'actor_type'=>'ANALYST'])['total'] === 0, 'incompatible filters return no rows');
    foreach (['DETAIL_ONLY_SENTINEL', "' OR 1=1 --", 'simulation history'] as $q) {
        timelineCheck($timeline->search($real, ['q'=>$q])['total'] === 0, 'search excludes details, SQL-like input and other cases');
    }
    $simRows = $timeline->search($sim);
    timelineCheck($simRows['total'] === 1 && (int)$simRows['rows'][0]['id'] === $simEvent, 'simulated history remains case scoped');
    $noRows = $timeline->search($empty, [], -9);
    timelineCheck($noRows['rows'] === [] && $noRows['page'] === 1 && $noRows['pages'] === 1, 'empty histories have a valid first page');
    foreach ([['q'=>[]],['q'=>str_repeat('x',201)],['q'=>"\xFF"],['event_type'=>'DROP'],['actor_type'=>[]],['sort'=>'id DESC; --']] as $input) {
        $bad = false;
        try { $timeline->search($real, $input); } catch (InvalidArgumentException $e) { $bad = true; }
        timelineCheck($bad, 'invalid filter input is rejected');
    }
    $manager = new IncidentManager($pdo);
    $preview = $manager->getIncident($real, 20)['timeline'];
    timelineCheck(count($preview) === 20 && !array_key_exists('details',$preview[0]) && array_map('intval',array_column($preview,'id')) === array_slice(array_reverse($all),0,20), 'case preview is limited and newest first without details');
    $legacy = $manager->getIncident($real)['timeline'];
    timelineCheck(count($legacy) === 29 && array_map('intval',array_column($legacy,'id')) === $all && $legacy[0]['details']['private'] === 'DETAIL_ONLY_SENTINEL', 'default manager/API retains full chronological history and decoded details');
    timelineCheck($pdo->inTransaction(), 'search leaves a borrowed transaction open');
    $pdo->rollBack();
    $outside = $timeline->search($real);
    timelineCheck($outside['total'] === 0 && !$pdo->inTransaction(), 'owned read transaction closes cleanly and rollback removed fixtures');
    echo "Incident timeline integration passed.\n";
} catch (Throwable $e) {
    if ($pdo->inTransaction()) $pdo->rollBack();
    fwrite(STDERR, $e->getMessage()."\n"); exit(1);
}
