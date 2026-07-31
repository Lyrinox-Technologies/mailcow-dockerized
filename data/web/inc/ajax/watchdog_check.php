<?php
require_once $_SERVER['DOCUMENT_ROOT'] . '/inc/prerequisites.inc.php';

header('Content-Type: application/json');

if (!isset($_SESSION['mailcow_cc_role']) || $_SESSION['mailcow_cc_role'] != 'admin') {
  http_response_code(403);
  echo json_encode(array(
    'name' => 'Forbidden',
    'status' => 'error',
    'summary' => 'Only administrators can run watchdog diagnostics.',
    'steps' => array()
  ));
  exit;
}

function watchdog_step($status, $label, $message) {
  return array(
    'status' => $status,
    'label' => $label,
    'message' => $message
  );
}

function watchdog_response($name, $status, $summary, $steps) {
  echo json_encode(array(
    'name' => $name,
    'status' => $status,
    'summary' => $summary,
    'steps' => $steps
  ));
  exit;
}

function watchdog_tcp_greeting($host, $port, $expect, $timeout = 7) {
  $errno = 0;
  $errstr = '';
  $socket = @fsockopen($host, $port, $errno, $errstr, $timeout);
  if (!$socket) {
    return array(false, trim($errstr . ' (' . $errno . ')'));
  }
  stream_set_timeout($socket, $timeout);
  $greeting = fgets($socket, 512);
  fclose($socket);

  if ($greeting === false) {
    return array(false, 'Connected, but no greeting was returned.');
  }

  return array(strpos($greeting, $expect) !== false, trim($greeting));
}

function watchdog_external_check() {
  $steps = array();
  $guid = license('guid');

  if (empty($guid)) {
    watchdog_response('External open relay check', 'error', 'Could not determine this instance GUID.', array(
      watchdog_step('error', 'GUID', 'No GUID was returned by license().')
    ));
  }

  $critical = false;
  $success = false;
  foreach (array('IPv4' => CURL_IPRESOLVE_V4, 'IPv6' => CURL_IPRESOLVE_V6) as $label => $ip_resolve) {
    $curl = curl_init('https://checks.mailcow.email');
    curl_setopt_array($curl, array(
      CURLOPT_CONNECTTIMEOUT => 3,
      CURLOPT_TIMEOUT => 10,
      CURLOPT_RETURNTRANSFER => true,
      CURLOPT_POST => true,
      CURLOPT_POSTFIELDS => http_build_query(array('guid' => $guid)),
      CURLOPT_IPRESOLVE => $ip_resolve
    ));
    $response = curl_exec($curl);
    $curl_error = curl_error($curl);
    $http_code = curl_getinfo($curl, CURLINFO_HTTP_CODE);
    curl_close($curl);

    if ($response === false || !empty($curl_error)) {
      $steps[] = watchdog_step('warning', $label, $curl_error);
      continue;
    }

    $decoded = json_decode($response, true);
    if ($http_code >= 400 || !is_array($decoded) || !isset($decoded['response'])) {
      $steps[] = watchdog_step('warning', $label, 'Invalid response from checks.mailcow.email.');
      continue;
    }

    $success = true;
    if ($decoded['response'] == 'critical') {
      $critical = true;
      $steps[] = watchdog_step('error', $label, isset($decoded['out']) ? $decoded['out'] : 'Open relay reported.');
    }
    else {
      $steps[] = watchdog_step('ok', $label, isset($decoded['out']) && !empty($decoded['out']) ? $decoded['out'] : 'No open relay reported.');
    }
  }

  if ($critical) {
    watchdog_response('External open relay check', 'error', 'checks.mailcow.email reported a critical open relay result.', $steps);
  }
  if (!$success) {
    watchdog_response('External open relay check', 'warning', 'The external checker could not be reached.', $steps);
  }
  watchdog_response('External open relay check', 'ok', 'No open relay was detected by the external checker.', $steps);
}

function watchdog_nginx_check() {
  $curl = curl_init('http://nginx:8081/');
  curl_setopt_array($curl, array(
    CURLOPT_CONNECTTIMEOUT => 3,
    CURLOPT_TIMEOUT => 7,
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_NOBODY => true
  ));
  curl_exec($curl);
  $curl_error = curl_error($curl);
  $http_code = curl_getinfo($curl, CURLINFO_HTTP_CODE);
  curl_close($curl);

  if (!empty($curl_error)) {
    watchdog_response('Nginx HTTP check', 'error', 'Nginx did not respond.', array(
      watchdog_step('error', 'HTTP', $curl_error)
    ));
  }

  $ok = ($http_code >= 200 && $http_code < 500);
  watchdog_response('Nginx HTTP check', $ok ? 'ok' : 'error', $ok ? 'Nginx responded over HTTP.' : 'Nginx returned an unexpected HTTP status.', array(
    watchdog_step($ok ? 'ok' : 'error', 'HTTP status', (string)$http_code)
  ));
}

function watchdog_redis_check() {
  global $redis;

  try {
    $pong = $redis->ping();
    $ok = ($pong === true || strtoupper((string)$pong) == 'PONG' || (string)$pong == '1');
    watchdog_response('Redis ping', $ok ? 'ok' : 'error', $ok ? 'Redis returned PONG.' : 'Redis ping returned an unexpected response.', array(
      watchdog_step($ok ? 'ok' : 'error', 'PING', is_bool($pong) ? ($pong ? 'true' : 'false') : (string)$pong)
    ));
  }
  catch (Throwable $e) {
    watchdog_response('Redis ping', 'error', 'Redis ping failed.', array(
      watchdog_step('error', 'PING', $e->getMessage())
    ));
  }
}

function watchdog_mysql_check() {
  global $pdo;

  try {
    $stmt = $pdo->query('SELECT COUNT(*) FROM information_schema.tables');
    $count = $stmt->fetchColumn();
    watchdog_response('MySQL query', 'ok', 'MySQL query completed.', array(
      watchdog_step('ok', 'information_schema.tables', $count . ' tables visible')
    ));
  }
  catch (Throwable $e) {
    watchdog_response('MySQL query', 'error', 'MySQL query failed.', array(
      watchdog_step('error', 'Query', $e->getMessage())
    ));
  }
}

function watchdog_postfix_check() {
  list($ok, $message) = watchdog_tcp_greeting('postfix', 589, '220');
  watchdog_response('Postfix SMTP check', $ok ? 'ok' : 'error', $ok ? 'Postfix SMTP listener responded.' : 'Postfix SMTP listener check failed.', array(
    watchdog_step($ok ? 'ok' : 'error', 'SMTP greeting', $message)
  ));
}

function watchdog_dovecot_check() {
  list($ok, $message) = watchdog_tcp_greeting('dovecot', 24, '220');
  watchdog_response('Dovecot LMTP check', $ok ? 'ok' : 'error', $ok ? 'Dovecot LMTP listener responded.' : 'Dovecot LMTP listener check failed.', array(
    watchdog_step($ok ? 'ok' : 'error', 'LMTP greeting', $message)
  ));
}

function watchdog_rspamd_check() {
  $curl = curl_init();
  curl_setopt_array($curl, array(
    CURLOPT_UNIX_SOCKET_PATH => '/var/lib/rspamd/rspamd.sock',
    CURLOPT_URL => 'http://rspamd/actions',
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_TIMEOUT => 7
  ));
  $response = curl_exec($curl);
  $curl_error = curl_error($curl);
  curl_close($curl);

  if ($response === false || !empty($curl_error)) {
    watchdog_response('Rspamd settings check', 'error', 'Rspamd socket check failed.', array(
      watchdog_step('error', 'Rspamd socket', $curl_error)
    ));
  }

  $decoded = json_decode($response, true);
  $ok = is_array($decoded) && isset($decoded['reject']);
  watchdog_response('Rspamd settings check', $ok ? 'ok' : 'error', $ok ? 'Rspamd returned action settings.' : 'Rspamd returned an unexpected response.', array(
    watchdog_step($ok ? 'ok' : 'error', 'Actions endpoint', $ok ? 'Reject score: ' . $decoded['reject'] : substr($response, 0, 300))
  ));
}

function watchdog_acme_check() {
  global $redis;

  try {
    $fail_time = $redis->get('ACME_FAIL_TIME');
    if (empty($fail_time)) {
      watchdog_response('ACME failure state', 'ok', 'No ACME failure marker is set.', array(
        watchdog_step('ok', 'ACME_FAIL_TIME', 'not set')
      ));
    }
    watchdog_response('ACME failure state', 'error', 'ACME failure marker is set.', array(
      watchdog_step('error', 'ACME_FAIL_TIME', (string)$fail_time)
    ));
  }
  catch (Throwable $e) {
    watchdog_response('ACME failure state', 'error', 'Could not read ACME failure marker.', array(
      watchdog_step('error', 'Redis GET', $e->getMessage())
    ));
  }
}

function watchdog_container_check() {
  $containers = docker('info');
  if (!is_array($containers)) {
    watchdog_response('Container state summary', 'error', 'Docker API did not return container information.', array(
      watchdog_step('error', 'Docker API', is_string($containers) ? $containers : 'No container data returned.')
    ));
  }

  $steps = array();
  $has_error = false;
  ksort($containers);
  foreach ($containers as $name => $container) {
    $running = isset($container['State']['Running']) && $container['State']['Running'] == 1;
    if (!$running) {
      $has_error = true;
    }
    $steps[] = watchdog_step($running ? 'ok' : 'error', $name, $running ? 'running' : 'not running');
  }

  watchdog_response('Container state summary', $has_error ? 'error' : 'ok', $has_error ? 'At least one mailcow container is not running.' : 'All reported mailcow containers are running.', $steps);
}

$check = isset($_GET['check']) ? $_GET['check'] : '';

switch ($check) {
  case 'external':
    watchdog_external_check();
    break;
  case 'nginx':
    watchdog_nginx_check();
    break;
  case 'redis':
    watchdog_redis_check();
    break;
  case 'mysql':
    watchdog_mysql_check();
    break;
  case 'postfix':
    watchdog_postfix_check();
    break;
  case 'dovecot':
    watchdog_dovecot_check();
    break;
  case 'rspamd':
    watchdog_rspamd_check();
    break;
  case 'acme':
    watchdog_acme_check();
    break;
  case 'containers':
    watchdog_container_check();
    break;
  default:
    http_response_code(400);
    watchdog_response('Unknown check', 'error', 'Unknown watchdog diagnostic requested.', array(
      watchdog_step('error', 'check', htmlspecialchars($check))
    ));
}
