<?php
require_once $_SERVER['DOCUMENT_ROOT'] . '/inc/prerequisites.inc.php';

header('Content-Type: application/json');

if (!isset($_SESSION['mailcow_cc_role']) || $_SESSION['mailcow_cc_role'] != 'admin') {
  http_response_code(403);
  echo json_encode(array(
    'name' => 'Forbidden',
    'status' => 'error',
    'summary' => 'Only administrators can run system checks.',
    'steps' => array()
  ));
  exit;
}

function system_check_step($status, $label, $message) {
  return array(
    'status' => $status,
    'label' => $label,
    'message' => $message
  );
}

function system_check_response($name, $status, $summary, $steps, $guidance = '') {
  echo json_encode(array(
    'name' => $name,
    'status' => $status,
    'summary' => $summary,
    'guidance' => $guidance,
    'steps' => $steps
  ));
  exit;
}

function system_check_read_smtp_response($socket) {
  $response = '';
  while (($line = fgets($socket, 512)) !== false) {
    $response .= trim($line) . "\n";
    if (preg_match('/^\d{3}\s/', $line)) {
      break;
    }
  }
  return $response;
}

function system_check_tcp_command($host, $port, $commands = array(), $expect = '', $timeout = 7, $smtp = false) {
  $errno = 0;
  $errstr = '';
  $socket = @fsockopen($host, $port, $errno, $errstr, $timeout);
  if (!$socket) {
    return array(false, trim($errstr . ' (' . $errno . ')'));
  }
  stream_set_timeout($socket, $timeout);
  $transcript = '';
  $transcript .= $smtp ? system_check_read_smtp_response($socket) : (string)fgets($socket, 512);
  foreach ($commands as $command) {
    fwrite($socket, $command . "\r\n");
    $transcript .= $smtp ? system_check_read_smtp_response($socket) : (string)fgets($socket, 512);
  }
  fclose($socket);

  if ($transcript === '') {
    return array(false, 'Connected, but no response was returned.');
  }

  return array($expect === '' || strpos($transcript, $expect) !== false, trim($transcript));
}

function system_check_external_check() {
  $steps = array();
  $guid = license('guid');

  if (empty($guid)) {
    system_check_response('Open relay check', 'error', 'Could not determine this instance GUID.', array(
      system_check_step('error', 'GUID', 'No GUID was returned by license().')
    ), 'The external relay check needs the mailcow GUID. Verify the database and license GUID initialization.');
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
      $steps[] = system_check_step('warning', $label, $curl_error);
      continue;
    }

    $decoded = json_decode($response, true);
    if ($http_code >= 400 || !is_array($decoded) || !isset($decoded['response'])) {
      $steps[] = system_check_step('warning', $label, 'Invalid response from checks.mailcow.email: ' . substr($response, 0, 300));
      continue;
    }

    $success = true;
    if ($decoded['response'] == 'critical') {
      $critical = true;
      $steps[] = system_check_step('error', $label, isset($decoded['out']) ? $decoded['out'] : 'Open relay reported.');
    }
    else {
      $steps[] = system_check_step('ok', $label, isset($decoded['out']) && !empty($decoded['out']) ? $decoded['out'] : 'No open relay reported.');
    }
  }

  if ($critical) {
    system_check_response('Open relay check', 'error', 'checks.mailcow.email reported a critical open relay result.', $steps, 'Treat this as urgent. Review NAT/firewall rules, trusted networks, forwarding hosts, and Postfix relay restrictions before accepting Internet traffic.');
  }
  if (!$success) {
    system_check_response('Open relay check', 'warning', 'The external checker could not be reached.', $steps, 'This usually means the UI container cannot reach checks.mailcow.email over one or both address families. Check outbound firewall rules, DNS, IPv6 routing, and proxy settings. This is inconclusive, not a pass.');
  }
  system_check_response('Open relay check', 'ok', 'No open relay was detected by the external checker.', $steps);
}

function system_check_nginx_check() {
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
    system_check_response('Web UI check', 'error', 'Nginx did not respond.', array(
      system_check_step('error', 'HTTP', $curl_error)
    ), 'Check nginx-mailcow container logs and confirm the internal nginx service is bound on port 8081.');
  }

  $ok = ($http_code >= 200 && $http_code < 500);
  system_check_response('Web UI check', $ok ? 'ok' : 'error', $ok ? 'Nginx responded over HTTP.' : 'Nginx returned an unexpected HTTP status.', array(
    system_check_step($ok ? 'ok' : 'error', 'HTTP status', (string)$http_code)
  ), $ok ? '' : 'Check nginx-mailcow configuration, generated templates, and upstream php-fpm connectivity.');
}

function system_check_redis_check() {
  global $redis;

  try {
    $pong = $redis->ping();
    $ok = ($pong === true || strtoupper((string)$pong) == 'PONG' || (string)$pong == '1');
    system_check_response('Redis ping', $ok ? 'ok' : 'error', $ok ? 'Redis returned PONG.' : 'Redis ping returned an unexpected response.', array(
      system_check_step($ok ? 'ok' : 'error', 'PING', is_bool($pong) ? ($pong ? 'true' : 'false') : (string)$pong)
    ));
  }
  catch (Throwable $e) {
    system_check_response('Redis ping', 'error', 'Redis ping failed.', array(
      system_check_step('error', 'PING', $e->getMessage())
    ), 'Check redis-mailcow health and REDISPASS consistency between containers.');
  }
}

function system_check_mysql_check() {
  global $pdo;

  try {
    $stmt = $pdo->query('SELECT COUNT(*) FROM information_schema.tables');
    $count = $stmt->fetchColumn();
    system_check_response('MySQL query', 'ok', 'MySQL query completed.', array(
      system_check_step('ok', 'information_schema.tables', $count . ' tables visible')
    ));
  }
  catch (Throwable $e) {
    system_check_response('MySQL query', 'error', 'MySQL query failed.', array(
      system_check_step('error', 'Query', $e->getMessage())
    ), 'Check mysql-mailcow logs, credentials in mailcow.conf, and whether migrations completed.');
  }
}

function system_check_postfix_check() {
  list($ok, $message) = system_check_tcp_command('postfix', 589, array(
    'EHLO system-check.local',
    'MAIL FROM:<system-check@invalid>',
    'RCPT TO:<system-check@localhost>'
  ), '250 2.1.5', 10, true);
  system_check_response('Postfix SMTP check', $ok ? 'ok' : 'error', $ok ? 'Postfix SMTP listener responded.' : 'Postfix SMTP listener check failed.', array(
    system_check_step($ok ? 'ok' : 'error', 'SMTP dialog', $message)
  ), $ok ? '' : 'Check postfix-mailcow logs and whether the internal listener on port 589 is accepting mail from the mailcow network. A timeout or empty response can indicate Postfix is overloaded or blocked.');
}

function system_check_dovecot_check() {
  $steps = array();
  list($imap_ok, $imap_message) = system_check_tcp_command('dovecot', 143, array(), 'OK', 7);
  $steps[] = system_check_step($imap_ok ? 'ok' : 'error', 'IMAP 143', $imap_message);
  list($sieve_ok, $sieve_message) = system_check_tcp_command('dovecot', 4190, array(), 'Dovecot ready', 7);
  $steps[] = system_check_step($sieve_ok ? 'ok' : 'warning', 'ManageSieve 4190', $sieve_message);
  $ok = $imap_ok && $sieve_ok;
  system_check_response('Dovecot listener check', $ok ? 'ok' : 'error', $ok ? 'Dovecot listeners responded.' : 'One or more Dovecot listeners did not respond.', $steps, $ok ? '' : 'Check dovecot-mailcow logs and internal listener bindings. IMAP failure affects mailbox access; ManageSieve failure affects filter management.');
}

function system_check_rspamd_check() {
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
    system_check_response('Rspamd settings check', 'error', 'Rspamd socket check failed.', array(
      system_check_step('error', 'Rspamd socket', $curl_error)
    ), 'Check rspamd-mailcow status and whether /var/lib/rspamd/rspamd.sock is mounted into php-fpm.');
  }

  $decoded = json_decode($response, true);
  $reject_score = null;
  if (is_array($decoded)) {
    if (isset($decoded['reject'])) {
      $reject_score = $decoded['reject'];
    }
    else {
      foreach ($decoded as $action) {
        if (isset($action['action']) && $action['action'] == 'reject') {
          $reject_score = isset($action['value']) ? $action['value'] : null;
          break;
        }
      }
    }
  }
  $ok = ($reject_score !== null);
  system_check_response('Rspamd settings check', $ok ? 'ok' : 'error', $ok ? 'Rspamd returned action settings.' : 'Rspamd returned an unexpected response.', array(
    system_check_step($ok ? 'ok' : 'error', 'Actions endpoint', $ok ? 'Reject score: ' . $reject_score : substr($response, 0, 300))
  ), $ok ? '' : 'Rspamd answered, but the action settings format was not recognized. Check the Rspamd version/API response and rspamd-mailcow logs.');
}

function system_check_tls_check() {
  $hostname = getenv('MAILCOW_HOSTNAME');
  if (empty($hostname)) {
    system_check_response('TLS certificate check', 'error', 'MAILCOW_HOSTNAME is not configured.', array(
      system_check_step('error', 'MAILCOW_HOSTNAME', 'not set')
    ), 'Set MAILCOW_HOSTNAME in mailcow.conf and regenerate/restart the affected services.');
  }

  $context = stream_context_create(array(
    'ssl' => array(
      'capture_peer_cert' => true,
      'verify_peer' => false,
      'verify_peer_name' => false,
      'SNI_enabled' => true,
      'peer_name' => $hostname
    )
  ));
  $client = @stream_socket_client('ssl://' . $hostname . ':443', $errno, $errstr, 10, STREAM_CLIENT_CONNECT, $context);
  if (!$client) {
    system_check_response('TLS certificate check', 'error', 'Could not connect to HTTPS for the configured hostname.', array(
      system_check_step('error', $hostname . ':443', trim($errstr . ' (' . $errno . ')'))
    ), 'Check DNS, NAT/firewall rules, HTTPS binding, and whether this host can resolve and reach MAILCOW_HOSTNAME.');
  }

  $params = stream_context_get_params($client);
  fclose($client);
  if (empty($params['options']['ssl']['peer_certificate'])) {
    system_check_response('TLS certificate check', 'error', 'No peer certificate was returned.', array(
      system_check_step('error', 'Certificate', 'missing')
    ), 'Check nginx TLS configuration and certificate files.');
  }

  $cert = openssl_x509_parse($params['options']['ssl']['peer_certificate']);
  $valid_to = isset($cert['validTo_time_t']) ? (int)$cert['validTo_time_t'] : 0;
  $days = $valid_to > 0 ? floor(($valid_to - time()) / 86400) : -1;
  $names = array();
  if (isset($cert['subject']['CN'])) {
    $names[] = $cert['subject']['CN'];
  }
  if (isset($cert['extensions']['subjectAltName'])) {
    $names = array_merge($names, array_map('trim', explode(',', str_replace('DNS:', '', $cert['extensions']['subjectAltName']))));
  }
  $name_ok = in_array($hostname, $names);
  $expiry_ok = $days >= 14;
  $status = ($name_ok && $expiry_ok) ? 'ok' : 'warning';
  $steps = array(
    system_check_step($name_ok ? 'ok' : 'warning', 'Name match', $name_ok ? $hostname . ' is present in the certificate.' : $hostname . ' was not found in CN/SAN.'),
    system_check_step($expiry_ok ? 'ok' : 'warning', 'Expiry', $days . ' days remaining')
  );
  system_check_response('TLS certificate check', $status, $status == 'ok' ? 'TLS certificate looks usable.' : 'TLS certificate needs attention.', $steps, $status == 'ok' ? '' : 'Check ACME status, DNS records, reverse proxy configuration, and whether the certificate includes MAILCOW_HOSTNAME.');
}

function system_check_acme_check() {
  global $redis;

  try {
    $fail_time = $redis->get('ACME_FAIL_TIME');
    if (empty($fail_time)) {
      system_check_response('ACME failure state', 'ok', 'No ACME failure marker is set.', array(
        system_check_step('ok', 'ACME_FAIL_TIME', 'not set')
      ));
    }
    system_check_response('ACME failure state', 'error', 'ACME failure marker is set.', array(
      system_check_step('error', 'ACME_FAIL_TIME', (string)$fail_time)
    ));
  }
  catch (Throwable $e) {
    system_check_response('ACME failure state', 'error', 'Could not read ACME failure marker.', array(
      system_check_step('error', 'Redis GET', $e->getMessage())
    ), 'Check Redis and ACME logs. This can hide certificate renewal failures.');
  }
}

function system_check_container_check() {
  $containers = docker('info');
  if (!is_array($containers)) {
    system_check_response('Container state summary', 'error', 'Docker API did not return container information.', array(
      system_check_step('error', 'Docker API', is_string($containers) ? $containers : 'No container data returned.')
    ), 'Check dockerapi-mailcow and Docker socket access.');
  }

  $steps = array();
  $has_error = false;
  ksort($containers);
  foreach ($containers as $name => $container) {
    $running = isset($container['State']['Running']) && $container['State']['Running'] == 1;
    if (!$running) {
      $has_error = true;
    }
    $steps[] = system_check_step($running ? 'ok' : 'error', $name, $running ? 'running' : 'not running');
  }

  system_check_response('Container state summary', $has_error ? 'error' : 'ok', $has_error ? 'At least one mailcow container is not running.' : 'All reported mailcow containers are running.', $steps, $has_error ? 'Inspect the stopped container logs and restart through docker compose after fixing the underlying error.' : '');
}

$check = isset($_GET['check']) ? $_GET['check'] : '';

switch ($check) {
  case 'external':
    system_check_external_check();
    break;
  case 'nginx':
    system_check_nginx_check();
    break;
  case 'redis':
    system_check_redis_check();
    break;
  case 'mysql':
    system_check_mysql_check();
    break;
  case 'postfix':
    system_check_postfix_check();
    break;
  case 'dovecot':
    system_check_dovecot_check();
    break;
  case 'rspamd':
    system_check_rspamd_check();
    break;
  case 'tls':
    system_check_tls_check();
    break;
  case 'acme':
    system_check_acme_check();
    break;
  case 'containers':
    system_check_container_check();
    break;
  default:
    http_response_code(400);
    system_check_response('Unknown check', 'error', 'Unknown system check requested.', array(
      system_check_step('error', 'check', htmlspecialchars($check))
    ));
}
