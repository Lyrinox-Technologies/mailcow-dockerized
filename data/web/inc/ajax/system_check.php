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

function system_check_resolver_check() {
  $targets = array(
    'Internal nginx service' => 'nginx',
    'Internal postfix service' => 'postfix',
    'Public mailcow check service' => 'checks.mailcow.email'
  );
  $steps = array();
  $has_error = false;

  foreach ($targets as $label => $host) {
    $records = dns_get_record($host, DNS_A + DNS_AAAA);
    $ok = is_array($records) && count($records) > 0;
    if (!$ok) {
      $has_error = true;
    }
    $values = array();
    if ($ok) {
      foreach ($records as $record) {
        if (isset($record['ip'])) {
          $values[] = $record['ip'];
        }
        if (isset($record['ipv6'])) {
          $values[] = $record['ipv6'];
        }
      }
    }
    system_check_sort_unique($values);
    $steps[] = system_check_step($ok ? 'ok' : 'error', $label, $ok ? implode(', ', $values) : 'No A/AAAA records returned.');
  }

  system_check_response('Resolver check', $has_error ? 'error' : 'ok', $has_error ? 'One or more DNS lookups failed.' : 'DNS resolution is working for internal and public names.', $steps, $has_error ? 'Check unbound-mailcow, Docker DNS, and upstream resolver connectivity. DNS failures can break ACME, updates, outbound delivery, and external reputation checks.' : '');
}

function system_check_sort_unique(&$values) {
  $values = array_values(array_unique(array_filter($values)));
  sort($values);
}

function system_check_hostname_dns_check() {
  $hostname = getenv('MAILCOW_HOSTNAME');
  if (empty($hostname)) {
    system_check_response('Hostname DNS check', 'error', 'MAILCOW_HOSTNAME is not configured.', array(
      system_check_step('error', 'MAILCOW_HOSTNAME', 'not set')
    ), 'Set MAILCOW_HOSTNAME in mailcow.conf.');
  }

  $steps = array();
  $has_warning = false;
  $a_records = array();
  foreach (dns_get_record($hostname, DNS_A) ?: array() as $record) {
    if (isset($record['ip'])) {
      $a_records[] = $record['ip'];
    }
  }
  system_check_sort_unique($a_records);
  if (empty($a_records)) {
    $has_warning = true;
  }
  $steps[] = system_check_step(empty($a_records) ? 'warning' : 'ok', 'A records', empty($a_records) ? 'No A records found.' : implode(', ', $a_records));

  $aaaa_records = array();
  foreach (dns_get_record($hostname, DNS_AAAA) ?: array() as $record) {
    if (isset($record['ipv6'])) {
      $aaaa_records[] = $record['ipv6'];
    }
  }
  system_check_sort_unique($aaaa_records);
  $steps[] = system_check_step('ok', 'AAAA records', empty($aaaa_records) ? 'No AAAA records found.' : implode(', ', $aaaa_records));

  $mx_records = dns_get_record($hostname, DNS_MX) ?: array();
  $mx_values = array();
  foreach ($mx_records as $record) {
    if (isset($record['target'])) {
      $mx_values[] = $record['target'];
    }
  }
  system_check_sort_unique($mx_values);
  $steps[] = system_check_step(empty($mx_values) ? 'warning' : 'ok', 'MX records', empty($mx_values) ? 'No MX records found for hostname.' : implode(', ', $mx_values));

  system_check_response('Hostname DNS check', $has_warning ? 'warning' : 'ok', $has_warning ? 'Hostname DNS records need attention.' : 'Hostname DNS records resolve.', $steps, $has_warning ? 'Ensure MAILCOW_HOSTNAME resolves publicly to this mailcow instance. Missing A records can break web, ACME, and autodiscovery.' : '');
}

function system_check_domain_dns_check() {
  $domains = mailbox('get', 'domains');
  if (!is_array($domains) || empty($domains)) {
    system_check_response('Mail domain DNS check', 'warning', 'No configured mail domains were found.', array(
      system_check_step('warning', 'Domains', 'No active domains returned.')
    ), 'Add mail domains before running domain DNS and deliverability checks.');
  }

  $steps = array();
  $checked = 0;
  $warnings = 0;
  foreach ($domains as $domain) {
    if ($checked >= 50) {
      $steps[] = system_check_step('warning', 'Domain limit', 'Only the first 50 domains were checked.');
      $warnings++;
      break;
    }

    $mx_records = dns_get_record($domain, DNS_MX) ?: array();
    $txt_records = dns_get_record($domain, DNS_TXT) ?: array();
    $dmarc_records = dns_get_record('_dmarc.' . $domain, DNS_TXT) ?: array();
    $has_mx = count($mx_records) > 0;
    $has_spf = false;
    foreach ($txt_records as $record) {
      if (isset($record['txt']) && stripos($record['txt'], 'v=spf1') === 0) {
        $has_spf = true;
        break;
      }
    }
    $has_dmarc = false;
    foreach ($dmarc_records as $record) {
      if (isset($record['txt']) && stripos($record['txt'], 'v=DMARC1') === 0) {
        $has_dmarc = true;
        break;
      }
    }

    $missing = array();
    if (!$has_mx) $missing[] = 'MX';
    if (!$has_spf) $missing[] = 'SPF';
    if (!$has_dmarc) $missing[] = 'DMARC';
    if (!empty($missing)) {
      $warnings++;
    }
    $steps[] = system_check_step(empty($missing) ? 'ok' : 'warning', $domain, empty($missing) ? 'MX, SPF, and DMARC are present.' : 'Missing: ' . implode(', ', $missing));
    $checked++;
  }

  system_check_response('Mail domain DNS check', $warnings > 0 ? 'warning' : 'ok', $warnings > 0 ? 'Some domain DNS records need attention.' : 'Checked domains have basic deliverability DNS records.', $steps, $warnings > 0 ? 'Review DNS for the listed domains. MX affects inbound delivery; SPF and DMARC affect outbound deliverability and spoofing protection.' : '');
}

function system_check_outbound_check() {
  $targets = array(
    'mailcow checks HTTPS' => 'https://checks.mailcow.email',
    'GitHub HTTPS' => 'https://api.github.com'
  );
  $steps = array();
  $has_error = false;
  foreach ($targets as $label => $url) {
    $curl = curl_init($url);
    curl_setopt_array($curl, array(
      CURLOPT_CONNECTTIMEOUT => 5,
      CURLOPT_TIMEOUT => 10,
      CURLOPT_RETURNTRANSFER => true,
      CURLOPT_NOBODY => true,
      CURLOPT_USERAGENT => 'mailcow-system-check'
    ));
    curl_exec($curl);
    $error = curl_error($curl);
    $code = curl_getinfo($curl, CURLINFO_HTTP_CODE);
    curl_close($curl);
    $ok = empty($error) && $code >= 200 && $code < 500;
    if (!$ok) {
      $has_error = true;
    }
    $steps[] = system_check_step($ok ? 'ok' : 'error', $label, $ok ? 'HTTP ' . $code : ($error ?: 'HTTP ' . $code));
  }

  system_check_response('Outbound connectivity check', $has_error ? 'error' : 'ok', $has_error ? 'One or more outbound HTTPS checks failed.' : 'Outbound HTTPS connectivity is available.', $steps, $has_error ? 'Check outbound firewall rules, DNS resolution, proxy settings, and IPv4/IPv6 routing from the mailcow network.' : '');
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
    'MAIL FROM:<>'
  ), '250 2.1.0', 10, true);
  system_check_response('Postfix SMTP check', $ok ? 'ok' : 'error', $ok ? 'Postfix SMTP listener responded.' : 'Postfix SMTP listener check failed.', array(
    system_check_step($ok ? 'ok' : 'error', 'SMTP dialog', $message)
  ), $ok ? '' : 'Check postfix-mailcow logs and whether the internal listener on port 589 is accepting mail from the mailcow network. A timeout, empty response, or MAIL FROM rejection can indicate Postfix is overloaded, blocked, or misconfigured.');
}

function system_check_dovecot_check() {
  $hostname = getenv('MAILCOW_HOSTNAME');
  if (empty($hostname)) {
    system_check_response('Dovecot listener check', 'error', 'MAILCOW_HOSTNAME is not configured.', array(
      system_check_step('error', 'MAILCOW_HOSTNAME', 'not set')
    ), 'Set MAILCOW_HOSTNAME in mailcow.conf. Public listener checks need the configured hostname.');
  }

  $steps = array();
  list($imap_ok, $imap_message) = system_check_tcp_command($hostname, 143, array(), 'OK', 7);
  $steps[] = system_check_step($imap_ok ? 'ok' : 'error', 'IMAP 143', $imap_message);
  list($sieve_ok, $sieve_message) = system_check_tcp_command($hostname, 4190, array(), 'Dovecot ready', 7);
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

function system_check_storage_check() {
  $exec_fields = array('cmd' => 'system', 'task' => 'df', 'dir' => '/var/vmail');
  $response = docker('post', 'dovecot-mailcow', 'exec', $exec_fields);
  $fields = explode(',', (string)json_decode($response, true));
  if (count($fields) < 5) {
    system_check_response('Mail storage check', 'error', 'Could not read /var/vmail disk usage.', array(
      system_check_step('error', 'df /var/vmail', 'Unexpected Docker API response.')
    ), 'Check dockerapi-mailcow and dovecot-mailcow access to /var/vmail.');
  }

  $usage_percent = (int)str_replace('%', '', $fields[4]);
  $status = 'ok';
  if ($usage_percent >= 90) {
    $status = 'error';
  }
  elseif ($usage_percent >= 80) {
    $status = 'warning';
  }
  $steps = array(
    system_check_step($status, $fields[0], $fields[2] . ' used of ' . $fields[1] . ' (' . $fields[4] . ')')
  );
  system_check_response('Mail storage check', $status, $status == 'ok' ? 'Mail storage has available capacity.' : 'Mail storage usage is high.', $steps, $status == 'ok' ? '' : 'Free disk space or expand the volume before Dovecot/Postfix begin failing writes.');
}

function system_check_queue_check() {
  $queue_json = mailq('get');
  $queue = json_decode($queue_json, true);
  if (!is_array($queue)) {
    system_check_response('Mail queue check', 'error', 'Could not read Postfix queue.', array(
      system_check_step('error', 'postqueue', 'Unexpected queue response.')
    ), 'Check postfix-mailcow and dockerapi-mailcow. Use the queue manager for message-level inspection.');
  }

  $count = count($queue);
  $status = 'ok';
  if ($count >= 1000) {
    $status = 'error';
  }
  elseif ($count >= 100) {
    $status = 'warning';
  }
  $steps = array(
    system_check_step($status, 'Queued messages', (string)$count)
  );
  system_check_response('Mail queue check', $status, $status == 'ok' ? 'Postfix queue size is low.' : 'Postfix queue size is elevated.', $steps, $status == 'ok' ? '' : 'Use the Queue Manager to inspect deferred reasons. Common causes include DNS failures, outbound blocks, remote throttling, and TLS policy issues.');
}

$check = isset($_GET['check']) ? $_GET['check'] : '';

switch ($check) {
  case 'external':
    system_check_external_check();
    break;
  case 'nginx':
    system_check_nginx_check();
    break;
  case 'resolver':
    system_check_resolver_check();
    break;
  case 'hostname_dns':
    system_check_hostname_dns_check();
    break;
  case 'domain_dns':
    system_check_domain_dns_check();
    break;
  case 'outbound':
    system_check_outbound_check();
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
  case 'storage':
    system_check_storage_check();
    break;
  case 'queue':
    system_check_queue_check();
    break;
  default:
    http_response_code(400);
    system_check_response('Unknown check', 'error', 'Unknown system check requested.', array(
      system_check_step('error', 'check', htmlspecialchars($check))
    ));
}
