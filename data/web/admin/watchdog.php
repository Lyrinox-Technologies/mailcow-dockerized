<?php
require_once $_SERVER['DOCUMENT_ROOT'] . '/inc/prerequisites.inc.php';
require_once $_SERVER['DOCUMENT_ROOT'] . '/inc/triggers.admin.inc.php';

protect_route(['admin']);

require_once $_SERVER['DOCUMENT_ROOT'] . '/inc/header.inc.php';
$_SESSION['return_to'] = $_SERVER['REQUEST_URI'];

$js_minifier->add('/web/js/site/watchdog.js');

$template = 'watchdog.twig';
$template_data = [
  'watchdog_checks' => [
    [
      'id' => 'external',
      'name' => 'External open relay check',
      'service' => 'External',
      'description' => 'Calls checks.mailcow.email with this instance GUID, matching the watchdog external check.'
    ],
    [
      'id' => 'nginx',
      'name' => 'Nginx HTTP check',
      'service' => 'nginx-mailcow',
      'description' => 'Checks that the internal nginx endpoint responds over HTTP.'
    ],
    [
      'id' => 'redis',
      'name' => 'Redis ping',
      'service' => 'redis-mailcow',
      'description' => 'Authenticates to Redis and verifies a PONG response.'
    ],
    [
      'id' => 'mysql',
      'name' => 'MySQL query',
      'service' => 'mysql-mailcow',
      'description' => 'Runs a lightweight metadata query through the UI database connection.'
    ],
    [
      'id' => 'postfix',
      'name' => 'Postfix SMTP check',
      'service' => 'postfix-mailcow',
      'description' => 'Connects to the internal submission listener and verifies the SMTP greeting.'
    ],
    [
      'id' => 'dovecot',
      'name' => 'Dovecot LMTP check',
      'service' => 'dovecot-mailcow',
      'description' => 'Connects to the internal LMTP listener and verifies the greeting.'
    ],
    [
      'id' => 'rspamd',
      'name' => 'Rspamd settings check',
      'service' => 'rspamd-mailcow',
      'description' => 'Calls the local Rspamd socket and verifies that scan settings are returned.'
    ],
    [
      'id' => 'acme',
      'name' => 'ACME failure state',
      'service' => 'acme-mailcow',
      'description' => 'Reads the ACME failure marker used by watchdog.'
    ],
    [
      'id' => 'containers',
      'name' => 'Container state summary',
      'service' => 'Docker API',
      'description' => 'Checks whether mailcow containers are running according to Docker.'
    ]
  ]
];

require_once $_SERVER['DOCUMENT_ROOT'] . '/inc/footer.inc.php';
