<?php
require_once $_SERVER['DOCUMENT_ROOT'] . '/inc/prerequisites.inc.php';
require_once $_SERVER['DOCUMENT_ROOT'] . '/inc/triggers.admin.inc.php';

protect_route(['admin']);

require_once $_SERVER['DOCUMENT_ROOT'] . '/inc/header.inc.php';
$_SESSION['return_to'] = $_SERVER['REQUEST_URI'];

$js_minifier->add('/web/js/site/system_check.js');

$template = 'system_check.twig';
$template_data = [
  'system_checks' => [
    [
      'id' => 'external',
      'name' => 'Open relay check',
      'category' => 'Security',
      'description' => 'Asks mailcow external checks whether this instance is reachable as an open relay.'
    ],
    [
      'id' => 'nginx',
      'name' => 'Web UI check',
      'category' => 'Core services',
      'description' => 'Checks that the internal nginx endpoint serving mailcow UI responds.'
    ],
    [
      'id' => 'redis',
      'name' => 'Redis ping',
      'category' => 'Core services',
      'description' => 'Authenticates to Redis and verifies a PONG response.'
    ],
    [
      'id' => 'mysql',
      'name' => 'MySQL query',
      'category' => 'Core services',
      'description' => 'Runs a lightweight metadata query through the UI database connection.'
    ],
    [
      'id' => 'postfix',
      'name' => 'Postfix SMTP check',
      'category' => 'Mail flow',
      'description' => 'Runs a minimal SMTP dialog against the internal Postfix listener.'
    ],
    [
      'id' => 'dovecot',
      'name' => 'Dovecot listener check',
      'category' => 'Mail access',
      'description' => 'Checks IMAP and ManageSieve listeners from the UI container.'
    ],
    [
      'id' => 'rspamd',
      'name' => 'Rspamd settings check',
      'category' => 'Spam filtering',
      'description' => 'Calls the local Rspamd socket and verifies that scan settings are returned.'
    ],
    [
      'id' => 'tls',
      'name' => 'TLS certificate check',
      'category' => 'TLS',
      'description' => 'Checks the configured mailcow hostname certificate over HTTPS.'
    ],
    [
      'id' => 'acme',
      'name' => 'ACME failure state',
      'category' => 'TLS',
      'description' => 'Reads the ACME failure marker used by the background monitor.'
    ],
    [
      'id' => 'containers',
      'name' => 'Container state summary',
      'category' => 'Core services',
      'description' => 'Checks whether mailcow containers are running according to Docker.'
    ]
  ]
];

require_once $_SERVER['DOCUMENT_ROOT'] . '/inc/footer.inc.php';
