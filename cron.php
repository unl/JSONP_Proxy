<?php

error_reporting(E_ALL | E_STRICT);

// Define path to application directory
defined('APPLICATION_PATH')
|| define('APPLICATION_PATH', realpath(dirname(__FILE__) . '/src'));

// Define application environment
defined('APPLICATION_ENV')
|| define('APPLICATION_ENV', (getenv('APPLICATION_ENV') ? getenv('APPLICATION_ENV') : 'prod'));


set_include_path(implode(PATH_SEPARATOR, array(
    realpath(APPLICATION_PATH . '/../lib'),
    get_include_path()
)));

require_once APPLICATION_PATH . '/JsonpProxy.php';
$app = new JsonpProxy(APPLICATION_ENV, APPLICATION_PATH . '/etc/config.xml');
$app->cleanupMultipart();
