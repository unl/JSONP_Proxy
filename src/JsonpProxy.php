<?php

class JsonpProxy
{
    const LOG_ERROR  = 1;
    const LOG_ACCESS = 2;

    const CORS_MODE_IGNORE_EMPTY  = 1;
    const CORS_MODE_COPY_SELF     = 2;
    const CORS_MODE_REQUIRE       = 3;

    protected $_logRegistry = array();

    /**
     * The application autoloader
     *
     * @var Zend_Loader_Autoloader
     */
    protected $_autoloader;

    /**
     * The database adapter for caching preflight results
     *
     * @var Zend_Db_Adadpter_Abstract
     */
    protected $_cacheDb;

    /**
     * The request object
     *
     * @var Zend_Controller_Request_Http
     */
    protected $_request;

    /**
     * The response object
     *
     * @var Zend_Controller_Response_Http
     */
    protected $_response;

    /**
     * Application environment
     *
     * @var string
     */
    protected $_environment;

    /**
     * The default configuration options
     *
     * @var unknown_type
     */
    protected $_defaultOptions = array(
        'log_mask' => 0,
        'allowed_methods' => array(),
        'allowed_hosts' => array(),
        'client' => array(),
        'multipart_timeout' => 24,
        'enforce_cors' => false,
        'cors_max_age' => 300,
    );

    protected $_corsSimpleMethods = array(
        'HEAD',
        'GET',
        'POST',
    );

    protected $_corsSimpleHeaders = array(
        'accept' => true,
        'accept-language' => true,
        'content-language' => true,
        'last-event-id' => true,
        'content-type' => array (
            'application/x-www-form-urlencoded',
            'multipart/form-data',
            'text/plain',
        )
    );

    protected $_corsSimpleResponseHeaders = array(
        'cache-control',
        'content-language',
        'content-type',
        'expires',
        'last-modified',
        'pragma',
    );

    /**
     * Application configuration
     *
     * @var array
     */
    protected $_options;

    public function __construct($environment, $options = null)
    {
        $this->_environment = (string) $environment;

        require_once 'Zend/Loader/Autoloader.php';
        $this->_autoloader = Zend_Loader_Autoloader::getInstance();

        require_once dirname(__FILE__) . '/JsonpProxy/Exception.php';

        foreach (array(Zend_Http_Client::HEAD, Zend_Http_Client::GET) as $method) {
            $this->_defaultOptions['allowed_methods'][] = $method;
        }

        $this->_cacheDb = Zend_Db::factory('Pdo_Sqlite', array(
            'dbname' => $this->_getBasePath('data') . '/cors.db'
        ));

        if (null !== $options) {
            if (is_string($options)) {
                $options = $this->_loadConfig($options);
            } elseif ($options instanceof Zend_Config) {
                $options = $options->toArray();
            } elseif (!is_array($options)) {
                throw new JsonpProxy_Exception('Invalid options provided; must be location of config file, a config object, or an array');
            }

            $this->setOptions($options);
        }
    }

    /**
     * Connects to the CORS database and checks to ensure the cache table exists.
     * Also, call <code>cleanCacheDb</code> to clear outdated entries.
     *
     * @return JsonpProxy
     */
    public function initCacheDb()
    {
        $db = $this->_cacheDb;
        if (!$db->describeTable('cache')) {
            $schema = file_get_contents($this->_getBasePath('data') . '/schema.sql');
            $db->getConnection()->exec($schema);
        }

        $this->cleanCacheDb();

        return $this;
    }

    /**
     * Deletes expired cache entries from the database
     *
     * @return JsonpProxy
     */
    public function cleanCacheDb()
    {
        $db = $this->_cacheDb;
        $db->delete('cache', 'created_at + max_age <= ' . time());

        return $this;
    }

    /**
     * Loads a configuration file and returns the options.
     *
     * @param string $file
     * @throws JsonpProxy_Exception
     * @return Ambiguous
     */
    protected function _loadConfig($file)
    {
        $environment = $this->getEnvironment();
        $suffix      = pathinfo($file, PATHINFO_EXTENSION);
        $suffix      = ($suffix === 'dist')
                     ? pathinfo(basename($file, ".$suffix"), PATHINFO_EXTENSION)
                     : $suffix;

        switch (strtolower($suffix)) {
            case 'ini':
                $config = new Zend_Config_Ini($file, $environment);
                break;

            case 'xml':
                $config = new Zend_Config_Xml($file, $environment);
                break;

            case 'json':
                $config = new Zend_Config_Json($file, $environment);
                break;

            case 'yaml':
            case 'yml':
                $config = new Zend_Config_Yaml($file, $environment);
                break;

            case 'php':
            case 'inc':
                $config = include $file;
                if (!is_array($config)) {
                    throw new JsonpProxy_Exception('Invalid configuration file provided; PHP file does not return array value');
                }
                return $config;
                break;

            default:
                throw new JsonpProxy_Exception('Invalid configuration file provided; unknown config type');
        }

        return $config->toArray();
    }

    /**
     * Sets the application configuration options
     *
     * @param array $options
     * @return JsonpProxy
     */
    public function setOptions(array $options)
    {
        $this->_options = array_merge($this->_defaultOptions, $options);

        $this->_options['allowed_methods'] = array_map("strtoupper", $this->_options['allowed_methods']);

        return $this;
    }

    /**
     * Returns the application environment
     *
     * @return string
     */
    public function getEnvironment()
    {
        return $this->_environment;
    }

    /**
     * Runs the proxy client by taking a request and issuing a response.
     *
     * @param Zend_Controller_Request_Abstract $request
     * @param Zend_Controller_Response_Abstract $response
     * @throws JsonpProxy_Exception
     * @return JsonpProxy
     */
    public function run(Zend_Controller_Request_Abstract $request = null, Zend_Controller_Response_Abstract $response = null)
    {
        if (null === $request) {
            $request  = new Zend_Controller_Request_Http();
        }
        $this->_request = $request;

        if (null === $response) {
            $response = new Zend_Controller_Response_Http();
        }
        $this->_response = $response;

        $ip = $request->getClientIp();
        $ua = $request->getServer('HTTP_USER_AGENT', '');
        $referer = $request->getServer('HTTP_REFERER', '');
        $isSecure = $request->getScheme() == 'https' ? true : false;

        try {

            // A callback must exist for every request
            if (!$callback = $request->getParam('c')) {
                throw new JsonpProxy_Exception('Missing callback');
            }

            // Handles multi-part requests
            if ($request->getParam('mp')) {
                $multipartTotal = intval($request->getParam('mp'));
                $multipartOffset = intval($request->getParam('mo', -1));
                if ($multipartOffset < 0) {
                    throw new JsonpProxy_Exception('Invalid multipart request, missing request offset');
                }
                if (!$multipartData = $request->getParam('md')) {
                    throw new JsonpProxy_Exception('Invalid multipart request, missing request data/payload');
                }

                $data = $this->_loadMultipart($ip, $callback);

                // Validate existing multipart info
                if (!empty($data)) {
                    if ($data['callback'] !== $callback || $data['total'] !== $multipartTotal) {
                        throw new JsonpProxy_Exception('Invalid multipart request, data mismatch');
                    }
                } else {
                    $data = array(
                        'callback' => $callback,
                        'total' => $multipartTotal,
                        'payload' => array(),
                    );
                }

                if (isset($data['payload'][$multipartOffset])) {
                    throw new JsonpProxy_Exception('Invalid multipart request, duplicate request offset received');
                }

                $data['payload'][$multipartOffset] = $multipartData;

                if (count($data['payload']) == $data['total']) {
                    $this->_removeMultipart($ip, $callback);
                    // Load the proper params into the request and process as normal
                    $params = array();
                    parse_str(implode('', $data['payload']), $params);

                    if (!isset($params['c']) || $params['c'] !== $callback) {
                        throw new JsonpProxy_Exception('Invalid multipart request, callback in payload mismatch');
                    }

                    $request->setParams($params);
                } else {
                    $this->_saveMultipart($ip, $callback, $data);
                    $response->setHttpResponseCode(202)
                        ->setHeader('Content-Type', 'text/javascript')
                        ->setBody('// Successful multipart request, awaiting remaining data');

                    $this->log($this->_formatAccessLog(array(
                        'ip' => $ip,
                        'method' => 'MULTIPART',
                        'url' => '-',
                        'status' => $response->getHttpResponseCode(),
                        'referer' => $referer,
                        'user-agent' => $ua,
                    )));
                    $response->sendResponse();

                    return $this;
                }
            }

            // Handles normal requests
            if (!$url = $request->getParam('u')) {
                throw new JsonpProxy_Exception('Missing target URL');
            }
            try {
                /* @var $uri Zend_Uri_Http */
                $uri = Zend_Uri::factory($url);
                if (!method_exists($uri, 'getHost') || !$this->_isHostAllowed($uri->getHost())) {
                    throw new JsonpProxy_Exception('Target URL\'s host is not allowed');
                }

                if ($isSecure && $uri->getScheme() != 'https') {
                    throw new JsonpProxy_Exception('Cannot cross HTTP/HTTPS protocols');
                }
            } catch (Zend_Uri_Exception $ex) {
                throw new JsonpProxy_Exception('Invalid target URL');
            }

            $method = strtoupper($request->getParam('m'));
            if (!in_array($method, $this->getOption('allowed_methods'))) {
                throw new JsonpProxy_Exception('Missing or invalid HTTP method');
            }

            // The request is valid

            $clientConfig = $this->getOption('client', array());
            if ($ua) {
                $clientConfig['useragent'] = $ua;
            }
            $client = new Zend_Http_Client($uri, $clientConfig);

            $credentialsFlag = false;
            if ($request->getParam('au') || $request->getParam('ap')) {
                $credentialsFlag = true;
                $client->setAuth($request->getParam('au'), $request->getParam('ap'));
            }

            $data = $request->getParam('d');
            $headers = $request->getParam('h', array());
            $contentType = false;

            foreach ($headers as $name => $value) {
                $name = strtolower($name);

                if ($name == 'content-type') {
                    $contentType = strtolower($value);
                } elseif ($name == 'referer' || $name == 'x-forwarded-for') {
                    unset($headers[$name]);
                }
            }
            unset($name, $value);

            $client->setHeaders('X-Forwarded-For', $ip);
            if ($referer) {
                $client->setHeaders('Referer', $referer);
            }

            if ($data && $method == Zend_Http_Client::GET) {
                if ($contentType == Zend_Http_Client::ENC_URLENCODED) {
                    $query = $client->getUri()->getQuery();
                    if (!empty($query)) {
                        $query .= '&';
                    }
                    $query .= $data;
                    $client->getUri()->setQuery($query);
                    unset($data);
                }
            }

            $corsClient = null;
            if ($corsMode = $this->getOption('enforce_cors')) {
                $corsCondition = true;
                $origin = $referer;

                if (empty($origin)) {
                    switch ($corsMode) {
                        case self::CORS_MODE_IGNORE_EMPTY:
                            $corsCondition = false;
                            break;
                        case self::CORS_MODE_COPY_SELF:
                            $origin = $request->getHttpHost();
                            if (empty($origin)) {
                                throw new JsonpProxy_Exception('CORS request cannot copy host');
                            }
                            $origin = ($isSecure ? 'https://' : 'http://') . $origin . '/';
                            break;
                        case self::CORS_MODE_REQUIRE:
                            throw new JsonpProxy_Exception('CORS request missing origin/referer');
                    }
                }

                if ($corsCondition) {
                    $refererUri = Zend_Uri::factory($origin);
                    $origin = $refererUri->getScheme() . '://' . $refererUri->getHost() . $refererUri->getPort();

                    // allow for transparent redirects even though we don't follow the Origin header spec
                    // $client->setConfig(array('maxredirects' => 0));
                    $client->setHeaders('Origin', $origin);
                    $corsClient = clone $client;

                    if (!$this->_isSimpleRequest($method, $headers)
                        && !$this->_doPreflightRequest($corsClient, $method, $headers, $origin, $credentialsFlag)) {
                        throw new JsonpProxy_Exception('CORS Preflight denied request');
                    }
                }
            }

            if ($headers) {
                $client->setHeaders($headers);
            }

            if ($data) {
                $client->setRawData($data, $contentType);
            }

            $proxyResponse = $client->request($method);

            if ($proxyResponse->isRedirect()) {
                throw new JsonpProxy_Exception('Redirection not allowed');
            }

            // check for CORS
            $responseHeaders = $proxyResponse->getHeaders();
            if (null !== $corsClient) {
                if (!$this->_doResourceCheck($origin, $credentialsFlag, $proxyResponse)) {
                    throw new JsonpProxy_Exception('CORS Request Network Failure');
                }

                $allowedHeaders = $this->_parseMultiValueCorsHeader($proxyResponse->getHeader('Access-Control-Expose-Headers'), true);

                foreach (array_keys($responseHeaders) as $name) {
                    if (!$this->_isSimpleResponseHeader(strtolower($name), $allowedHeaders)) {
                        unset($responseHeaders[$name]);
                    }
                }
            }

            $result = array(
                'status' => $proxyResponse->getStatus(),
                'statusText' => $proxyResponse->getMessage(),
                'responseHeaders' => $responseHeaders,
                'responseText' => $proxyResponse->getBody(),
            );

            $response->setHttpResponseCode($result['status'])
                ->setHeader('Content-Type', 'text/javascript')
                ->setBody($callback . '('
                    . ($this->getEnvironment() == 'dev'
                    ? Zend_Json::prettyPrint(Zend_Json::encode($result))
                    : Zend_Json::encode($result)) . ');');


        } catch (JsonpProxy_Exception $ex) {
            $this->log($this->_formatErrorLog(array(
                'ip' => $ip,
                'message' => $ex->getMessage(),
            )), self::LOG_ERROR, Zend_Log::ERR);
            $this->_initBadResponse($ex->getMessage());
        } catch (Zend_Http_Client_Exception $ex) {
            $this->log($this->_formatErrorLog(array(
                'ip' => $ip,
                'message' => $ex->getMessage(),
            )), self::LOG_ERROR, Zend_Log::ERR);
            $this->_initBadResponse($ex->getMessage());
        }

        $this->log($this->_formatAccessLog(array(
            'ip' => $ip,
            'method' => isset($method) ? $method : '-',
            'url' => isset($url) ? $url : '-',
            'status' => $response->getHttpResponseCode(),
            'referer' => $referer,
            'user-agent' => $ua,
        )));

        $response->sendResponse();

        return $this;
    }

    /**
     * Does a preflight CORS request, if not cached, and checks for success
     *
     * @param Zend_Http_Client $client
     * @param string $method
     * @param array $headers
     * @param string $origin
     * @param boolean $credentialsFlag
     * @return boolean
     */
    protected function _doPreflightRequest($client, $method, $headers, $origin, $credentialsFlag)
    {
        $this->initCacheDb();

        $url = $client->getUri(true);
        $matches = $this->_getCacheDbMatches($origin, $url, $credentialsFlag);
        $maxAgeLimit = $this->getOption('cors_max_age', 0);
        $acrh = array_keys(array_change_key_case($headers));
        sort($acrh);

        $methodOk = false;
        foreach ($matches as $row) {
            if ($row['method'] === $method) {
                $methodOk = true;
                break;
            }
        }

        $headersOk = true;
        foreach ($acrh as $header) {
            $headerOk = false;
            foreach ($matches as $row) {
                if ($row['header'] === $header) {
                    $headerOk = true;
                }
                break;
            }
            if (!$headerOk) {
                $headersOk = false;
                break;
            }
        }

        if ($methodOk && $headersOk) {
            return true;
        }

        $client->setHeaders('Access-Control-Request-Method', $method);
        $acrh = implode(',', $acrh);
        if ($acrh) {
            $client->setHeaders('Access-Control-Request-Headers', $acrh);
        }
        $client->setAuth(false);

        try {
            $corsResponse = $client->request(Zend_Http_Client::OPTIONS);
            if ($corsResponse->isRedirect() || !$this->_doResourceCheck($origin, $credentialsFlag, $corsResponse)) {
                $this->_clearCache($origin, $url);
                return false;
            }
        } catch (Exception $ex) {
            $this->_clearCache($origin, $url);
            return false;
        }

        $allowedMethods = $this->_parseMultiValueCorsHeader($corsResponse->getHeader('Access-Control-Allow-Methods'));
        $allowedHeaders = $this->_parseMultiValueCorsHeader($corsResponse->getHeader('Access-Control-Allow-Headers'), true);

        if (!$this->_isSimpleMethod($method, $allowedMethods)
            || !$this->_isSimpleHeaders($headers, $allowedHeaders)) {
            $this->_clearCache($origin, $url);
            return false;
        }

        $acma = $corsResponse->getHeader('Access-Control-Max-Age');
        if ($maxAgeLimit) {
            if (null === $acma || is_array($acma)) {
                $acma = $maxAgeLimit;
            }
        }

        if (!$acma) {
            return true;
        }

        $matches = $this->_getCacheDbMatches($origin, $url, $credentialsFlag);
        foreach ($allowedMethods as $aMethod) {
            $matched = false;
            foreach ($matches as $row) {
                if ($row['method'] === $method) {
                    $matched = true;
                    $this->_cacheDb->update('cache', array(
                        'max_age' => $acma,
                        'created_at' => time(),
                    ), array(
                        'origin = ?' => $origin,
                        'url = ?' => $url,
                        'credentials' => $credentialsFlag,
                        'method' => $aMethod,
                    ));
                    break;
                }
            }
            if (!$matched) {
                $this->_cacheDb->insert('cache', array(
                    'origin' => $origin,
                    'url' => $url,
                    'max_age' => $acma,
                    'credentials' => $credentialsFlag,
                    'method' => $aMethod,
                    'header' => '',
                    'created_at' => time(),
                ));
            }
        }

        foreach ($allowedHeaders as $header) {
            $matched = false;
            foreach ($matches as $row) {
                if ($row['header'] === $header) {
                    $matched = true;
                    $this->_cacheDb->update('cache', array(
                        'max_age' => $acma,
                        'created_at' => time(),
                    ), array(
                        'origin = ?' => $origin,
                        'url = ?' => $url,
                        'credentials' => $credentialsFlag,
                        'header' => $header,
                    ));
                    break;
                }
            }
            if (!$matched) {
                $this->_cacheDb->insert('cache', array(
                    'origin' => $origin,
                    'url' => $url,
                    'max_age' => $acma,
                    'credentials' => $credentialsFlag,
                    'method' => '',
                    'header' => $header,
                    'created_at' => time(),
                ));
            }
        }

        return true;
    }

    /**
     * Checks the preflight cache database for all entries that match the
     * given request params.
     *
     * @param string $origin
     * @param string $url
     * @param boolean $credentialsFlag
     */
    protected function _getCacheDbMatches($origin, $url, $credentialsFlag)
    {
        $db = $this->_cacheDb;

        $select = $db->select()
            ->from('cache')
            ->where('origin = ?', $origin)
            ->where('url = ?', $url)
            ->where('credentials = ?', $credentialsFlag)
            ->where('created_at + max_age > ?', time());

        $stmt = $db->query($select);

        return $stmt->fetchAll();
    }

    /**
     * Removes specific entries from the preflight cache for a the given
     * request params.
     *
     * @param unknown_type $origin
     * @param unknown_type $url
     * @return JsonpProxy
     */
    protected function _clearCache($origin, $url)
    {
        $this->_cacheDb->delete('cache', array(
            'origin = ?' => $origin,
            'url = ?' => $url,
        ));

        return $this;
    }

    /**
     * Parses a multi-value CORS header and returns an array of the header values
     *
     * @param string|array $header
     * @param boolean $caseInsensitive
     * @return array
     */
    protected function _parseMultiValueCorsHeader($header, $caseInsensitive = false)
    {
        $values = array();

        if (is_string($header)) {
            $header = array($header);
        }
        if (is_array($header)) {
            foreach ($header as $value) {
                $newValues = array_map('trim', explode(',', $value));
                if ($caseInsensitive) {
                    $newValues = array_map('strtolower', $newValues);
                }
                $values = array_merge($allowedMethods, $newValues);
            }
        }

        return $values;
    }

    /**
     * Performs a CORS resource response check and returns the success value
     *
     * @param string $origin
     * @param boolean $credentialsFlag
     * @param Zend_Http_Response $response
     * @return boolean
     */
    protected function _doResourceCheck($origin, $credentialsFlag, $response)
    {
        $acao = $response->getHeader('Access-Control-Allow-Origin');

        if (is_array($acao)) {
            return false;
        }

        $acao = trim($acao);
        if ($acao != $origin && ($credentialsFlag || $acao != '*')) {
            return false;
        }

        $acac = $response->getHeader('Access-Control-Allow-Credentials');
        if ($credentialsFlag && (is_array($acac) || trim($acac) !== 'true')) {
            return false;
        }

        return true;
    }

    /**
     * Formats the input array of params into a string for the access log
     *
     * @param array $info
     * @return string
     */
    protected function _formatAccessLog($info)
    {
        $msg = "[client {$info['ip']}] \"{$info['method']} {$info['url']}\" {$info['status']} \"{$info['referer']}\" \"{$info['user-agent']}\"";
        return $msg;
    }

    /**
     * Formats the input array of params into a string for the error log
     *
     * @param array $info
     * @return string
     */
    protected function _formatErrorLog($info)
    {
        $msg = "[client {$info['ip']}] {$info['message']}";
        return $msg;
    }

    /**
     * Returns the file path for a multipart proxy request data file
     *
     * @param string $ip
     * @param string $callback
     * @return string
     */
    protected function _getMultipartFilePath($ip, $callback)
    {
        $filenameHash = md5($ip . $callback);
        return $this->_getBasePath('var/tmp/') . 'mp_' . $filenameHash;
    }

    /**
     * Loads and unserializes a multipart proxy request data file
     *
     * @param string $ip
     * @param string $callback
     * @return mixed
     */
    protected function _loadMultipart($ip, $callback)
    {
        $multipartPath = $this->_getMultipartFilePath($ip, $callback);
        if (!file_exists($multipartPath)) {
            return array();
        }

        $data = unserialize(file_get_contents($multipartPath));
        if (!is_array($data)) {
            return array();
        }

        return $data;
    }

    /**
     * Serializes and writes a multipart proxy request to the filesystem
     *
     * @param string $ip
     * @param string $callback
     * @param mixed $data
     * @return JsonpProxy
     */
    protected function _saveMultipart($ip, $callback, $data)
    {
        $multipartPath = $this->_getMultipartFilePath($ip, $callback);
        file_put_contents($multipartPath, serialize($data), LOCK_EX);

        return $this;
    }

    /**
     * Removes a multipart proxy request file if it exists
     *
     * @param string $ip
     * @param string $callback
     * @return JsonpProxy
     */
    protected function _removeMultipart($ip, $callback)
    {
        $multipartPath = $this->_getMultipartFilePath($ip, $callback);
        if (file_exists($multipartPath)) {
            unlink($multipartPath);
        }

        return $this;
    }

    /**
     * Checks the filesystem for multipart proxy request files that have
     * expired according to the <code>multipart_timeout</code> option
     *
     * @return JsonpProxy
     */
    public function cleanupMultipart()
    {
        $multipartTimeout = $this->getOption('multipart_timeout');
        if (!$multipartTimeout) {
            return $this;
        }
        $now = time();

        foreach (glob($this->_getBasePath('var/tmp/') . 'mp_*') as $filename) {
            $lastModified = filemtime($filename);
            if ($lastModified + $multipartTimeout <= $now) {
                unlink($filename);
            }
        }

        return $this;
    }

    /**
     * Returns a configuration option or the given default on empty
     *
     * @param string $option
     * @param mixed $default
     * @return mixed
     */
    public function getOption($option, $default = null)
    {
        return isset($this->_options[$option]) ? $this->_options[$option] : $default;
    }

    /**
     * Checks the configured option <code>allowed_hosts</code> to ensure the
     * given host is allowed to be access with this proxy.
     *
     * @param string $host
     * @return boolean
     */
    protected function _isHostAllowed($host)
    {
        $host = strtolower($host);
        $allowedHosts = $this->getOption('allowed_hosts', array());

        // Allow same orgin requests if no other host are specified
        if (empty($allowedHosts) && $this->_request->getHttpHost()) {
            $thisHost = explode(':', $this->_request->getHttpHost(), 2);
            $allowedHosts[] = $thisHost[0];
        }

        foreach ($allowedHosts as $aHost) {
            $aHost = strtolower($aHost);
            if ($aHost[0] === '.') {
                $reHost = '/(?:\\.|^)' . preg_quote(substr($aHost, 1), '/') . '$/';
                if (preg_match($reHost, $host)) {
                    return true;
                }
            } else {
                if ($aHost === $host) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Returns if the given method and headers make up a simple CORS request
     * as defined by the spec.
     *
     * @see http://www.w3.org/TR/cors/
     * @param unknown_type $method
     * @param unknown_type $headers
     * @return boolean
     */
    protected function _isSimpleRequest($method, $headers)
    {
        if (!$this->_isSimpleMethod($method) || !$this->_isSimpleHeaders($headers)) {
            return false;
        }

        return true;
    }

    /**
     * Returns if the given method is simple as defined by CORS spec.
     * Optionally, an array of additional, acceptible methods can be passed
     * (as is used after a preflight request).
     *
     * @see http://www.w3.org/TR/cors/
     * @param string $method
     * @param array $additionalMethods
     * @return boolean
     */
    protected function _isSimpleMethod($method, $additionalMethods = array())
    {
        if (!in_array($method, $this->_corsSimpleMethods)
            && !in_array($method, $additionalMethods)) {
            return false;
        }

        return true;
    }

    /**
     * Returns if the given array of header names and values are simple as
     * defined by the CORS spec.
     * Optionally, an array of additional, acceptible header names can be passed
     * (as is used after a preflight request).
     *
     * @see http://www.w3.org/TR/cors/
     * @param array $headers
     * @param array $additionalHeaders
     * @return boolean
     */
    protected function _isSimpleHeaders($headers, $additionalHeaders = array())
    {
        foreach ($headers as $name => $value) {
            $name = strtolower($name);
            $value = strtolower($value);
            if (!array_key_exists($name, $this->_corsSimpleHeaders)
                && !in_array($name, $additionalHeaders)) {
                return false;
            }

            $valueNoParam = explode(';', $value, 2);
            $valueNoParam = $valueNoParam[0];
            if (is_array($this->_corsSimpleHeaders[$name])
                && !in_array($valueNoParam, $this->_corsSimpleHeaders[$name])) {
                return false;
            }
        }

        return true;
    }

    /**
     * Returns if the given header name is simple according to the CORS spec.
     * Optionally, an array of additional, acceptible header names can be passed
     * (as is used after a preflight request).
     *
     * @see http://www.w3.org/TR/cors/
     * @param string $header
     * @param array $additionalHeaders
     * @return boolean
     */
    protected function _isSimpleResponseHeader($header, $additionalHeaders = array())
    {
        if (!in_array($header, $this->_corsSimpleResponseHeaders)
            && !in_array($header, $additionalHeaders)) {
            return false;
        }

        return true;
    }

    /**
     * Sets the response object to a failure
     *
     * @param Zend_Controller_Response_Http $response
     * @param string $body
     * @param boolean $exit
     * @return JsonpProxy
     */
    protected function _initBadResponse($body)
    {
        if ($this->_response) {
            $this->_response->setHttpResponseCode(400);
            $this->_response->setBody($body);
        }

        return $this;
    }

    /**
     * Sets the log type bitmask
     *
     * @param unknown_type $mask
     * @return JsonpProxy
     */
    public function enableLog($mask)
    {
        $this->_logMask = $mask;
        return $this;
    }

    /**
     * Attempt to log a message to a specific log
     *
     * @param string $message The text to log
     * @param int $type       The log to write to
     * @param int $priority   A logging level from <code>Zend_Log</code>
     * @return JsonpProxy
     */
    public function log($message, $type = self::LOG_ACCESS, $priority = Zend_Log::INFO)
    {
        if (!$this->_isLogEnabled($type)) {
            return $this;
        }

        $logger = $this->_getLogger($type);
        if (!$logger) {
            return $this;
        }

        $logger->log($message, $priority);
        return $this;
    }

    /**
     * Checks the log bitmask for a specific log type
     *
     * @param int $type
     * @return boolean
     */
    protected function _isLogEnabled($type)
    {
        return $this->getOption('log_mask') & $type;
    }

    /**
     * Retrieve the <code>Zend_Log</code> instance for a specific log type
     *
     * @param int $type
     * @return Zend_Log|boolean
     */
    protected function _getLogger($type)
    {
        if (isset($this->_logRegistry[$type])) {
            return $this->_logRegistry[$type];
        }

        $logFile = false;
        switch ($type) {
            case self::LOG_ERROR:
                $logFile = 'error.log';
                break;
            case self::LOG_ACCESS:
                $logFile = 'access.log';
                break;
        }

        if ($logFile) {
            $base = $this->_getBasePath('var/log/');
            $writer = new Zend_Log_Writer_Stream($base . $logFile);
            $logger = new Zend_Log($writer);
            $this->_logRegistry[$type] = $logger;
            return  $logger;
        }

        return false;
    }

    /**
     * Returns the file path to a resource at the install base of the application
     *
     * @param string $path
     * @return string
     */
    protected function _getBasePath($path = '')
    {
        $path = ltrim($path, '/');

        if (defined('APPLICATION_PATH')) {
            return realpath(APPLICATION_PATH . '/..') . '/' . $path;
        }

        return dirname(dirname(__FILE__)) . '/' . $path;
    }
}
