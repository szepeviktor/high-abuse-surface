<?php

/**
 * Plugin Name: Stop Windows UA spoofing
 * Description: Block state-changing operations for spoofed Windows UAs
 * Plugin URI: https://github.com/szepeviktor/high-abuse-surface
 */

if (
    ($_SERVER['SERVER_PROTOCOL'] ?? '') === 'HTTP/1.1'
    && preg_match('#^Mozilla/5.*Windows#', ($_SERVER['HTTP_USER_AGENT'] ?? '')) === 1
    && (empty($_SERVER['HTTP_ACCEPT']) || empty($_SERVER['HTTP_ACCEPT_ENCODING']) || empty($_SERVER['HTTP_ACCEPT_LANGUAGE']))
    && !is_read_only_request()
) {
    error_log('State-changing operation stopped: ua_spoofing_write_request');
    http_response_code(403);

?>
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>403 Forbidden</title>
  <style>
    body { font-family: serif; margin: 24px; color: #000; background: #fff; }
    h1 { font-size: 2rem; margin: 0 0 0.5rem; }
    hr { border: 0; border-top: 1px solid #aaa; margin: 1rem 0; }
    p { margin: 0.5rem 0; max-width: 75ch; }
    code { font-family: monospace; font-size: 0.95em; }
    .muted { color: #444; }
  </style>
</head>
<body>
  <h1>Forbidden</h1>
  <p>You don&apos;t have permission to access this resource.</p>
  <hr>

  <p><strong>Reason</strong></p>
  <p class="muted">
    This request was identified as an automated or non-standard client attempt to perform a
    <strong>state-changing</strong> (non read-only) operation.
    For security and service stability, only read-only requests are allowed from such clients.
  </p>

  <p class="muted">
    Detected pattern:
    <code>browser-like User-Agent</code> + <code>non read-only request</code>.
  </p>

  <hr>
  <p>If you are a customer, please retry using a normal browser session.</p>
</body>
</html>
<?php

    exit;
}

/**
 * Decide whether the current HTTP request is read-only.
 */
function is_read_only_request(): bool
{
    if (php_sapi_name() === 'cli') {
        return true;
    }

    if (!in_array($_SERVER['REQUEST_METHOD'] ?? '', ['GET', 'HEAD', 'OPTIONS'])) {
        return false;
    }

    // Strong WordPress signals for non-read-only execution contexts.
    if ((defined('DOING_AJAX') && DOING_AJAX) || (defined('DOING_CRON') && DOING_CRON)) {
        return false;
    }

    if (defined('XMLRPC_REQUEST') && XMLRPC_REQUEST) {
        return false;
    }

    if (defined('WP_ADMIN') && WP_ADMIN) {
        return false;
    }

    // Method override tricks: treat as non-read-only.
    if (
        (!empty($_SERVER['HTTP_X_HTTP_METHOD_OVERRIDE']))
        || (!empty($_GET['_method']) && is_string($_GET['_method']))
        || (!empty($_POST['_method']) && is_string($_POST['_method']))
    ) {
        return false;
    }

    // Any request body strongly suggests a state-changing or at least suspicious request.
    $contentLength = isset($_SERVER['CONTENT_LENGTH']) && is_string($_SERVER['CONTENT_LENGTH'])
        ? (int) $_SERVER['CONTENT_LENGTH']
        : 0;

    $transferEncoding = isset($_SERVER['HTTP_TRANSFER_ENCODING']) && is_string($_SERVER['HTTP_TRANSFER_ENCODING'])
        ? strtolower($_SERVER['HTTP_TRANSFER_ENCODING'])
        : '';

    if ($contentLength > 0 || strpos($transferEncoding, 'chunked') !== false) {
        return false;
    }

    // If PHP parsed POST/files, it is definitely not read-only (even if method says GET).
    if (!empty($_POST) || !empty($_FILES)) {
        return false;
    }

    // Disallow sensitive or action-oriented parameters (CSRF/nonces/login/update patterns).
    static $denyParams = [
        '_wpnonce',
        'wpnonce',
        'nonce',
        'token',
        'password',
        'pass',
        'pwd',
        'log',
        'login',
        'user',
        'username',
        'email',
        'action',
        'update',
        'save',
        'delete',
        'remove',
        'create',
        'set',
        'reset',
    ];

    foreach ($denyParams as $key) {
        // Presence is suspicious, even if empty (conservative policy).
        if (array_key_exists($key, $_REQUEST)) {
            return false;
        }
    }

    $path = wp_parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);

    if ($path === wp_parse_url(wp_login_url('', true), PHP_URL_PATH)) {
        return false;
    }

    // REST: prefer core truth when available (constant), otherwise fall back to route detection.
    $isRest = false;

    if (defined('REST_REQUEST') && REST_REQUEST) {
        $isRest = true;
    } elseif (!empty($_GET['rest_route']) && is_string($_GET['rest_route'])) {
        $isRest = true;
    } elseif ($path !== '') {
        $prefix = '/wp-json';
        $needleA = $prefix . '/';

        // Match only at the beginning and with boundary (exact prefix or prefix + '/').
        if ($path === $prefix || strpos($path, $needleA) === 0) {
            $isRest = true;
        }
    }

    if ($isRest) {
        $route = detect_rest_route_from_current_request($path, $_GET);

        /**
         * Filter: allowlist of REST routes considered read-only.
         *
         * Use regex patterns (delimited), e.g. '#^/wp/v2/posts(?:/|$)#'.
         *
         * @param string[] $allowlist
         */
        $allowlist = (array) apply_filters('mu_read_only_rest_routes', [
            '#^/oembed/1\.0/#',
            '#^/wp/v2/(posts|pages)(?:/|$)#',
        ]);

        foreach ($allowlist as $pattern) {
            if (!is_string($pattern) || $pattern === '') {
                continue;
            }

            // Assume patterns are valid (developer responsibility); no error silencing.
            if (preg_match($pattern, $route) === 1) {
                return true;
            }
        }

        return false;
    }

    // Expensive reads: treat as non-read-only by default (attackers love these).
    if (array_key_exists('s', $_GET)) {
        return false;
    }

    // Otherwise, a plain frontend GET/HEAD/OPTIONS without suspicious markers.
    return true;
}

/**
 * Detect the current REST route path from the current request.
 *
 * @param string               $path Parsed URL path from REQUEST_URI
 * @param array<string, mixed> $get  Usually $_GET
 *
 * @return string Route starting with '/', e.g. '/wp/v2/posts'
 */
function detect_rest_route_from_current_request(string $path, array $get): string
{
    if (!empty($get['rest_route']) && is_string($get['rest_route'])) {
        $route = $get['rest_route'];

        return $route[0] === '/' ? $route : '/' . $route;
    }

    if ($path === '') {
        return '/';
    }

    // Avoid calling rest_get_url_prefix() in MU context; assume default.
    $prefix = '/wp-json';
    $needleA = $prefix . '/';

    if ($path === $prefix) {
        return '/';
    }

    if (strpos($path, $needleA) !== 0) {
        return '/';
    }

    $route = substr($path, strlen($prefix));
    if ($route === false || $route === '') {
        return '/';
    }

    return $route[0] === '/' ? $route : '/' . $route;
}
