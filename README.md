# High Abuse Surface

Curated IP range lists of networks frequently associated with automated abuse.

The repository is data-first: you can consume the CIDR lists with any tooling.

Made on top of [known hostile networks](https://github.com/szepeviktor/debian-server-tools/tree/master/security/myattackers-ipsets).

## Log tool

A Python script that replaces client IPs with network names.

```shell
tail -f /var/log/apache2/*access.log | high-abuse-surface/ip-label.py
```

## Example tools

A WordPress MU plugin to stop Windows UA spoofing.

## Analyze HTTP requests from bots

```php
if (
    // Browsers send HTTP/2 request, except company proxies, firewalls
    ($_SERVER['SERVER_PROTOCOL'] ?? '') === 'HTTP/1.1'
    // Connection: header is not included in HTTP/2 requests
    && ($_SERVER['HTTP_CONNECTION'] ?? '') === 'keep-alive'
    // Accept: and Accept-Encoding: and Accept-Language: are always included
    && ($_SERVER['HTTP_ACCEPT'] ?? '') === '*/*'
    && ($_SERVER['HTTP_ACCEPT_ENCODING'] ?? '') === 'gzip, deflate'
    && !isset($_SERVER['HTTP_ACCEPT_LANGUAGE'])
    // User-Agent: header is always included
    && preg_match('#^Mozilla/.*Windows.*Chrome/#', ($_SERVER['HTTP_USER_AGENT'] ?? '')) === 1
    // Analyze referer
    && !isset($_SERVER['HTTP_REFERER'])
    // Analyze cookies
    && !isset($_SERVER['HTTP_COOKIE'])
) {
    http_response_code(403);
    echo 'Forbidden';
    exit;
}
```
