<?php

/**
 * DNS Multi-Protocol Proxy
 * * Supports: 
 * - DNS-over-UDP (Port 53)
 * - DNS-over-TCP (Port 53)
 * - DNS-over-TLS (Port 853)
 * - Proxies all to DoH Upstreams
 */

// Configuration
$config = [
    'udp_port'     => 53,
    'tcp_port'     => 53,
    'dot_port'     => 853,
    'listen_ip'    => '0.0.0.0',
    'cache_ttl'    => 600,
    'timeout'      => 4,
    'batch_size'   => 3,
    // Paths for DoT SSL (Required for Port 853)
    'ssl_cert'     => '/path/to/fullchain.pem', 
    'ssl_key'      => '/path/to/privkey.pem',
];

$upstreams = [
     "https://1.0.0.1/dns-query",
    "https://8.8.4.4/dns-query",
    "https://208.67.220.220/dns-query",
    "https://dns.nextdns.io/dns-query",
    "https://doh.opendns.com/dns-query",
    "https://unfiltered.adguard-dns.com/dns-query",
    "https://freedns.controld.com/p0",
    "https://public.dns.iij.jp/dns-query",
    "https://doh.dns.sb/dns-query",
    "https://jp.tiar.app/dns-query",
    "https://dns.dnsguard.pub/dns-query",
    "https://doh.cleanbrowsing.org/doh/security-filter/",
    "https://wikimedia-dns.org/dns-query",
    "https://doh.ffmuc.net/dns-query",
    "https://sky.rethinkdns.com/dns-query"
];

if (php_sapi_name() !== 'cli') {
    die("This script must be run from the CLI (command line).\n");
}

/**
 * Resolves a DNS binary message via DoH upstreams
 */
function resolve_via_doh($dns_wire_data) {
    global $upstreams, $config;
    
    $shuffled = $upstreams;
    shuffle($shuffled);
    $batch = array_slice($shuffled, 0, $config['batch_size']);

    $mh = curl_multi_init();
    $chs = [];

    foreach ($batch as $url) {
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_POST           => true,
            CURLOPT_POSTFIELDS     => $dns_wire_data,
            CURLOPT_HTTPHEADER     => [
                "Content-Type: application/dns-message",
                "Accept: application/dns-message",
            ],
            CURLOPT_TIMEOUT        => $config['timeout'],
            CURLOPT_SSL_VERIFYPEER => true,
        ]);
        curl_multi_add_handle($mh, $ch);
        $chs[] = $ch;
    }

    $response = null;
    do {
        curl_multi_exec($mh, $running);
        while ($info = curl_multi_info_read($mh)) {
            $handle = $info['handle'];
            if ($info['result'] === CURLE_OK && curl_getinfo($handle, CURLINFO_HTTP_CODE) === 200) {
                $temp = curl_multi_getcontent($handle);
                if ($temp && strlen($temp) > 12) { // Valid DNS header length
                    $response = $temp;
                    break 2; 
                }
            }
        }
        if ($running) curl_multi_select($mh, 0.1);
    } while ($running);

    foreach ($chs as $ch) {
        curl_multi_remove_handle($mh, $ch);
        curl_close($ch);
    }
    curl_multi_close($mh);

    return $response;
}

// 1. Setup UDP Socket (Standard DNS)
$udp_socket = socket_create(AF_INET, SOCK_DGRAM, SOL_UDP);
socket_bind($udp_socket, $config['listen_ip'], $config['udp_port']);
socket_set_nonblock($udp_socket);

// 2. Setup TCP Socket (Standard DNS)
$tcp_socket = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
socket_set_option($tcp_socket, SOL_SOCKET, SO_REUSEADDR, 1);
socket_bind($tcp_socket, $config['listen_ip'], $config['tcp_port']);
socket_listen($tcp_socket);
socket_set_nonblock($tcp_socket);

// 3. Setup DoT Socket (TLS)
// Note: Requires valid certs. For testing, you might need a stream_context approach instead of raw sockets.
$dot_ctx = stream_context_create([
    'ssl' => [
        'local_cert' => $config['ssl_cert'],
        'local_pk'   => $config['ssl_key'],
        'verify_peer' => false,
    ]
]);
$dot_server = @stream_socket_server(
    "tls://{$config['listen_ip']}:{$config['dot_port']}", 
    $errno, $errstr, STREAM_SERVER_BIND | STREAM_SERVER_LISTEN, $dot_ctx
);
if ($dot_server) stream_set_blocking($dot_server, false);

echo "DNS Proxy started...\nUDP: {$config['udp_port']}\nTCP: {$config['tcp_port']}\nDoT: {$config['dot_port']}\n";

// Main Loop
while (true) {
    // Handle UDP
    $buf = "";
    $from = "";
    $port = 0;
    if (@socket_recvfrom($udp_socket, $buf, 512, 0, $from, $port)) {
        $res = resolve_via_doh($buf);
        if ($res) socket_sendto($udp_socket, $res, strlen($res), 0, $from, $port);
    }

    // Handle TCP
    if ($client = @socket_accept($tcp_socket)) {
        // DNS over TCP prefixes message with 2-byte length
        $len_buf = socket_read($client, 2);
        if ($len_buf) {
            $len = unpack('n', $len_buf)[1];
            $query = socket_read($client, $len);
            $res = resolve_via_doh($query);
            if ($res) {
                $res_len = pack('n', strlen($res));
                socket_write($client, $res_len . $res);
            }
        }
        socket_close($client);
    }

    // Handle DoT (Simplified)
    if ($dot_server && ($dot_client = @stream_socket_accept($dot_server, 0))) {
        $len_buf = fread($dot_client, 2);
        if ($len_buf) {
            $len = unpack('n', $len_buf)[1];
            $query = fread($dot_client, $len);
            $res = resolve_via_doh($query);
            if ($res) {
                fwrite($dot_client, pack('n', strlen($res)) . $res);
            }
        }
        fclose($dot_client);
    }

    usleep(5000); // Prevent CPU spiking
}