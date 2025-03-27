<?php
$allowedDomains = [
    "aniplaynow.live",
    "localhost:3000",
    "localhost:3001",
];

$origin = isset($_SERVER['HTTP_ORIGIN']) ? $_SERVER['HTTP_ORIGIN'] : (isset($_SERVER['HTTP_REFERER']) ? $_SERVER['HTTP_REFERER'] : '');

$allowed = false;
foreach ($allowedDomains as $allowedDomain) {
    if (strpos($origin, $allowedDomain) !== false) {
        $allowed = true;
        break;
    }
}

if (!$allowed) {
    http_response_code(403);
    header('Content-Type: application/json');
    echo json_encode(["error" => "Access denied, Domain not allowed in Whitelist. "]);
    exit;
}

header("Access-Control-Allow-Origin: $origin");
header("Access-Control-Allow-Methods: GET, OPTIONS");
header("Access-Control-Allow-Headers: Origin, X-Requested-With, Content-Type, Accept");

$allowedExtensions = ['ts', 'png', 'jpg', 'webp', 'ico', 'html', 'js', 'css', 'txt', 'm3u8'];

if (!isset($_GET['url']) || empty($_GET['url'])) {
    http_response_code(400);
    echo json_encode(["error" => "URL parameter is required"]);
    exit;
}

$url = trim($_GET['url']);

if (!filter_var($url, FILTER_VALIDATE_URL) || preg_match('/^(file|php|data):/', $url)) {
    http_response_code(400);
    echo json_encode(["error" => "Invalid or blocked URL"]);
    exit;
}

$extension = strtolower(pathinfo(parse_url($url, PHP_URL_PATH), PATHINFO_EXTENSION));

if (!in_array($extension, $allowedExtensions)) {
    http_response_code(403);
    echo json_encode(["error" => "File type not allowed"]);
    exit;
}

$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $url);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 5);
curl_setopt($ch, CURLOPT_TIMEOUT, 15);
curl_setopt($ch, CURLOPT_HTTPHEADER, [
    "Referer: https://megacloud.club/",
    "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Accept: */*"
]);

$response = curl_exec($ch);
$contentType = curl_getinfo($ch, CURLINFO_CONTENT_TYPE);
$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
curl_close($ch);

if ($response === false || $httpCode !== 200) {
    http_response_code($httpCode !== 200 ? $httpCode : 500);
    echo json_encode(["error" => "Failed to fetch resource", "status" => $httpCode]);
    exit;
}

if ($extension === 'ts') {
    header("Content-Type: video/mp2t");
    header("Cache-Control: max-age=3600, public");
    echo $response;
    exit;
}

if ($extension === 'm3u8') {
    $baseUrl = preg_replace('/[^\/]+$/', '', $url);
    $modifiedContent = preg_replace_callback('/(.*?\.(m3u8|ts|jpg|png|webp|html|js|css|ico|txt))/', function ($matches) use ($baseUrl) {
        $absoluteUrl = strpos($matches[1], 'http') === 0 ? $matches[1] : $baseUrl . ltrim($matches[1], '/');
        return "https://cdn.aniplaynow.live/?url=" . urlencode($absoluteUrl);
    }, $response);

    $filteredContent = preg_replace('/#EXT-X-MEDIA:TYPE=AUDIO[^\r\n]*/', '', $modifiedContent);

    header("Content-Type: application/vnd.apple.mpegurl");
    header("Cache-Control: max-age=3600, public");
    echo $filteredContent;
    exit;
}

header("Content-Type: $contentType");
header("Cache-Control: max-age=3600, public");
echo $response;
