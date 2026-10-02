<?php
/** Public login URL round-trip contract, without booting WordPress or a database. */
$source = file_get_contents(__DIR__ . '/../access-platform-sso.php');
function source_method($source, $name) {
    $start = strpos($source, 'function ' . $name . '(');
    $start = strrpos(substr($source, 0, $start), "\n") + 1;
    $brace = strpos($source, '{', $start);
    $depth = 1;
    for ($end = $brace + 1; $depth; $end++) {
        if ($source[$end] === '{') $depth++;
        if ($source[$end] === '}') $depth--;
    }
    return substr($source, $start, $end - $start);
}
eval('class LoginUrlSubject {' . source_method($source, 'get_login_url') . source_method($source, 'get_safe_redirect_url') . '}');
function home_url() { return 'https://libertyclassroom.com/'; }
function admin_url($suffix) { return home_url() . 'wp-admin/' . $suffix; }
function wp_parse_url($url, $component) { return parse_url($url, $component); }
function esc_url_raw($url, $protocols) { return $url; }
function wp_validate_redirect($url, $fallback) {
    $host = parse_url($url, PHP_URL_HOST);
    return $host && $host !== 'libertyclassroom.com' ? $fallback : $url;
}
// WordPress re-encodes existing query values, but expects new values to be pre-encoded.
// https://developer.wordpress.org/reference/functions/add_query_arg/
function add_query_arg($key, $value, $url = null) {
    if (is_array($key)) { $new = $key; $url = $value; }
    else $new = array($key => $value);
    $parts = explode('?', $url, 2);
    parse_str($parts[1] ?? '', $existing);
    $values = array_merge(array_map('urlencode', $existing), $new);
    $pairs = array();
    foreach ($values as $k => $v) $pairs[] = $k . '=' . $v;
    return $parts[0] . '?' . implode('&', $pairs);
}
function expect($condition, $message) {
    if (!$condition) throw new RuntimeException($message);
}
$subject = new LoginUrlSubject();
foreach (array(
    'https://libertyclassroom.com/wp-admin/admin-post.php?action=tsol_library_authorize&client_id=library&state=abc&code_challenge=xyz&scope=&redirect_uri=https%3A%2F%2Flibrary.libertyclassroom.com%2Fcallback',
    'https://libertyclassroom.com/course/?q=freedom%20%26%20economics&filter=one%2Btwo#lesson',
    '/members/?one=1&two=2',
) as $destination) {
    parse_str(parse_url($subject->get_login_url($destination), PHP_URL_QUERY), $outer);
    expect(array_keys($outer) === array('action', 'return_to'), 'Nested authorization parameters escaped into the SSO start query');
    expect($outer['return_to'] === $destination, 'Return URL did not round-trip exactly');
}
parse_str(parse_url($subject->get_login_url(''), PHP_URL_QUERY), $empty);
expect($empty === array('action' => 'access_sso_start'), 'Empty destination changed default behavior');
parse_str(parse_url($subject->get_login_url('https://attacker.example/?action=bad'), PHP_URL_QUERY), $unsafe);
expect($unsafe['return_to'] === home_url(), 'External return URL bypassed same-site validation');
echo "Login return URL round trips and redirect safety passed.\n";
