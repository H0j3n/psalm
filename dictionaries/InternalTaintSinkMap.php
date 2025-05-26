<?php

use Psalm\Type\TaintKind;

// This maps internal function names to sink types that we don’t want to end up there

/**
 * @var non-empty-array<string, non-empty-list<list<TaintKind::*>>>
 */
return [
// 'exec' => [['shell']],
// 'create_function' => [[], ['eval']],
// // Only include functions that actually execute/include files, not just read them
// 'parse_ini_file' => [['include']],  // Can execute PHP code
// 'readfile' => [['include']],        // Can include files
// 'header' => [['header']],
// 'symlink' => [['file']],
// 'tempnam' => [['file']],
// 'igbinary_unserialize' => [['unserialize']],
// 'ldap_search' => [[], ['ldap'], ['ldap']],
// 'mysqli_query' => [[], ['sql']],
// 'mysqli::query' => [['sql']],
// 'mysqli_real_query' => [[], ['sql']],
// 'mysqli::real_query' => [['sql']],
// 'mysqli_multi_query' => [[], ['sql']],
// 'mysqli::multi_query' => [['sql']],
// 'mysqli_prepare' => [[], ['sql']],
// 'mysqli::prepare' => [['sql']],
// 'mysqli_stmt::__construct' => [[], ['sql']],
// 'mysqli_stmt_prepare' => [[], ['sql']],
// 'mysqli_stmt::prepare' => [['sql']],
// 'passthru' => [['shell']],
// 'pcntl_exec' => [['shell']],
// 'pg_exec' => [[], ['sql']],
// 'pg_prepare' => [[], [], ['sql']],
// 'pg_put_line' => [[], ['sql']],
// 'pg_query' => [[], ['sql']],
// 'pg_query_params' => [[], ['sql']],
// 'pg_send_prepare' => [[], [], ['sql']],
// 'pg_send_query' => [[], ['sql']],
// 'pg_send_query_params' => [[], ['sql'], []],
// 'setcookie' => [['cookie'], ['cookie']],
// 'shell_exec' => [['shell']],
// 'system' => [['shell']],
// 'unserialize' => [['unserialize']],
// 'popen' => [['shell']],
// 'proc_open' => [['shell']],
// 'curl_init' => [['ssrf']],
// 'curl_setopt' => [[], [], ['ssrf']],
// 'getimagesize' => [['ssrf']],
// WordPress LFI - Enhanced detection for CVE-2025-2294 and similar vulnerabilities
'get_template_part' => [['include']],
'load_template' => [['include']],
// Extract function can lead to variable overwriting and LFI
'extract' => [['include']],
];
