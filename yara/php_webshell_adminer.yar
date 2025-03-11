rule Detect_Malicious_PHP_Adminer {
    meta:
        author = "Mr. Naeem"
        description = "Detects a malicious PHP Adminer"
        score = 60
        hash = "2fd7e6d8f987b243ab1839249551f62adce19704c47d3d0c8dd9e57ea5b9c6b3"
        created = "2025-03-11"
        version = "1.0"

    strings:
        $php_tag = "<?php"
        $error_func = "adminer_errors"
        $title = "<title>',$mi,'</title>"
        $adminer_cookie = "$_COOKIE[\"adminer_version\"]" nocase
        $adminer_cookie2 = "$_COOKIE[\"adminer_permanent\"]" nocase
        $adminer_cookie3 = "$_COOKIE[\"adminer_key\"]" nocase
        $adminer_pwd = "get_temp_dir().\"/adminer.key\"" wide ascii
        $adminer_icon = "lzw_decompress" wide ascii

    condition:
        all of ($php_tag, $error_func, $adminer_cookie, $adminer_cookie2, $adminer_cookie3) and
        (1 of ($title, $adminer_pwd, $adminer_icon)) and
        filesize < 3000KB and 1 of them
}
