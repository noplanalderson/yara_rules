rule Detect_Malicious_PHP_NauPHP {
    meta:
        author = "Mr. Naeem"
        description = "Detects a malicious PHP script"
        created = "2024-12-16"
        version = "1.0"

    strings:
        $php_tag = "<?php"
        $session_start = "session_start();"
        $remote_function = "geturlsinfo(https://"
        $curl_exec = "curl_exec"
        $file_get_contents = "file_get_contents"
        $stream_get_contents = "stream_get_contents"
        $eval_execution = "eval('?>' . $a);"
        $check_login = "is_logged_in()"
        $password_field = "<input type=\"password\" id=\"password\" name=\"password\">"

    condition:
        all of ($php_tag, $session_start, $eval_execution) and
        (2 of ($remote_function, $curl_exec, $file_get_contents, $stream_get_contents, $check_login, $password_field))
}
