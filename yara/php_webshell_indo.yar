rule Detect_Malicious_PHP_NauPHP {
    meta:
        author = "Mr. Naeem"
        description = "Detects a malicious PHP script created or used by Indonesian Hacktivist (NauPHP)"
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

rule Detect_Malicious_PHP_Chankro {
    meta:
        author = "Mr. Naeem"
        description = "Detects a malicious PHP script created or used by Indonesian Hacktivist (Chankro)"
        created = "2024-12-16"
        version = "1.1"

    strings:
        $php_tag = "<?php"
        $title = "BypassServ By HaxorSec" nocase
        $cmd_input = "$_POST['cmd_input']"
        $cmd_biasa = "$_POST['cmd_biasa']"
        $chankro = "$a($full . '/chankro.so'"
        $acpid = "$a($full . '/acpid.socket'"

    condition:
        all of ($php_tag, $chankro, $acpid) and
        (1 of ($title, $cmd_biasa, $cmd_input, $chankro, $acpid))
}

rule Detect_Malicious_PHP_Galerz {
    meta:
        author = "Mr. Naeem"
        description = "Detects a malicious PHP script created or used by Indonesian Hacktivist (Galerz)"
        created = "2025-03-20"
        version = "1.0"
    
    strings:
        $php_tag = "<?php"
        $title = "gALerZ xh33L b4cKdDoRz" nocase
        $func1 = "get_magic_quotes_gpc"
        $func2 = "is_writable"
        $func3 = "is_readable"
        $func4 = "file_get_contents"
        $str1  = "<input type=\"submit\" value=\"gALerZ\" />" nocase wide ascii
        $str2  = "$_GET['filesrc']" nocase
        $str3  = "$_POST['opt']" nocase
    
    condition:
        all of ($php_tag, $func1, $func2, $func3, $func4) and
        (1 of ($title, $str1, $str2, $str3))
}

rule MaliciousHTAccess 
{
    meta:
        description = "Detects potentially malicious .htaccess files with suspicious rewrite rules and file restrictions"
        author = "Security Engineer"
        date = "2025-03-20"
        version = "1.1"

    strings:
        $rewriteEngine = "RewriteEngine on"
        $rewriteRuleIndex = "RewriteRule ^(.*)$ index.php/$1 [L,QSA]"
        $rewriteCondFile = "RewriteCond %{REQUEST_FILENAME} !-f"
        $rewriteCondDir = "RewriteCond %{REQUEST_FILENAME} !-d"

        $redirectToHttps = "RewriteCond %{HTTPS} off"
        $redirectRuleHttps = "RewriteRule ^(.*)$ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]"

        $filesMatchMalicious = /<FilesMatch \".{1,100}(php|asp|aspx|exe|pht|shtm|phar|bak|pdf|zip|doc|txt|jpg|jpeg|png|gif|unknown).{0,100}\">/
        $denyAll = "Deny from all"
        
        $wpIncludesBlock = "RewriteRule ^wp-includes/[^/]+\\.php$ - [F,L]"
        $wpAdminBlock = "RewriteRule ^wp-admin/includes/ - [F,L]"
        
        $cpanelPHPHandler = "AddHandler application/x-httpd-ea-php"

    condition:
        (all of ($rewriteEngine, $rewriteRuleIndex, $rewriteCondFile, $rewriteCondDir)) or 
        (all of ($redirectToHttps, $redirectRuleHttps)) or 
        (all of ($filesMatchMalicious, $denyAll)) or 
        (any of ($wpIncludesBlock, $wpAdminBlock)) or 
        ($cpanelPHPHandler)
}
