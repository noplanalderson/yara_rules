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
        author = "Mr. Naeem"
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

rule EvilTwinWebShell
{
    meta:
        description = "Detects PHP Webshell 'Evil Twin' and its variants, including obfuscated file uploaders."
        author = "Mr. Naeem"
        date = "2025-04-29"
        version = "1.0"
        reference = "Targets webshells with 'evil_file' parameter, obfuscated file I/O functions, and 'Evil Twin' branding."

    strings:
        // PHP tags
        $php_tag1 = "<?=" ascii
        $php_tag2 = "<?php" ascii

        // Title and branding
        $title1 = "Evil Twin" nocase ascii
        $title2 = "EvilTwin" nocase ascii
        $title3 = "eviltw.in" nocase ascii

        // File upload parameter
        $file_param = "evil_file" nocase ascii

        // Obfuscated function names (exact matches from sample)
        $file_get_contents = "\"f\".\"i\".\"l\".\"e\".\"_\".\"g\".\"e\".\"t\".\"_\".\"c\".\"o\".\"n\".\"t\".\"e\".\"n\".\"t\".\"s\"" ascii
        $file_put_contents = "\"f\".\"i\".\"l\".\"e\".\"_\".\"p\".\"u\".\"t\".\"_\".\"c\".\"o\".\"n\".\"t\".\"e\".\"n\".\"t\".\"s\"" ascii
        $tmp_name = "\"t\".\"m\".\"p\".\"_\".\"n\".\"a\".\"m\".\"e\"" ascii
        $hex2bin = "\"h\".\"ex\".\"2b\".\"in\"" ascii
        $file_exists = "\"f\".\"il\".\"e_e\".\"xi\".\"st\".\"s\"" ascii
        $touch = "\"t\".\"ou\".\"ch\"" ascii
        $str_replace = "\"st\".\"r_re\".\"pla\".\"ce\"" ascii
        $basename = "\"ba\".\"sen\".\"ame\"" ascii

        // Common webshell function names (non-obfuscated)
        $func1 = "file_get_contents" ascii
        $func2 = "file_put_contents" ascii
        $func3 = "hex2bin" ascii
        $func4 = "eval" ascii
        $func5 = "exec" ascii

        // Generic obfuscation patterns (string concatenation)
        $obf1 = /\"[a-z]\"\.\"[a-z]\"\.\"[a-z]\"/ ascii  // Matches patterns like "f"."i"."l"
        $obf2 = /\"[a-z]{2,4}\"\.\"[a-z]{2,4}\"/ ascii  // Matches patterns like "file"."_put"

    condition:
        (
            // Core indicators: file upload parameter and obfuscated file I/O
            $file_param and 
            2 of ($file_get_contents, $file_put_contents, $tmp_name, $hex2bin, $file_exists, $touch, $str_replace, $basename)
        ) or
        (
            // Alternative: PHP tag, title, and suspicious functions
            1 of ($php_tag1, $php_tag2) and
            1 of ($title1, $title2, $title3) and
            1 of ($func1, $func2, $func3, $func4, $func5, $obf1, $obf2)
        )
}


rule HaxorWebshellv2
{
    meta:
        description = "Detect Haxor Webshell Variant, including obfuscated file downloader."
        author = "Mr. Naeem"
        date = "2025-05-27"
        version = "1.0"

    strings:
        // PHP tags
        $phptag1 = "<?php" ascii
        $phptag2 = "<?" ascii
        $phptag3 = "<script language=\"php\">" ascii

        // Web interface strings
        $title = "sysadmin access" ascii
        $form = "method=\"POST\"" nocase ascii
        $input = "type=\"password\"" ascii
        $submit = "type=\"submit\"" ascii

        // Function names
        $func1 = "is_logged_in" ascii
        $func2 = "hex2str" ascii
        $func3 = "geturlsinfo" ascii
        $func4 = "function_exists" ascii
        $func5 = "curl_setopt" ascii
        $func6 = "eval" ascii
        $func7 = "password_verify" ascii
        $func8 = "base64_decode" ascii

        // Variables (contextualized)
        $var1 = "$destiny" nocase ascii
        $var2 = "$dream" nocase ascii
        $var3 = "$_POST['password']" nocase ascii

        // Obfuscated function names (hex-encoded)
        $str1 = "73747265616d5f6765745f636f6e74656e7473" ascii // stream_get_contents
        $str2 = "666f70656e" ascii // fopen
        $str3 = "66696c655f6765745f636f6e74656e7473" ascii // file_get_contents
        $str4 = "6375726c5f65786563" ascii // curl_exec

        // Suspicious URL patterns
        $url1 = /https?:\/\/[a-zA-Z0-9.-]+\.pages\.dev/ ascii
        $url2 = /\.jpg/ ascii

        // Additional webshell behavior
        $cookie = "setcookie" ascii
        $hex_pattern = /[0-9a-f]{8,}/ ascii // Generic hex strings

    condition:
        any of ($phptag*) and (
            // High-confidence indicators: eval or curl with obfuscation
            (2 of ($func6, $func5, $str4, $func8)) or
            // Function-based detection
            (4 of ($func1, $func2, $func3, $func4, $func5, $func6, $func7, $func8))
         ) and (
            // Variable and obfuscation combo
            (2 of ($var1, $var2, $var3) and 1 of ($str1, $str2, $str3, $str4, $hex_pattern)) or
            // Web interface and obfuscation
            (4 of ($title, $form, $input, $submit, $str1, $str2, $str3, $str4, $url1, $url2, $cookie))
        )
}

rule LitespeedShell 
{
    meta:
        description = "Goodbye Litespeed WebShell"
        author = "Mr. Naeem"
        date = "2025-06-18"
        version = "1.0"
    
    strings:
        $func1 = "base64_encode" ascii
        $func2 = "base64_decode" ascii
        $func3 = "proc_open" ascii
        $func4 = "move_uploaded_file" ascii
        $func5 = "stream_get_contents" ascii
        $func6 = "file_get_contents" ascii
        $func7 = "deleteDirectory" ascii
        $func8 = "proc_close" ascii
        $func9 = "realpath" ascii
        $func10 = "stat" ascii
        $func11 = "is_writable" ascii
        $func12 = "is_resource" ascii
        $func13 = "file_exists" ascii
        $func14 = "file_put_contents" ascii
        $str1 = "cmd_input" nocase ascii
        $str2 = "view_file" nocase ascii
        $var1 = "$descriptorspec" nocase ascii
        $var2 = "$pipes" nocase ascii
        $var3 = "$command" nocase ascii
        $var4 = "$process" nocase ascii
        $var5 = /(\$file|\$path|\$filename|\$target)/ nocase ascii
        $pattern = /move_uploaded_file\s*\(\s*\$_FILES\[[^\]]+\]\["tmp_name"\]\s*,\s*\$[a-zA-Z0-9_]+\s*\)/

    condition:
        (
            (
                all of ($func3, $func5, $func8, $func11) and 
                any of ($var*)
            ) or 
            (
                (4 of ($func1, $func2, $func4, $func6, $func7, $func9, $func10, $func11, $func12, $func13, $func14)) and
                $pattern and
                any of ($var*) and
                any of ($str*)
            )
        ) or (
            any of ($func*) and $pattern
        )
}

rule FilesMan
{
    meta:
        description = "FilesMan WebShell"
        author = "Mr. Naeem"
        date = "2025-07-01"
        version = "1.0"

    strings:
        $php = "<?php" ascii
        $func1 = "session_start" nocase ascii
        $func2 = "set_time_limit" nocase ascii
        $func3 = "ini_set" nocase ascii
        $func4 = "clearstatcache" nocase ascii
        $func5 = "set_time_limit(0)" nocase ascii
        $sigFunc1 = "login_shell" nocase ascii
        $sigFunc2 = "suggest_exploit" nocase ascii
        $sigFunc3 = "unx()" nocase ascii
        $sigFunc4 = "s()" nocase ascii
        $sigFunc5 = "cmd" nocase ascii
        $sigFunc6 = "unlinkDir" nocase ascii
        $sigFunc7 = "remove_dot" nocase ascii
        $var1 = "$GLOBALS" ascii
        $var2 = "$gzdcjjppeft" ascii
        $var3 = "$iqxsvenssxc" ascii
        $var4 = "$klpelcka" ascii
        $str1 = "pwnki" ascii
        $str2 = "name=\"pass\"" ascii

    condition:
        $php and (
            any of ($func*) and 
            any of ($sigFunc*) and
            any of ($var*) and
            any of ($str*)
        )

}

rule SEOCloakingShell
{
    meta:
        description = "SEO Cloaking WebShell"
        author = "Mr. Naeem"
        date = "2025-07-14"
        version = "1.0"
    
    strings:
        $ua_check1 = "Googlebot" ascii
        $ua_check2 = "Google-Site-Verification" ascii
        $ua_check3 = "Google-InspectionTool" ascii
        $ua_check4 = "Googlebot-Mobile" ascii
        $ua_check5 = "Googlebot-News" ascii
        $ua_code  = "strpos($_SERVER['HTTP_USER_AGENT']" ascii
        $lang_code = "$_SERVER['HTTP_ACCEPT_LANGUAGE']" ascii
        $redir_code = "header(\"Location: https://" ascii
        $file_get  = "file_get_contents(" ascii
        $include   = "include(" ascii

    condition:
        3 of ($ua_check*) and
        $ua_code and
        $file_get and
        $include and
        $lang_code and
        $redir_code
}

rule Webshell_403
{
    meta:
        description = "SEO Cloaking WebShell"
        author = "Mr. Naeem"
        date = "2025-07-14"
        version = "1.0"
    
    strings:
        $conf1 = "$CONFIG" nocase ascii
        $conf2 = "$use_auth" nocase ascii
        $conf3 = "$auth_users" nocase ascii
        $conf4 = "$ip_ruleset" nocase ascii
        $conf5 = "$ip_silent" nocase ascii
        $conf6 = "$ip_whitelist" nocase ascii
        $conf7 = "$ip_blacklist" nocase ascii
        $func1 = "set_time_limit(" nocase ascii
        $func2 = "getClientIP(" nocase ascii
        $func3 = "FM_Zipper" nocase ascii
        $func4 = "FM_Config" nocase ascii
        $func5 = "curl_init(" nocase ascii
        $upload = "move_uploaded_file(" nocase ascii
        $script = "<script src=" ascii
        $session = "FM_SESSION_ID" ascii

    condition:
        3 of ($conf*) and 
        2 of ($func*) and
        $script and $session and $upload
}

rule GamblingPage
{
    meta:
        description = "Online Gambling Page"
        author = "Mr. Naeem"
        date = "2025-07-14"
        version = "1.0"

    strings:
        $html = "<html" nocase ascii
        $meta = "<meta name=\"google-site-verification\"" ascii
        $ampTag = "<link rel=\"amphtml\"" ascii
        $str1 = "shopify" nocase ascii
        $str2 = "belanja" nocase ascii
        $str3 = "keranjang" nocase ascii
        $str4 = "rating" nocas ascii
        $url1 = "https://www.k24klik.com" ascii
        $url2 = "https://res.cloudinary.com" ascii
        $url3 = "https://twitter.com" ascii
        $url4 = "https://facebook.com" ascii 

    condition:
        $html and $meta and $ampTag
        and (all of ($str*) or 1 of ($url*))

}

rule alfaWebShellTools
{
    meta:
        description = "Alfa Webshell Tools"
        author = "Mr. Naeem"
        date = "2025-07-14"
        version = "1.0"
    
    strings:
        $var1 = "USEFUL" ascii
        $var2 = "DOWNLOADERS" ascii
        $var3 = "VAR_NAMED" ascii
        $var4 = "VIRTUAL_DOMAINS" ascii
        $str1 = "/etc/virtual/domainowners" ascii
        $str2 = "/etc/named.conf" ascii
        $func1= "awk" ascii
        $func2= "uname" ascii
        $func3= "stat" ascii

    condition:
        all of ($var*) and all of ($str*) and all of ($func*)
}

rule alfaWebShellTools_in_C
{
    meta:
        description = "Alfa Webshell Tools"
        author = "Mr. Naeem"
        date = "2025-07-14"
        version = "1.0"
    
    strings:
        $include = "#include" ascii
        $var1 = "sockaddr_in" ascii
        $var2 = "server_addr" ascii
        $var3 = "sock" ascii
        $var4 = "server_ip" ascii
        $func1= "connectToServer" ascii
        $func2= "connect" ascii
        $func3= "execl" ascii
        $func4= "socket" ascii

    condition:
        $include and 2 of ($var*) and 2 of ($func*)
}