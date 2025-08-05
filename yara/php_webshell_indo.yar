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
        $str4 = "rating" nocase ascii
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
        $include and any of ($var*) and any of ($func*)
}

rule simplePHPUpload {
    
    meta:
        description = "Simple PHP Upload"
        author = "Mr. Naeem"
        date = "2025-07-29"
        version = "1.0"

    strings:
        $php = "<?php" ascii
        $formUpload = "enctype=multipart/form-data" ascii
        $pattern1 = /copy\s*\(\s*\$_FILES\s*\[\s*['"]?\w+['"]?\]\s*\[\s*['"]?tmp_name['"]?\]\s*,\s*\$_FILES\s*\[\s*['"]?\w+['"]?\]\s*\[\s*['"]?name['"]?\]\s*\)/
        $pattern2 = /move_uploaded_file\s*\(\s*\$_FILES\[[^\]]+\]\["tmp_name"\]\s*,\s*\$[a-zA-Z0-9_]+\s*\)/
        $str1 = "sukses" nocase ascii
        $str2 = "gagal" nocase ascii

    condition:
        $php and $formUpload and 1 of ($pattern*) and all of ($str*)
}

rule PHP_Backdoor_Eval_Remote_Code_Execution
{
    meta:
        description = "Detects PHP backdoor using eval()"
        author = "TangerangKota-CSIRT"
        date = "2025-08-05"
        severity = "critical"
        category = "backdoor"
        reference = "Custom analysis"

    strings:
        $eval_pattern1 = /eval\s*\(\s*\$[a-zA-Z_][a-zA-Z0-9_]*\s*\.\s*get\s*\(/
        $eval_pattern2 = /eval\s*\(\s*['"][^'"]{1,100}['"]\s*\.\s*get\s*\(/
        
        $b64_github_raw = "aHR0cHM6Ly9yYXcuZ2l0aHVidXNlcmNvbnRlbnQuY29tL"
        $b64_pastebin = "aHR0cHM6Ly9wYXN0ZWJpbi5jb20v"
        $b64_raw_content = "cmF3LmdpdGh1YnVzZXJjb250ZW50"
        
        $suspicious_var1 = /\$[a-zA-Z_]{1,20}[a-zA-Z0-9_]{0,20}\s*=\s*.{1,100};/  
        $suspicious_var2 = /\$[a-zA-Z_][a-zA-Z0-9_]{1,20}\s*=\s*['"]<[?]php['"];/  

        $curl_function = /function\s+get\s*\(\s*\$url\s*\)\s*\{.{1,500}curl_init.{1,300}CURLOPT_URL.{1,300}curl_exec.{1,300}\}/s

        $obfuscated_eval1 = /\$[a-zA-Z_][a-zA-Z0-9_]{1,20}\s*=\s*['"]eval['"]\s*;.{1,100}\$[a-zA-Z_][a-zA-Z0-9_]{1,20}\s*\(/
        $obfuscated_eval2 = /call_user_func\s*\(\s*['"]eval['"]\s*,/

    condition:
        (uint32(0) == 0x3c3f7068 or uint16(0) == 0x3c3f) and
        (
            ($eval_pattern1 or $eval_pattern2) and
            ($b64_github_raw or $b64_pastebin or $b64_raw_content) and
            $curl_function
        ) or
        (
            ($suspicious_var1 or $suspicious_var2) and
            ($eval_pattern1 or $eval_pattern2 or $obfuscated_eval1 or $obfuscated_eval2)
        ) or
        (
            #b64_github_raw >= 1 and
            #eval_pattern1 >= 1 and
            #curl_function >= 1 and
            #suspicious_var1 >= 1
        )
}

rule PHP_Backdoor_Base64_Remote_Execution
{
    meta:
        description = "Detects PHP backdoor using base64 encoded remote URLs"
        author = "TangerangKota-CSIRT"
        date = "2025-08-05"
        severity = "high"
        category = "backdoor"

    strings:
        $b64_decode_eval = /eval\s*\(\s*[^)]{1,100}base64_decode\s*\(/
        $b64_http = /aHR0cHM6Ly9bA-Za-z0-9+\/]{10,100}={0,2}/
        $b64_raw_github = "aHR0cHM6Ly9yYXcuZ2l0aHVidXNlcmNvbnRlbnQu"

        $b64_php_ext = /[A-Za-z0-9+\/]{0,20}cGhw[A-Za-z0-9+\/]{0,20}/
        $b64_txt_ext = /[A-Za-z0-9+\/]{0,20}dHh0[A-Za-z0-9+\/]{0,20}/

        $remote_include = /include\s*\(\s*[^)]{1,100}base64_decode/
        $remote_require = /require\s*\(\s*[^)]{1,100}base64_decode/

    condition:
        (uint32(0) == 0x3c3f7068 or uint16(0) == 0x3c3f) and
        (
            ($b64_decode_eval and ($b64_http or $b64_raw_github)) or
            (($remote_include or $remote_require) and ($b64_php_ext or $b64_txt_ext)) or
            (#b64_http >= 2 and $b64_decode_eval)
        )
}

rule PHP_Suspicious_Curl_Remote_Execution
{
    meta:
        description = "Detects suspicious curl usage for remote code execution"
        author = "TangerangKota-CSIRT"
        date = "2025-08-05"
        severity = "medium"
        category = "suspicious"

    strings:
        $curl_init = "curl_init"
        $curl_exec = "curl_exec"
        $curl_setopt = "CURLOPT_RETURNTRANSFER"

        $curl_eval = /curl_exec[^;]{1,200};.{1,200}eval\s*\(/s

        $remote_url1 = /https?:\/\/[a-zA-Z0-9.-]{1,100}\/[^\s'")}]*(\.php|\.txt|backdoor|shell)/
        $remote_url2 = /raw\.githubusercontent\.com/
        $remote_url3 = /pastebin\.com\/raw/

        $dynamic_call = /call_user_func\s*\(\s*\$[a-zA-Z_]{1,20}/
        $variable_func = /\$[a-zA-Z_][a-zA-Z0-9_]{0,20}\s*\(/

    condition:
        (uint32(0) == 0x3c3f7068 or uint16(0) == 0x3c3f) and
        all of ($curl_*) and
        (
            $curl_eval or
            ($remote_url1 or $remote_url2 or $remote_url3) or
            ($dynamic_call and ($curl_init or $curl_exec)) or
            $variable_func
        )
}

rule PHP_Backdoor_WordPress_Config_Infection
{
    meta:
        description = "Detects malicious code injection in WordPress configuration files"
        author = "TangerangKota-CSIRT"
        date = "2025-08-05"
        severity = "critical"
        category = "backdoor"
        reference = "WordPress wp-config.php infection"

    strings:
        $wp_config1 = "wp-config.php"
        $wp_config2 = "DB_NAME"
        $wp_config3 = "WordPress"
        $wp_config4 = "ABSPATH"

        $malicious_eval = /eval\s*\([^)]{1,100}get\s*\([^)]{1,100}base64_decode/
        $malicious_func = /function\s+get\s*\([^)]{1,100}\)\s*\{.{1,300}curl_/s

        $before_abspath = /eval.{1,300}ABSPATH/s
        $after_db_config = /DB_HOST.{1,300}eval/s

    condition:
        any of ($wp_config*) and
        ($malicious_eval or $malicious_func) and
        (
            $before_abspath or $after_db_config or 
            (filesize < 50KB and #malicious_eval >= 1)
        )
}

rule PHP_Anti_False_Positive_Whitelist
{
    meta:
        description = "Whitelist rule to prevent false positives on legitimate code"
        author = "TangerangKota-CSIRT"
        date = "2025-08-05"
        severity = "info"
        category = "whitelist"

    strings:
        $laravel = "Illuminate\\"
        $symfony = "Symfony\\"
        $wordpress_core = "wp-includes/version.php"
        $drupal_core = "core/lib/Drupal"

        $legitimate_eval1 = /eval\s*\(\s*['"][^'"]{1,100}return[^'"]{1,100}['"]/
        $legitimate_eval2 = /eval\s*\(\s*\$[a-zA-Z_]{1,20}\s*\.\s*['"]\s*;\s*['"]/

        $phpunit = "PHPUnit"
        $composer = "composer"
        $test_file = /test.{0,100}\.php$/

    condition:
        any of ($laravel, $symfony, $wordpress_core, $drupal_core, $phpunit, $composer) or
        $test_file or
        $legitimate_eval1 or $legitimate_eval2
}

rule PHP_Hexencoded_Remote_Loader
{
    meta:
        description = "Detects PHP webshell using hex-encoded URLs for remote code loading"
        author = "TangerangKota-CSIRT"
        date = "2025-08-05"
        severity = "critical"
        category = "webshell"
        reference = "Hex-encoded remote PHP script loader with multiple download methods"
        
    strings:
        // Hex-encoded URL patterns (common GitHub raw URLs)
        $hex_github1 = "68747470733a2f2f7261772e676974687562" // https://raw.github
        $hex_github2 = "68747470733a2f2f7261772e6769746875622e636f6d" // https://raw.github.com
        $hex_https = "68747470733a2f2f" // https://
        
        // Hex to string conversion function
        $hex2str_func = /function\s+hex2str\s*\(\s*\$\w+\s*\)/
        $hexdec_usage = "hexdec(" nocase
        $chr_hexdec = /chr\s*\(\s*hexdec\s*\(/
        
        // Multiple download methods
        $file_get_contents = "file_get_contents(" nocase
        $curl_download = /function\s+downloadWithCurl/
        $fopen_download = /function\s+downloadWithFopen/
        $allow_url_fopen = "'allow' . '_ur' . 'l_fo' . 'pe' . 'n'" 
        
        // Obfuscated function names
        $obfuscated_curl = "'c' . 'u' . 'rl' . '_i' . 'n' . 'i' . 't'"
        $obfuscated_allow = /['"]a['"][\s]*\.[\s]*['"]llow['"][\s]*\.[\s]*['"]_ur['"][\s]*\.[\s]*['"]l_fo['"][\s]*\.[\s]*['"]pe['"][\s]*\.[\s]*['"]n['"]/
        
        // Execution patterns
        $eval_phpscript = /eval\s*\(\s*['"]>\?['"][\s]*\.[\s]*\$\w+\s*\)/
        // $die_message = "Gagal mendownload script PHP"
        
    condition:
        uint16(0) == 0x3c3f and // PHP file
        filesize < 50KB and
        
        // Must have hex-to-string conversion
        $hex2str_func and
        $hexdec_usage and
        $chr_hexdec and
        
        // Must have hex-encoded URL
        (
            $hex_github1 or
            $hex_github2 or
            ($hex_https and #hex_https >= 1)
        ) and
        
        // Must have multiple download methods
        $file_get_contents and
        (
            $curl_download or
            $fopen_download
        ) and
        
        // Must have eval execution
        $eval_phpscript and
        
        // Obfuscation indicators
        (
            $obfuscated_curl or
            $obfuscated_allow or
            $allow_url_fopen
        )
}

rule PHP_Multi_Method_Remote_Loader
{
    meta:
        description = "Detects PHP scripts with multiple remote loading methods and fallbacks"
        author = "TangerangKota-CSIRT"
        date = "2025-08-05"
        severity = "high"
        category = "webshell"
        
    strings:
        $download1 = "downloadWithFileGetContents" nocase
        $download2 = "downloadWithCurl" nocase  
        $download3 = "downloadWithFopen" nocase
        
        $fallback1 = /if\s*\(\s*\$\w+\s*===\s*false\s*\)/
        $eval_pattern = /eval\s*\(\s*['"]>\?['"][\s]*\.[\s]*\$\w+/
        
        $ini_get = "ini_get(" nocase
        $function_exists = "function_exists(" nocase
        
    condition:
        uint16(0) == 0x3c3f and // PHP file
        filesize < 100KB and
        
        // Must have at least 2 download methods
        2 of ($download*) and
        
        // Must have fallback logic
        #fallback1 >= 2 and
        
        // Must have eval execution
        $eval_pattern and
        
        // Must check for PHP capabilities
        $ini_get and
        $function_exists
}

rule Hex_Encoded_GitHub_Raw_Access
{
    meta:
        description = "Detects hex-encoded GitHub raw content URLs in PHP scripts"
        author = "TangerangKota-CSIRT"
        date = "2025-08-05"
        severity = "medium"
        category = "suspicious"
        
    strings:
        // Specific hex patterns for GitHub raw URLs
        $hex_raw_github = "68747470733a2f2f7261772e676974687562" // https://raw.github
        $hex_githubusercontent = "68747470733a2f2f7261772e6769746875622e636f6d" // https://raw.github.com
        
        // ALFA webshell specific hex
        $hex_alfa_url = "68747470733a2f2f7261772e6769746875622e636f6d2f43616c6c4d654261746f7361792f414c46415f313333372f6d61696e2f616c66612e706870"
        
        // Hex conversion functions
        $hex_to_str = /function\s+\w*hex\w*str\w*\s*\(/
        $str_conversion = /for\s*\([^}]*hexdec[^}]*chr\s*\(/
        
    condition:
        uint16(0) == 0x3c3f and // PHP file
        
        (
            // Specific ALFA webshell hex
            $hex_alfa_url or
            
            // Generic GitHub raw hex patterns
            (
                ($hex_raw_github or $hex_githubusercontent) and
                ($hex_to_str or $str_conversion)
            )
        )
}

rule PHP_Obfuscated_Function_Names
{
    meta:
        description = "Detects PHP scripts using string concatenation to obfuscate function names"
        author = "TangerangKota-CSIRT"
        date = "2025-08-05"
        severity = "medium"
        category = "obfuscation"
        
    strings:
        // Obfuscated curl_init
        $obf_curl = /'c'[\s]*\.[\s]*'u'[\s]*\.[\s]*'rl'[\s]*\.[\s]*'_i'[\s]*\.[\s]*'n'[\s]*\.[\s]*'i'[\s]*\.[\s]*'t'/
        
        // Obfuscated allow_url_fopen
        $obf_allow = /'a'[\s]*\.[\s]*'llow'[\s]*\.[\s]*'_ur'[\s]*\.[\s]*'l_fo'[\s]*\.[\s]*'pe'[\s]*\.[\s]*'n'/
        
        // Generic obfuscation patterns
        $concat_pattern1 = /['"][a-z]?['"][\s]*\.[\s]*['"][a-z]+['"][\s]*\.[\s]*['"][a-z_]+['"]/
        // $concat_pattern1 = /['"]\s*\.\s*['"]/
        $concat_pattern2 = /function_exists\s*\(\s*['"][a-z]?['"][\s]*\.[\s]*['"][a-z]+['"]/
        $concat_pattern3 = /ini_get\s*\(\s*['"][a-z]?['"][\s]*\.[\s]*['"][a-z_]+['"]/
        
    condition:
        uint16(0) == 0x3c3f and // PHP file
        
        (
            // Specific obfuscated functions
            $obf_curl or
            $obf_allow or
            
            // Generic concatenation patterns
            2 of ($concat_pattern*)
        )
}

rule PHP_Backdoor_Remote_Eval_Login_Bypass
{
    meta:
        description = "Detects PHP backdoor with remote eval and fake login using MD5-hashed password"
        author = "TangerangKota-CSIRT"
        date = "2025-08-05"
        severity = "high"
        reference = "https://raw.githubusercontent.com/GanestSeven/backdoor-mini/main/aw.txt"

    strings:
        // Auth bypass via cookie
        $cookie_check = /\$_COOKIE\s*\[\s*['"]user_id['"]\s*\]\s*===\s*['"][a-zA-Z0-9]+['"]/

        // MD5 hashed check
        $md5_check = /md5\s*\(\s*\$_POST\s*\[\s*['"]password['"]\s*\]\s*\)\s*===\s*['"][a-fA-F0-9]{32}['"]/

        // Remote code
        $curl_exec = "curl_exec"
        $file_get_contents = "file_get_contents"
        $stream_get_contents = "stream_get_contents"

        // Remote URL (GitHub raw or any HTTP)
        $remote_url = /https?:\/\/[^\"']{1,80}/

        // Eval injection
        $eval_payload = /eval\s*\(\s*['"]\?>['"]\s*\.\s*\$[a-zA-Z_][a-zA-Z0-9_]*\s*\)/

        // Fake login form
        $login_form = /<form\s+method\s*=\s*["']POST["'].*<input\s+type\s*=\s*["']password["'].*<\/form>/s

    condition:
        filesize < 100KB and
        1 of ($cookie_check, $md5_check) and
        1 of ($curl_exec, $file_get_contents, $stream_get_contents) and
        $eval_payload and
        $login_form
}

rule PHP_Remote_Backdoor_Eval_Auth_Bypass_v2
{
    meta:
        description = "Detects PHP backdoor with remote eval, auth bypass via cookie, and MD5-hashed fake login"
        author = "TangerangKota-CSIRT"
        date = "2025-08-05"
        severity = "critical"
        reference = "https://raw.githubusercontent.com/GanestSeven/backdoor-mini/main/aw.txt"
        tags = "php backdoor eval remote curl login md5"

    strings:
        // Hardcoded authentication via cookie
        $auth_cookie = /\$_COOKIE\s*\[\s*['"]user_id['"]\s*\]\s*===\s*['"][a-zA-Z0-9_]+['"]/

        // Fake login password check with MD5
        $md5_auth = /md5\s*\(\s*\$_POST\s*\[\s*['"]password['"]\s*\]\s*\)\s*===\s*['"][a-fA-F0-9]{32}['"]/

        // Use of eval() on fetched content with prepended PHP closing tag
        $eval_injection = /eval\s*\(\s*['"]\?>['"]\s*\.\s*\$[a-zA-Z_][a-zA-Z0-9_]*\s*\)/

        // Remote URL used for fetching PHP content (GitHub, raw, etc.)
        $remote_url = /https?:\/\/raw\.githubusercontent\.com\/[a-zA-Z0-9\/._-]+\.txt/

        // Typical curl usage pattern in backdoors
        $curl_pattern = "curl_setopt($conn, CURLOPT_RETURNTRANSFER, 1);"
        $ua_pattern = "Mozilla/5.0 (Windows NT 6.1; rv:32.0) Gecko/20100101 Firefox/32.0"

        // Login form for phishing password
        $login_form = /<form[^>]+method\s*=\s*["']POST["'][^>]*>.*["']password["'].*<\/form>/s

        // Optional visual lure (ASCII art often used in deface/backdoor)
        $ascii_pattern = "⣴⣾⣿⣿⣶⡄"

    condition:
        filesize < 80KB and
        (
            all of ($auth_cookie, $md5_auth, $eval_injection, $remote_url) and
            1 of ($curl_pattern, $ua_pattern) and
            $login_form
        ) and
        // Avoid false positive from known frameworks
        not (
            "wp-content" in filename or
            "laravel" in filename or
            "symfony" in filename or
            "drupal" in filename
        )
}