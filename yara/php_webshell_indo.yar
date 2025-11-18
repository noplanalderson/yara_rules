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
        uint16(0) == 0x3f3c and
        (
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
            (filesize < 50KB and $malicious_eval)
        )
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
        
        $eval_pattern = /eval\s*\(\s*['"]>\?['"][\s]*\.[\s]*\$\w+/
        
        $ini_get = "ini_get(" nocase
        $function_exists = "function_exists(" nocase
        
    condition:
        uint16(0) == 0x3c3f and // PHP file
        filesize < 100KB and
        
        // Must have at least 2 download methods
        2 of ($download*) and
        
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
        1 of ($curl_exec, $file_get_contents, $stream_get_contents, $remote_url) and
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

    condition:
        filesize < 80KB and
        (
            all of ($auth_cookie, $md5_auth, $eval_injection, $remote_url) and
            1 of ($curl_pattern, $ua_pattern) and
            $login_form
        )
}

rule Fake_Gmaps_Webshell
{
    meta:
        description = "Detects Fake Gmaps Webshell"
        author = "TangerangKota-CSIRT"
        date = "2025-08-05"
        severity = "critical"
        tags = "php backdoor eval remote curl hex"

    strings:
        $php = "<?php" nocase
        $func1 = "hex2str" nocase
        $func2 = "file_get_contents" nocase
        $func3 = "function_exists" nocase
        $func4 = "fopen" nocase
        $func5 = "eval" nocase
        $func6 = "hexdec" nocase

    condition:
        $php and all of ($func*)
}

rule Solevisible_Simple_Upload
{
    meta:
        description = "Detects Solevisible Simple File Upload"
        author = "TangerangKota-CSIRT"
        date = "2025-08-05"
        severity = "critical"
        tags = "php backdoor simple-upload"

    strings:
        $php = "<?php" nocase
        $signature = "solevisible" nocase ascii
        $str1 = "$_SERVER['REMOTE_ADDR']" ascii
        $str2 = "$_POST['_upl']" ascii
        $str3 = "enctype='multipart/form-data'"
        $func = "@move_uploaded_file(" ascii

    condition:
        $php and (
            $signature or (
                    all of ($str*) and $func
                )
            )
}

rule CGI_Webshell_Base64_Command_Execution {
    meta:
        description = "Deteksi CGI web shell dengan eksekusi command via base64"
        author = "Security Team"
        date = "2025-11-18"
        severity = "critical"
        reference = "Generic CGI web shell with base64 encoded command execution"
        category = "webshell"
        
    strings:
        // CGI headers
        $cgi_header1 = "Content-type: text/html" nocase
        $cgi_header2 = "Content-type:text/html" nocase
        
        // Base64 operations
        $base64_decode1 = "base64 --decode"
        $base64_decode2 = "base64.b64decode"
        $base64_decode3 = "decode_base64"
        $base64_decode4 = "base64_decode"
        
        // Command execution patterns
        $exec1 = "eval ${" nocase
        $exec2 = "os.popen" nocase
        $exec3 = "system(" nocase
        $exec4 = /child_stdin,\s*child_stdout\s*=\s*os\.popen2/
        
        // CGI variable parsing
        $cgi_var1 = "REQUEST_METHOD" nocase
        $cgi_var2 = "QUERY_STRING" nocase
        $cgi_var3 = "CONTENT_LENGTH" nocase
        $cgi_var4 = "STDIN" nocase
        
        // Suspicious parameter names
        $param_cmd = /['"]cmd['"]/
        $param_check = /['"]check['"]/
        
        // POST data reading
        $post_read1 = "read(STDIN"
        $post_read2 = "read -N $CONTENT_LENGTH"
        $post_read3 = "cgi.FieldStorage"
        
    condition:
        // File size reasonable for a web shell (< 10KB)
        filesize < 10KB and
        
        // Must have CGI header
        any of ($cgi_header*) and
        
        // Must have base64 decode
        any of ($base64_decode*) and
        
        // Must have command execution
        any of ($exec*) and

        // Must have post read
        any of ($post_read*) and
        
        // Must have CGI variable handling
        2 of ($cgi_var*) and
        
        // Must have suspicious parameter names
        all of ($param_*)
}

rule Bash_CGI_Webshell {
    meta:
        description = "Deteksi Bash CGI web shell dengan eval command"
        author = "Security Team"
        date = "2025-11-18"
        severity = "critical"
        hash1 = "Sample hash of malicious file 1"
        category = "webshell"
        filetype = "bash"
        
    strings:
        $shebang = "#!/bin/bash"
        
        // CGI functions
        $func1 = "function cgi_get_POST_vars"
        $func2 = "function cgi_decodevar"
        $func3 = "function cgi_getvars"
        
        // Base64 decode with eval
        $pattern1 = /query=\$\(echo \$cmd \| base64 --decode\)/
        $pattern2 = /eval \$\{query\}/
        
        // CGI environment
        $env1 = "$REQUEST_METHOD"
        $env2 = "$QUERY_STRING"
        $env3 = "$CONTENT_LENGTH"
        
        // Output pattern
        $output = "<pre>" nocase
        
    condition:
        $shebang at 0 and
        all of ($func*) and
        all of ($pattern*) and
        2 of ($env*) and
        $output
}

rule Python_CGI_Webshell {
    meta:
        description = "Deteksi Python CGI web shell dengan command execution"
        author = "Security Team"
        date = "2025-11-18"
        severity = "critical"
        hash1 = "Sample hash of malicious file 2"
        category = "webshell"
        filetype = "python"
        
    strings:
        $shebang = "#!/usr/bin/python"
        
        // Python imports
        $import1 = "import os"
        $import2 = "import cgi"
        $import3 = "import base64"
        $import4 = "import cgitb"
        
        // CGI form handling
        $cgi_form = "cgi.FieldStorage"
        
        // Base64 decode
        $base64_op = "base64.b64decode"
        
        // Command execution
        $exec1 = "os.popen2"
        $exec2 = /child_stdin,\s*child_stdout/
        
        // Parameter retrieval
        $param1 = "form.getvalue('cmd')"
        $param2 = "form.getvalue('check')"
        
        // Output
        $output = "Content-type:text/html"
        
    condition:
        $shebang at 0 and
        3 of ($import*) and
        $cgi_form and
        $base64_op and
        any of ($exec*) and
        all of ($param*) and
        $output
}

rule Perl_CGI_Webshell {
    meta:
        description = "Deteksi Perl CGI web shell dengan system command"
        author = "Security Team"
        date = "2025-11-18"
        severity = "critical"
        hash1 = "Sample hash of malicious file 3"
        category = "webshell"
        filetype = "perl"
        
    strings:
        $shebang = /^#!\/usr\/(local\/)?bin\/perl/
        
        // Perl modules
        $module = "use MIME::Base64"
        
        // Base64 decode
        $base64 = "decode_base64"
        
        // CGI environment
        $env1 = "$ENV{'REQUEST_METHOD'}"
        $env2 = "$ENV{'CONTENT_LENGTH'}"
        
        // STDIN reading
        $stdin = "read(STDIN"
        
        // Command execution
        $exec = /system\(decode_base64/
        
        // Parameter parsing
        $param_parse1 = "split(/&/"
        $param_parse2 = "split(/=/"
        
        // Suspicious parameters
        $param_cmd = /$in\{[\"']cmd[\"']\}/
        $param_check = /$in\{[\"']check[\"']\}/
        
    condition:
        $shebang at 0 and
        $module and
        $base64 and
        all of ($env*) and
        $stdin and
        $exec and
        all of ($param_parse*) and
        all of ($param_cmd, $param_check)
}

rule Generic_CGI_Base64_Backdoor {
    meta:
        description = "Deteksi generic CGI backdoor dengan base64 encoding"
        author = "Security Team"
        date = "2025-11-18"
        severity = "high"
        category = "webshell"
        
    strings:
        // Shebangs
        $shebang1 = "#!/bin/bash"
        $shebang2 = "#!/usr/bin/python"
        $shebang3 = /^#!\/usr\/(local\/)?bin\/perl/
        
        // CGI indicators
        $cgi1 = "Content-type:" nocase
        $cgi2 = "REQUEST_METHOD" nocase
        $cgi3 = "CONTENT_LENGTH" nocase
        
        // Base64 patterns
        $b64_1 = "base64" nocase
        $b64_2 = "decode" nocase
        
        // Command execution keywords
        $cmd1 = "eval"
        $cmd2 = "system"
        $cmd3 = "popen"
        $cmd4 = "exec"
        
        // Suspicious parameter pattern
        $param = /['"\$]\w*\{?['"]?(cmd|command|execute|shell)['"]\}?/ nocase
        
        // HTML pre tag (common in web shells for output)
        $html_pre = "<pre>" nocase
        
    condition:
        filesize < 20KB and
        any of ($shebang*) and
        2 of ($cgi*) and
        all of ($b64_*) and
        any of ($cmd*) and
        $param and
        $html_pre
}

rule Webshell_Suspicious_Function_Combinations {
    meta:
        description = "Deteksi kombinasi fungsi mencurigakan dalam CGI scripts"
        author = "Security Team"
        date = "2025-11-18"
        severity = "high"
        category = "webshell"
        
    strings:
        // Decoding functions
        $decode1 = "decode" nocase
        $decode2 = "b64decode"
        $decode3 = "base64_decode"
        $decode4 = "--decode"
        
        // Execution functions
        $exec1 = "eval" nocase
        $exec2 = "system" nocase
        $exec3 = "exec" nocase
        $exec4 = "popen" nocase
        $exec5 = "shell_exec"
        $exec6 = "passthru"
        
        // Input handling
        $input1 = "REQUEST_METHOD" nocase
        $input2 = "POST" nocase
        $input3 = "STDIN" nocase
        $input4 = "FieldStorage"
        $input5 = "read(" nocase
        
        // Output
        $output1 = "Content-type" nocase
        $output2 = "text/html" nocase
        
    condition:
        filesize < 50KB and
        any of ($decode*) and
        2 of ($exec*) and
        2 of ($input*) and
        all of ($output*)
}

rule Webshell_Double_Encoding_Pattern {
    meta:
        description = "Deteksi pola double encoding (base64 + execution)"
        author = "Security Team"
        date = "2025-11-18"
        severity = "critical"
        category = "webshell"
        
    strings:
        // Pattern: decode parameter then execute
        $pattern1 = /base64[^)]{0,50}decode[^)]{0,50}(eval|system|exec|popen)/
        $pattern2 = /decode_base64[^)]{0,50}system/
        $pattern3 = /b64decode[^)]{0,50}(eval|exec|system)/
        
        // Variable assignment from decoded input
        $var_decode1 = /\w+\s*=\s*[^;]{0,100}base64[^;]{0,50}decode/
        $var_decode2 = /\w+\s*=\s*decode_base64/
        
        // CGI context
        $cgi = /Content-type:\s*text\/html/i
        
    condition:
        filesize < 30KB and
        $cgi and
        (any of ($pattern*) or 2 of ($var_decode*))
}

rule Webshell_Command_Parameter_Names {
    meta:
        description = "Deteksi nama parameter command yang umum digunakan web shell"
        author = "Security Team"
        date = "2025-11-18"
        severity = "medium"
        category = "webshell"
        
    strings:
        $shebang = /^#!/
        
        // Suspicious parameter names
        $param1 = /['"\$]\{?['"]?cmd['"]?\}?[^a-zA-Z]/
        $param2 = /['"\$]\{?['"]?command['"]?\}?[^a-zA-Z]/
        $param3 = /['"\$]\{?['"]?execute['"]?\}?[^a-zA-Z]/
        $param4 = /['"\$]\{?['"]?shell['"]?\}?[^a-zA-Z]/
        $param5 = /['"\$]\{?['"]?exec['"]?\}?[^a-zA-Z]/
        
        // Additional suspicious parameter
        $param_check = /['"\$]\{?['"]?check['"]?\}?[^a-zA-Z]/
        
        // Execution context
        $exec = /(eval|system|exec|popen)/
        
        // CGI context
        $cgi = "REQUEST_METHOD"
        
    condition:
        $shebang at 0 and
        $cgi and
        $exec and
        2 of ($param*) and
        $param_check
}

rule Solevisible_htaccess {
    meta:
        description = "Solevisible HtAccess for running alfa webshell backconnect"
        author = "Security Team"
        date = "2025-11-18"
        severity = "medium"
        category = "backconnect"

    strings:
        $type = "x-httpd-cgi" ascii
        $handler = "cgi-script" ascii
        $signature = ".alfa" ascii

    condition:
        filesize < 1KB and all of them
}

rule FileLoader_webshell {
    meta:
        description = "FileLoader Webshell"
        author = "Mr. Naeem"
        date = "2025-11-18"
        severity = "high"
        category = "webshell"

    strings:
        $class_name1 = "FileLoader" nocase
        $class_name2 = "FindExecutor" nocase
        $malfunc1 = "proc_open(" ascii
        $malfunc2 = "is_resource(" ascii
        $malfunc3 = "stream_get_contents(" ascii
        $malfunc4 = "proc_close(" ascii
        
    condition:
        uint16(0) == 0x3f3c and
        (
            all of ($class_name*) and all of ($malfunc*)
        )
}

rule Webshell_Downloader {
    meta:
        description = "Webshell Downloader"
        author = "Mr. Naeem"
        date = "2025-11-18"
        severity = "high"
        category = "webshell"

    strings:
        $func1 = "set_time_limit(0)" ascii
        $func2 = "move_uploaded_file(" ascii
        $func3 = "curl_exec(" ascii
        $func4 = "fopen(" ascii
        $func5 = "fclose(" ascii
        $str1 = "<form method='POST' enctype='multipart/form-data'>" nocase ascii
        $str2 = "FILTER_VALIDATE_URL" ascii
    
    condition:
        uint16(0) == 0x3f3c and
        (
            $func1 and ($func2 or all of ($func2, $func3, $func4, $func5)) and 1 of ($str*)
        )
}

rule BotCloaker {
    meta:
        description = "SEO Cloaker"
        author = "Mr. Naeem"
        date = "2025-11-18"
        severity = "medium"
        category = "webshell"

    strings:
        $func1 = "is_bot()" nocase ascii
        $func2 = "file_get_contents(" ascii
        $str1 = "HTTP_USER_AGENT" ascii
        $str2 = /\"(bot|ahrefs|google|bingbot|googlebot|yandexbot|baiduspider|duckduckbot|facebookexternalhit|facebookbot|yahoo)\"/i
        $str3 = /https?:\/\/([a-z0-9\-.]+)./i

    condition:
        uint16(0) == 0x3f3c and
        (
            1 of ($func*) and all of ($str*)
        )
}

rule PHP_Webshell_UAF_Exploit {
    meta:
        description = "Deteksi PHP web shell dengan UAF (Use-After-Free) exploit untuk RCE"
        author = "Security Team"
        date = "2025-11-18"
        severity = "critical"
        category = "webshell"
        subcategory = "php_exploit"
        reference = "PHP UAF exploit with file manager capabilities"
        
    strings:
        $php_tag = "<?php"
        
        // UAF exploit functions
        $uaf_func1 = "function str2ptr(&$str, $p = 0, $s = 8)"
        $uaf_func2 = "function ptr2str($ptr, $m = 8)"
        $uaf_func3 = "function write(&$str, $p, $v, $n = 8)"
        $uaf_func4 = "function leak($addr, $p = 0, $s = 8)"
        $uaf_func5 = "function parse_elf($base)"
        $uaf_func6 = "function get_binary_base($binary_leak)"
        $uaf_func7 = "function get_system($basic_funcs)"
        
        // UAF exploit classes
        $class_ryat = /class\s+ryat\s*\{[^}]*__destruct/
        $class_helper = /class\s+Helper\s*\{[^}]*public\s+\$a,\s*\$b,\s*\$c,\s*\$d/
        
        // UAF payload patterns
        $uaf_payload = /'a:4:\{i:0;i:1;i:1;a:1:\{i:0;O:4:"ryat":2:\{s:4:"ryat";R:3;s:4:"chtg";i:2;\}\}i:1;i:3;i:2;R:5;\}'/
        
        // Memory manipulation
        $mem_manip1 = "$closure_handlers = str2ptr($abc, 0)"
        $mem_manip2 = "$php_heap = str2ptr($abc, 0x58)"
        $mem_manip3 = "write($abc, 0x"
        $mem_manip4 = "$binary_leak = leak($closure_handlers"
        
        // ELF parsing (Linux exploitation)
        $elf_check1 = "$e_type = leak($base, 0x10, 2)"
        $elf_check2 = "$e_phoff = leak($base, 0x20)"
        $elf_check3 = "if($leak == 0x10102464c457f)"
        
        // System function hooking
        $system_hook1 = "if(!($zif_system = get_system($basic_funcs)))"
        $system_hook2 = "write($abc, 0xd0 + 0x68, $zif_system)"
        $system_hook3 = "($helper->b)($xmd)"
        
        // File manager functions
        $fm_func1 = "function download_file($download)"
        $fm_func2 = "function delete_file($delete)"
        $fm_func3 = "function edit_file($edit)"
        $fm_func4 = "function upload_file($path,$file)"
        
        // Error suppression (common in malware)
        $suppress1 = "error_reporting(0)"
        $suppress2 = "ini_set('display_errors', 0)"
        $suppress3 = "ignore_user_abort(true)"
        $suppress4 = "set_time_limit(0)"
        
    condition:
        filesize < 50KB and
        $php_tag at 0 and
        (
            // Strong UAF exploit indicators
            (
                4 of ($uaf_func*) and
                any of ($class_*) and
                any of ($mem_manip*)
            ) or
            
            // UAF payload + system hook
            (
                $uaf_payload and
                any of ($system_hook*)
            ) or
            
            // ELF parsing + system function
            (
                2 of ($elf_check*) and
                any of ($system_hook*)
            ) or
            
            // Complete package: exploit + file manager
            (
                3 of ($uaf_func*) and
                3 of ($fm_func*) and
                2 of ($suppress*)
            )
        )
}

rule PHP_Webshell_Advanced_File_Manager {
    meta:
        description = "Deteksi PHP web shell dengan file manager lengkap"
        author = "Security Team"
        date = "2025-11-18"
        severity = "critical"
        category = "webshell"
        subcategory = "file_manager"
        
    strings:
        $php = "<?php"
        
        // File operations
        $file_op1 = "function download_file("
        $file_op2 = "function delete_file("
        $file_op3 = "function edit_file("
        $file_op4 = "function save_edit("
        $file_op5 = "function view_file("
        $file_op6 = "function new_file("
        $file_op7 = "function new_dir("
        $file_op8 = "function upload_file("
        
        // Directory operations
        $dir_op1 = "function get_dir()"
        $dir_op2 = "function get_path()"
        $dir_op3 = "function get_back($path)"
        $dir_op4 = "scandir($path)"
        
        // Authentication
        $auth1 = "function admin_login()"
        $auth2 = "password_verify"
        $auth3 = "setcookie(md5($_SERVER['HTTP_HOST'])"
        
        // File info functions
        $info1 = "function filesize_convert("
        $info2 = "function fileTime("
        $info3 = "posix_getpwuid(fileowner"
        
        // HTML generation
        $html1 = "function makeForm("
        $html2 = "function makeTable("
        $html3 = "function makeLink("
        $html4 = "function makeInput("
        
        // Suspicious parameters
        $param1 = "get_get('delete')"
        $param2 = "get_get('edit')"
        $param3 = "get_get('download')"
        $param4 = "get_post('upload')"
        
    condition:
        filesize < 100KB and
        $php at 0 and
        (
            // File manager core
            (
                5 of ($file_op*) and
                2 of ($dir_op*)
            ) or
            
            // Complete web shell
            (
                4 of ($file_op*) and
                any of ($auth*) and
                2 of ($html*) and
                2 of ($param*) and
                all of ($info*)
            )
        )
}

rule PHP_Webshell_Memory_Corruption_Exploit {
    meta:
        description = "Deteksi PHP memory corruption exploit (UAF/Type confusion)"
        author = "Security Team"
        date = "2025-11-18"
        severity = "critical"
        category = "exploit"
        subcategory = "memory_corruption"
        
    strings:
        $php = "<?php"
        
        // Memory address manipulation
        $mem1 = /\$address\s*<<=\s*8/
        $mem2 = /\$address\s*\|=\s*ord\(\$str\[\$p\+\$j\]\)/
        $mem3 = /for\s*\(\s*\$[ij]\s*=\s*\$s-1;\s*\$[ij]\s*>=\s*0/
        
        // Pointer operations
        $ptr1 = /function\s+str2ptr\s*\(/
        $ptr2 = /function\s+ptr2str\s*\(/
        $ptr3 = /\$ptr\s*>>=\s*8/
        
        // Memory write
        $write1 = /\$str\[\$p\s*\+\s*\$i\]\s*=\s*chr\(\$v\s*&\s*0xff\)/
        $write2 = /write\s*\(\s*\$\w+,\s*0x[0-9a-f]+/i
        
        // Closure/Object manipulation
        $closure1 = "$helper->b = function ($x) { };"
        $closure2 = "$closure_handlers = str2ptr"
        $closure3 = "$closure_obj = str2ptr"
        
        // Fake object creation
        $fake1 = "# fake value"
        $fake2 = "# fake reference"
        $fake3 = "$fake_obj_offset"
        
        // GC manipulation
        $gc = "gc_collect_cycles()"
        
        // Unserialize exploit
        $unser = /unserialize\s*\(\s*\$poc\s*\)/
        
    condition:
        filesize < 100KB and
        $php at 0 and
        (
            // Memory manipulation pattern
            (
                2 of ($mem*) and
                2 of ($ptr*) and
                any of ($write*)
            ) or
            
            // Closure exploitation
            (
                2 of ($closure*) and
                any of ($fake*) and
                $gc
            ) or
            
            // Complete UAF exploit
            (
                any of ($ptr*) and
                any of ($write*) and
                $unser and
                $gc
            )
        )
}

rule PHP_Webshell_Linux_ELF_Parser {
    meta:
        description = "Deteksi PHP yang melakukan parsing ELF binary (Linux exploitation)"
        author = "Security Team"
        date = "2025-11-18"
        severity = "critical"
        category = "exploit"
        subcategory = "elf_manipulation"
        
    strings:
        $php = "<?php"
        
        // ELF header parsing
        $elf1 = "$e_type = leak($base, 0x10, 2)"
        $elf2 = "$e_phoff = leak($base, 0x20)"
        $elf3 = "$e_phentsize = leak($base, 0x36, 2)"
        $elf4 = "$e_phnum = leak($base, 0x38, 2)"
        
        // ELF program header
        $ph1 = "$p_type  = leak($header, 0, 4)"
        $ph2 = "$p_flags = leak($header, 4, 4)"
        $ph3 = "$p_vaddr = leak($header, 0x10)"
        $ph4 = "$p_memsz = leak($header, 0x28)"
        
        // PT_LOAD flags check
        $ptload1 = "if($p_type == 1 && $p_flags == 6)"
        $ptload2 = "# PT_LOAD, PF_Read_Write"
        $ptload3 = "if($p_type == 1 && $p_flags == 5)"
        $ptload4 = "# PT_LOAD, PF_Read_exec"
        
        // ELF magic check
        $magic = "if($leak == 0x10102464c457f)"
        
        // Binary base search
        $base_search1 = "$start = $binary_leak & 0xfffffffffffff000"
        $base_search2 = "for($i = 0; $i < 0x1000; $i++)"
        $base_search3 = "$addr = $start - 0x1000 * $i"
        
    condition:
        filesize < 100KB and
        $php at 0 and
        (
            // ELF parsing
            (
                3 of ($elf*) and
                2 of ($ph*)
            ) or
            
            // PT_LOAD handling
            (
                any of ($ptload*) and
                $magic
            ) or
            
            // Binary base detection
            (
                all of ($base_search*) and
                $magic
            )
        )
}

rule PHP_Webshell_System_Function_Hook {
    meta:
        description = "Deteksi PHP yang melakukan hooking system() function"
        author = "Security Team"
        date = "2025-11-18"
        severity = "critical"
        category = "exploit"
        subcategory = "function_hooking"
        
    strings:
        $php = "<?php"
        
        // System function search
        $sys1 = "function get_system($basic_funcs)"
        $sys2 = "$f_name == 0x6d6574737973" // 'system' in hex
        $sys3 = "if(!($zif_system = get_system("
        
        // Basic functions search
        $basic1 = "function get_basic_funcs($base, $elf)"
        $basic2 = "# 'constant' constant check"
        $basic3 = "if($deref != 0x746e6174736e6f63)"
        $basic4 = "# 'bin2hex' constant check"
        $basic5 = "if($deref != 0x786568326e6962)"
        
        // Function hooking
        $hook1 = "write($abc, 0xd0 + 0x38, 1, 4)" // internal func type
        $hook2 = "write($abc, 0xd0 + 0x68, $zif_system)" // internal func handler
        $hook3 = "# internal func handler"
        
        // Command execution
        $exec1 = "($helper->b)($xmd)"
        $exec2 = "function pwn($xmd)"
        
    condition:
        filesize < 100KB and
        $php at 0 and
        (
            // System function detection
            (
                2 of ($sys*) and
                any of ($basic*)
            ) or
            
            // Function hooking mechanism
            (
                2 of ($hook*) and
                any of ($exec*)
            ) or
            
            // Complete hooking chain
            (
                any of ($sys*) and
                any of ($hook*) and
                any of ($exec*)
            )
        )
}

rule PHP_Webshell_Cookie_Auth_Bypass {
    meta:
        description = "Deteksi PHP web shell dengan cookie-based authentication"
        author = "Security Team"
        date = "2025-11-18"
        severity = "high"
        category = "webshell"
        subcategory = "authentication"
        
    strings:
        $php = "<?php"
        
        // Cookie authentication
        $cookie1 = /setcookie\s*\(\s*md5\s*\(\s*\$_SERVER\['HTTP_HOST'\]\)/
        $cookie2 = /if\s*\(\s*!isset\s*\(\s*\$_COOKIE\[md5\s*\(\s*\$_SERVER\['HTTP_HOST'\]\)\]\)/
        
        // Password verification
        $pass1 = "password_verify($_POST['password']"
        $pass2 = "$hashed_password = '$2y$"
        
        // Login form
        $login1 = "function admin_login()"
        $login2 = "<input type=\"password\" name=\"password\">"
        
        // Resource manipulation
        $resource1 = "ignore_user_abort(true)"
        $resource2 = "set_time_limit(0)"
        $resource3 = "ini_set('memory_limit', '-1')"
        $resource4 = "ini_set('max_execution_time', 5000)"
        
        // Error suppression
        $error1 = "error_reporting(0)"
        $error2 = "ini_set('display_errors', 0)"
        
    condition:
        filesize < 100KB and
        $php at 0 and
        (
            // Cookie-based auth
            (
                $cookie1 and $cookie2 and
                any of ($pass*)
            ) or
            
            // Login + resource manipulation
            (
                any of ($login*) and
                3 of ($resource*) and
                all of ($error*)
            )
        )
}

rule PHP_Webshell_Complete_Package {
    meta:
        description = "Deteksi PHP web shell lengkap dengan UAF exploit + file manager"
        author = "Security Team"
        date = "2025-11-18"
        severity = "critical"
        category = "webshell"
        subcategory = "complete_package"
        reference = "Combined detection for full-featured web shell"
        
    strings:
        $php = "<?php"
        
        // Core indicators from different components
        $uaf = "function pwn($xmd)"
        $fm = "function get_dir()"
        $auth = "function admin_login()"
        $exploit = "gc_collect_cycles()"
        $elf = "function parse_elf($base)"
        $system = "($helper->b)($xmd)"
        
        // Command input
        $cmd_input1 = /<input type=['"](text|password)['"] name=['"]c['"]/
        $cmd_input2 = /if\s*\(\s*isset\s*\(\s*\$_POST\['c'\]\)/
        
        // File operations
        $file_ops = /(download|delete|edit|upload)_file\s*\(/
        
        // Memory operations
        $mem_ops = /(str2ptr|ptr2str|leak|write)\s*\(/
        
    condition:
        filesize < 100KB and
        $php at 0 and
        (
            // Full package
            (
                $uaf and $fm and $auth
            ) or
            
            // Exploit + file manager
            (
                $exploit and $elf and
                #file_ops > 3
            ) or
            
            // System hook + command input
            (
                $system and
                any of ($cmd_input*) and
                #mem_ops > 3
            )
        )
}

rule PHP_Webshell_Suspicious_Hex_Constants {
    meta:
        description = "Deteksi PHP dengan hex constants mencurigakan (exploit signatures)"
        author = "Security Team"
        date = "2025-11-18"
        severity = "high"
        category = "exploit"
        
    strings:
        $php = "<?php"
        
        // Magic numbers and constants
        $hex1 = "0x746e6174736e6f63" // 'constant' in hex
        $hex2 = "0x786568326e6962" // 'bin2hex' in hex
        $hex3 = "0x6d6574737973" // 'system' in hex
        $hex4 = "0x10102464c457f" // ELF magic
        $hex5 = "0xfffffffffffff000"
        
        // Memory offsets
        $offset1 = "0x68"
        $offset2 = "0xd0"
        $offset3 = "0x58"
        
    condition:
        filesize < 100KB and
        $php at 0 and
        3 of ($hex*) and
        2 of ($offset*)
}

rule Webshell_string_concat {
    meta:
        description = "Deteksi PHP encoded and concatenate string"
        author = "Security Team"
        date = "2025-11-18"
        severity = "high"
        category = "webshell"

    strings:
        $php = "<?php"
        $concatenated_str = /\$(\w){1,10}\s?\.=\s?"([\w\+]{4,10})";/i
        $func1 = "set_time_limit(0);" ascii
        $func2 = "error_reporting(0);" ascii
        $func3 = "eval(" ascii
    
    condition:
        $php at 0 and filesize < 1MB and $concatenated_str and all of ($func*)
}