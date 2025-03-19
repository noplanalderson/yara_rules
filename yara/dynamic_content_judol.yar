rule Detect_Gambling_Dynamic_Webpage {
    meta:
        author = "Mr. Naeem"
        description = "Detects an online gambling dynamic webpage"
        created = "2025-03-19"
        version = "1.0"

    strings:
        $php_tag = "<?php"
        $check_referrer = "$_SERVER['HTTP_REFERER']"
        $block_google_removal = "https://search.google.com/search-console/remove-outdated-content?hl=en"
        $str1 = "smile2024.html" nocase
        $str2 = "smile.txt" nocase
        $str3 = "slot" nocase
        $str4 = "daftar slot" nocase
        $str5 = "slot online" nocase
        $str6 = "daftar slot online" nocase
        $var1 = "$BRAND"
        $var2 = "$tunnel"
        $var3 = "$NUMLIST"
        $func1 = "feedback404()"
        $func2 = "file($filename, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES)"

    condition:
        all of ($php_tag, $check_referrer, $block_google_removal, $str3) and
        (1 of ($str1, $str2, $str4, $str5, $str6, $var1, $var2, $var3, $func1, $func2))
}

rule Detect_Gambling_Dynamic_Webpage2 {
    meta:
        author = "Mr. Naeem"
        description = "Detects an online gambling dynamic webpage 2"
        created = "2025-03-19"
        version = "1.0"

    strings:
        $php_tag = "<?php"
        $str1 = "program.php" nocase
        $str2 = "smile.txt" nocase
        $str3 = "slot" nocase
        $str4 = "Sitemap telah dibuat." nocase
        $str5 = "sitemap.xml" nocase
        $func1 = "file($judulFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES)"
        $func2 = "fopen("
        $func3 = "fwrite("

    condition:
        all of ($php_tag, $func1, $func2, $func3) and
        (1 of ($str1, $str2, $str3, $str4, $str5))
}
