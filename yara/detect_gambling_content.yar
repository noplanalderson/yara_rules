rule Detect_Gambling_HTMLContent {
    meta:
        author = "Mr. Naeem"
        description = "Detects malicious keywords related to gambling and online betting sites"
        created = "2024-12-16"
        version = "1.0"
        keywords1 = "/slot (gacor|online|toto|online|dana|gacor gampang menang)/i"
        keywords2 = "/toto (canada|hk|indonesia|thailand)/i"
        keywords3 = "/judi (online|bola|slot)/i"
        keywords4 = "/situs (judi|slot) ?terpercaya/i"
        keywords5 = "/racikansobet|agen777|maxwin?n/i"

    strings:
        $keywords1 = /slot (gacor|online|toto|online|dana|gacor gampang menang)/i
        $keywords2 = /toto (canada|hk|indonesia|thailand)/i
        $keywords3 = /judi (online|bola|slot)/i
        $keywords4 = /situs (judi|slot) ?terpercaya/i
        $keywords5 = /racikansobet|agen777|maxwin?n/i

    condition:
        (
            uint32(0) == 0x3c21444f or  // "<!DO"
            uint32(0) == 0x3c68746d or  // "<htm"
            uint32(0) == 0x3c48544d      // "<HTM"
        ) and 1 of ($keywords1, $keywords2, $keywords3, $keywords4, $keywords5)
}

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

rule Online_Gambling_Indonesian_HTML {
    meta:
        description = "Deteksi konten judi online berbahasa Indonesia dalam HTML"
        author = "Security Team"
        date = "2025-11-18"
        severity = "high"
        reference = "Based on Wazuh gambling detection rules"
        
    strings:
        // Meta tags gambling indicators
        $meta_title1 = /<meta[^>]+content="[^"]*\b(slot|togel|casino|poker|judi|betting|taruhan)\b[^"]*"/i
        $meta_title2 = /<title>[^<]*\b(slot|togel|casino|poker|judi|betting|taruhan)\b[^<]*<\/title>/i
        
        // Common gambling terms in Indonesian
        $indo_gambling1 = /\b(slot (gacor|thailand|server|terpercaya|online)|bet kecil|link slot)\b/i
        $indo_gambling2 = /\b(togel (online|hongkong|singapore|macau|sydney)|nomor togel)\b/i
        $indo_gambling3 = /\b(situs (judi|slot|togel|poker)|bandar (togel|slot|judi))\b/i
        $indo_gambling4 = /\b(slot bet \d+|deposit (pulsa|dana|ovo|gopay))\b/i
        $indo_gambling5 = /\bserver (thailand|kamboja|singapore|myanmar|vietnam)\b/i
        
        // Gambling platform names and patterns
        $platform1 = /\b(rans\d+|naga\d+|dewa\d+|raja\d+|slot\d+|toto\d+)\b/i
        $platform2 = /\b(maxwin|jackpot|rtp (tinggi|tertinggi)|scatter|bonus)\b/i
        $platform3 = /\b(pragmatic|habanero|pgsoft|joker123|spadegaming)\b/i
        
        // Gambling URLs and domains
        $url1 = /https?:\/\/[^"\s]*(slot|togel|casino|poker|bet|judi|gacor)[^"\s]*/i
        $url2 = /\.(go\.id|ac\.id|or\.id)\/[^"\s]*(slot|togel|judi|bet)/i
        
        // Gambling keywords in meta tags
        $keyword1 = /<meta[^>]+name="keywords"[^>]+content="[^"]*\b(slot|togel|judi|poker|casino|bet)\b[^"]*"/i
        
        // Description patterns
        $desc1 = /<meta[^>]+name="description"[^>]+content="[^"]*\b(terpercaya|menang|kemenangan|bettor|player)\b[^"]*\b(slot|togel|judi)\b[^"]*"/i
        
        // Gambling action words
        $action1 = /\b(daftar|login|deposit|withdraw) (slot|togel|judi|casino)/i
        $action2 = /\b(main|bermain) (slot|togel|poker) (online|terpercaya)/i
        
        // HTML structure indicators
        $html_start = "<!doctype html" nocase
        $html_tag = /<html[^>]*>/i
        
    condition:
        // Must be HTML file
        ($html_start at 0 or $html_tag in (0..200)) and
        
        // Multiple gambling indicators
        (
            // Strong indicators (any 2)
            (
                ($meta_title1 or $meta_title2) and
                ($keyword1 or $desc1)
            ) or
            
            // Indonesian gambling terms (any 3)
            (
                3 of ($indo_gambling*)
            ) or
            
            // Platform names + gambling terms (any platform + any term)
            (
                any of ($platform*) and
                any of ($indo_gambling*)
            ) or
            
            // URLs + gambling terms
            (
                any of ($url*) and
                2 of ($indo_gambling*)
            ) or
            
            // Action words + multiple terms
            (
                any of ($action*) and
                2 of ($indo_gambling*, $platform*)
            )
        )
}

rule Online_Gambling_Compromised_Government_Site {
    meta:
        description = "Deteksi situs pemerintah yang terkompromi dengan konten judi"
        author = "Security Team"
        date = "2025-11-18"
        severity = "critical"
        
    strings:
        // Government domains
        $gov_domain1 = /https?:\/\/[^"\s]*\.(go\.id|ac\.id)[^"\s]*/i
        
        // Gambling content in government URL path
        $gov_path1 = /\.(go\.id|ac\.id)\/[^"\s]*(slot|togel|judi|poker|bet|gacor|casino)/i
        
        // Gambling meta tags
        $gambling_meta = /<meta[^>]+content="[^"]*\b(slot|togel|casino|judi)\b[^"]*"/i
        
        // Gambling title
        $gambling_title = /<title>[^<]*\b(slot|togel|casino|judi|poker)\b[^<]*<\/title>/i
        
    condition:
        ($gov_domain1 or $gov_path1) and
        ($gambling_meta or $gambling_title)
}

rule Online_Gambling_Keywords_Concentration {
    meta:
        description = "Deteksi konsentrasi tinggi kata kunci judi online"
        author = "Security Team"
        date = "2025-11-18"
        severity = "medium"
        
    strings:
        // Core gambling terms
        $g1 = "slot" nocase
        $g2 = "togel" nocase
        $g3 = "casino" nocase
        $g4 = "poker" nocase
        $g5 = "judi" nocase
        $g6 = "betting" nocase
        $g7 = "gacor" nocase
        $g8 = "maxwin" nocase
        $g9 = "jackpot" nocase
        $g10 = "terpercaya" nocase
        $g11 = "deposit" nocase
        $g12 = "bet" nocase
        $g13 = "server thailand" nocase
        $g14 = "rtp" nocase
        $g15 = "scatter" nocase
        
        $html = "<!doctype html" nocase
        
    condition:
        $html at 0 and
        // High concentration: 8 or more gambling terms
        8 of ($g*)
}

rule Online_Gambling_Provider_Names {
    meta:
        description = "Deteksi nama provider judi online populer"
        author = "Security Team"
        date = "2025-11-18"
        severity = "high"
        
    strings:
        // Game providers
        $provider1 = "pragmatic play" nocase
        $provider2 = "habanero" nocase
        $provider3 = "pgsoft" nocase
        $provider4 = "pg soft" nocase
        $provider5 = "joker123" nocase
        $provider6 = "spadegaming" nocase
        $provider7 = "playtech" nocase
        $provider8 = "microgaming" nocase
        $provider9 = "nexus engine" nocase
        $provider10 = "cq9" nocase
        
        // Gambling context
        $context1 = /\b(slot|casino|game) (online|provider|terpercaya)\b/i
        $context2 = /\b(main|bermain|daftar) (slot|casino)\b/i
        
        $html = "<!doctype html" nocase
        
    condition:
        $html at 0 and
        2 of ($provider*) and
        any of ($context*)
}