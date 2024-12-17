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
        keywords5 = "/racikansobet|agen777|jackpot/i"

    strings:
        $keywords1 = /slot (gacor|online|toto|online|dana|gacor gampang menang)/i
        $keywords2 = /toto (canada|hk|indonesia|thailand)/i
        $keywords3 = /judi (online|bola|slot)/i
        $keywords4 = /situs (judi|slot) ?terpercaya/i
        $keywords5 = /racikansobet|agen777|jackpot/i

    condition:
        1 of ($keywords1, $keywords2, $keywords3, $keywords4, $keywords5)
}
