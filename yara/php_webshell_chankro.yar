rule Detect_Malicious_PHP_Chankro {
    meta:
        author = "Mr. Naeem"
        description = "Detects a malicious PHP Chankro"
        created = "2024-12-16"
        version = "1.0"

    strings:
        $php_tag = "<?php"
        $title = "BypassServ By HaxorSec"
        $cmd_input = "$_POST['cmd_input']"
        $cmd_biasa = "$_POST['cmd_biasa']"
        $chankro = "$a($full . '/chankro.so'"
        $acpid = "$a($full . '/acpid.socket'"

    condition:
        all of ($php_tag, $chankro, $acpid) and
        (1 of ($title, $cmd_biasa, $cmd_input, $chankro, $acpid))
}
