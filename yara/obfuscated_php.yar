rule eval_statement
{
    meta:
        description = "Obfuscated PHP eval statements"
        family = "PHP.Obfuscated"
        filetype = "PHP"
        hash = "9da32d35a28d2f8481a4e3263e2f0bb3836b6aebeacf53cd37f2fe24a769ff52"
        hash = "8c1115d866f9f645788f3689dff9a5bacfbee1df51058b4161819c750cf7c4a1"
        hash = "14083cf438605d38a206be33542c7a4d48fb67c8ca0cfc165fa5f279a6d55361"

    strings:
        $obf = /eval[\( \t]+((base64_decode[\( \t]+)|(str_rot13[\( \t]+)|(gzinflate[\( \t]+)|(gzuncompress[\( \t]+)|(strrev[\( \t]+)|(gzdecode[\( \t]+))+/

    condition:
        all of them
}