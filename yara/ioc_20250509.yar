rule Bashrc_Backdoor_Persistence
{
    meta:
        description = "Detect backdoor or persistence in .bashrc/.profile"
        author = "TangerangKota-CSIRT"
        version = "1.0"

    strings:
        $b1 = /curl\s+https?:\/\/[^\s]+/ ascii nocase
        $b2 = /wget\s+https?:\/\/[^\s]+/ ascii nocase
        $b3 = /\/tmp\/.*\.sh/ ascii
        $b4 = /echo\s+.*base64\s+-d/ ascii
        $b5 = /bash\s+-c\s+['"][^'"]+['"]/ ascii
        $b6 = /nohup\s+.*\&/ ascii
        $b7 = /eval\s+\$/ ascii
        $b8 = /python\s+-c\s+['"].*['"]/ ascii
        $b9 = /python3\s+-c\s+['"].*['"]/ ascii

    condition:
        2 of ( $b* ) or
        all of them
}

rule ELF_Suspicious_Backdoor_Activity
{
    meta:
        author = "TangerangKota-CSIRT"
        description = "Detect binary using execl, fork, sleep, and socket (backdoor behavior)"
        threat_level = "high"
        version = "1.0"

    strings:
        $execl = "execl" ascii
        $fork  = "fork" ascii
        $sleep = "sleep" ascii
        $sock  = "socket" ascii
        $binsh = "/bin/sh" ascii
        $binbash = "/bin/bash" ascii
        $netip = /(\d{1,3}\.){3}\d{1,3}/ ascii  //IP Addrress

    condition:
        uint32(0) == 0x7f454c46 and
        all of ($execl, $fork, $sleep, $sock) and
        1 of ($binsh, $netip, $binbash)
}

rule Cron_Backdoor_Persistence
{
    meta:
        description = "Detect backdoor or C2 activity in crontab"
        author = "TangerangKota-CSIRT"
        version = "1.0"

    strings:
        $c1 = /wget\s+http/ ascii
        $c2 = /curl\s+http/ ascii
        $c3 = /bash\s+-c/ ascii
        $c4 = /python\s+-c/ ascii
        $c5 = /\/tmp\/.*\.sh/ ascii
        $c6 = /sh\s+.*&/ ascii
        $c7 = /cd\s+\/tmp/ ascii
        $c8 = /chmod\s+\+x\s+\/tmp/ ascii
        $c9 = /eval\s+\$/ ascii
        $c10 = /python3\s+-c/ ascii

    condition:
        2 of ( $c* ) or
        all of them
}


rule Linux_Generic_Backdoor_Detector
{
    meta:
        description = "Detect potential Linux backdoor/malware in ELF, binaries or C source code"
        author = "TangerangKota-CSIRT"
        version = "1.0"
        date = "2025-04-30"
        category = "Linux Threat Detection"

    strings:
        // ELF Header
        $elf = { 7F 45 4C 46 }

        // Suspicious Function
        $c1 = "system(" ascii
        $c2 = "popen(" ascii
        $c3 = "execve(" ascii
        $c4 = "execl(" ascii
        $c5 = "fork(" ascii
        $c6 = "dlopen(" ascii
        $c7 = "LD_PRELOAD" ascii
        $c8 = "ptrace" ascii
        $c9 = "kill(" ascii
        $c10 = "strcpy(" ascii
        $c11 = "gets(" ascii

        // Backdooring Commands
        $s1 = "/bin/sh" ascii
        $s2 = "/bin/bash" ascii
        $s3 = "chmod +x" ascii
        $s4 = "wget http" ascii
        $s5 = "curl http" ascii
        $s6 = "nohup" ascii
        $s7 = "sleep 666" ascii
        $s8 = "echo -e" ascii
        $s9 = "base64 -d" ascii

        // Suspicious Network
        $n1 = "0.0.0.0"
        $n2 = "127.0.0.1"
        $n3 = "PORT="
        $n4 = "connect(" ascii
        $n5 = "socket(" ascii
        $n6 = "inet_" ascii
        $n7 = "bind(" ascii

        // Malware C2 IPs
        $ip1 = "66.29.130.61"
        $ip2 = "192.68.69.153"

        // Malware IoC Hash
        $h1 = "d41d8cd98f00b204e9800998ecf8427e"
        $h2 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    condition:
        // Target ELF binaries
        (uint32(0) == 0x464c457f or any of ($c*)) and
        (
            3 of ($s*) or
            3 of ($c*) or
            2 of ($n*) or
            any of ($ip*) or
            any of ($h*)
        ) or all of them
}

/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2016-10-04
	Identifier: Mirai
*/

/* Rule Set ----------------------------------------------------------------- */

rule Mirai_Botnet_Malware {
	meta:
		description = "Detects Mirai Botnet Malware"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2016-10-04"
      modified = "2023-01-27"
		hash1 = "05c78c3052b390435e53a87e3d31e9fb17f7c76bb4df2814313bca24735ce81c"
		hash2 = "05c78c3052b390435e53a87e3d31e9fb17f7c76bb4df2814313bca24735ce81c"
		hash3 = "20683ff7a5fec1237fc09224af40be029b9548c62c693844624089af568c89d4"
		hash4 = "2efa09c124f277be2199bee58f49fc0ce6c64c0bef30079dfb3d94a6de492a69"
		hash5 = "420bf9215dfb04e5008c5e522eee9946599e2b323b17f17919cd802ebb012175"
		hash6 = "62cdc8b7fffbaf5683a466f6503c03e68a15413a90f6afd5a13ba027631460c6"
		hash7 = "70bb0ec35dd9afcfd52ec4e1d920e7045dc51dca0573cd4c753987c9d79405c0"
		hash8 = "89570ae59462e6472b6769545a999bde8457e47ae0d385caaa3499ab735b8147"
		hash9 = "bf0471b37dba7939524a30d7d5afc8fcfb8d4a7c9954343196737e72ea4e2dc4"
		hash10 = "c61bf95146c68bfbbe01d7695337ed0e93ea759f59f651799f07eecdb339f83f"
		hash11 = "d9573c3850e2ae35f371dff977fc3e5282a5e67db8e3274fd7818e8273fd5c89"
		hash12 = "f1100c84abff05e0501e77781160d9815628e7fd2de9e53f5454dbcac7c84ca5"
		hash13 = "fb713ccf839362bf0fbe01aedd6796f4d74521b133011b408e42c1fd9ab8246b"
		id = "a678e9f7-d516-5bdb-962e-b9d39d8a64bb"
	strings:
		$x1 = "POST /cdn-cgi/" ascii
		$x2 = "/dev/misc/watchdog" fullword ascii
		$x3 = "/dev/watchdog" ascii
		$x5 = ".mdebug.abi32" fullword ascii

		$s1 = "LCOGQGPTGP" fullword ascii
		$s2 = "QUKLEKLUKVJOG" fullword ascii
		$s3 = "CFOKLKQVPCVMP" fullword ascii
		$s4 = "QWRGPTKQMP" fullword ascii
		$s5 = "HWCLVGAJ" fullword ascii
		$s6 = "NKQVGLKLE" fullword ascii
	condition:
		uint16(0) == 0x457f and filesize < 200KB and
		(
			( 1 of ($x*) and 1 of ($s*) ) or
			4 of ($s*)
		)
}

/* Rule Set ----------------------------------------------------------------- */

rule Mirai_1_May17 {
   meta:
      description = "Detects Mirai Malware"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2017-05-12"
      super_rule = 1
      hash1 = "172d050cf0d4e4f5407469998857b51261c80209d9fa5a2f5f037f8ca14e85d2"
      hash2 = "9ba8def84a0bf14f682b3751b8f7a453da2cea47099734a72859028155b2d39c"
      hash3 = "a393449a5f19109160384b13d60bb40601af2ef5f08839b5223f020f1f83e990"
      id = "ac85ee28-a01f-5c3d-a534-0c19a3dc92e7"
   strings:
      $s1 = "GET /bins/mirai.x86 HTTP/1.0" fullword ascii
   condition:
      ( uint16(0) == 0x457f and filesize < 5000KB and all of them )
}

rule Miari_2_May17 {
   meta:
      description = "Detects Mirai Malware"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2017-05-12"
      super_rule = 1
      hash1 = "9ba8def84a0bf14f682b3751b8f7a453da2cea47099734a72859028155b2d39c"
      hash2 = "a393449a5f19109160384b13d60bb40601af2ef5f08839b5223f020f1f83e990"
      id = "1c2cc98d-8ca5-5055-8f86-7f85c046ccd9"
   strings:
      $s1 = "User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2272.101 Safari/537.36" fullword ascii
      $s2 = "GET /g.php HTTP/1.1" fullword ascii
      $s3 = "https://%[^/]/%s" fullword ascii
      $s4 = "pass\" value=\"[^\"]*\"" fullword ascii
      $s5 = "jbeupq84v7.2y.net" fullword ascii
   condition:
      ( uint16(0) == 0x457f and filesize < 5000KB and 2 of them )
}

rule MAL_ELF_LNX_Mirai_Oct10_1 {
   meta:
      description = "Detects ELF Mirai variant"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2018-10-27"
      modified = "2023-01-27"
      hash1 = "3be2d250a3922aa3f784e232ce13135f587ac713b55da72ef844d64a508ddcfe"
      id = "7bb28f03-03ba-581a-bc03-bd09a52787d9"
   strings:
      $x1 = " -r /vi/mips.bushido; "
      $x2 = "/bin/busybox chmod 777 * /tmp/" ascii

      $s1 = "POST /ctrlt/DeviceUpgrade_1 HTTP/1.1" fullword ascii
      $s2 = "loadURL>$(echo HUAWEIUPNP)</NewDownloadURL></u:Upgrade></s:Body></s:Envelope>" fullword ascii
      $s3 = "POST /cdn-cgi/" ascii
   condition:
      uint16(0) == 0x457f and filesize < 200KB and (
         ( 1 of ($x*) and 1 of ($s*) ) or
         all of ($x*)
      )
}

rule MAL_ELF_LNX_Mirai_Oct10_2 {
   meta:
      description = "Detects ELF malware Mirai related"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2018-10-27"
      hash1 = "fa0018e75f503f9748a5de0d14d4358db234f65e28c31c8d5878cc58807081c9"
      id = "421b7708-030e-50d1-bf2e-e91758a48c00"
   strings:
      $c01 = { 50 4F 53 54 20 2F 63 64 6E 2D 63 67 69 2F 00 00
               20 48 54 54 50 2F 31 2E 31 0D 0A 55 73 65 72 2D
               41 67 65 6E 74 3A 20 00 0D 0A 48 6F 73 74 3A }
   condition:
      uint16(0) == 0x457f and filesize < 200KB and all of them
}

rule MAL_Mirai_Nov19_1 {
   meta:
      description = "Detects Mirai malware"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/bad_packets/status/1194049104533282816"
      date = "2019-11-13"
      hash1 = "bbb83da15d4dabd395996ed120435e276a6ddfbadafb9a7f096597c869c6c739"
      hash2 = "fadbbe439f80cc33da0222f01973f27cce9f5ab0709f1bfbf1a954ceac5a579b"
      id = "40edcb29-9e10-5b87-ba79-8e3f629829e5"
   strings:
      $s1 = "SERVZUXO" fullword ascii
      $s2 = "-loldongs" fullword ascii
      $s3 = "/dev/null" fullword ascii
      $s4 = "/bin/busybox" fullword ascii
      $sc1 = { 47 72 6F 75 70 73 3A 09 30 }
   condition:
      uint16(0) == 0x457f and filesize <= 100KB and 4 of them
}

rule MAL_ARM_LNX_Mirai_Mar13_2022 {
   meta:
      description = "Detects new ARM Mirai variant"
      author = "Mehmet Ali Kerimoglu a.k.a. CYB3RMX"
      date = "2022-03-16"
      hash1 = "0283b72913b8a78b2a594b2d40ebc3c873e4823299833a1ff6854421378f5a68"
      id = "54d8860e-fc45-5571-b68c-66590c67a705"
   strings:
      $str1 = "/home/landley/aboriginal/aboriginal/build/temp-armv6l/gcc-core/gcc/config/arm/lib1funcs.asm"
      $str2 = "/home/landley/aboriginal/aboriginal/build/temp-armv6l/gcc-core/gcc/config/arm/lib1funcs.asm"
      $str3 = "/home/landley/aboriginal/aboriginal/build/temp-armv6l/gcc-core/gcc/config/arm"
      $str4 = "/home/landley/aboriginal/aboriginal/build/simple-cross-compiler-armv6l/bin/../cc/include"
      $attck1 = "attack.c"
      $attck2 = "attacks.c"
      $attck3 = "anti_gdb_entry"
      $attck4 = "resolve_cnc_addr"
      $attck5 = "attack_gre_eth"
      $attck6 = "attack_udp_generic"
      $attck7 = "attack_get_opt_ip"
      $attck8 = "attack_icmpecho"
   condition:
      uint16(0) == 0x457f and ( 3 of ($str*) or 4 of ($attck*) )
}

rule Linux_Rootkit_ATD_Family
{
    meta:
        description = "Detect Linux Rootkit/Malware ATD ELF family"
        author = "TangerangKota-CSIRT"
        date = "2025-04-28"
        version = "1.0"

    strings:
        // Hash indicators
        $h1 = "cdb4ee2aea69cc6a83331bbe96dc2caa9a299d21329efb0336fc02a82e1839a8"
        $h2 = "9c70f766d3b84fc2bb298efa37cc9191f28bec336329cc11468cfadbc3b137f4"
        $h3 = "6ad9157a6f0d12b0d83244c2db7d75b546f52c05e4379e6c3fd80c9801d4099a"
        $h4 = "c0fd960e125b298e5fdd027134f028205ba8f62bea9a731ff0715e4cd414704a"
        $h5 = "52cbb9eae20e6521c5b82be685b9abdfb74d1f45b1a39e541322c0f2aee4f7e0"
        $h6 = "572908d5eef30c5184f1786f36d8337e"
        $h7 = "eee2c137a5fd45a9bee4500b7c02e1104f4f8d15"

        // IP indicators
        $ip1 = "66.29.130.61"
        $ip2 = "224.0.0.251"
        $ip3 = "192.68.69.153"

        // Commands artifacts
        $cmd1 = "/bin/sh -c \"sudo chown user /tmp/atd\\.elf"
        $cmd2 = "chmod +x /tmp/atd\\.elf"
        $cmd3 = "iptables -t nat -F"
        $cmd4 = "iptables -t mangle -F"
        $cmd5 = "iptables -P FORWARD ACCEPT"
        $cmd6 = "iptables -P OUTPUT ACCEPT"

        // Hardcoded strings
        $str1 = "iptables -X 2> /dev/null"
        $str2 = "iptables -F 2> /dev/null"
        $str3 = "bash"
        $str4 = "/bin/sh"
        $str5 = "Host:"
        $str6 = "Port:"
        $str7 = "Respawn Delay:"
        $str8 = "Shell:"

    condition:
        2 of ($cmd*) or
        2 of ($ip*) or
        4 of ($str*) or
        any of ($h*) or
        all of them
}

rule Linux_Rootkit_ATD_Family2
{
    meta:
        description = "Detect Linux Rootkit/Malware ATD ELF Family"
        author = "TangerangKota-CSIRT"
        date = "2025-04-30"
        version = "1.2"

    strings:
        // Valid hash-only indicators
        $hash1 = "cdb4ee2aea69cc6a83331bbe96dc2caa9a299d21329efb0336fc02a82e1839a8"
        $hash2 = "9c70f766d3b84fc2bb298efa37cc9191f28bec336329cc11468cfadbc3b137f4"
        $hash3 = "6ad9157a6f0d12b0d83244c2db7d75b546f52c05e4379e6c3fd80c9801d4099a"
        $hash4 = "c0fd960e125b298e5fdd027134f028205ba8f62bea9a731ff0715e4cd414704a"
        $hash5 = "52cbb9eae20e6521c5b82be685b9abdfb74d1f45b1a39e541322c0f2aee4f7e0"
        $hash6 = "572908d5eef30c5184f1786f36d8337e"
        $hash7 = "eee2c137a5fd45a9bee4500b7c02e1104f4f8d15"

        // IP Address
        $ip1 = "66.29.130.61"
        $ip2 = "224.0.0.251"
        $ip3 = "192.68.69.153"

        // Command Injection
        $cmd1 = "/bin/sh -c \"sudo chown user /tmp/atd.elf" nocase ascii
        $cmd2 = "chmod +x /tmp/atd.elf" nocase ascii
        $cmd3 = "iptables -t nat -F" nocase ascii
        $cmd4 = "iptables -t mangle -F" nocase ascii
        $cmd5 = "iptables -P FORWARD ACCEPT" nocase ascii
        $cmd6 = "iptables -P OUTPUT ACCEPT" nocase ascii

        // Static Strings Detected
        $str1 = "iptables -X 2> /dev/null" ascii
        $str2 = "iptables -F 2> /dev/null" ascii
        $str3 = "bash" ascii
        $str4 = "/bin/sh" ascii
        $str5 = "Host:" ascii
        $str6 = "Port:" ascii
        $str7 = "Respawn Delay:" ascii
        $str8 = "Shell:" ascii

    condition:
        uint32(0) == 0x464c457f and // Must be ELF
        filesize > 1024 and        // Avoid matching empty or dummy files
        (
            (
                2 of ($cmd*) and 2 of ($ip*) and 3 of ($str*)
            )
            or
            any of ($hash*)
        ) or all of them
}

rule Linux_Persistence_Techniques
{
    meta:
        description = "Detect Linux rootkit persistence on LD_PRELOAD, Cron, or Systemd Service Injection"
        author = "TangerangKota-CSIRT"
        date = "2025-04-30"
        version = "1.0"

    strings:
        // LD_PRELOAD Detect
        $ld1 = "LD_PRELOAD" nocase ascii
        $ld2 = "/etc/ld.so.preload" ascii
        $ld3 = "export LD_PRELOAD=" ascii

        // Cron Persistence
        $cron1 = "/etc/cron.d/" ascii
        $cron2 = "/var/spool/cron/" ascii
        $cron3 = "/etc/crontab" ascii
        $cron4 = "* * * * *" ascii

        // Systemd Service Hijack
        $sysd1 = "[Service]" ascii
        $sysd2 = "ExecStart=" ascii
        $sysd3 = "/etc/systemd/system/" ascii
        $sysd4 = "Type=forking" ascii
        $sysd5 = "Restart=always" ascii

        // Suspicious Command Injection
        $cmd1 = "wget http" ascii
        $cmd2 = "curl http" ascii
        $cmd3 = "base64 -d" ascii
        $cmd4 = "chmod +x" ascii
        $cmd5 = "nohup" ascii

    condition:
        filesize < 5MB and
        (
            2 of ($ld*) or
            2 of ($cron*) or
            3 of ($sysd*) or
            (
                any of ($cmd*) and 1 of ($ld*, $cron*, $sysd*)
            )
        ) or all of them
}
