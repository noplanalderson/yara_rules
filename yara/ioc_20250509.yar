rule Bashrc_Backdoor_Persistence
{
    meta:
        description = "Detects backdoors or persistence mechanisms in .bashrc or .profile files"
        author = "TangerangKota-CSIRT, refined by Grok"
        version = "1.2"
        date = "2025-05-09"
        reference = "https://chatgpt.com"

    strings:
        // Filepath patterns to ensure context
        $file_context = /(^|\n)\s*(source|\.)\s+.{1,100}(bashrc|profile)/ ascii nocase

        // Suspicious commands with bounded patterns
        $b1 = /curl\s+https?:\/\/[a-zA-Z0-9\.\-_\/]{1,100}/ ascii nocase
        $b2 = /wget\s+https?:\/\/[a-zA-Z0-9\.\-_\/]{1,100}/ ascii nocase
        $b3 = /\/tmp\/[a-zA-Z0-9\._\-]{1,50}\.sh/ ascii
        $b4 = /echo\s+.{1,100}base64\s+-d\s*>>\s*[^\s]+/ ascii
        $b5 = /bash\s+-c\s+['"][a-zA-Z0-9\s\/\-\_\.\|&;]{1,100}['"]/ ascii
        $b6 = /nohup\s+[a-zA-Z0-9\s\/\-\_\.\|&;]{1,100}\s*\&/ ascii
        $b7 = /eval\s+\$[a-zA-Z0-9_]{1,50}/ ascii
        $b8 = /python\s+-c\s+['"][a-zA-Z0-9\s\/\-\_\.\|&;]{1,100}['"]/ ascii
        $b9 = /python3\s+-c\s+['"][a-zA-Z0-9\s\/\-\_\.\|&;]{1,100}['"]/ ascii

    condition:
        $file_context and
        (
            // High-confidence indicators
            any of ( $b1, $b2, $b3, $b4 ) or
            // Two or more medium-confidence indicators
            2 of ( $b5, $b6, $b7, $b8, $b9 )
        )
}

rule ELF_Suspicious_Backdoor_Activity
{
    meta:
        author = "TangerangKota-CSIRT, refined by Grok"
        description = "Detects ELF binaries with potential backdoor behavior involving exec, fork, sleep, and network activity"
        threat_level = "high"
        version = "1.2"
        date = "2025-05-09"
        reference = "https://chatgpt.com"

    strings:
        // Function names for execution and process control
        $exec1 = "execl" ascii
        $exec2 = "execlp" ascii
        $exec3 = "execve" ascii
        $fork1 = "fork" ascii
        $fork2 = "vfork" ascii
        $sleep1 = "sleep" ascii
        $sleep2 = "nanosleep" ascii
        $sock1 = "socket" ascii
        $sock2 = "connect" ascii

        // Shell-related strings
        $binsh = "/bin/sh" ascii
        $binbash = "/bin/bash" ascii

        // Optimized IP address pattern
        $netip = /(25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})\.(25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})\.(25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})\.(25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})/ ascii

        // Optional: Network-related indicators
        $netcall = /connect\s*\([^;]+sockaddr/ ascii

    condition:
        // Ensure ELF file (magic number 0x7f454c46 = ELF)
        uint32(0) == 0x7f454c46 and
        (
            // Core backdoor behavior: execution, process, and network
            1 of ($exec*) and
            1 of ($fork*) and
            1 of ($sleep*) and
            1 of ($sock*) and
            // Contextual indicators
            1 of ($binsh, $binbash, $netip, $netcall)
        ) and
        // Optional: Ensure $netip is near network-related strings for context
        (not $netip or $netip in ((@sock1 - 1000)..(@sock1 + 1000)) or $netip in ((@sock2 - 1000)..(@sock2 + 1000)))
}

rule Cron_Backdoor_Persistence
{
    meta:
        description = "Detects backdoors or C2 activity in crontab files"
        author = "TangerangKota-CSIRT, refined by Grok"
        version = "1.1"
        date = "2025-05-09"
        reference = "https://x.ai/grok"

    strings:
        // Crontab context (cron schedule format: minute, hour, day, month, weekday)
        $cron_context = /([^\n]{1,20}\s+){5}/ ascii

        // Suspicious commands with bounded patterns
        $c1 = /wget\s+http[s]?:\/\/[a-zA-Z0-9\.\-_\/]{1,100}/ ascii nocase
        $c2 = /curl\s+http[s]?:\/\/[a-zA-Z0-9\.\-_\/]{1,100}/ ascii nocase
        $c3 = /bash\s+-c\s+['"]?[a-zA-Z0-9\s\/\-\_\.\|&;]{1,100}['"]?/ ascii
        $c4 = /python\s+-c\s+['"][a-zA-Z0-9\s\/\-\_\.\|&;]{1,100}['"]/ ascii
        $c5 = /\/tmp\/[a-zA-Z0-9\._\-]{1,50}\.sh/ ascii
        $c6 = /sh\s+[a-zA-Z0-9\/\-\_\.]{1,100}\s*\&/ ascii
        $c7 = /cd\s+\/tmp\s*[\|;]/ ascii
        $c8 = /chmod\s+\+x\s+\/tmp\/[a-zA-Z0-9\._\-]{1,50}/ ascii
        $c9 = /eval\s+\$[a-zA-Z0-9_]{1,50}/ ascii
        $c10 = /python3\s+-c\s+['"][a-zA-Z0-9\s\/\-\_\.\|&;]{1,100}['"]/ ascii

    condition:
        $cron_context and
        (
            // High-confidence indicators (network or tmp script activity)
            any of ( $c1, $c2, $c5, $c7, $c8 ) or
            // Two or more medium-confidence indicators
            2 of ( $c3, $c4, $c6, $c9, $c10 )
        )
}

# rule Linux_Generic_Backdoor_Detector
# {
#     meta:
#         description = "Detect potential Linux backdoor/malware in ELF, binaries or C source code"
#         author = "TangerangKota-CSIRT"
#         version = "1.0"
#         date = "2025-04-30"
#         category = "Linux Threat Detection"

#     strings:
#         // ELF Header
#         $elf = { 7F 45 4C 46 }

#         // Suspicious Function
#         $c1 = "system(" ascii
#         $c2 = "popen(" ascii
#         $c3 = "execve(" ascii
#         $c4 = "execl(" ascii
#         $c5 = "fork(" ascii
#         $c6 = "dlopen(" ascii
#         $c7 = "LD_PRELOAD" ascii
#         $c8 = "ptrace" ascii
#         $c9 = "kill(" ascii
#         $c10 = "strcpy(" ascii
#         $c11 = "gets(" ascii

#         // Backdooring Commands
#         $s1 = "/bin/sh" ascii
#         $s2 = "/bin/bash" ascii
#         $s3 = "chmod +x" ascii
#         $s4 = "wget http" ascii
#         $s5 = "curl http" ascii
#         $s6 = "nohup" ascii
#         $s7 = "sleep 666" ascii
#         $s8 = "echo -e" ascii
#         $s9 = "base64 -d" ascii

#         // Suspicious Network
#         $n1 = "0.0.0.0"
#         $n2 = "127.0.0.1"
#         $n3 = "PORT="
#         $n4 = "connect(" ascii
#         $n5 = "socket(" ascii
#         $n6 = "inet_" ascii
#         $n7 = "bind(" ascii

#         // Malware C2 IPs
#         $ip1 = "66.29.130.61"
#         $ip2 = "192.68.69.153"

#         // Malware IoC Hash
#         $h1 = "d41d8cd98f00b204e9800998ecf8427e"
#         $h2 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

#     condition:
#         // Target ELF binaries
#         (uint32(0) == 0x464c457f or any of ($c*)) and
#         (
#             3 of ($s*) or
#             3 of ($c*) or
#             2 of ($n*) or
#             any of ($ip*) or
#             any of ($h*)
#         ) or all of them
# }

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