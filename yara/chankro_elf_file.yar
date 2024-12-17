rule Detect_ELF_SO_File_64bit_With_Sections {
    meta:
        description = "Detects ELF 64-bit shared object (.so) files with section header analysis"
        author = "Mr. Naeem"
        created = "2024-12-16"
        version = "1.1"
        elf_magic = "7f454c46"  // ELF magic: 0x7f 45 4c 46
        // elf_type = "02"         // Type: DYN (Shared object file)
        // elf_class = "02"        // Class: ELF64 (64-bit)
        // elf_machine = "3e"      // Machine: x86-64 (AMD64)

    strings:
        // ELF magic (file header signature)
        $elf_magic = { 7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00 }  // ELF magic bytes (0x7f 45 4c 46)
        
        // ELF64 Class (indicating 64-bit architecture)
        // $elf_class_64 = { 02 }         // ELF64 Class: 64-bit
        
        // ELF Type: DYN (Shared object file)
        // $elf_type_dyn = { 02 }         // Type: DYN (Shared object file)
        
        // Machine: x86-64 (AMD64)
        // $elf_machine_x86_64 = { 3E }   // x86-64 architecture

        // Section names relevant for ELF shared object detection
        $section_note = ".note.gnu.buildid"   // Section name: .note.gnu.buildid
        $section_gnu_hash = ".gnu.hash"       // Section name: .gnu.hash
        $section_dynsym = ".dynsym"           // Section name: .dynsym
        $section_dynstr = ".dynstr"           // Section name: .dynstr
        $section_rela_dyn = ".rela.dyn"       // Section name: .rela.dyn
        $section_rela_plt = ".rela.plt"       // Section name: .rela.plt
        $pwn = "pwn"
    condition:
        // Memastikan file memiliki magic bytes ELF dan merupakan file ELF64
        $elf_magic at 0 and
        // $elf_class_64 at 4 and
        // $elf_type_dyn at 16 and
        // $elf_machine_x86_64 at 18 and

        // Memastikan file memiliki salah satu nama section yang relevan
        any of ($section_note, $section_gnu_hash, $section_dynsym, $section_dynstr, $section_rela_dyn, $section_rela_plt, $pwn)
}
