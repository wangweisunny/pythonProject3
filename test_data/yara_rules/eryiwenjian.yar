rule Malware_Generic
{
    meta:
        author = "Your Name"
        date = "2023-12-01"
        description = "Detects generic malware based on common patterns"
        version = "1.0"

    strings:
        $pe_header = { 4D 5A } // MZ header (PE file)
        $pe_stub = { 50 45 } // PE header
        $xor_pattern = { 55 8B EC 83 EC ?? } // XOR encryption pattern (common in shellcode)
        $api_call = { 6A 00 E8 ?? ?? ?? ?? 83 C4 04 } // Common API call pattern
        $packed_code = { 55 8B EC 83 EC 10 33 C0 60 } // Packed code pattern
        $shellcode = { E8 ?? ?? ?? ?? 83 C4 04 } // Shellcode jump pattern

    condition:
        uint16(0) == 0x5A4D and // Check for MZ header
        filesize > 1024 and // Ensure file is larger than 1KB
        2 of ($xor_pattern, $api_call, $packed_code, $shellcode) // Match at least 2 of the patterns
}