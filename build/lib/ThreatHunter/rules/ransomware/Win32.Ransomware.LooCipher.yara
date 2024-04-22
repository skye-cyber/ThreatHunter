rule Win32_Ransomware_LooCipher : tc_detection malicious
{
    meta:

        author              = "ReversingLabs"

        source              = "ReversingLabs"
        status              = "RELEASED"
        sharing             = "TLP:WHITE"
        category            = "MALWARE"
        malware             = "LOOCIPHER"
        description         = "Yara rule that detects LooCipher ransomware."

        tc_detection_type   = "Ransomware"
        tc_detection_name   = "LooCipher"
        tc_detection_factor = 5

    strings:

        $remote_connection = {
            6A ?? 83 EC ?? 8B CC 89 A5 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 8D 8D ?? 
            ?? ?? ?? 51 E8 ?? ?? ?? ?? 83 C4 ?? 50 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 8D ?? ?? 
            ?? ?? E8 ?? ?? ?? ?? 6A ?? 8D 85 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 50 B9 ?? ?? 
            ?? ?? E8 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 50 E8 ?? ?? 
            ?? ?? 83 C4 ?? 68 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 8D 85 ?? ?? ?? ?? 
            50 68 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 8D 8D ?? ?? ?? ?? 51 68 ?? ?? 
            ?? ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 8D ?? ?? 
            ?? ?? E8 ?? ?? ?? ?? 50 8D 95 ?? ?? ?? ?? 52 E8 ?? ?? ?? ?? 83 C4 ?? 50 8D 85 ?? ?? 
            ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 50 8D 8D ?? ?? ?? ?? 51 E8 ?? ?? ?? ?? 83 C4 ?? 50 
            8D 95 ?? ?? ?? ?? 52 E8 ?? ?? ?? ?? 83 C4 ?? 50 8D 85 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 
            83 C4 ?? 50 8D 8D ?? ?? ?? ?? 51 E8 ?? ?? ?? ?? 83 C4 ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? 
            ?? ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 8D ?? ?? 
            ?? ?? E8 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? 
            ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 8D ?? ?? ?? 
            ?? E8
        }

        $encrypt_files = {
            55 8B EC 6A ?? 68 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 81 EC ?? ?? ?? ?? 53 56 57 8D BD 
            ?? ?? ?? ?? B9 ?? ?? ?? ?? B8 ?? ?? ?? ?? F3 AB A1 ?? ?? ?? ?? 33 C5 89 45 ?? 50 8D 
            45 ?? 64 A3 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? 6A ?? E8 ?? ?? ?? ?? 83 C4 ?? 
            50 E8 ?? ?? ?? ?? 83 C4 ?? 68 ?? ?? ?? ?? 8D 4D ?? E8 ?? ?? ?? ?? C7 45 ?? ?? ?? ?? 
            ?? 8D 4D ?? E8 ?? ?? ?? ?? C6 45 ?? ?? 8D 4D ?? E8 ?? ?? ?? ?? 0F B7 4D ?? 3B C1 74 
            ?? E8 ?? ?? ?? ?? 8B F0 8D 4D ?? E8 ?? ?? ?? ?? 8B C8 83 E9 ?? 8B C6 33 D2 F7 F1 89 
            55 ?? 6A ?? 8B 45 ?? 50 8D 8D ?? ?? ?? ?? 51 8D 4D ?? E8 ?? ?? ?? ?? 89 85 ?? ?? ?? 
            ?? 8B 95 ?? ?? ?? ?? 89 95 ?? ?? ?? ?? C6 45 ?? ?? 8B 85 ?? ?? ?? ?? 50 8D 4D ?? E8 
            ?? ?? ?? ?? C6 45 ?? ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? EB ?? 8D 45 ?? 50 8B 4D ?? 
            E8 ?? ?? ?? ?? 8B 8D ?? ?? ?? ?? 83 C9 ?? 89 8D ?? ?? ?? ?? C6 45 ?? ?? 8D 4D ?? E8 
            ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? 8D 4D ?? E8 ?? ?? ?? ?? 8B 45 ?? 52 8B CD 50 8D 15 
            ?? ?? ?? ?? E8 ?? ?? ?? ?? 58 5A 8B 4D ?? 64 89 0D ?? ?? ?? ?? 59 5F 5E 5B 8B 4D ?? 
            33 CD E8 ?? ?? ?? ?? 81 C4 ?? ?? ?? ?? 3B EC E8 ?? ?? ?? ?? 8B E5 5D C3
        }

        $find_files = {
            52 B9 ?? ?? ?? ?? E8 ?? ?? ?? ?? 88 85 ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? 8D 8D ?? ?? 
            ?? ?? E8 ?? ?? ?? ?? 0F B6 85 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 68 ?? ?? ?? ?? B9 
            ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 0F B6 C0 85 C0 0F 84 ?? ?? ?? 
            ?? 68 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? 68 ?? ?? ?? 
            ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? C6 45 ?? ?? 68 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? E8 
            ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 EC ?? 8B F4 89 
            A5 ?? ?? ?? ?? 50 8D 85 ?? ?? ?? ?? 50 8D 8D ?? ?? ?? ?? 51 8D 8D ?? ?? ?? ?? E8 ?? 
            ?? ?? ?? 8B 50 ?? 52 8B 00 50 8B CE E8 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? C6 45 ?? ?? B9 
            ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 6A ?? 8D 8D ?? ?? ?? ?? 51 C6 45 ?? ?? E8 ?? ?? ?? ?? 
            83 C4 ?? 89 85 ?? ?? ?? ?? 8B 95 ?? ?? ?? ?? 89 95 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 50 
            B9 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? 
            68 ?? ?? ?? ?? 6A ?? 6A ?? 8D 8D ?? ?? ?? ?? 51 E8 ?? ?? ?? ?? EB ?? 83 EC ?? 8B CC 
            89 A5 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? B9 ?? ?? ?? 
            ?? E8 ?? ?? ?? ?? 50 6A ?? 8D 85 ?? ?? ?? ?? 50 C7 45 ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 
            83 C4 ?? 89 85 ?? ?? ?? ?? 8B 8D ?? ?? ?? ?? 89 8D ?? ?? ?? ?? 8B 95 ?? ?? ?? ?? 52 
            B9 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? ?? 
            ?? ?? ?? 8D 85 ?? ?? ?? ?? 50 B9 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 8B 8D 
            ?? ?? ?? ?? 89 8D ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? 8B 95 ?? ?? ?? ?? 52 B9 ?? ?? ?? 
            ?? E8 ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? EB
        }

    condition:
        uint16(0) == 0x5A4D and
        (
            $find_files
        ) and 
        (
            $encrypt_files
        ) and 
        (
            $remote_connection
        )
}