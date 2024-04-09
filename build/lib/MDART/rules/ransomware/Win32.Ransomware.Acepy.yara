rule Win32_Ransomware_Acepy : tc_detection malicious
{
    meta:

        author              = "ReversingLabs"

        source              = "ReversingLabs"
        status              = "RELEASED"
        sharing             = "TLP:WHITE"
        category            = "MALWARE"
        malware             = "ACEPY"
        description         = "Yara rule that detects Acepy ransomware."

        tc_detection_type   = "Ransomware"
        tc_detection_name   = "Acepy"
        tc_detection_factor = 5

    strings:

        $find_files = {
            E9 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 83 E0 ?? 83 F8 ?? 0F 84 ?? ?? ?? ?? B8 ?? ?? ?? ??
            50 8D 85 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? B9 ?? ?? ?? ?? 51 50 E8 ?? ?? ?? ??
            83 C4 ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? E9 ?? ?? ?? ?? 8B 45 ?? 8B 08 51 E8 ?? ?? ?? ??
            83 C4 ?? 50 8D 85 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 83 F8 ?? 0F 84 ?? ?? ?? ??
            E9 ?? ?? ?? ?? E9 ?? ?? ?? ?? B8 ?? ?? ?? ?? 50 8D 85 ?? ?? ?? ?? 50 E8 ?? ?? ?? ??
            B8 ?? ?? ?? ?? 50 8D 85 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 8D 85 ?? ?? ?? ?? 50
            8B 85 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 F8 ?? 0F 85 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 50
            E8 ?? ?? ?? ?? B8 ?? ?? ?? ?? 50 B8 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? E8 ?? ??
            ?? ?? B8 ?? ?? ?? ?? C9 C3
        }

        $encrypt_files = {
            55 89 E5 81 EC ?? ?? ?? ?? 90 B8 ?? ?? ?? ?? 50 8B 45 ?? 50 E8 ?? ?? ?? ?? 83 C4 ??
            89 45 ?? 8B 45 ?? 83 F8 ?? 0F 84 ?? ?? ?? ?? E9 ?? ?? ?? ?? B8 ?? ?? ?? ?? E9 ?? ??
            ?? ?? B8 ?? ?? ?? ?? 50 B8 ?? ?? ?? ?? 50 8B 45 ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 8B 45
            ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 89 45 ?? B8 ?? ?? ?? ?? 50 B8 ?? ?? ?? ?? 50 8B 45 ??
            50 E8 ?? ?? ?? ?? 83 C4 ?? 8B 45 ?? 40 50 B8 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 ??
            89 45 ?? 8B 45 ?? 50 B8 ?? ?? ?? ?? 50 8B 45 ?? 50 8B 45 ?? 50 E8 ?? ?? ?? ?? 83 C4
            ?? B8 ?? ?? ?? ?? 89 45 ?? 8B 45 ?? 8B 4D ?? 39 C8 0F 83 ?? ?? ?? ?? E9 ?? ?? ?? ??
            8B 45 ?? 89 C1 40 89 45 ?? EB ?? 8B 45 ?? 8B 4D ?? 01 C1 8B 45 ?? 8B 55 ?? 01 C2 8B
            45 ?? 50 89 4D ?? 89 55 ?? E8 ?? ?? ?? ?? 83 C4 ?? 89 45 ?? 8B 45 ?? 8B 4D ?? 31 D2
            F7 F1 8B 45 ?? 01 D0 8B 4D ?? 0F BE 09 0F BE 10 31 D1 8B 45 ?? 88 08 EB ?? B8 ?? ??
            ?? ?? 50 8B 45 ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 8B 4D ?? 51 B9 ?? ?? ?? ?? 51 50 E8 ??
            ?? ?? ?? 83 C4 ?? 8B 45 ?? 50 B8 ?? ?? ?? ?? 50 8B 45 ?? 50 8B 45 ?? 50 E8 ?? ?? ??
            ?? 83 C4 ?? 8B 45 ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 8B 45 ?? C9 C3
        }

        $drop_ransom_note = {
            55 89 E5 81 EC ?? ?? ?? ?? 90 B8 ?? ?? ?? ?? 50 8B 45 ?? 50 E8 ?? ?? ?? ?? 83 C4 ??
            89 45 ?? 8B 45 ?? 83 F8 ?? 0F 84 ?? ?? ?? ?? E9 ?? ?? ?? ?? B8 ?? ?? ?? ?? E9 ?? ??
            ?? ?? B8 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 8B 4D ?? 51 50 B8 ?? ?? ?? ?? 50 B8
            ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 8B 45 ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? B8 ?? ??
            ?? ?? C9 C3
        }

    condition:
        uint16(0) == 0x5A4D and
        (
            (
                $find_files
            ) and
            (
                $encrypt_files
            ) and
            (
                $drop_ransom_note
            )
        )
}