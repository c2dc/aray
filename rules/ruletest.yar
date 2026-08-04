rule MAORI_Ransomware
{
        meta:
                author = "lherrera@globalcybersec.com"
                description = "YARA rule for detect MAORI Ransomware"

	strings:
                $N_1 = "local.maori.onion"
                $N_2 = "ReadFromIP"
                $N_3 = "LookupAddr"
                $N_4 = "LookupHost"
                $N_5 = "LookupPort"
                $N_6 = "ReadFromInet4"
                $N_7 = "ReadFromInet6"
                $N_8 = "LookupMX"
                $N_9 = "LookupIP"
                $N_10 = "LookupNS"
                $N_11 = "LookupCNAME"

                $SQ_1 = "SQLScanner"
                $SQ_2 = "config.pgpass"
                $SQ_3 = "QueryRow"
                $SQ_4 = "SendQuery"

                $E_1 = "BuildNameToCertificate"
                $E_2 = "NewCBCEncrypter"
                $E_3 = "NewPublicKey"
                $E_4 = "NewPrivateKey"
                $E_5 = "Encrypt"
                $E_6 = "HashStrBytes"

                $R_1 = { 72 75 6e 74 69 6d 65 2e 67 6f }
                $R_2 = { 69 6e 74 65 72 6e 61 6c 2f 63 70 75 2f 63 70 75 2e 67 6f }
                $R_3 = { 6d 7a 59 57 72 57 71 47 6b 2e 67 6f }

        condition:
                filesize > 1KB and
                uint32(0) == 0x464C457F and
                all of ($N_*) or
                all of ($SQ_*) or
                all of ($E_*) or
                1 of ($R_*)
}
