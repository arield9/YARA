rule abused_screenconnect_config
{
    meta:
        description = "Detect ScreenConnect EXEs with suspicious host in ?h= parameter"
        author = "Ariel Davidpur (arield9)"
        date = "2025-04-23"

    strings:
        // ScreenConnect config marker (to reduce false positives)
        $sc_marker = "<ScreenConnect.ApplicationSettings>"

        // Match a full domain after ?h=, like ?h=relay.example.com
        $suspicious_host = /\\?h=[a-z0-9\-\.]{5,100}/ nocase

        // Legitimate domain to exclude
        $legit_domain = "screenconnect.com"

    condition:
        // Make sure it's a ScreenConnect binary
        $sc_marker in (filesize - 5000 .. filesize) and

        // Look for host definition in the last 5000 bytes
        $suspicious_host in (filesize - 5000 .. filesize) and

        // Ensure it's NOT pointing to the legitimate domain
        not $legit_domain in (filesize - 5000 .. filesize)
}