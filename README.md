# YubiKey CSR Generator

This tool generates a Certificate Signing Request (CSR) using a private key from a YubiKey device.

## Usage

`GenerateYKCSR [options]`

## Options

- `--new-pk`, `--replace-private-key`: Indicates whether to replace the existing private key in the slot. If specified or set to true, a new private key will be generated. (Default: `false`)
- `--slot`, `--slot-number`: The slot number on the YubiKey device to be used for the key generation or retrieval. (Default: PivSlot Key Management hex value)
- `--out`, `--out-file`: The file path where the generated CSR will be written. If not provided, the CSR will be printed to the console.
- `--text`: Print CSR to the console irrespective of the file output option. (Default: `false`)
- `--cn`, `--common-name`: The Common Name (CN) attribute to be included in the CSR's Distinguished Name (DN).
- `--c`, `--country`, `--region`: The Country or Region (C) attribute for the CSR's DN.
- `--dc`, `--domain-component`: The Domain Component (DC) attribute for the CSR's DN.
- `--e`, `--email`: The Email Address (E) attribute for the CSR's DN.
- `--l`, `--locality`, `--city`: The Locality (L) attribute for the CSR's DN, typically represents the city or locality.
- `--ou`, `--organizational-unit`: The Organizational Unit (OU) attribute for the CSR's DN, typically represents the department within an organization.
- `--o`, `--organization`: The Organization (O) attribute for the CSR's DN.
- `--st`, `--state`, `--province`: The State or Province (ST) attribute for the CSR's DN.
- `--s-dns`, `--san-dns`: [Multiple] DNS name to be added to the Subject Alternative Name (SAN) extension.
- `--s-e`, `--san-email`: [Multiple] Email address to be added to the SAN extension.
- `--s-ip`, `--san-ip`: [Multiple] IP address to be added to the SAN extension.
- `--s-uri`, `--san-uri`: [Multiple] URI to be added to the SAN extension.
- `--s-upn`, `--san-user-principal-name`: [Multiple] User Principal Name (UPN) to be added to the SAN extension.
