[![CodeQL](https://github.com/SheepReaper/yk-csr-generator/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/SheepReaper/yk-csr-generator/actions/workflows/github-code-scanning/codeql)
[![.github/workflows/release.yml](https://github.com/SheepReaper/yk-csr-generator/actions/workflows/release.yml/badge.svg?event=release)](https://github.com/SheepReaper/yk-csr-generator/actions/workflows/release.yml)

# YubiKey CSR Generator

This tool generates a Certificate Signing Request (CSR) using a private key from a YubiKey device.

## Usage

`yk-csr-gen [options]`

## Options

- `--new-pk`, `--replace-private-key`: Indicates whether to replace the existing private key in the slot. If specified or set to true, a new private key will be generated. (Default: `False`)
- `--slot`, `--slot-number <82|83|84|85|86|87|88|89|8A|8B|8C|8D|8E|8F|90|91|92|93|94|95|9A|9C|9D|9E>`: The slot number on the YubiKey device to be used for the key generation or retrieval. (Default: `9D`)
- `--out`, `--out-file <out-file>`: The file path where the generated CSR will be written. If not provided, CSR will be printed to the console.
- `--out-pub`, `--out-pub-file <out-pub-file>`: If specified, the file path where the public key extracted from the CSR will be written.
- `--text`: Print CSR to console irrespective of file output option. (Default: `False`)
- `--text-pub`: Print the public key to the console. (Default: `False`)
- `--hash <1.3.14.3.2.26|2.16.840.1.101.3.4.2.1|2.16.840.1.101.3.4.2.2|2.16.840.1.101.3.4.2.3|SHA1|sha1|SHA256|sha256|SHA384|sha384|SHA512|sha512>`: Specifies the hash algorithm to use for the CSR. Supported hash algorithms are SHA1, SHA256, SHA384, and SHA512. OIDs and friendly names (case-insensitive) of the algorithms can be used. (Default: `SHA256`)
- `--cn`, `--common-name <common-name>`: The Common Name (CN) attribute to be included in the CSR's Distinguished Name (DN).
- `--c`, `--country`, `--region <country>`: The Country or Region (C) attribute for the CSR's DN.
- `--dc`, `--domain-component <domain-component>`: The Domain Component (DC) attribute for the CSR's DN.
- `--e`, `--email <email>`: The Email Address (E) attribute for the CSR's DN.
- `--city`, `--l`, `--locality <locality>`: The Locality (L) attribute for the CSR's DN, typically represents the city or locality.
- `--organizational-unit`, `--ou <organizational-unit>`: The Organizational Unit (OU) attribute for the CSR's DN, typically represents the department within an organization.
- `--o`, `--organization <organization>`: The Organization (O) attribute for the CSR's DN.
- `--province`, `--st`, `--state <province>`: The State or Province (ST) attribute for the CSR's DN.
- `--s-dns`, `--san-dns <san-dns>`: [Multiple] DNS name to be added to the Subject Alternative Name (SAN) extension.
- `--s-e`, `--san-email <san-email>`: [Multiple] Email address to be added to the SAN extension.
- `--s-ip`, `--san-ip <san-ip>`: [Multiple] IP address to be added to the SAN extension.
- `--s-uri`, `--san-uri <san-uri>`: [Multiple] URI to be added to the SAN extension.
- `--s-upn`, `--san-user-principal-name <san-user-principal-name>`: [Multiple] User Principal Name (UPN) to be added to the SAN extension.
- `--oid <oid>`: [EXPERIMENTAL] [Multiple] Specify custom OID values in the form of o.i.d=value.
- `--version`: Show version information.
- `-?, -h, --help`: Show help and usage information.
