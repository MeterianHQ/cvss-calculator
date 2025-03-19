# CVSS calculator

A simple CVSS score calculator usable from the command line and written in Go. It's based on the excellent [Go-CVSS](https://github.com/pandatix/go-cvss) score calculation library by Pandatix. 
Fast and easy to use, given a vector it computes the score. 

It currently supports :
 - [CVSS 2.0](https://www.first.org/cvss/v2/guide)
 - [CVSS 3.0](https://www.first.org/cvss/v3.0/specification-document)
 - [CVSS 3.1](https://www.first.org/cvss/v3.1/specification-document)
 - [CVSS 4.0](https://www.first.org/cvss/v4.0/specification-document)
 
## Usage

The usage is straightforward. Once you downloaded the latest release, you can use it from your command line:
```
$ cvssc "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
{
  "version": "4.0",
  "vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
  "score": 9.3
}
```

You can also compute multiple vectors with one execution, just specify them on the command line:
```
$ cvssc "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N" "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
{
  "version": "4.0",
  "vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
  "score": 9.3
}
{
  "version": "3.1",
  "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
  "score": 9.8
}
```

A help mechanism is available (-h / --help):
```
$ cvssc -h
CVSS Calculator version 1.0
 - produces a JSON representation of one or more CVSS vectors
 - supports CVSS2.0, CVSS3.0, CVSS3.1, CVSS4.0

Usage:
  cvssc [--help|-h] [--version|-v] <CVSS_vector1> [<CVSS_vector2> ...]

Supported vector formats:
  CVSS:4.0/...
  CVSS:3.1/...
  CVSS:3.0/...
  AV:... (for CVSS v2)

Example:
  cvssc "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N"
```

A simple version reporting is also available (-v / --version):
```
$ cvssc -v
CVSS Calculator version 1.0
```
## License
Released under the MIT license

## Credits
All the credit should go to the the excellent [Go-CVSS](https://github.com/pandatix/go-cvss) score calculation library by Pandatix, as this is just a simple wrapper to use it from the command line.


