X509Toolkit
===========

This application provides a set of utilities for working with X.509 certificates. It can be used to view, convert, validate, and extract X.509 certificates from various sources, including PCAP/PCAPNG files.

Using the utility
-----------------

    Usage:
      X509Toolkit <command> [options]

    Commands:
      convert      -i <input> -f <PEM|DER> [-o <output>]
                   Convert an X.509 certificate between PEM and DER formats.
                   If -o is not specified, the result is written to stdout.

      info         -i <input>
                   Display detailed information about the certificate, including subject,
                   issuer, serial number, validity period, and more.

      json         -i <input> [-o <output>]
                   Parse the certificate and output its structure as a formatted JSON object.
                   If -o is not specified, the result is written to stdout.

      expire       -i <input>
                   Show the certificate's expiration date and the number of days until it expires.

      pcap-extract -i <pcap> -f <PEM|DER> [-o <directory>] [-s]
                   Extract X.509 certificates from a packet capture (pcap/pcapng) file.
                   Certificates are written to the output directory or to stdout in the specified format.
                   Use -s to display extraction statistics after processing.
                   If -o is not specified, the certificates are written to stdout.

    Examples:
      X509Toolkit convert -i cert.der -o cert.pem -f PEM
      X509Toolkit info -i cert.pem
      X509Toolkit json -i cert.pem -o cert.json
      X509Toolkit expire -i cert.pem
      X509Toolkit pcap-extract -i tls.pcap -o MyCertDir -f PEM -s
