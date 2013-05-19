// This is an example program that demonstrates processing certificates from a
// log entries file. It looks for certificates that contain ".corp" names and
// prints them to stdout.

package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/agl/certificatetransparency"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <log entries file>\n", os.Args[0])
		os.Exit(1)
	}
	fileName := os.Args[1]

	in, err := os.Open(fileName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to open entries file: %s\n", err)
		os.Exit(1)
	}
	defer in.Close()

	entriesFile := certificatetransparency.EntriesFile{in}

	outputLock := new(sync.Mutex)

	entriesFile.Map(func(ent *certificatetransparency.EntryAndPosition, err error) {
		if err != nil {
			return
		}

		cert, err := x509.ParseCertificate(ent.Entry.X509Cert)
		if err != nil {
			return
		}

		dump := false
		if strings.HasSuffix(cert.Subject.CommonName, ".corp") {
			dump = true
		}
		for _, san := range cert.DNSNames {
			if strings.HasSuffix(san, ".corp") {
				dump = true
			}
		}

		if dump {
			outputLock.Lock()
			pem.Encode(os.Stdout, &pem.Block{Type: "CERTIFICATE", Bytes: ent.Entry.X509Cert})
			outputLock.Unlock()
		}
	})
}
