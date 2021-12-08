package main

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/big"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/digitorus/timestamp"
	"github.com/grantae/certinfo"
)

// ExampleCreateRequest_ParseResponse demonstrates the creation of a time-stamp request, sending
// it to the server and parsing the response.
// nolint: govet
func main() {

	var fresh_tsr bool
	var inspect_tsr bool
	var tsa_host string
	var request_cert bool
	var display_cert bool
	var tsr_file string
	var write_tsr bool

	flag.StringVar(&tsa_host, "url", "https://freetsa.org/tsr", "TS Authority url")
	flag.BoolVar(&display_cert, "d", false, "Display certificate (if any)")
	flag.BoolVar(&request_cert, "c", true, "Request authority's certificate")
	flag.BoolVar(&inspect_tsr, "i", false, "Inspect a response (DER base64 encoded)")
	flag.StringVar(&tsr_file, "t", "-", "TSR file to inspect")
	flag.BoolVar(&fresh_tsr, "r", true, "Request a time stamp")
	flag.BoolVar(&write_tsr, "w", false, "Write response (DER based64 encoded) to standard output")

	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage:\t%s [options] [filename]\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()

	// There is optionally a single non-flag argument, which is the file name to be stamped
	// if it is missing we use standard input.

	var filename string
	switch flag.NArg() {
	case 0:
		filename = "" // will use stdin
	case 1:
		filename = flag.Arg(0)
	default:
		flag.Usage()
		os.Exit(2)
	}

	var tsr []byte
	var err error
	if fresh_tsr {
		var input io.Reader
		if filename == "" {
			input = os.Stdin
		} else {
			input, err = os.Open(filename)
			if err != nil {
				log.Fatalf("failed to open file: %v", err)
			}
		}

		tsq_options := &timestamp.RequestOptions{
			Hash:         crypto.SHA256,
			Certificates: request_cert,
		}

		r, err := stamp_file(input, tsa_host, tsq_options)
		if err != nil {
			log.Fatal(err)
		}
		tsr = r
	} else {
		r, err := tsr_from_file(tsr_file)
		if err != nil {
			log.Fatal(err)
		}
		tsr = r
	}

	if write_tsr {
		tsr_string := base64.StdEncoding.EncodeToString(tsr)
		fmt.Println(tsr_string)
	} else {
		fmt.Println(tsr_info(tsr, display_cert))
	}

}

func tsr_from_file(filename string) ([]byte, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %v", err)
	}
	defer file.Close()

	decoder := base64.NewDecoder(base64.StdEncoding, file)
	tsr, err := ioutil.ReadAll(decoder)
	if err != nil {
		return nil, fmt.Errorf("failed to read data from file: %v", err)
	}
	return tsr, nil
}

func stamp_file(file io.Reader, service string, options *timestamp.RequestOptions) ([]byte, error) {

	tsq, err := timestamp.CreateRequest(file, options)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	tsr, err := http.Post(service, "application/timestamp-query", bytes.NewReader(tsq))
	if err != nil {
		return nil, fmt.Errorf("failed to get response: %v", err)
	}

	if tsr.StatusCode > 200 {
		return nil, fmt.Errorf("response is not OK: %v", err)
	}

	resp, err := ioutil.ReadAll(tsr.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %v", err)
	}
	return resp, nil
}

// It would be really nice if I could implement String() for timestamp.Timestamp,
// but go won't let me. So I am literally copying the structure over and giving it
// a local private name. I am not including the things that we won't need to print
type myTimestamp struct {
	HashAlgorithm crypto.Hash
	HashedMessage []byte

	Time         time.Time
	Accuracy     time.Duration
	SerialNumber *big.Int
	Policy       asn1.ObjectIdentifier
	// Ordering     bool
	// Nonce        *big.Int
	Qualified bool

	Certificates []*x509.Certificate

	AddTSACertificate bool

	// Extensions contains raw X.509 extensions from the Extensions field of the
	// Time-Stamp. When parsing time-stamps, this can be used to extract
	// non-critical extensions that are not parsed by this package. When
	// marshaling time-stamps, the Extensions field is ignored, see
	// ExtraExtensions.
	// Extensions []pkix.Extension

	// ExtraExtensions contains extensions to be copied, raw, into any marshaled
	// Time-Stamp response. Values override any extensions that would otherwise
	// be produced based on the other fields. The ExtraExtensions field is not
	// populated when parsing Time-Stamp responses, see Extensions.
	// ExtraExtensions []pkix.Extension
}

func (t myTimestamp) String() string {
	// Don't use the printf %x, as that will strip leading zeros
	imprint := fmt.Sprintf("%s:\t%s", "Message-imprint", hex.EncodeToString(t.HashedMessage))
	stampedTime := fmt.Sprintf("%s\t%s", "Time", t.Time)
	alg := fmt.Sprintf("%s:\t%s", "hash-algorithm", t.HashAlgorithm)
	policy := fmt.Sprintf("%s:\t%s", "Policy", t.Policy)
	sn := fmt.Sprintf("%s:\t%s", "SN", t.SerialNumber)

	certtext := "Certificate not included"
	if t.AddTSACertificate {
		certtext, _ = certinfo.CertificateText(t.Certificates[0])
	}

	rows := []string{
		imprint,
		stampedTime,
		sn,
		alg,
		policy,
		certtext,
	}
	return strings.Join(rows, "\n")
}

func tsr_info(tsr []byte, display_cert bool) (string, error) {

	t, err := timestamp.ParseResponse(tsr)
	if err != nil {
		return "", fmt.Errorf("could not parse: %v", err)
	}
	mt := &myTimestamp{
		HashedMessage:     t.HashedMessage,
		HashAlgorithm:     t.HashAlgorithm,
		Time:              t.Time,
		Accuracy:          t.Accuracy,
		SerialNumber:      t.SerialNumber,
		Policy:            t.Policy,
		Qualified:         t.Qualified,
		Certificates:      t.Certificates,
		AddTSACertificate: t.AddTSACertificate && display_cert,
	}

	return mt.String(), nil
}
