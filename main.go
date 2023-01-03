package main

import (
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"github.com/lestrrat-go/jwx/jwk"
	"log"
	"os"
)

type JWKStruct struct {
	Kid     string   `json:"kid,omitempty"`
	Alg     string   `json:"alg,omitempty"`
	Use     string   `json:"use,omitempty"`
	Kty     string   `json:"kty,omitempty"`
	Crv     string   `json:"crv,omitempty"`
	D       string   `json:"d,omitempty"`
	Dp      string   `json:"dp,omitempty"`
	Dq      string   `json:"dq,omitempty"`
	E       string   `json:"e,omitempty"`
	K       string   `json:"k,omitempty"`
	N       string   `json:"n,omitempty"`
	P       string   `json:"p,omitempty"`
	Q       string   `json:"q,omitempty"`
	Qi      string   `json:"qi,omitempty"`
	X       string   `json:"x,omitempty"`
	X5c     []string `json:"x5c,omitempty"`
	X5t     string   `json:"x5t,omitempty"`
	X5ts256 string   `json:"x5t#S256,omitempty"`
	Y       string   `json:"y,omitempty"`
}

func main() {
	alg := flag.String("alg", "PS256", "The JWA alg to be set")
	use := flag.String("use", "sig", "The usage of the key")
	kid := flag.String("kid", "", "The kid of the key")
	kidFromFile := flag.Bool("kidFromFile", false, "Generate the kid from filename")
	//out := flag.String("out", "", "The jwk file to be created")
	x5atts := flag.Bool("x5atts", false, "If the x5* attributes should be created")

	flag.Parse()
	pemFiles := flag.Args()

	if len(pemFiles) == 0 {
		fmt.Fprintf(os.Stderr, "Usage of %s:\n <options> pemfile1 <pemfile2>...", os.Args[0])
		flag.PrintDefaults()
		os.Exit(-1)
	}

	keys := []JWKStruct{}
	for _, s := range pemFiles {
		f, err := os.ReadFile(s)
		if err != nil {
			log.Fatal(err)
		}
		key, err := jwk.ParseKey([]byte(f), jwk.WithPEM(true))
		rawContent, _ := json.Marshal(key)

		keyId := *kid
		if *kidFromFile {
			keyId = s
		}
		newKey := JWKStruct{
			Kid: keyId,
			Alg: *alg,
			Use: *use,
		}
		err = json.Unmarshal(rawContent, &newKey)

		if *x5atts {
			chain := make([]string, 0)

			certPEMBlock := []byte(f)
			firstCert := true
			var certDERBlock *pem.Block
			for {
				certDERBlock, certPEMBlock = pem.Decode(certPEMBlock)
				if certDERBlock == nil {
					break
				}
				if certDERBlock.Type == "CERTIFICATE" {
					certificate := certDERBlock.Bytes
					if firstCert {
						t256 := sha256.Sum256(certificate)
						tsha1 := sha1.Sum(certificate)
						newKey.X5t = base64.URLEncoding.EncodeToString(tsha1[:])
						newKey.X5ts256 = base64.URLEncoding.EncodeToString(t256[:])
						firstCert = false
					}
					chain = append(chain, base64.StdEncoding.EncodeToString(certificate))
				}
			}
			newKey.X5c = chain
		}
		keys = append(keys, newKey)
	}
	keysJwk := make(map[string][]JWKStruct)
	keysJwk["keys"] = keys

	keysContent, _ := json.MarshalIndent(keysJwk, "", "    ")

	fmt.Println(string(keysContent))

}
