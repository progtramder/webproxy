//
// Copyright 2017 by Progtramder. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
//

package webproxy

import (
	"sync"
	"crypto/tls"
	"crypto/x509"
	"crypto/rsa"
	"crypto/rand"
	"time"
	"math/big"
	"crypto/x509/pkix"
	"encoding/pem"
	"strings"
)

var (
	once         sync.Once
	rootCert     *x509.Certificate
	rootKey      *rsa.PrivateKey
	rootCertErr  error
	hostCerts    = make(map[string] tls.Certificate)
)

var rootCertPem = `-----BEGIN CERTIFICATE-----
MIIDFjCCAf6gAwIBAgIQbrDZTZb5QEPZdld9oX8DEDANBgkqhkiG9w0BAQsFADAq
MRMwEQYDVQQKEwpBbHBoYS1GaXJtMRMwEQYDVQQDEwpBbHBoYS1GaXJtMB4XDTE3
MDczMTE0MDgxNVoXDTI3MDcyOTE0MDgxNVowKjETMBEGA1UEChMKQWxwaGEtRmly
bTETMBEGA1UEAxMKQWxwaGEtRmlybTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC
AQoCggEBAMbmriLBWUwytoEX6MNHgbEfNr2qzu5Dq0I37B6xRdt0tZef3pABhto8
6fYkTAG8EZM5aLXdsFrIKLqM9MzSEj/h2Ac33mJQu+kK9b2oZVVqqZAcnCWCMMN9
INeDRXQ91jJxdGzjoUcIJzTraiUtqmjcyhTUcUx2c+uASl7rwVQ+wZCee51o7BEa
lur7Ek5hyCIXSpxDXoI1szho6Wau0rYxUf4NhLNXDKy0RK8teq8kAJVcuqXP8pkb
3YdGOGSH2xoejSDqXwz4+OSKWAu28pYJh3CEDIWSiQqK9SI5vsh6kuBD+dq2ilXv
V9NuengsXeZv69PIQ4E9sHVON9qSR/0CAwEAAaM4MDYwDgYDVR0PAQH/BAQDAgKk
MBMGA1UdJQQMMAoGCCsGAQUFBwMBMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcN
AQELBQADggEBADJbkTffnXP8WVLEgBmEI74ITNeJ92thd4zSDmSf2a8zVKZNquKl
4vcU8SeWDY9JL2wF95m4K0wVxHL9zfUEbaHKQTK8wpQM23Kpear8VhGpL2n6MGzi
Tg/I8qfF0kX9mIP+zmAaq8nc1oMJvnY+FD8JGjvA56ahJ/eXsbXE5uYz7n9+2Eaq
j2nDCBnjrPRBOUs2QF0Spbicb0T4x/WsktRffMQIS7GQEaOi3hsso36FbpYCX1oW
Nia0jPZWoV3xUbhIAkFqCqKa+IEvopHqXlIKZhCCeZadxvydRzje/mP32FLiAhR2
DiR8aL53kueGVvyGuyRiOnnEKn5XgjVXZgU=
-----END CERTIFICATE-----
`
var rootKeyPem = `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAxuauIsFZTDK2gRfow0eBsR82varO7kOrQjfsHrFF23S1l5/e
kAGG2jzp9iRMAbwRkzlotd2wWsgouoz0zNISP+HYBzfeYlC76Qr1vahlVWqpkByc
JYIww30g14NFdD3WMnF0bOOhRwgnNOtqJS2qaNzKFNRxTHZz64BKXuvBVD7BkJ57
nWjsERqW6vsSTmHIIhdKnENegjWzOGjpZq7StjFR/g2Es1cMrLREry16ryQAlVy6
pc/ymRvdh0Y4ZIfbGh6NIOpfDPj45IpYC7bylgmHcIQMhZKJCor1Ijm+yHqS4EP5
2raKVe9X0256eCxd5m/r08hDgT2wdU432pJH/QIDAQABAoIBAGvyZi+Wn9Aq9cG6
KClTdZ+bQSpOuV+2egvGLe+6Zh9kh+lyamfdbEKlLJTZviZy21b7oUiSuFOMrg4Q
0gsXN7BT8dp5B8hz6Ifh2tzDt7tT2BLOdDAnKC/wiRJtvBQKO2XFDVrLb4wNcLnX
yhPDZOjkawhDA/prjx4Q0kwRxyrgrzGVZbY2lcJbce302Tds1mfkJeoSP9iIRcVV
zM0EifKP7HbHxpy9s7HEkoHgHANEn9RYJiUWlNlKeXHXyTKIrSocsWEVyMJ5WoUQ
TKRyUraXasDiUrSr+cTs8OfQEDvcEV16esZE8Hi5nx2Ax1J4UEHvhVMFYcIYoEia
NLG8jAECgYEA2VY4HWOva941ZyXRFlkRhg3RfvrEYhvMvYEVxm/faCTJXh1Rf8H8
D7bLh9ciGNjlfxxradjpmi09XcD/4SM7F9TOGzuiNOo/gBD90B/VAHdwQ/3inJuN
TfwaLWhmGLUqYjYBsf0CvYjzciPTyWZo+MB1k5sr8p7DEAWYxEbrM/ECgYEA6kjg
f/+19bZmInWKNMJBEplvurcWWXyTz7sKr43GYjmy0D7KFmoge97RVFkBJe32ZLut
hrcLAoNd2JbR8zjhNK7YQCmim/gZpubRYlhe168NGryVjMTVVeHTUJ3WAlkC8Btg
KbBU3CI+oiauHnKdfOmixV/NkeVl/vk/xxjEsM0CgYAqkGMvBk3dv0gQKmzXhpwS
9/PWfYAmgrFHT9eW5GQJfmLdhrpmXfRik3cq5GwuF5Rin4s90Jh3dHK3QMwcKI0z
Lp8q4DP1TwceqrU6pHFPxRR8jGVsLF6xLjVmPTL5lcl2MIOGezmlKwQaj3+zytW2
GeMtBE/IFWW4ZpAzqHv50QKBgDtLxJ5AzwHob0MrcpZVz/hwIyojqqFteU+rLFIw
VNSJe+te6PDxXVVcmKh7emHqL2FhatLcwwmYzAjEa1DexYj687qRjxlgmsV2R+pX
KXH3WR66OjONod0BseUGfaLMeoTguN70RRYOCMIrfggwxBFYZJ0F2Vais8Truque
ZjHFAoGBAJ4lkHYExD5TQcyFZVA3wV/J5aAuMx4Vn+gXKEp9bHxsWdkaciuGGZl+
EkS8spYu+Hfy+uLE/NvEw/ksImoyS2aGou117KXtEm8C4PtrwKTvGzSTK/knNyVQ
9UZOJpxNZ+l+uYtszCy1JA4Jt7mgmGC5wC4wu934Mc336LSroTM7
-----END RSA PRIVATE KEY-----
`

func loadRootCert() error {
	once.Do(initRootCert)
	return rootCertErr
}

func initRootCert() {
	block, _ := pem.Decode([]byte(rootCertPem))
	rootCert, rootCertErr = x509.ParseCertificate(block.Bytes)

	block, _ = pem.Decode([]byte(rootKeyPem))
	rootKey, rootCertErr = x509.ParsePKCS1PrivateKey(block.Bytes)
}

func createCertForHost(host string) (tls.Certificate, error) {

	host = strings.TrimSuffix(host, ":443")

	for key, val := range hostCerts {
		if key == host {
			return val, nil
		}
	}

	//Create cert for the host
	private, err := rsa.GenerateKey(rand.Reader, 2048)

	notBefore := time.Now()
	notAfter := rootCert.NotAfter

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, _   := rand.Int(rand.Reader, serialNumberLimit)

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Alpha-Firm"},
			CommonName  : host,
		},
		NotBefore:   notBefore,
		NotAfter:    notAfter,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, rootCert, &private.PublicKey, rootKey)
	if err != nil {
		return tls.Certificate{}, err
	}

	cert := tls.Certificate{}
	cert.Certificate = append(cert.Certificate, derBytes)
	cert.PrivateKey  = private

	hostCerts[host] = cert
	return cert, nil
}
