/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/
package ca

import (
	"crypto/x509"
        "os"
	"github.com/hyperledger/fabric/internal/cryptogen/csp"
)

// baseDir/name
func NewIntermediateCA(
	baseDir,
	org,
	name,
	country,
	province,
	locality,
	orgUnit,
	streetAddress,
	postalCode string,
        signCA *CA,
) (*CA, error) {
	var ca *CA

	err := os.MkdirAll(baseDir, 0o755)
	if err != nil {
		return nil, err
	}

	priv, err := csp.GeneratePrivateKey(baseDir)
	if err != nil {
		return nil, err
	}

	template := x509Template()
	// this is a CA
	template.IsCA = true
	template.KeyUsage |= x509.KeyUsageDigitalSignature |
		x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign |
		x509.KeyUsageCRLSign
	template.ExtKeyUsage = []x509.ExtKeyUsage{
		x509.ExtKeyUsageClientAuth,
		x509.ExtKeyUsageServerAuth,
	}

	// set the organization for the subject
	subject := subjectTemplateAdditional(country, province, locality, orgUnit, streetAddress, postalCode)
	subject.Organization = []string{org}
	subject.CommonName = name

	template.Subject = subject
	template.SubjectKeyId = computeSKI(priv)
/*
	x509Cert, err := genCertificateECDSA(
		baseDir,
		name,
		&template,
		&template,
		&priv.PublicKey,
		priv,
	)
	if err != nil {
		return nil, err
	}
*/
	ca = &CA{
		Name: name,
		Signer:             signCA.Signer, 
		SignCert:           signCA.SignCert,
		Country:            country,
		Province:           province,
		Locality:           locality,
		OrganizationalUnit: orgUnit,
		StreetAddress:      streetAddress,
		PostalCode:         postalCode,
	}

	return ca, err
}

