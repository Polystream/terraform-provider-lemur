package lemur

type Config struct {
	Host  string
	Token string
}

type CreateCertificateRequest struct {
	Authority          CreateCertificateRequestAuthority `json:"authority"`
	Name               string                            `json:"name"`
	Owner              string                            `json:"owner"`
	CommonName         string                            `json:"commonName"`
	Notify             bool                              `json:"notify"`
	Organization       string                            `json:"organization,omitempty"`
	Location           string                            `json:"location,omitempty"`
	State              string                            `json:"state,omitempty"`
	OrganizationalUnit string                            `json:"organizationalUnit,omitempty"`
	Country            string                            `json:"country,omitempty"`
	Description        string                            `json:"description"`
	Rotation           bool                              `json:"rotation"`
	ValidityYears      int                               `json:"validityYears"`
	Extensions         CreateCertificateExtensions       `json:"extensions,omitempty"`
}

type CreateCertificateRequestAuthority struct {
	Name string `json:"name"`
}

type CreateCertificateExtensions struct {
	SubAltNames      CreateCertificateAltNames         `json:"subAltNames,omitempty"`
	ExtendedKeyUsage CreateCertificateExtendedKeyUsage `json:"extendedKeyUsage,omitempty"`
}

type CreateCertificateAltNames struct {
	Names []CreateCertificateNames `json:"names,omitempty"`
}

type CreateCertificateNames struct {
	NameType string `json:"nameType"`
	Value    string `json:"value"`
}

type CreateCertificateExtendedKeyUsage struct {
	UseClientAuthentication bool `json:"useClientAuthentication"`
	UseServerAuthentication bool `json:"useServerAuthentication"`
}
