package lemur

type Config struct {
	Host  string
	Token string
}

type CreateCertificateRequest struct {
	Authority          CreateCertificateRequestAuthority `json:"authority"`
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
}

type CreateCertificateRequestAuthority struct {
	Name string `json:"name"`
}
