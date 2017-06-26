package lemur

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"

	"encoding/json"

	"strconv"

	"github.com/hashicorp/terraform/helper/schema"
)

func dataSourceLemurCertificate() *schema.Resource {
	return &schema.Resource{
		Read: dataSourceLemurCertificateRead,

		Schema: map[string]*schema.Schema{
			"common_name": &schema.Schema{
				Type:     schema.TypeString,
				Required: true,
			},
			"owner": &schema.Schema{
				Type:     schema.TypeString,
				Required: true,
			},
			"authority": &schema.Schema{
				Type:     schema.TypeString,
				Required: true,
			},
			"description": &schema.Schema{
				Type:     schema.TypeString,
				Required: true,
			},
			"validity_years": &schema.Schema{
				Type:     schema.TypeInt,
				Required: true,
			},
			"organization": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},
			"location": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},
			"state": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},
			"organizational_unit": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},
			"country": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			"chain": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
			},
			"public_certificate": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
			},
			"private_certificate": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
			},
		},
	}
}

func dataSourceLemurCertificateRead(d *schema.ResourceData, meta interface{}) error {
	config := meta.(Config)

	client := &http.Client{}
	commonName := d.Get("common_name").(string)

	findExistingURL := config.Host + "/api/1/certificates?filter=cn;" + commonName
	findExisting, err := http.NewRequest("GET", findExistingURL, nil)
	if err != nil {
		return fmt.Errorf("Error creating request: %s", findExistingURL)
	}
	findExisting.Header.Set("Authorization", "bearer "+config.Token)

	findExistingResponse, err := client.Do(findExisting)
	if err != nil {
		return fmt.Errorf("Error during making a request: %s", findExistingURL)
	}

	defer findExistingResponse.Body.Close()

	if findExistingResponse.StatusCode != 200 {
		return fmt.Errorf("HTTP request error. Response code: %d", findExistingResponse.StatusCode)
	}

	responseBytes, err := ioutil.ReadAll(findExistingResponse.Body)
	if err != nil {
		return fmt.Errorf("Error while reading response body. %s", err)
	}

	var certificatesResponse map[string]interface{}
	err = json.Unmarshal(responseBytes, &certificatesResponse)
	if err != nil {
		return fmt.Errorf("Error while reading response body. %s", err)
	}

	var certificateID int
	totalResults := certificatesResponse["total"].(float64)
	if totalResults > 0 {
		items := certificatesResponse["items"].([]interface{})
		for _, item := range items {
			itemMap := item.(map[string]interface{})
			if itemMap["active"].(bool) {
				certificateID = int(itemMap["id"].(float64))
			}
		}
	} else {
		certificateID, err = createCertificate(d, config)
		if err != nil {
			return fmt.Errorf("Error creating certificate. %s", err)
		}
	}

	getPublicCertificateData(certificateID, d, config)
	getPrivateCertificateData(certificateID, d, config)
	d.SetId(strconv.Itoa(certificateID))

	return nil
}

func getPublicCertificateData(certificateID int, d *schema.ResourceData, config Config) error {
	client := &http.Client{}

	url := config.Host + "/api/1/certificates/" + strconv.Itoa(certificateID)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return fmt.Errorf("Error creating request: %s", url)
	}
	req.Header.Set("Authorization", "bearer "+config.Token)

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("Error during making a request: %s", url)
	}

	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("HTTP request error. Response code: %d", resp.StatusCode)
	}

	responseBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("Error while reading response body. %s", err)
	}

	var certificatesResponse map[string]interface{}
	err = json.Unmarshal(responseBytes, &certificatesResponse)
	if err != nil {
		return fmt.Errorf("Error while reading response body. %s", err)
	}

	d.Set("chain", certificatesResponse["chain"].(string))
	d.Set("public_certificate", certificatesResponse["body"].(string))

	return nil
}

func getPrivateCertificateData(certificateID int, d *schema.ResourceData, config Config) error {
	client := &http.Client{}

	url := config.Host + "/api/1/certificates/" + strconv.Itoa(certificateID) + "/key"
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return fmt.Errorf("Error creating request: %s", url)
	}
	req.Header.Set("Authorization", "bearer "+config.Token)

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("Error during making a request: %s", url)
	}

	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("HTTP request error. Response code: %d", resp.StatusCode)
	}

	responseBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("Error while reading response body. %s", err)
	}

	var keyReponse map[string]interface{}
	err = json.Unmarshal(responseBytes, &keyReponse)
	if err != nil {
		return fmt.Errorf("Error while reading response body. %s", err)
	}

	d.Set("private_certificate", keyReponse["key"].(string))

	return nil
}

func createCertificate(d *schema.ResourceData, config Config) (int, error) {
	client := &http.Client{}

	url := config.Host + "/api/1/certificates"
	requestData := CreateCertificateRequest{
		Authority: CreateCertificateRequestAuthority{
			Name: d.Get("authority").(string),
		},
		Owner:         d.Get("owner").(string),
		CommonName:    d.Get("common_name").(string),
		Description:   d.Get("description").(string),
		Rotation:      true,
		Notify:        true,
		ValidityYears: d.Get("validity_years").(int),
	}

	val, ok := d.GetOk("organization")
	if ok {
		requestData.Organization = val.(string)
	}
	val, ok = d.GetOk("location")
	if ok {
		requestData.Location = val.(string)
	}
	val, ok = d.GetOk("state")
	if ok {
		requestData.State = val.(string)
	}
	val, ok = d.GetOk("organizational_unit")
	if ok {
		requestData.OrganizationalUnit = val.(string)
	}
	val, ok = d.GetOk("country")
	if ok {
		requestData.Country = val.(string)
	}

	jsonValue, _ := json.Marshal(requestData)

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonValue))
	if err != nil {
		return -1, fmt.Errorf("Error creating request: %s", url)
	}
	req.Header.Set("Authorization", "bearer "+config.Token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return -1, fmt.Errorf("Error during making a request: %s", url)
	}

	defer resp.Body.Close()

	responseBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return -1, fmt.Errorf("Error while reading response body. %s", err)
	}

	if resp.StatusCode != 200 {
		return -1, fmt.Errorf("HTTP request error. Response code: %d \n%s", resp.StatusCode, string(responseBytes[:]))
	}

	var keyReponse map[string]interface{}
	err = json.Unmarshal(responseBytes, &keyReponse)
	if err != nil {
		return -1, fmt.Errorf("Error while reading response body. %s", err)
	}

	return int(keyReponse["id"].(float64)), nil
}
