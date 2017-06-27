package lemur

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"

	"github.com/hashicorp/terraform/helper/schema"
)

func getCertificateID(d *schema.ResourceData, config Config) (int, error) {
	client := &http.Client{}
	commonName := d.Get("common_name").(string)

	findExistingURL := config.Host + "/api/1/certificates?filter=cn;" + commonName
	findExisting, err := http.NewRequest("GET", findExistingURL, nil)
	if err != nil {
		return -1, fmt.Errorf("Error creating request: %s", findExistingURL)
	}
	findExisting.Header.Set("Authorization", "bearer "+config.Token)

	findExistingResponse, err := client.Do(findExisting)
	if err != nil {
		return -1, fmt.Errorf("Error during making a request: %s", findExistingURL)
	}

	defer findExistingResponse.Body.Close()

	if findExistingResponse.StatusCode != 200 {
		return -1, fmt.Errorf("HTTP request error. Response code: %d", findExistingResponse.StatusCode)
	}

	responseBytes, err := ioutil.ReadAll(findExistingResponse.Body)
	if err != nil {
		return -1, fmt.Errorf("Error while reading response body. %s", err)
	}

	var certificatesResponse map[string]interface{}
	err = json.Unmarshal(responseBytes, &certificatesResponse)
	if err != nil {
		return -1, fmt.Errorf("Error while reading response body. %s", err)
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
			return -1, fmt.Errorf("Error creating certificate. %s", err)
		}
	}

	return certificateID, nil
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

func exportCertificate(certificateID int, d *schema.ResourceData, config Config) error {
	client := &http.Client{}

	url := config.Host + "/api/1/certificates/" + strconv.Itoa(certificateID) + "/export"

	requestData := map[string]interface{}{
		"plugin": map[string]interface{}{
			"pluginOptions": []map[string]string{
				map[string]string{
					"name":  "type",
					"value": "PKCS12 (.p12)",
				},
			},
			"slug": "openssl-export",
		},
	}
	jsonValue, _ := json.Marshal(requestData)

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonValue))
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

	var exportResponse map[string]interface{}
	err = json.Unmarshal(responseBytes, &exportResponse)
	if err != nil {
		return fmt.Errorf("Error while reading response body. %s", err)
	}

	d.Set("passphrase", exportResponse["passphrase"].(string))
	d.Set("base_64", exportResponse["data"].(string))

	return nil
}
