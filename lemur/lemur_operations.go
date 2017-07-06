package lemur

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"

	"github.com/hashicorp/terraform/helper/hashcode"
	"github.com/hashicorp/terraform/helper/schema"
)

func resourceSANHash(v interface{}) int {
	var buf bytes.Buffer
	m := v.(map[string]interface{})
	if m["type"] != nil {
		buf.WriteString(fmt.Sprintf("%s", m["type"].(string)))
	}
	if m["value"] != nil {
		buf.WriteString(fmt.Sprintf("%s", m["value"].(string)))
	}
	return hashcode.String(buf.String())
}

func resourceEKUHash(v interface{}) int {
	var buf bytes.Buffer
	m := v.(map[string]interface{})
	buf.WriteString(fmt.Sprintf("%t", m["use_client_authentication"].(bool)))
	buf.WriteString(fmt.Sprintf("%t", m["use_server_authentication"].(bool)))
	return hashcode.String(buf.String())
}

func getCertificateID(d *schema.ResourceData, config Config) (int, error) {
	client := &http.Client{}
	name := d.Get("name").(string)

	findExistingURL := config.Host + "/api/1/certificates?filter=name;" + name
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

	certificateID := 0
	totalResults := certificatesResponse["total"].(float64)
	if totalResults > 0 {
		items := certificatesResponse["items"].([]interface{})
		for _, item := range items {
			itemMap := item.(map[string]interface{})
			if itemMap["active"].(bool) && itemMap["name"].(string) == name {
				certificateID = int(itemMap["id"].(float64))
				break
			}
		}
	}

	if certificateID == 0 {
		certificateID, err = createCertificate(d, config)
		if err != nil {
			return -1, fmt.Errorf("Error creating certificate. %s", err)
		}
	}

	return certificateID, nil
}

func getPublicCertificateData(certificateID int, d *schema.ResourceData, config Config) (string, string, error) {
	client := &http.Client{}

	url := config.Host + "/api/1/certificates/" + strconv.Itoa(certificateID)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", "", fmt.Errorf("Error creating request: %s", url)
	}
	req.Header.Set("Authorization", "bearer "+config.Token)

	resp, err := client.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("Error during making a request: %s", url)
	}

	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", "", fmt.Errorf("HTTP request error. Response code: %d", resp.StatusCode)
	}

	responseBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", "", fmt.Errorf("Error while reading response body. %s", err)
	}

	var certificatesResponse map[string]interface{}
	err = json.Unmarshal(responseBytes, &certificatesResponse)
	if err != nil {
		return "", "", fmt.Errorf("Error while reading response body. %s", err)
	}

	chain := ""
	if certificatesResponse["chain"] != nil {
		chain = certificatesResponse["chain"].(string)
	}

	return chain, certificatesResponse["body"].(string), nil
}

func getPrivateCertificateData(certificateID int, d *schema.ResourceData, config Config) (string, error) {
	client := &http.Client{}

	url := config.Host + "/api/1/certificates/" + strconv.Itoa(certificateID) + "/key"
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", fmt.Errorf("Error creating request: %s", url)
	}
	req.Header.Set("Authorization", "bearer "+config.Token)

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("Error during making a request: %s", url)
	}

	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("HTTP request error. Response code: %d", resp.StatusCode)
	}

	responseBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("Error while reading response body. %s", err)
	}

	var keyReponse map[string]interface{}
	err = json.Unmarshal(responseBytes, &keyReponse)
	if err != nil {
		return "", fmt.Errorf("Error while reading response body. %s", err)
	}

	return keyReponse["key"].(string), nil
}

func createCertificate(d *schema.ResourceData, config Config) (int, error) {
	client := &http.Client{}

	url := config.Host + "/api/1/certificates"
	requestData := CreateCertificateRequest{
		Authority: CreateCertificateRequestAuthority{
			Name: d.Get("authority").(string),
		},
		Name:          d.Get("name").(string),
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

	requestData.Extensions = CreateCertificateExtensions{}

	if sans := d.Get("san").(*schema.Set); sans.Len() > 0 {
		requestData.Extensions.SubAltNames = CreateCertificateAltNames{
			Names: []CreateCertificateNames{},
		}
		for _, san := range sans.List() {
			san := san.(map[string]interface{})

			sanValue := CreateCertificateNames{
				NameType: san["type"].(string),
				Value:    san["value"].(string),
			}

			requestData.Extensions.SubAltNames.Names = append(requestData.Extensions.SubAltNames.Names, sanValue)
		}
	}

	if keyUsages, ok := d.GetOk("extended_key_usage"); ok {
		keyUsages := keyUsages.(*schema.Set).List()
		keyUsage := keyUsages[0].(map[string]interface{})
		requestData.Extensions.ExtendedKeyUsage = CreateCertificateExtendedKeyUsage{
			UseClientAuthentication: keyUsage["use_client_authentication"].(bool),
			UseServerAuthentication: keyUsage["use_server_authentication"].(bool),
		}
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

func exportCertificatePKCS(certificateID int, d *schema.ResourceData, config Config) (string, string, error) {
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
		return "", "", fmt.Errorf("Error creating request: %s", url)
	}
	req.Header.Set("Authorization", "bearer "+config.Token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("Error during making a request: %s", url)
	}

	defer resp.Body.Close()

	responseBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", "", fmt.Errorf("Error while reading response body. %s", err)
	}

	if resp.StatusCode != 200 {
		return "", "", fmt.Errorf("HTTP request error. Response code: %d \n%s", resp.StatusCode, string(responseBytes[:]))
	}

	var exportResponse map[string]interface{}
	err = json.Unmarshal(responseBytes, &exportResponse)
	if err != nil {
		return "", "", fmt.Errorf("Error while reading response body. %s", err)
	}

	return exportResponse["data"].(string), exportResponse["passphrase"].(string), nil
}

func exportCertificateCRT(certificateID int, d *schema.ResourceData, config Config) (string, error) {
	client := &http.Client{}

	url := config.Host + "/api/1/certificates/" + strconv.Itoa(certificateID) + "/export"

	requestData := map[string]interface{}{
		"plugin": map[string]interface{}{
			"pluginOptions": []map[string]string{
				map[string]string{
					"name":  "type",
					"value": "CRT (.crt)",
				},
			},
			"slug": "openssl-export",
		},
	}
	jsonValue, _ := json.Marshal(requestData)

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonValue))
	if err != nil {
		return "", fmt.Errorf("Error creating request: %s", url)
	}
	req.Header.Set("Authorization", "bearer "+config.Token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("Error during making a request: %s", url)
	}

	defer resp.Body.Close()

	responseBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("Error while reading response body. %s", err)
	}

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("HTTP request error. Response code: %d \n%s", resp.StatusCode, string(responseBytes[:]))
	}

	var exportResponse map[string]interface{}
	err = json.Unmarshal(responseBytes, &exportResponse)
	if err != nil {
		return "", fmt.Errorf("Error while reading response body. %s", err)
	}

	return exportResponse["data"].(string), nil
}

func exportCertificateJKSKeystore(certificateID int, d *schema.ResourceData, config Config) (string, string, error) {
	client := &http.Client{}

	url := config.Host + "/api/1/certificates/" + strconv.Itoa(certificateID) + "/export"

	requestData := map[string]interface{}{
		"plugin": map[string]interface{}{
			"pluginOptions": []map[string]string{
				map[string]string{
					"name":  "passphrase",
					"value": "sadfsdafsdafsdafsdafsdafs",
				},
			},
			"slug": "java-keystore-jks",
		},
	}
	jsonValue, _ := json.Marshal(requestData)

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonValue))
	if err != nil {
		return "", "", fmt.Errorf("Error creating request: %s", url)
	}
	req.Header.Set("Authorization", "bearer "+config.Token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("Error during making a request: %s", url)
	}

	defer resp.Body.Close()

	responseBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", "", fmt.Errorf("Error while reading response body. %s", err)
	}

	if resp.StatusCode != 200 {
		return "", "", fmt.Errorf("HTTP request error. Response code: %d \n%s", resp.StatusCode, string(responseBytes[:]))
	}

	var exportResponse map[string]interface{}
	err = json.Unmarshal(responseBytes, &exportResponse)
	if err != nil {
		return "", "", fmt.Errorf("Error while reading response body. %s", err)
	}

	return exportResponse["data"].(string), exportResponse["passphrase"].(string), nil
}

func exportCertificateJKSTruststore(certificateID int, d *schema.ResourceData, config Config) (string, string, error) {
	client := &http.Client{}

	url := config.Host + "/api/1/certificates/" + strconv.Itoa(certificateID) + "/export"

	requestData := map[string]interface{}{
		"plugin": map[string]interface{}{
			"pluginOptions": []map[string]string{
				map[string]string{
					"name":  "passphrase",
					"value": "sadfsdafsdafsdafsdafsdafs",
				},
			},
			"slug": "java-truststore-jks",
		},
	}
	jsonValue, _ := json.Marshal(requestData)

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonValue))
	if err != nil {
		return "", "", fmt.Errorf("Error creating request: %s", url)
	}
	req.Header.Set("Authorization", "bearer "+config.Token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("Error during making a request: %s", url)
	}

	defer resp.Body.Close()

	responseBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", "", fmt.Errorf("Error while reading response body. %s", err)
	}

	if resp.StatusCode != 200 {
		return "", "", fmt.Errorf("HTTP request error. Response code: %d \n%s", resp.StatusCode, string(responseBytes[:]))
	}

	var exportResponse map[string]interface{}
	err = json.Unmarshal(responseBytes, &exportResponse)
	if err != nil {
		return "", "", fmt.Errorf("Error while reading response body. %s", err)
	}

	return exportResponse["data"].(string), exportResponse["passphrase"].(string), nil
}
