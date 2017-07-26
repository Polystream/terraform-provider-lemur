package lemur

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"

	"strings"

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

func getCertificate(d *schema.ResourceData, config Config) (map[string]interface{}, error) {
	client := &http.Client{}
	name := d.Get("name").(string)

	findExistingURL := config.Host + "/api/1/certificates?filter=name;" + name
	findExisting, err := http.NewRequest("GET", findExistingURL, nil)
	if err != nil {
		return nil, fmt.Errorf("Error creating request: %s", findExistingURL)
	}
	findExisting.Header.Set("Authorization", "bearer "+config.Token)

	findExistingResponse, err := client.Do(findExisting)
	if err != nil {
		return nil, fmt.Errorf("Error during making a request: %s", findExistingURL)
	}

	defer findExistingResponse.Body.Close()

	if findExistingResponse.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP request error. Response code: %d", findExistingResponse.StatusCode)
	}

	responseBytes, err := ioutil.ReadAll(findExistingResponse.Body)
	if err != nil {
		return nil, fmt.Errorf("Error while reading response body. %s", err)
	}

	var certificatesResponse map[string]interface{}
	err = json.Unmarshal(responseBytes, &certificatesResponse)
	if err != nil {
		return nil, fmt.Errorf("Error while reading response body. %s", err)
	}

	totalResults := certificatesResponse["total"].(float64)
	if totalResults > 0 {
		items := certificatesResponse["items"].([]interface{})
		for _, item := range items {
			itemMap := item.(map[string]interface{})
			if itemMap["active"].(bool) && strings.HasPrefix(name, itemMap["name"].(string)) {
				return itemMap, nil
			}
		}
	}

	return nil, nil
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
