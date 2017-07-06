package lemur

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"

	"github.com/hashicorp/terraform/helper/schema"
)

func dataSourceLemurAuthority() *schema.Resource {
	return &schema.Resource{
		Read: dataSourceLemurAuthorityRead,

		Schema: map[string]*schema.Schema{
			"name": &schema.Schema{
				Type:     schema.TypeString,
				Required: true,
			},

			"pem": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
			},
			"crt_base_64": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
			},
		},
	}
}

func dataSourceLemurAuthorityRead(d *schema.ResourceData, meta interface{}) error {
	config := meta.(Config)

	if d.Id() != "" {
		return fmt.Errorf("Error during making a request: %s", d.Id())
	}

	authorityID, certificateID, err := findAuthority(d, config)
	if err != nil {
		return err
	}

	_, publicCert, err := getPublicCertificateData(certificateID, d, config)
	if err != nil {
		return err
	}

	crtBase64, err := exportCertificateCRT(certificateID, d, config)
	if err != nil {
		return err
	}

	d.Set("pem", publicCert)

	d.Set("crt_base_64", crtBase64)

	d.SetId(strconv.Itoa(authorityID))

	return nil
}

func findAuthority(d *schema.ResourceData, config Config) (int, int, error) {
	client := &http.Client{}
	name := d.Get("name").(string)

	findExistingURL := config.Host + "/api/1/authorities?filter=name;" + name
	findExisting, err := http.NewRequest("GET", findExistingURL, nil)
	if err != nil {
		return -1, -1, fmt.Errorf("Error creating request: %s", findExistingURL)
	}
	findExisting.Header.Set("Authorization", "bearer "+config.Token)

	findExistingResponse, err := client.Do(findExisting)
	if err != nil {
		return -1, -1, fmt.Errorf("Error during making a request: %s", findExistingURL)
	}

	defer findExistingResponse.Body.Close()

	if findExistingResponse.StatusCode != 200 {
		return -1, -1, fmt.Errorf("HTTP request error. Response code: %d", findExistingResponse.StatusCode)
	}

	responseBytes, err := ioutil.ReadAll(findExistingResponse.Body)
	if err != nil {
		return -1, -1, fmt.Errorf("Error while reading response body. %s", err)
	}

	var authotitiesResponse map[string]interface{}
	err = json.Unmarshal(responseBytes, &authotitiesResponse)
	if err != nil {
		return -1, -1, fmt.Errorf("Error while reading response body. %s", err)
	}

	authorityID := 0
	certificateID := 0
	totalResults := authotitiesResponse["total"].(float64)
	if totalResults > 0 {
		items := authotitiesResponse["items"].([]interface{})
		for _, item := range items {
			itemMap := item.(map[string]interface{})
			if itemMap["active"].(bool) && itemMap["name"].(string) == name {
				authorityID = int(itemMap["id"].(float64))
				certificateData := itemMap["authorityCertificate"].(map[string]interface{})

				certificateID = int(certificateData["id"].(float64))
				break
			}
		}
	} else {
		return -1, -1, fmt.Errorf("Unable to find authotity with name. %s", name)
	}

	if authorityID == 0 {
		return -1, -1, fmt.Errorf("Unable to find authotity with name. %s", name)
	}

	return authorityID, certificateID, nil
}
