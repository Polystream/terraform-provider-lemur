package lemur

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/terraform/terraform"
)

func Provider() terraform.ResourceProvider {
	return &schema.Provider{
		Schema: map[string]*schema.Schema{
			"host": &schema.Schema{
				Type:        schema.TypeString,
				Required:    true,
				DefaultFunc: schema.EnvDefaultFunc("LEMUR_HOST", ""),
				Description: "The address of the Lemur server",
			},

			"username": &schema.Schema{
				Type:        schema.TypeString,
				Required:    true,
				DefaultFunc: schema.EnvDefaultFunc("LEMUR_USERNAME", ""),
				Description: "The username to authenticate with",
			},

			"password": &schema.Schema{
				Type:        schema.TypeString,
				Required:    true,
				DefaultFunc: schema.EnvDefaultFunc("LEMUR_PASSWORD", ""),
				Description: "The password to authenticate with",
			},
		},

		ResourcesMap: map[string]*schema.Resource{
			"lemur_certificate": resourceLemurCertificate(),
		},

		DataSourcesMap: map[string]*schema.Resource{
			"lemur_authority": dataSourceLemurAuthority(),
		},

		ConfigureFunc: providerConfigure,
	}
}

func providerConfigure(d *schema.ResourceData) (interface{}, error) {
	host := d.Get("host").(string)
	username := d.Get("username").(string)
	password := d.Get("password").(string)

	client := &http.Client{}

	authURL := host + "/api/1/auth/login"
	loginData := map[string]string{"username": username, "password": password}
	jsonValue, _ := json.Marshal(loginData)

	req, err := http.NewRequest("POST", authURL, bytes.NewBuffer(jsonValue))
	if err != nil {
		return nil, fmt.Errorf("Error creating request: %s", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("Error during making a request: %s", authURL)
	}

	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("Authentication request error. Response code: %d", resp.StatusCode)
	}

	bytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("Error while reading response body. %s", err)
	}

	var jsonReponse map[string]interface{}
	err = json.Unmarshal(bytes, &jsonReponse)
	if err != nil {
		return nil, fmt.Errorf("Error while reading response body. %s", err)
	}

	token := jsonReponse["token"].(string)

	config := Config{
		Host:  host,
		Token: token,
	}

	return config, nil
}
