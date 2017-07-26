package lemur

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"

	"github.com/hashicorp/terraform/helper/schema"
)

func resourceLemurCertificate() *schema.Resource {
	return &schema.Resource{
		Create: resourceLemurCertificateCreate,
		Read:   resourceLemurCertificateRead,
		Exists: resourceLemurCertificateExists,
		Update: resourceLemurCertificateUpdate,
		Delete: resourceLemurCertificateDelete,

		Schema: map[string]*schema.Schema{
			"name": &schema.Schema{
				Type:     schema.TypeString,
				Required: true,
			},
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
			"san": {
				Type:     schema.TypeSet,
				Optional: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"type": {
							Type:     schema.TypeString,
							Required: true,
						},
						"value": {
							Type:     schema.TypeString,
							Required: true,
						},
					},
				},
				Set: resourceSANHash,
			},
			"extended_key_usage": {
				Type:     schema.TypeSet,
				Optional: true,
				MaxItems: 1,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"use_client_authentication": {
							Type:     schema.TypeBool,
							Required: true,
						},
						"use_server_authentication": {
							Type:     schema.TypeBool,
							Required: true,
						},
					},
				},
				Set: resourceSANHash,
			},

			"pem_chain": &schema.Schema{
				Type:      schema.TypeString,
				Optional:  true,
				Computed:  true,
				Sensitive: true,
			},
			"pem_public_certificate": &schema.Schema{
				Type:      schema.TypeString,
				Optional:  true,
				Computed:  true,
				Sensitive: true,
			},
			"pem_private_certificate": &schema.Schema{
				Type:      schema.TypeString,
				Optional:  true,
				Computed:  true,
				Sensitive: true,
			},
			"pkcs_passphrase": &schema.Schema{
				Type:      schema.TypeString,
				Optional:  true,
				Computed:  true,
				Sensitive: true,
			},
			"pkcs_base_64": &schema.Schema{
				Type:      schema.TypeString,
				Optional:  true,
				Computed:  true,
				Sensitive: true,
			},
			"jks_keystore_passphrase": &schema.Schema{
				Type:      schema.TypeString,
				Optional:  true,
				Computed:  true,
				Sensitive: true,
			},
			"jks_keystore_base_64": &schema.Schema{
				Type:      schema.TypeString,
				Optional:  true,
				Computed:  true,
				Sensitive: true,
			},
			"jks_truststore_passphrase": &schema.Schema{
				Type:      schema.TypeString,
				Optional:  true,
				Computed:  true,
				Sensitive: true,
			},
			"jks_truststore_base_64": &schema.Schema{
				Type:      schema.TypeString,
				Optional:  true,
				Computed:  true,
				Sensitive: true,
			},
			"certificate_id": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
				Computed: true,
			},
		},
	}
}

func resourceLemurCertificateCreate(d *schema.ResourceData, meta interface{}) error {
	exists, err := resourceLemurCertificateExists(d, meta)
	if err != nil {
		return err
	}
	if exists {
		return resourceLemurCertificateRead(d, meta)
	}

	client := &http.Client{}
	config := meta.(Config)

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
		return fmt.Errorf("Error creating request: %s", url)
	}
	req.Header.Set("Authorization", "bearer "+config.Token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("Error during making a request: %s", url)
	}

	defer resp.Body.Close()

	responseBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("Error while reading response body. %s", err)
	}

	if resp.StatusCode != 200 {
		return fmt.Errorf("HTTP request error. Response code: %d \n%s", resp.StatusCode, string(responseBytes[:]))
	}

	var keyReponse map[string]interface{}
	err = json.Unmarshal(responseBytes, &keyReponse)
	if err != nil {
		return fmt.Errorf("Error while reading response body. %s", err)
	}

	return resourceLemurCertificateRead(d, meta)
}

func resourceLemurCertificateUpdate(d *schema.ResourceData, meta interface{}) error {
	exists, err := resourceLemurCertificateExists(d, meta)
	if err != nil {
		return err
	}
	if exists {
		return nil
	}
	return fmt.Errorf("Update is not supported: %s", d.Id())
}

func resourceLemurCertificateExists(d *schema.ResourceData, meta interface{}) (bool, error) {
	client := &http.Client{}
	config := meta.(Config)
	name := d.Get("name").(string)

	findExistingURL := config.Host + "/api/1/certificates?filter=name;" + name
	findExisting, err := http.NewRequest("GET", findExistingURL, nil)
	if err != nil {
		return false, fmt.Errorf("Error creating request: %s", findExistingURL)
	}
	findExisting.Header.Set("Authorization", "bearer "+config.Token)

	findExistingResponse, err := client.Do(findExisting)
	if err != nil {
		return false, fmt.Errorf("Error during making a request: %s", findExistingURL)
	}

	defer findExistingResponse.Body.Close()

	if findExistingResponse.StatusCode != 200 {
		return false, fmt.Errorf("HTTP request error. Response code: %d", findExistingResponse.StatusCode)
	}

	responseBytes, err := ioutil.ReadAll(findExistingResponse.Body)
	if err != nil {
		return false, fmt.Errorf("Error while reading response body. %s", err)
	}

	var certificatesResponse map[string]interface{}
	err = json.Unmarshal(responseBytes, &certificatesResponse)
	if err != nil {
		return false, fmt.Errorf("Error while reading response body. %s", err)
	}

	totalResults := certificatesResponse["total"].(float64)
	if totalResults > 0 {
		items := certificatesResponse["items"].([]interface{})
		for _, item := range items {
			itemMap := item.(map[string]interface{})
			if itemMap["active"].(bool) && strings.HasPrefix(name, itemMap["name"].(string)) {
				return true, nil
			}
		}
	}

	return false, nil
}

func resourceLemurCertificateDelete(d *schema.ResourceData, meta interface{}) error {
	return fmt.Errorf("Delete: %t", false)
}

func resourceLemurCertificateRead(d *schema.ResourceData, meta interface{}) error {
	config := meta.(Config)

	certificate, err := getCertificate(d, config)
	if err != nil {
		return err
	}
	if certificate == nil {
		d.SetId("")
		return nil
	}

	currentCertificateID := 0
	v, ok := d.GetOk("certificate_id")
	if ok {
		currentCertificateID = v.(int)
	}

	authority := certificate["authority"].(map[string]interface{})

	d.Set("authority", authority["name"].(string))
	d.Set("common_name", certificate["commonName"].(string))
	d.Set("owner", certificate["owner"].(string))

	certificateID := int(certificate["id"].(float64))
	d.Set("certificate_id", certificateID)
	d.SetId(strconv.Itoa(certificateID))

	if certificateID != currentCertificateID {

		chain, publicCert, err := getPublicCertificateData(certificateID, d, config)
		if err != nil {
			return err
		}

		privateCert, err := getPrivateCertificateData(certificateID, d, config)
		if err != nil {
			return err
		}

		pkcsBase64, pkcsPassphrase, err := exportCertificatePKCS(certificateID, d, config)

		jksKeystoreBase64, jksKeystorePassphrase, err := exportCertificateJKSKeystore(certificateID, d, config)

		jksTruststoreBase64, jksTruststorePassphrase, err := exportCertificateJKSTruststore(certificateID, d, config)

		d.Set("pem_chain", chain)
		d.Set("pem_public_certificate", publicCert)
		d.Set("pem_private_certificate", privateCert)

		d.Set("pkcs_passphrase", pkcsPassphrase)
		d.Set("pkcs_base_64", pkcsBase64)

		d.Set("jks_keystore_passphrase", jksKeystorePassphrase)
		d.Set("jks_keystore_base_64", jksKeystoreBase64)

		d.Set("jks_truststore_passphrase", jksTruststorePassphrase)
		d.Set("jks_truststore_base_64", jksTruststoreBase64)
	}

	return nil
}
