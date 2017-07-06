package lemur

import (
	"fmt"
	"strconv"

	"github.com/hashicorp/terraform/helper/schema"
)

func dataSourceLemurCertificate() *schema.Resource {
	return &schema.Resource{
		Read: dataSourceLemurCertificateRead,

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
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
			},
			"pem_public_certificate": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
			},
			"pem_private_certificate": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
			},
			"pkcs_passphrase": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
			},
			"pkcs_base_64": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
			},
			"jks_keystore_passphrase": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
			},
			"jks_keystore_base_64": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
			},
			"jks_truststore_passphrase": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
			},
			"jks_truststore_base_64": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
			},
		},
	}
}

func dataSourceLemurCertificateRead(d *schema.ResourceData, meta interface{}) error {
	config := meta.(Config)

	if d.Id() != "" {
		return fmt.Errorf("Error during making a request: %s", d.Id())
	}

	certificateID, err := getCertificateID(d, config)
	if err != nil {
		return err
	}

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

	d.SetId(strconv.Itoa(certificateID))

	return nil
}
