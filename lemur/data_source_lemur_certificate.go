package lemur

import (
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
		},
	}
}

func dataSourceLemurCertificateRead(d *schema.ResourceData, meta interface{}) error {
	config := meta.(Config)

	certificate, err := getCertificate(d, config)
	if err != nil {
		return err
	}
	if certificate == nil {
		d.SetId("")
		return nil
	}

	authority := certificate["authority"].(map[string]interface{})

	d.Set("authority", authority["name"].(string))
	d.Set("common_name", certificate["commonName"].(string))
	d.Set("owner", certificate["owner"].(string))

	certificateID := int(certificate["id"].(float64))
	d.Set("certificate_id", certificateID)
	d.SetId(strconv.Itoa(certificateID))

	chain, publicCert, err := getPublicCertificateData(certificateID, d, config)
	if err != nil {
		return err
	}

	privateCert, err := getPrivateCertificateData(certificateID, d, config)
	if err != nil {
		return err
	}

	d.Set("pem_chain", chain)
	d.Set("pem_public_certificate", publicCert)
	d.Set("pem_private_certificate", privateCert)

	return nil
}
