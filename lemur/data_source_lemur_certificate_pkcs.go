package lemur

import (
	"strconv"

	"github.com/hashicorp/terraform/helper/schema"
)

func dataSourceLemurCertificatePKCS() *schema.Resource {
	return &schema.Resource{
		Read: dataSourceLemurCertificatePKCSRead,

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

			"passphrase": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
			},
			"base_64": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
			},
		},
	}
}

func dataSourceLemurCertificatePKCSRead(d *schema.ResourceData, meta interface{}) error {
	config := meta.(Config)

	certificateID, err := getCertificateID(d, config)
	if err != nil {
		return err
	}

	err = exportCertificate(certificateID, d, config)
	if err != nil {
		return err
	}

	d.SetId(strconv.Itoa(certificateID))

	return nil
}
