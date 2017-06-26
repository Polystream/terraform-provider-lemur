package main

import (
	"github.com/hashicorp/terraform/plugin"
	"github.com/terraform-providers/terraform-provider-lemur/lemur"
)

func main() {
	plugin.Serve(&plugin.ServeOpts{
		ProviderFunc: lemur.Provider})
}
