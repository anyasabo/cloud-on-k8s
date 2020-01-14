// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package runner

import (
	"fmt"
	"log"
)

const (
	AzOSDriverID                    = "azos"
	AzOSVaultPath                   = "secret/devops-ci/cloud-on-k8s/ci-azr-k8s-operator"
	AzOSResourceGroupVaultFieldName = "resource-group"
	AzOSAcrNameVaultFieldName       = "acr-name"
	AzOSConfigFileName              = "deployer-config-azos.yml"
	DefaultAzOSRunConfigTemplate    = `id: azos-dev
overrides:
  clusterName: %s-dev-cluster
  azos:
    resourceGroup: %s
    acrName: %s
`
)

type AzOSDriverFactory struct {
}

type AzOSDriver struct {
	plan        Plan
	ctx         map[string]interface{}
	vaultClient *VaultClient
}

func (adf *AzOSDriverFactory) Create(plan Plan) (Driver, error) {
	var vaultClient *VaultClient
	if plan.VaultInfo != nil {
		var err error
		vaultClient, err = NewClient(*plan.VaultInfo)
		if err != nil {
			return nil, err
		}

		if plan.AzOS.ResourceGroup == "" {
			resourceGroup, err := vaultClient.Get(AzOSVaultPath, AzOSAcrNameVaultFieldName)
			if err != nil {
				return nil, err
			}
			plan.AzOS.ResourceGroup = resourceGroup
		}

		if plan.AzOS.AcrName == "" {
			acrName, err := vaultClient.Get(AzOSVaultPath, AzOSAcrNameVaultFieldName)
			if err != nil {
				return nil, err
			}
			plan.AzOS.AcrName = acrName
		}
	}

	return &AzOSDriver{
		plan: plan,
		ctx: map[string]interface{}{
			"ResourceGroup":     plan.AzOS.ResourceGroup,
			"ClusterName":       plan.ClusterName,
			"NodeCount":         plan.AzOS.NodeCount,
			"MachineType":       plan.MachineType,
			"KubernetesVersion": plan.KubernetesVersion,
			"AcrName":           plan.AzOS.AcrName,
			"Location":          plan.AzOS.Location,
		},
		vaultClient: vaultClient,
	}, nil
}

func (d *AzOSDriver) Execute() error {
	if err := d.auth(); err != nil {
		return err
	}

	exists, err := d.clusterExists()
	if err != nil {
		return err
	}

	switch d.plan.Operation {
	case "delete":
		if exists {
			if err := d.delete(); err != nil {
				return err
			}
		} else {
			log.Printf("not deleting as cluster doesn't exist")
		}
	case "create":
		if exists {
			log.Printf("not creating as cluster exists")
		} else {
			if err := d.create(); err != nil {
				return err
			}

			if err := d.configureDocker(); err != nil {
				return err
			}
		}

		if err := d.GetCredentials(); err != nil {
			return err
		}

		if err := createStorageClass(DefaultStorageClass); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unknown operation %s", d.plan.Operation)
	}

	return nil
}

func (d *AzOSDriver) GetCredentials() error {
	log.Print("Getting credentials...")
	// TODO sabo fix this. get-creds doesnt exist
	cmd := `az aks get-credentials --overwrite-existing --resource-group {{.ResourceGroup}} --name {{.ClusterName}}`
	return NewCommand(cmd).AsTemplate(d.ctx).Run()
}

func (d *AzOSDriver) clusterExists() (bool, error) {
	log.Print("Checking if cluster exists...")

	cmd := "az openshift show --name {{.ClusterName}} --resource-group {{.ResourceGroup}}"
	contains, err := NewCommand(cmd).AsTemplate(d.ctx).WithoutStreaming().OutputContainsAny("not be found", "was not found")
	if contains {
		return false, nil
	}

	return err == nil, err
}

func (d *AzOSDriver) auth() error {
	if d.plan.ServiceAccount {
		log.Print("Authenticating as service account...")
		secrets, err := d.vaultClient.GetMany(AzOSVaultPath, "appId", "password", "tenant")
		if err != nil {
			return err
		}
		appID, tenantSecret, tenantID := secrets[0], secrets[1], secrets[2]

		cmd := "az login --service-principal -u {{.AppId}} -p {{.TenantSecret}} --tenant {{.TenantId}}"
		return NewCommand(cmd).
			AsTemplate(map[string]interface{}{
				"AppId":        appID,
				"TenantSecret": tenantSecret,
				"TenantId":     tenantID,
			}).
			WithoutStreaming().
			Run()
	}

	log.Print("Authenticating as user...")
	return NewCommand("az login").Run()
}

func (d *AzOSDriver) create() error {
	log.Print("Creating cluster...")

	servicePrincipal := ""
	if d.plan.ServiceAccount {
		// our service principal doesn't have permissions to create a service principal for aks cluster
		// instead, we reuse the current service principal as the one for aks cluster
		secrets, err := d.vaultClient.GetMany(AzOSVaultPath, "appId", "password")
		if err != nil {
			return err
		}
		servicePrincipal = fmt.Sprintf(" --service-principal %s --client-secret %s", secrets[0], secrets[1])
	}
	// TODO sabo do we need appid, app secret, aad tenant id, and customer admin?
	cmd := `az openshift create --resource-group {{.ResourceGroup}} --name {{.ClusterName}} -l {.Location}} ` +
		// `--aad-client-app-id $APPID --aad-client-app-secret $SECRET --aad-tenant-id $TENANT --customer-admin-group-id $GROUPID ` +
		`--compute-vm-size {{.MachineType}} --compute-count {{.NodeCount}}` + servicePrincipal

	if err := NewCommand(cmd).AsTemplate(d.ctx).Run(); err != nil {
		return err
	}

	return nil
}

func (d *AzOSDriver) delete() error {
	log.Print("Deleting cluster...")
	cmd := "az openshift delete --yes --name {{.ClusterName}} --resource-group {{.ResourceGroup}}"
	return NewCommand(cmd).AsTemplate(d.ctx).Run()
}

// TODO sabo is this necessary?
func (d *AzOSDriver) configureDocker() error {
	log.Print("Configuring Docker...")
	if err := NewCommand("az acr login --name {{.AcrName}}").AsTemplate(d.ctx).Run(); err != nil {
		return err
	}

	if d.plan.ServiceAccount {
		// it's already set for the ServiceAccount
		return nil
	}

	cmd := `az aks show --resource-group {{.ResourceGroup}} --name {{.ClusterName}} --query "servicePrincipalProfile.clientId" --output tsv`
	clientIds, err := NewCommand(cmd).AsTemplate(d.ctx).StdoutOnly().OutputList()
	if err != nil {
		return err
	}

	cmd = `az acr show --resource-group {{.ResourceGroup}} --name {{.AcrName}} --query "id" --output tsv`
	acrIds, err := NewCommand(cmd).AsTemplate(d.ctx).StdoutOnly().OutputList()
	if err != nil {
		return err
	}

	return NewCommand(`az role assignment create --assignee {{.ClientId}} --role acrpull --scope {{.AcrId}}`).
		AsTemplate(map[string]interface{}{
			"ClientId": clientIds[0],
			"AcrId":    acrIds[0],
		}).
		Run()
}
