package k3s

import (
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"strconv"

	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/hashicorp/terraform-plugin-sdk/helper/validation"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"golang.org/x/crypto/ssh"
)

func resourceInstallation() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceInstallationCreate,
		ReadContext:   resourceInstallationRead,
		UpdateContext: resourceInstallationUpdate,
		DeleteContext: resourceInstallationDelete,
		Schema: map[string]*schema.Schema{
			"host": {
				Description: "The host to install k3s on.",
				Type:        schema.TypeString,
				Optional:    true,
			},
			"port": {
				Description:  "The port of the remote ssh server to connect to. Defaults to `22`.",
				Type:         schema.TypeInt,
				Optional:     true,
				DefaultFunc:  schema.EnvDefaultFunc("K3S_SSH_PORT", 22),
				ValidateFunc: validation.IsPortNumber,
			},
			"version": {
				Description: "The version of k3s to install.",
				Type:        schema.TypeString,
				Optional:    true,
			},
		},
	}
}

func resourceInstallationCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	var diags diag.Diagnostics

	config := m.(SshConfig)

	var host string

	port := strconv.Itoa(d.Get("port").(int))
	version := d.Get("version").(string)

	if v, ok := d.GetOk("host"); ok {
		host = net.JoinHostPort(v.(string), port)
	} else {
		host = config.host
	}

	tflog.Trace(ctx, "Dailing ssh connection", map[string]interface{}{
		"host": host,
		"user": config.sshConfig.User,
	})

	client, err := ssh.Dial("tcp", host, config.sshConfig)
	if err != nil {
		return diag.FromErr(err)
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return diag.FromErr(err)
	}
	defer session.Close()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	session.Stdout = &stdout
	session.Stderr = &stderr

	if version != "" {
		session.Setenv("K3S_VERSION", d.Get("version").(string))
	}

	// download the k3s install script
	res, err := http.Get("https://get.k3s.io")
	if err != nil {
		return diag.FromErr(err)
	}

	installScript, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return diag.FromErr(err)
	}

	err = session.Run(string(installScript))
	if err != nil {
		err = fmt.Errorf("%s\n\nStdout:\n%s\n\nStderr:\n%s", err, stdout.String(), stderr.String())
		return diag.FromErr(err)
	}

	tflog.Info(ctx, "Response from setup command:", map[string]interface{}{
		"stdout": stdout.String(),
		"stderr": stderr.String(),
	})

	d.SetId(host)

	return diags
}

func resourceInstallationRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	// Warning or errors can be collected in a slice type
	var diags diag.Diagnostics

	return diags
}

func resourceInstallationUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	return resourceInstallationRead(ctx, d, m)
}

func resourceInstallationDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	// Warning or errors can be collected in a slice type
	var diags diag.Diagnostics

	return diags
}
