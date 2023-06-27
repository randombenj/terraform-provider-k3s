package k3s

import (
	"context"
	"fmt"
	"net"
	"strconv"

	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/hashicorp/terraform-plugin-sdk/helper/validation"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"golang.org/x/crypto/ssh"
)

type SshConfig struct {
	// host (including port)
	host string
	// required ssh configuration to connect to host
	sshConfig *ssh.ClientConfig
}

var sshSchema = map[string]*schema.Schema{
	"user": {
		Description: "The user that should be used to connect to the remote ssh server.",
		Type:        schema.TypeString,
		Optional:    true,
		DefaultFunc: schema.EnvDefaultFunc("K3S_SSH_USER", nil),
	},
	"password": {
		Description: `The password that should be used to authenticate with the remote ssh server.
			Cannot be used with 'private_key'.`,
		Type:     schema.TypeString,
		Optional: true,
		ConflictsWith: []string{
			"private_key",
		},
		DefaultFunc: schema.EnvDefaultFunc("K3S_SSH_USER", nil),
	},
	"private_key": {
		Description: `The SSH private key to authenticate with the remote ssh server.
			The key can be provided as string or loaded from a file using the 'file' function.
			Supported private keys are unencrypted pem encoded RSA (PKCS#1), PKCS#8, DSA (OpenSSL), and ECDSA private keys.
			Mutually exclusive with 'password'."`,
		Type:     schema.TypeString,
		Optional: true,
		ConflictsWith: []string{
			"password",
		},
		DefaultFunc: schema.EnvDefaultFunc("K3S_SSH_USER", nil),
		// ValidateDiagFunc: validate.PrivateKey(),
	},
	"user_certificate": {
		Description: `The ssh user certificate to authenticate with the remote ssh server.
			The certificate can be provided as text or loaded from a file using the 'file' function.
			Expected format of the certificate is a base64 encoded OpenSSH public key ('authorized_keys' format).
			Must be used with in conjunction with 'private_key'. Mutually exclusive with 'password'.`,
		Type:     schema.TypeString,
		Optional: true,
		ConflictsWith: []string{
			"password",
		},
		DefaultFunc: schema.EnvDefaultFunc("K3S_SSH_USER_CERT", nil),
		// ValidateDiagFunc: validate.AuthorizedKey(),
	},
	"host": {
		Description: "The host of the remote ssh server to connect to.",
		Type:        schema.TypeString,
		Optional:    true,
		DefaultFunc: schema.EnvDefaultFunc("K3S_SSH_HOST", nil),
	},
	"host_key": {
		Description: "The public key or the CA certificate of the remote ssh host to verify the remote authenticity. Expected format of the host key is a base64 encoded OpenSSH public key (`authorized_keys` format).",
		Type:        schema.TypeString,
		Optional:    true,
		DefaultFunc: schema.EnvDefaultFunc("K3S_SSH_HOST_KEY", nil),
		// ValidateDiagFunc: validate.AuthorizedKey(),
	},
	"port": {
		Description:  "The port of the remote ssh server to connect to. Defaults to `22`.",
		Type:         schema.TypeInt,
		Optional:     true,
		DefaultFunc:  schema.EnvDefaultFunc("K3S_SSH_PORT", 22),
		ValidateFunc: validation.IsPortNumber,
	},
	"timeout": {
		Description: "Timeout of a single connection attempt. Should be provided as a string like `30s` or `5m`. Defaults to 30 seconds (`30s`).",
		Type:        schema.TypeString,
		Optional:    true,
		// ValidateDiagFunc: validate.All(
		// 	validate.DurationAtLeast(1*time.Second),
		// 	validate.DurationAtMost(60*time.Minute),
		// ),
		DefaultFunc: schema.EnvDefaultFunc("K3S_SSH_TIMEOUT", "30s"),
	},
	// "use_ssh_agent": {
	// 	Description: "If `true`, an ssh agent is used to to authenticate. Defaults to `false`.",
	// 	Type:        schema.TypeBool,
	// 	Optional:    true,
	// 	DefaultFunc: schema.EnvDefaultFunc("K3S_SSH_USE_SSH_AGENT", nil),
	// },
	// "ssh_agent_identity": {
	// 	Description: "The preferred identity from the ssh agent for authentication. Expected format of an identity is a base64 encoded OpenSSH public key (`authorized_keys` format).",
	// 	Type:        schema.TypeString,
	// 	Optional:    true,
	// 	ConflictsWith: []string{
	// 		"password",
	// 	},
	// 	// ValidateDiagFunc: validate.AuthorizedKey(),
	// 	DefaultFunc: schema.EnvDefaultFunc("K3S_SSH_AGENT_IDENTITY", nil),
	// },
}

// Provider -
func Provider() *schema.Provider {
	return &schema.Provider{
		Schema: sshSchema,
		ResourcesMap: map[string]*schema.Resource{
			"k3s_installation": resourceInstallation(),
		},
		DataSourcesMap:       map[string]*schema.Resource{},
		ConfigureContextFunc: configure(),
	}
}

func configure() schema.ConfigureContextFunc {
	return func(ctx context.Context, d *schema.ResourceData) (interface{}, diag.Diagnostics) {
		host := d.Get("host").(string)
		port := strconv.Itoa(d.Get("port").(int))
		user := d.Get("user").(string)
		password := d.Get("password").(string)
		privateKey := d.Get("private_key").(string)
		// userCertificate := d.Get("ssh.user_certificate").(string)

		if host != "" {
			host = net.JoinHostPort(host, port)
		}

		var auth []ssh.AuthMethod

		if password != "" {
			auth = append(auth, ssh.Password(password))
			tflog.Trace(ctx, "Adding password authentication")
		}
		if privateKey != "" {
			key, err := ssh.ParsePrivateKey([]byte(privateKey))
			if err != nil {
				return nil, diag.FromErr(fmt.Errorf("failed to parse ssh private key from provider config: %w", err))
			}
			tflog.Trace(ctx, "Adding key authentication")
			auth = append(auth, ssh.PublicKeys(key))
		}

		config := &ssh.ClientConfig{
			User: user,
			Auth: auth,
			// FIXME:
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		}

		if host != "" {
			connection, err := ssh.Dial("tcp", host, config)
			if err != nil {
				return nil, diag.FromErr(fmt.Errorf("failed to dial ssh connection: %w", err))
			}
			connection.Close()
		}

		return SshConfig{
			host:      host,
			sshConfig: config,
		}, nil
	}
}
