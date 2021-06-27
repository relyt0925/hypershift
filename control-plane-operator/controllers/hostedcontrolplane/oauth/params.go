package oauth

import (
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"

	configv1 "github.com/openshift/api/config/v1"
	hyperv1 "github.com/openshift/hypershift/api/v1alpha1"
	"github.com/openshift/hypershift/control-plane-operator/controllers/hostedcontrolplane/config"
)

type OAuthServerParams struct {
	OwnerRef                config.OwnerRef `json:"ownerRef"`
	ExternalOauthHost            string          `json:"externalOauthHost"`
	ExternalOauthPort            int32           `json:"externalOauthPort"`
	ExternalKASHost             string `json:"externalKASHost"`
	ExternalKASPort             int32 `json:"externalKASPort"`

	OAuthServerImage        string
	config.DeploymentConfig `json:",inline"`
	OAuth                   configv1.OAuth     `json:"oauth"`
	APIServer               configv1.APIServer `json:"apiServer"`
}

type OAuthConfigParams struct {
	ExternalOauthHost             string
	ExternalOauthPort             int32
	ExternalKASHost             string
	ExternalKASPort             int32

	ServingCert              *corev1.Secret
	CipherSuites             []string
	MinTLSVersion            string
	IdentityProviders        []configv1.IdentityProvider
	AccessTokenMaxAgeSeconds int32
	BaseDomain string
}

func NewOAuthServerParams(hcp *hyperv1.HostedControlPlane, images map[string]string, oauthHost string, oauthPort int32, kasHost string, kasPort int32) *OAuthServerParams {
	p := &OAuthServerParams{
		OwnerRef:         config.OwnerRefFrom(hcp),
		ExternalOauthHost:     oauthHost,
		ExternalOauthPort:     oauthPort,
		ExternalKASPort: kasPort,
		ExternalKASHost: kasHost,
		OAuthServerImage: images["oauth-server"],
		OAuth: configv1.OAuth{
			Spec: configv1.OAuthSpec{
				TokenConfig: configv1.TokenConfig{
					AccessTokenMaxAgeSeconds: 86400,
				},
			},
		},
		APIServer: configv1.APIServer{
			Spec: configv1.APIServerSpec{
				TLSSecurityProfile: &configv1.TLSSecurityProfile{
					Type:         configv1.TLSProfileIntermediateType,
					Intermediate: &configv1.IntermediateTLSProfile{},
				},
			},
		},
	}
	p.Scheduling = config.Scheduling{
		PriorityClass: config.DefaultPriorityClass,
	}
	p.Resources = map[string]corev1.ResourceRequirements{
		oauthContainerMain().Name: {
			Requests: corev1.ResourceList{
				corev1.ResourceMemory: resource.MustParse("150Mi"),
				corev1.ResourceCPU:    resource.MustParse("25m"),
			},
		},
	}
	//TODO: minor hack to prototype
	p.OAuth.Spec.IdentityProviders = []configv1.IdentityProvider{
		configv1.IdentityProvider{
			Name: "IAM",
			MappingMethod: configv1.MappingMethodLookup,
			IdentityProviderConfig: configv1.IdentityProviderConfig{
				Type: configv1.IdentityProviderTypeOpenID,
				OpenID: &configv1.OpenIDIdentityProvider{
					//TODO: Need iam_id in ID section
					Claims: configv1.OpenIDClaims{
					Email: []string{
						"email",
					},
					Name: []string{
						"name",
					},
					PreferredUsername: []string{
						"preferred_username",
					},
					},
					ClientID: "clientid",
					ClientSecret: configv1.SecretNameReference{
						Name: "my-secret",
					},
					//TODO: No support for the token accountid url
					Issuer: "https://iam.test.cloud.ibm.com/identity",
				},
			},
		},
	}

	switch hcp.Spec.ControllerAvailabilityPolicy {
	case hyperv1.HighlyAvailable:
		p.Replicas = 3
	default:
		p.Replicas = 1
	}
	return p
}

func (p *OAuthServerParams) ConfigParams(servingCert *corev1.Secret) *OAuthConfigParams {
	return &OAuthConfigParams{
		ExternalOauthHost:             p.ExternalOauthHost,
		ExternalOauthPort:             p.ExternalOauthPort,
		ExternalKASHost: p.ExternalKASHost,
		ExternalKASPort: p.ExternalKASPort,
		ServingCert:              servingCert,
		CipherSuites:             config.CipherSuites(p.APIServer.Spec.TLSSecurityProfile),
		MinTLSVersion:            config.MinTLSVersion(p.APIServer.Spec.TLSSecurityProfile),
		IdentityProviders:        p.OAuth.Spec.IdentityProviders,
		AccessTokenMaxAgeSeconds: p.OAuth.Spec.TokenConfig.AccessTokenMaxAgeSeconds,
	}
}

type OAuthServiceParams struct {
	OAuth    *configv1.OAuth `json:"oauth"`
	OwnerRef config.OwnerRef `json:"ownerRef"`
}

func NewOAuthServiceParams(hcp *hyperv1.HostedControlPlane) *OAuthServiceParams {
	return &OAuthServiceParams{
		OwnerRef: config.OwnerRefFrom(hcp),
	}
}
