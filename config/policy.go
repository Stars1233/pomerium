package config

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	envoy_config_cluster_v3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	envoy_config_route_v3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/pomerium/pomerium/internal/hashutil"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/urlutil"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	configpb "github.com/pomerium/pomerium/pkg/grpc/config"
	"github.com/pomerium/pomerium/pkg/identity"
)

// Policy contains route specific configuration and access settings.
type Policy struct {
	ID          string `mapstructure:"-" yaml:"-" json:"-"`
	Name        string `mapstructure:"name" yaml:"-" json:"name,omitempty"`
	Description string `mapstructure:"description" yaml:"description,omitempty" json:"description,omitempty"`
	LogoURL     string `mapstructure:"logo_url" yaml:"logo_url,omitempty" json:"logo_url,omitempty"`

	From string       `mapstructure:"from" yaml:"from"`
	To   WeightedURLs `mapstructure:"to" yaml:"to"`
	// Redirect is used for a redirect action instead of `To`
	Redirect *PolicyRedirect `mapstructure:"redirect" yaml:"redirect"`
	Response *DirectResponse `mapstructure:"response" yaml:"response,omitempty" json:"response,omitempty"`

	// LbWeights are optional load balancing weights applied to endpoints specified in To
	// this field exists for compatibility with mapstructure
	LbWeights []uint32 `mapstructure:"_to_weights,omitempty" json:"-" yaml:"-"`

	// Identity related policy
	AllowedUsers     []string                 `mapstructure:"allowed_users" yaml:"allowed_users,omitempty" json:"allowed_users,omitempty"`
	AllowedDomains   []string                 `mapstructure:"allowed_domains" yaml:"allowed_domains,omitempty" json:"allowed_domains,omitempty"`
	AllowedIDPClaims identity.FlattenedClaims `mapstructure:"allowed_idp_claims" yaml:"allowed_idp_claims,omitempty" json:"allowed_idp_claims,omitempty"`

	// Additional route matching options
	Prefix             string `mapstructure:"prefix" yaml:"prefix,omitempty" json:"prefix,omitempty"`
	Path               string `mapstructure:"path" yaml:"path,omitempty" json:"path,omitempty"`
	Regex              string `mapstructure:"regex" yaml:"regex,omitempty" json:"regex,omitempty"`
	RegexPriorityOrder *int64 `mapstructure:"regex_priority_order" yaml:"regex_priority_order,omitempty" json:"regex_priority_order,omitempty"`
	compiledRegex      *regexp.Regexp

	// Path Rewrite Options
	PrefixRewrite            string `mapstructure:"prefix_rewrite" yaml:"prefix_rewrite,omitempty" json:"prefix_rewrite,omitempty"`
	RegexRewritePattern      string `mapstructure:"regex_rewrite_pattern" yaml:"regex_rewrite_pattern,omitempty" json:"regex_rewrite_pattern,omitempty"`
	RegexRewriteSubstitution string `mapstructure:"regex_rewrite_substitution" yaml:"regex_rewrite_substitution,omitempty" json:"regex_rewrite_substitution,omitempty"`

	// Host Rewrite Options
	HostRewrite                      string `mapstructure:"host_rewrite" yaml:"host_rewrite,omitempty" json:"host_rewrite,omitempty"`
	HostRewriteHeader                string `mapstructure:"host_rewrite_header" yaml:"host_rewrite_header,omitempty" json:"host_rewrite_header,omitempty"`
	HostPathRegexRewritePattern      string `mapstructure:"host_path_regex_rewrite_pattern" yaml:"host_path_regex_rewrite_pattern,omitempty" json:"host_path_regex_rewrite_pattern,omitempty"`
	HostPathRegexRewriteSubstitution string `mapstructure:"host_path_regex_rewrite_substitution" yaml:"host_path_regex_rewrite_substitution,omitempty" json:"host_path_regex_rewrite_substitution,omitempty"`

	// Allow unauthenticated HTTP OPTIONS requests as per the CORS spec
	// https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS#Preflighted_requests
	CORSAllowPreflight bool `mapstructure:"cors_allow_preflight" yaml:"cors_allow_preflight,omitempty"`

	// Allow any public request to access this route. **Bypasses authentication**
	AllowPublicUnauthenticatedAccess bool `mapstructure:"allow_public_unauthenticated_access" yaml:"allow_public_unauthenticated_access,omitempty"`

	// Allow any authenticated user
	AllowAnyAuthenticatedUser bool `mapstructure:"allow_any_authenticated_user" yaml:"allow_any_authenticated_user,omitempty"`

	// UpstreamTimeout is the route specific timeout. Must be less than the global
	// timeout. If unset, route will fallback to the proxy's DefaultUpstreamTimeout.
	UpstreamTimeout *time.Duration `mapstructure:"timeout" yaml:"timeout,omitempty"`

	// IdleTimeout is distinct from UpstreamTimeout and defines period of time there may be no data over this connection
	// value of zero completely disables this setting
	// see https://www.envoyproxy.io/docs/envoy/latest/api-v3/config/route/v3/route_components.proto#envoy-v3-api-field-config-route-v3-routeaction-idle-timeout
	IdleTimeout *time.Duration `mapstructure:"idle_timeout" yaml:"idle_timeout,omitempty"`

	// Enable proxying of websocket connections by removing the default timeout handler.
	// Caution: Enabling this feature could result in abuse via DOS attacks.
	AllowWebsockets bool `mapstructure:"allow_websockets"  yaml:"allow_websockets,omitempty"`

	// AllowSPDY enables proxying of SPDY upgrade requests
	AllowSPDY bool `mapstructure:"allow_spdy" yaml:"allow_spdy,omitempty"`

	// TLSSkipVerify controls whether a client verifies the server's certificate
	// chain and host name.
	// If TLSSkipVerify is true, TLS accepts any certificate presented by the
	// server and any host name in that certificate.
	// In this mode, TLS is susceptible to man-in-the-middle attacks.
	// This should be used only for testing.
	TLSSkipVerify bool `mapstructure:"tls_skip_verify" yaml:"tls_skip_verify,omitempty"`

	// TLSServerName overrides the hostname in the `to` field. This is useful
	// if your backend is an HTTPS server with a valid certificate, but you
	// want to communicate to the backend with an internal hostname (e.g.
	// Docker container name).
	TLSServerName           string `mapstructure:"tls_server_name" yaml:"tls_server_name,omitempty"`
	TLSDownstreamServerName string `mapstructure:"tls_downstream_server_name" yaml:"tls_downstream_server_name,omitempty"`
	TLSUpstreamServerName   string `mapstructure:"tls_upstream_server_name" yaml:"tls_upstream_server_name,omitempty"`

	// TLSCustomCA defines the  root certificate to use with a given
	// route when verifying server certificates.
	TLSCustomCA     string `mapstructure:"tls_custom_ca" yaml:"tls_custom_ca,omitempty"`
	TLSCustomCAFile string `mapstructure:"tls_custom_ca_file" yaml:"tls_custom_ca_file,omitempty"`

	// Contains the x.509 client certificate to present to the upstream host.
	TLSClientCert     string           `mapstructure:"tls_client_cert" yaml:"tls_client_cert,omitempty"`
	TLSClientKey      string           `mapstructure:"tls_client_key" yaml:"tls_client_key,omitempty"`
	TLSClientCertFile string           `mapstructure:"tls_client_cert_file" yaml:"tls_client_cert_file,omitempty"`
	TLSClientKeyFile  string           `mapstructure:"tls_client_key_file" yaml:"tls_client_key_file,omitempty"`
	ClientCertificate *tls.Certificate `yaml:",omitempty" hash:"ignore"`

	// TLSDownstreamClientCA defines the root certificate to use with a given route to verify
	// downstream client certificates (e.g. from a user's browser).
	TLSDownstreamClientCA     string `mapstructure:"tls_downstream_client_ca" yaml:"tls_downstream_client_ca,omitempty"`
	TLSDownstreamClientCAFile string `mapstructure:"tls_downstream_client_ca_file" yaml:"tls_downstream_client_ca_file,omitempty"`

	// TLSUpstreamAllowRenegotiation allows server-initiated TLS renegotiation.
	TLSUpstreamAllowRenegotiation bool `mapstructure:"tls_upstream_allow_renegotiation" yaml:"allow_renegotiation,omitempty"`

	// SetRequestHeaders adds a collection of headers to the upstream request
	// in the form of key value pairs. Note bene, this will overwrite the
	// value of any existing value of a given header key.
	SetRequestHeaders map[string]string `mapstructure:"set_request_headers" yaml:"set_request_headers,omitempty"`

	// RemoveRequestHeaders removes a collection of headers from an upstream request.
	// Note that this has lower priority than `SetRequestHeaders`, if you specify `X-Custom-Header` in both
	// `SetRequestHeaders` and `RemoveRequestHeaders`, then the header won't be removed.
	RemoveRequestHeaders []string `mapstructure:"remove_request_headers" yaml:"remove_request_headers,omitempty"`

	// PreserveHostHeader disables host header rewriting.
	//
	// This option only takes affect if the destination is a DNS name. If the destination is an IP address,
	// use SetRequestHeaders to explicitly set the "Host" header.
	//
	// https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_set_header
	PreserveHostHeader bool `mapstructure:"preserve_host_header" yaml:"preserve_host_header,omitempty"`

	// PassIdentityHeaders controls whether to add a user's identity headers to the upstream request.
	// These include:
	//
	//  - X-Pomerium-Jwt-Assertion
	//  - X-Pomerium-Claim-*
	//
	PassIdentityHeaders *bool `mapstructure:"pass_identity_headers" yaml:"pass_identity_headers,omitempty"`

	// KubernetesServiceAccountToken is the kubernetes token to use for upstream requests.
	KubernetesServiceAccountToken string `mapstructure:"kubernetes_service_account_token" yaml:"kubernetes_service_account_token,omitempty"`
	// KubernetesServiceAccountTokenFile contains the kubernetes token to use for upstream requests.
	KubernetesServiceAccountTokenFile string `mapstructure:"kubernetes_service_account_token_file" yaml:"kubernetes_service_account_token_file,omitempty"`

	// EnableGoogleCloudServerlessAuthentication adds "Authorization: Bearer ID_TOKEN" headers
	// to upstream requests.
	EnableGoogleCloudServerlessAuthentication bool `mapstructure:"enable_google_cloud_serverless_authentication" yaml:"enable_google_cloud_serverless_authentication,omitempty"`

	// JWTIssuerFormat controls the format of the 'iss' claim in JWTs passed to upstream services by this route.
	// Possible values:
	// - "hostOnly" (default): Issuer strings will be the hostname of the route, with no scheme or trailing slash.
	// - "uri": Issuer strings will be a complete URI, including the scheme and ending with a trailing slash.
	JWTIssuerFormat JWTIssuerFormat `mapstructure:"jwt_issuer_format" yaml:"jwt_issuer_format,omitempty"`
	// BearerTokenFormat indicates how authorization bearer tokens are interepreted. Possible values:
	// - "default": Only Bearer tokens prefixed with Pomerium- will be interpreted by Pomerium
	// - "idp_access_token": The Bearer token will be interpreted as an IdP access token.
	// - "idp_identity_token": The Bearer token will be interpreted as an IdP identity token.
	// When unset the global option will be used.
	BearerTokenFormat *BearerTokenFormat `mapstructure:"bearer_token_format" yaml:"bearer_token_format,omitempty"`

	// Allowlist of group names/IDs to include in the Pomerium JWT.
	// This expands on any global allowlist set in the main Options.
	JWTGroupsFilter JWTGroupsFilter

	SubPolicies []SubPolicy `mapstructure:"sub_policies" yaml:"sub_policies,omitempty" json:"sub_policies,omitempty"`

	EnvoyOpts *envoy_config_cluster_v3.Cluster `mapstructure:"_envoy_opts" yaml:"-" json:"-"`

	// RewriteResponseHeaders rewrites response headers. This can be used to change the Location header.
	RewriteResponseHeaders []RewriteHeader `mapstructure:"rewrite_response_headers" yaml:"rewrite_response_headers,omitempty" json:"rewrite_response_headers,omitempty"`

	// SetResponseHeaders sets response headers.
	SetResponseHeaders map[string]string `mapstructure:"set_response_headers" yaml:"set_response_headers,omitempty"`

	// IDPClientID is the client id used for the identity provider.
	IDPClientID string `mapstructure:"idp_client_id" yaml:"idp_client_id,omitempty"`
	// IDPClientSecret is the client secret used for the identity provider.
	IDPClientSecret string `mapstructure:"idp_client_secret" yaml:"idp_client_secret,omitempty"`
	// IDPAccessTokenAllowedAudiences are the allowed audiences for idp access token validation.
	IDPAccessTokenAllowedAudiences *[]string `mapstructure:"idp_access_token_allowed_audiences" yaml:"idp_access_token_allowed_audiences,omitempty"`

	// ShowErrorDetails indicates whether or not additional error details should be displayed.
	ShowErrorDetails bool `mapstructure:"show_error_details" yaml:"show_error_details" json:"show_error_details"`

	Policy *PPLPolicy `mapstructure:"policy" yaml:"policy,omitempty" json:"policy,omitempty"`

	DependsOn []string `mapstructure:"depends_on" yaml:"depends_on,omitempty" json:"depends_on,omitempty"`

	// MCP is an experimental support for Model Context Protocol upstreams
	MCP                      *MCP                      `mapstructure:"mcp" yaml:"mcp,omitempty" json:"mcp,omitempty"`
	CircuitBreakerThresholds *CircuitBreakerThresholds `mapstructure:"circuit_breaker_thresholds" yaml:"circuit_breaker_thresholds,omitempty" json:"circuit_breaker_thresholds,omitempty"`
}

// MCP is an experimental support for Model Context Protocol upstreams configuration
type MCP struct {
	// exactly one of server or client should be specified
	Server *MCPServer `mapstructure:"server" yaml:"server,omitempty" json:"server,omitempty"`
	Client *MCPClient `mapstructure:"client" yaml:"client,omitempty" json:"client,omitempty"`
}

func (p *MCP) GetServer() *MCPServer {
	if p == nil {
		return nil
	}
	return p.Server
}

// MCPServer holds configuration for an MCP server route
type MCPServer struct {
	// UpstreamOAuth2 specifies that before the request reaches the MCP upstream server, it should acquire an OAuth2 token
	UpstreamOAuth2 *UpstreamOAuth2 `mapstructure:"upstream_oauth2" yaml:"upstream_oauth2,omitempty" json:"upstream_oauth2,omitempty"`
	// MaxRequestBytes is the maximum request body size in bytes that can be sent to the MCP server
	MaxRequestBytes *uint32 `mapstructure:"max_request_bytes" yaml:"max_request_bytes,omitempty" json:"max_request_bytes,omitempty"`
	// Path is the path to append to the URL when returning the server URL in the .mcp/routes endpoint. Defaults to "/"
	Path *string `mapstructure:"path" yaml:"path,omitempty" json:"path,omitempty"`
}

// MCPClient holds configuration for an MCP client route
type MCPClient struct{}

func (p *MCPServer) GetMaxRequestBytes() uint32 {
	if p == nil || p.MaxRequestBytes == nil {
		return 4 * 1024
	}
	return *p.MaxRequestBytes
}

func (p *MCPServer) GetPath() string {
	if p == nil || p.Path == nil {
		return "/"
	}
	return *p.Path
}

// HasUpstreamOAuth2 checks if the route is for the MCP Server and if it has an upstream OAuth2 configuration
func (p *MCP) GetServerUpstreamOAuth2() *UpstreamOAuth2 {
	if p != nil && p.Server != nil {
		return p.Server.UpstreamOAuth2
	}
	return nil
}

type UpstreamOAuth2 struct {
	ClientID     string         `mapstructure:"client_id" yaml:"client_id,omitempty" json:"client_id,omitempty"`
	ClientSecret string         `mapstructure:"client_secret" yaml:"client_secret,omitempty" json:"client_secret,omitempty"`
	Endpoint     OAuth2Endpoint `mapstructure:"endpoint" yaml:"endpoint,omitempty" json:"endpoint,omitempty"`
	Scopes       []string       `mapstructure:"scopes" yaml:"scopes,omitempty" json:"scopes,omitempty"`
}

type OAuth2Endpoint struct {
	AuthURL   string                  `mapstructure:"auth_url" yaml:"auth_url,omitempty" json:"auth_url,omitempty"`
	TokenURL  string                  `mapstructure:"token_url" yaml:"token_url,omitempty" json:"token_url,omitempty"`
	AuthStyle OAuth2EndpointAuthStyle `mapstructure:"auth_style" yaml:"auth_style,omitempty" json:"auth_style,omitempty"`
}

type OAuth2EndpointAuthStyle string

const (
	// OAuth2EndpointAuthStyleInHeader indicates that the auth style is in the header
	OAuth2EndpointAuthStyleInHeader OAuth2EndpointAuthStyle = "header"
	// OAuth2EndpointAuthStyleInParams indicates that the auth style is in the params
	OAuth2EndpointAuthStyleInParams OAuth2EndpointAuthStyle = "params"
	// OAuth2EndpointAuthStyleAuto indicates that the auth style is auto
	OAuth2EndpointAuthStyleAuto OAuth2EndpointAuthStyle = ""
)

// RewriteHeader is a policy configuration option to rewrite an HTTP header.
type RewriteHeader struct {
	Header string `mapstructure:"header" yaml:"header" json:"header"`
	Prefix string `mapstructure:"prefix" yaml:"prefix,omitempty" json:"prefix,omitempty"`
	Value  string `mapstructure:"value" yaml:"value,omitempty" json:"value,omitempty"`
}

// A SubPolicy is a protobuf Policy within a protobuf Route.
type SubPolicy struct {
	ID               string                   `mapstructure:"id" yaml:"id" json:"id"`
	Name             string                   `mapstructure:"name" yaml:"name" json:"name"`
	AllowedUsers     []string                 `mapstructure:"allowed_users" yaml:"allowed_users,omitempty" json:"allowed_users,omitempty"`
	AllowedDomains   []string                 `mapstructure:"allowed_domains" yaml:"allowed_domains,omitempty" json:"allowed_domains,omitempty"`
	AllowedIDPClaims identity.FlattenedClaims `mapstructure:"allowed_idp_claims" yaml:"allowed_idp_claims,omitempty" json:"allowed_idp_claims,omitempty"`
	Rego             []string                 `mapstructure:"rego" yaml:"rego" json:"rego,omitempty"`
	SourcePPL        string                   `mapstructure:"source_ppl" yaml:"source_ppl,omitempty" json:"source_ppl,omitempty"`

	// Explanation is the explanation for why a policy failed.
	Explanation string `mapstructure:"explanation" yaml:"explanation" json:"explanation,omitempty"`
	// Remediation are the steps a user needs to take to gain access.
	Remediation string `mapstructure:"remediation" yaml:"remediation" json:"remediation,omitempty"`
}

// PolicyRedirect is a route redirect action.
type PolicyRedirect struct {
	HTTPSRedirect  *bool   `mapstructure:"https_redirect" yaml:"https_redirect,omitempty" json:"https_redirect,omitempty"`
	SchemeRedirect *string `mapstructure:"scheme_redirect" yaml:"scheme_redirect,omitempty" json:"scheme_redirect,omitempty"`
	HostRedirect   *string `mapstructure:"host_redirect" yaml:"host_redirect,omitempty" json:"host_redirect,omitempty"`
	PortRedirect   *uint32 `mapstructure:"port_redirect" yaml:"port_redirect,omitempty" json:"port_redirect,omitempty"`
	PathRedirect   *string `mapstructure:"path_redirect" yaml:"path_redirect,omitempty" json:"path_redirect,omitempty"`
	PrefixRewrite  *string `mapstructure:"prefix_rewrite" yaml:"prefix_rewrite,omitempty" json:"prefix_rewrite,omitempty"`
	ResponseCode   *int32  `mapstructure:"response_code" yaml:"response_code,omitempty" json:"response_code,omitempty"`
	StripQuery     *bool   `mapstructure:"strip_query" yaml:"strip_query,omitempty" json:"strip_query,omitempty"`
}

func (r *PolicyRedirect) validate() error {
	if r == nil {
		return nil
	}

	if _, err := r.GetEnvoyResponseCode(); err != nil {
		return err
	}
	return nil
}

// GetEnvoyResponseCode returns the ResponseCode as the corresponding Envoy enum value.
func (r *PolicyRedirect) GetEnvoyResponseCode() (envoy_config_route_v3.RedirectAction_RedirectResponseCode, error) {
	if r == nil || r.ResponseCode == nil {
		return envoy_config_route_v3.RedirectAction_RedirectResponseCode(0), nil
	}
	switch code := *r.ResponseCode; code {
	case http.StatusMovedPermanently:
		return envoy_config_route_v3.RedirectAction_MOVED_PERMANENTLY, nil
	case http.StatusFound:
		return envoy_config_route_v3.RedirectAction_FOUND, nil
	case http.StatusSeeOther:
		return envoy_config_route_v3.RedirectAction_SEE_OTHER, nil
	case http.StatusTemporaryRedirect:
		return envoy_config_route_v3.RedirectAction_TEMPORARY_REDIRECT, nil
	case http.StatusPermanentRedirect:
		return envoy_config_route_v3.RedirectAction_PERMANENT_REDIRECT, nil
	default:
		return 0, fmt.Errorf("unsupported redirect response code %d (supported values: 301, 302, 303, 307, 308)", code)
	}
}

// A DirectResponse is the response to an HTTP request.
type DirectResponse struct {
	Status int    `mapstructure:"status" yaml:"status,omitempty" json:"status,omitempty"`
	Body   string `mapstructure:"body" yaml:"body,omitempty" json:"body,omitempty"`
}

// NewPolicyFromProto creates a new Policy from a protobuf policy config route.
func NewPolicyFromProto(pb *configpb.Route) (*Policy, error) {
	var timeout *time.Duration
	if pb.GetTimeout() != nil {
		t := pb.GetTimeout().AsDuration()
		timeout = &t
	}
	var idleTimeout *time.Duration
	if pb.GetIdleTimeout() != nil {
		t := pb.GetIdleTimeout().AsDuration()
		idleTimeout = &t
	}

	p := &Policy{
		AllowAnyAuthenticatedUser:        pb.GetAllowAnyAuthenticatedUser(),
		AllowedDomains:                   pb.GetAllowedDomains(),
		AllowedIDPClaims:                 identity.NewFlattenedClaimsFromPB(pb.GetAllowedIdpClaims()),
		AllowedUsers:                     pb.GetAllowedUsers(),
		AllowPublicUnauthenticatedAccess: pb.GetAllowPublicUnauthenticatedAccess(),
		AllowSPDY:                        pb.GetAllowSpdy(),
		AllowWebsockets:                  pb.GetAllowWebsockets(),
		CircuitBreakerThresholds:         CircuitBreakerThresholdsFromPB(pb.CircuitBreakerThresholds),
		CORSAllowPreflight:               pb.GetCorsAllowPreflight(),
		Description:                      pb.GetDescription(),
		DependsOn:                        pb.GetDependsOn(),
		EnableGoogleCloudServerlessAuthentication: pb.GetEnableGoogleCloudServerlessAuthentication(),
		From:                              pb.GetFrom(),
		HostPathRegexRewritePattern:       pb.GetHostPathRegexRewritePattern(),
		HostPathRegexRewriteSubstitution:  pb.GetHostPathRegexRewriteSubstitution(),
		HostRewrite:                       pb.GetHostRewrite(),
		HostRewriteHeader:                 pb.GetHostRewriteHeader(),
		ID:                                pb.GetId(),
		IdleTimeout:                       idleTimeout,
		IDPClientID:                       pb.GetIdpClientId(),
		IDPClientSecret:                   pb.GetIdpClientSecret(),
		JWTGroupsFilter:                   NewJWTGroupsFilter(pb.JwtGroupsFilter),
		JWTIssuerFormat:                   JWTIssuerFormatFromPB(pb.JwtIssuerFormat),
		KubernetesServiceAccountToken:     pb.GetKubernetesServiceAccountToken(),
		KubernetesServiceAccountTokenFile: pb.GetKubernetesServiceAccountTokenFile(),
		LogoURL:                           pb.GetLogoUrl(),
		MCP:                               MCPFromPB(pb.GetMcp()),
		Name:                              pb.GetName(),
		PassIdentityHeaders:               pb.PassIdentityHeaders,
		Path:                              pb.GetPath(),
		Prefix:                            pb.GetPrefix(),
		PrefixRewrite:                     pb.GetPrefixRewrite(),
		PreserveHostHeader:                pb.GetPreserveHostHeader(),
		Regex:                             pb.GetRegex(),
		RegexPriorityOrder:                pb.RegexPriorityOrder,
		RegexRewritePattern:               pb.GetRegexRewritePattern(),
		RegexRewriteSubstitution:          pb.GetRegexRewriteSubstitution(),
		RemoveRequestHeaders:              pb.GetRemoveRequestHeaders(),
		SetRequestHeaders:                 pb.GetSetRequestHeaders(),
		SetResponseHeaders:                pb.GetSetResponseHeaders(),
		ShowErrorDetails:                  pb.GetShowErrorDetails(),
		TLSClientCert:                     pb.GetTlsClientCert(),
		TLSClientCertFile:                 pb.GetTlsClientCertFile(),
		TLSClientKey:                      pb.GetTlsClientKey(),
		TLSClientKeyFile:                  pb.GetTlsClientKeyFile(),
		TLSCustomCA:                       pb.GetTlsCustomCa(),
		TLSCustomCAFile:                   pb.GetTlsCustomCaFile(),
		TLSDownstreamClientCA:             pb.GetTlsDownstreamClientCa(),
		TLSDownstreamClientCAFile:         pb.GetTlsDownstreamClientCaFile(),
		TLSDownstreamServerName:           pb.GetTlsDownstreamServerName(),
		TLSServerName:                     pb.GetTlsServerName(),
		TLSSkipVerify:                     pb.GetTlsSkipVerify(),
		TLSUpstreamAllowRenegotiation:     pb.GetTlsUpstreamAllowRenegotiation(),
		TLSUpstreamServerName:             pb.GetTlsUpstreamServerName(),
		UpstreamTimeout:                   timeout,
	}
	if pb.IdpAccessTokenAllowedAudiences != nil {
		values := slices.Clone(pb.IdpAccessTokenAllowedAudiences.Values)
		p.IDPAccessTokenAllowedAudiences = &values
	} else {
		p.IDPAccessTokenAllowedAudiences = nil
	}
	if pb.Redirect.IsSet() {
		p.Redirect = &PolicyRedirect{
			HTTPSRedirect:  pb.Redirect.HttpsRedirect,
			SchemeRedirect: pb.Redirect.SchemeRedirect,
			HostRedirect:   pb.Redirect.HostRedirect,
			PortRedirect:   pb.Redirect.PortRedirect,
			PathRedirect:   pb.Redirect.PathRedirect,
			PrefixRewrite:  pb.Redirect.PrefixRewrite,
			ResponseCode:   pb.Redirect.ResponseCode,
			StripQuery:     pb.Redirect.StripQuery,
		}
	} else if pb.Response != nil {
		p.Response = &DirectResponse{
			Status: int(pb.Response.GetStatus()),
			Body:   pb.Response.GetBody(),
		}
	} else {
		var err error
		p.To, err = ParseWeightedUrls(pb.To...)
		if err != nil && !errors.Is(err, errEmptyUrls) {
			return nil, fmt.Errorf("error parsing to URLs: %w", err)
		}

		if len(pb.LoadBalancingWeights) == len(p.To) {
			for i, w := range pb.LoadBalancingWeights {
				p.To[i].LbWeight = w
			}
		}
	}

	p.EnvoyOpts = pb.EnvoyOpts
	if p.EnvoyOpts == nil {
		p.EnvoyOpts = new(envoy_config_cluster_v3.Cluster)
	}
	if pb.Name != "" && p.EnvoyOpts.Name == "" {
		p.EnvoyOpts.Name = pb.Name
	}

	p.BearerTokenFormat = BearerTokenFormatFromPB(pb.BearerTokenFormat)

	for _, rwh := range pb.RewriteResponseHeaders {
		p.RewriteResponseHeaders = append(p.RewriteResponseHeaders, RewriteHeader{
			Header: rwh.GetHeader(),
			Prefix: rwh.GetPrefix(),
			Value:  rwh.GetValue(),
		})
	}

	for _, sp := range pb.GetPolicies() {
		p.SubPolicies = append(p.SubPolicies, SubPolicy{
			ID:               sp.GetId(),
			Name:             sp.GetName(),
			AllowedUsers:     sp.GetAllowedUsers(),
			AllowedDomains:   sp.GetAllowedDomains(),
			AllowedIDPClaims: identity.NewFlattenedClaimsFromPB(sp.GetAllowedIdpClaims()),
			Rego:             sp.GetRego(),
			SourcePPL:        sp.GetSourcePpl(),

			Explanation: sp.GetExplanation(),
			Remediation: sp.GetRemediation(),
		})
	}
	return p, nil
}

// ToProto converts the policy to a protobuf type.
func (p *Policy) ToProto() (*configpb.Route, error) {
	var timeout *durationpb.Duration
	if p.UpstreamTimeout == nil {
		timeout = durationpb.New(defaultOptions.DefaultUpstreamTimeout)
	} else {
		timeout = durationpb.New(*p.UpstreamTimeout)
	}
	var idleTimeout *durationpb.Duration
	if p.IdleTimeout != nil {
		idleTimeout = durationpb.New(*p.IdleTimeout)
	}
	sps := make([]*configpb.Policy, 0, len(p.SubPolicies))
	for _, sp := range p.SubPolicies {
		p := &configpb.Policy{
			Id:               sp.ID,
			Name:             sp.Name,
			AllowedUsers:     sp.AllowedUsers,
			AllowedDomains:   sp.AllowedDomains,
			AllowedIdpClaims: sp.AllowedIDPClaims.ToPB(),
			Explanation:      sp.Explanation,
			Remediation:      sp.Remediation,
			Rego:             sp.Rego,
		}
		if sp.SourcePPL != "" {
			p.SourcePpl = proto.String(sp.SourcePPL)
		}
		sps = append(sps, p)
	}

	pb := &configpb.Route{
		AllowAnyAuthenticatedUser:        p.AllowAnyAuthenticatedUser,
		AllowedDomains:                   p.AllowedDomains,
		AllowedIdpClaims:                 p.AllowedIDPClaims.ToPB(),
		AllowedUsers:                     p.AllowedUsers,
		AllowPublicUnauthenticatedAccess: p.AllowPublicUnauthenticatedAccess,
		AllowSpdy:                        p.AllowSPDY,
		AllowWebsockets:                  p.AllowWebsockets,
		CircuitBreakerThresholds:         CircuitBreakerThresholdsToPB(p.CircuitBreakerThresholds),
		CorsAllowPreflight:               p.CORSAllowPreflight,
		Description:                      p.Description,
		DependsOn:                        p.DependsOn,
		EnableGoogleCloudServerlessAuthentication: p.EnableGoogleCloudServerlessAuthentication,
		EnvoyOpts:                         p.EnvoyOpts,
		From:                              p.From,
		Id:                                p.ID,
		IdleTimeout:                       idleTimeout,
		JwtGroupsFilter:                   p.JWTGroupsFilter.ToSlice(),
		JwtIssuerFormat:                   p.JWTIssuerFormat.ToPB(),
		KubernetesServiceAccountToken:     p.KubernetesServiceAccountToken,
		KubernetesServiceAccountTokenFile: p.KubernetesServiceAccountTokenFile,
		LogoUrl:                           p.LogoURL,
		Mcp:                               MCPToPB(p.MCP),
		Name:                              p.Name,
		PassIdentityHeaders:               p.PassIdentityHeaders,
		Path:                              p.Path,
		Policies:                          sps,
		Prefix:                            p.Prefix,
		PrefixRewrite:                     p.PrefixRewrite,
		PreserveHostHeader:                p.PreserveHostHeader,
		Regex:                             p.Regex,
		RegexPriorityOrder:                p.RegexPriorityOrder,
		RegexRewritePattern:               p.RegexRewritePattern,
		RegexRewriteSubstitution:          p.RegexRewriteSubstitution,
		RemoveRequestHeaders:              p.RemoveRequestHeaders,
		SetRequestHeaders:                 p.SetRequestHeaders,
		SetResponseHeaders:                p.SetResponseHeaders,
		ShowErrorDetails:                  p.ShowErrorDetails,
		Timeout:                           timeout,
		TlsClientCert:                     p.TLSClientCert,
		TlsClientCertFile:                 p.TLSClientCertFile,
		TlsClientKey:                      p.TLSClientKey,
		TlsClientKeyFile:                  p.TLSClientKeyFile,
		TlsCustomCa:                       p.TLSCustomCA,
		TlsCustomCaFile:                   p.TLSCustomCAFile,
		TlsDownstreamClientCa:             p.TLSDownstreamClientCA,
		TlsDownstreamClientCaFile:         p.TLSDownstreamClientCAFile,
		TlsDownstreamServerName:           p.TLSDownstreamServerName,
		TlsServerName:                     p.TLSServerName,
		TlsSkipVerify:                     p.TLSSkipVerify,
		TlsUpstreamAllowRenegotiation:     p.TLSUpstreamAllowRenegotiation,
		TlsUpstreamServerName:             p.TLSUpstreamServerName,
	}
	if pb.Name == "" {
		pb.Name = fmt.Sprint(p.RouteID())
	}
	if p.HostPathRegexRewritePattern != "" {
		pb.HostPathRegexRewritePattern = proto.String(p.HostPathRegexRewritePattern)
	}
	if p.HostPathRegexRewriteSubstitution != "" {
		pb.HostPathRegexRewriteSubstitution = proto.String(p.HostPathRegexRewriteSubstitution)
	}
	if p.HostRewrite != "" {
		pb.HostRewrite = proto.String(p.HostRewrite)
	}
	if p.HostRewriteHeader != "" {
		pb.HostRewriteHeader = proto.String(p.HostRewriteHeader)
	}
	if p.IDPClientID != "" {
		pb.IdpClientId = proto.String(p.IDPClientID)
	}
	if p.IDPClientSecret != "" {
		pb.IdpClientSecret = proto.String(p.IDPClientSecret)
	}
	if p.IDPAccessTokenAllowedAudiences != nil {
		pb.IdpAccessTokenAllowedAudiences = &configpb.Route_StringList{
			Values: slices.Clone(*p.IDPAccessTokenAllowedAudiences),
		}
	} else {
		pb.IdpAccessTokenAllowedAudiences = nil
	}
	if p.Redirect != nil {
		pb.Redirect = &configpb.RouteRedirect{
			HttpsRedirect:  p.Redirect.HTTPSRedirect,
			SchemeRedirect: p.Redirect.SchemeRedirect,
			HostRedirect:   p.Redirect.HostRedirect,
			PortRedirect:   p.Redirect.PortRedirect,
			PathRedirect:   p.Redirect.PathRedirect,
			PrefixRewrite:  p.Redirect.PrefixRewrite,
			ResponseCode:   p.Redirect.ResponseCode,
			StripQuery:     p.Redirect.StripQuery,
		}
	} else if p.Response != nil {
		pb.Response = &configpb.RouteDirectResponse{
			Status: uint32(p.Response.Status),
			Body:   p.Response.Body,
		}
	} else {
		to, weights, err := p.To.Flatten()
		if err != nil {
			return nil, err
		}

		pb.To = to
		pb.LoadBalancingWeights = weights
	}

	pb.BearerTokenFormat = p.BearerTokenFormat.ToPB()

	for _, rwh := range p.RewriteResponseHeaders {
		pb.RewriteResponseHeaders = append(pb.RewriteResponseHeaders, &configpb.RouteRewriteHeader{
			Header: rwh.Header,
			Matcher: &configpb.RouteRewriteHeader_Prefix{
				Prefix: rwh.Prefix,
			},
			Value: rwh.Value,
		})
	}

	return pb, nil
}

// Validate checks the validity of a policy.
func (p *Policy) Validate() error {
	var err error
	source, err := urlutil.ParseAndValidateURL(p.From)
	if err != nil {
		return fmt.Errorf("config: policy bad source url %w", err)
	}

	// Make sure there's no path set on the from url
	if (source.Scheme == "http" || source.Scheme == "https") && !(source.Path == "" || source.Path == "/") {
		return fmt.Errorf("config: policy source url (%s) contains a path, but it should be set using the path field instead",
			source.String())
	}
	if source.Scheme == "http" {
		log.Info().Msgf("config: policy source url (%s) uses HTTP but only HTTPS is supported",
			source.String())
	}

	if len(p.To) == 0 && p.Redirect == nil && p.Response == nil {
		return errEitherToOrRedirectOrResponseRequired
	}

	toSchemes := make(map[string]struct{})
	for _, u := range p.To {
		if err = u.Validate(); err != nil {
			return fmt.Errorf("config: %s: %w", u.URL.String(), err)
		}
		toSchemes[u.URL.Scheme] = struct{}{}
	}

	// It is an error to mix TCP and non-TCP To URLs.
	if _, hasTCP := toSchemes["tcp"]; hasTCP && len(toSchemes) > 1 {
		return fmt.Errorf("config: cannot mix tcp and non-tcp To URLs")
	}
	if _, hasUDP := toSchemes["udp"]; hasUDP && len(toSchemes) > 1 {
		return fmt.Errorf("config: cannot mix udp and non-udp To URLs")
	}

	if err := p.Redirect.validate(); err != nil {
		return fmt.Errorf("config: %w", err)
	}

	// Only allow public access if no other whitelists are in place
	if p.AllowPublicUnauthenticatedAccess && (p.AllowAnyAuthenticatedUser || p.AllowedDomains != nil || p.AllowedUsers != nil) {
		return fmt.Errorf("config: policy route marked as public but contains whitelists")
	}

	// Only allow any authenticated user if no other whitelists are in place
	if p.AllowAnyAuthenticatedUser && (p.AllowedDomains != nil || p.AllowedUsers != nil) {
		return fmt.Errorf("config: policy route marked accessible for any authenticated user but contains whitelists")
	}

	if (p.TLSClientCert == "" && p.TLSClientKey != "") || (p.TLSClientCert != "" && p.TLSClientKey == "") ||
		(p.TLSClientCertFile == "" && p.TLSClientKeyFile != "") || (p.TLSClientCertFile != "" && p.TLSClientKeyFile == "") {
		return fmt.Errorf("config: client certificate key and cert both must be non-empty")
	}

	if p.TLSClientCert != "" && p.TLSClientKey != "" {
		p.ClientCertificate, err = cryptutil.CertificateFromBase64(p.TLSClientCert, p.TLSClientKey)
		if err != nil {
			return fmt.Errorf("config: couldn't decode client cert %w", err)
		}
	} else if p.TLSClientCertFile != "" && p.TLSClientKeyFile != "" {
		p.ClientCertificate, err = cryptutil.CertificateFromFile(p.TLSClientCertFile, p.TLSClientKeyFile)
		if err != nil {
			return fmt.Errorf("config: couldn't load client cert file %w", err)
		}
	}

	if p.TLSCustomCA != "" {
		_, err := base64.StdEncoding.DecodeString(p.TLSCustomCA)
		if err != nil {
			return fmt.Errorf("config: couldn't decode custom ca: %w", err)
		}
	} else if p.TLSCustomCAFile != "" {
		ca, err := os.ReadFile(p.TLSCustomCAFile)
		if err != nil {
			return fmt.Errorf("config: couldn't load client ca file: %w", err)
		}
		p.TLSCustomCA = base64.StdEncoding.EncodeToString(ca)
	}

	const clientCADeprecationMsg = "config: %s is deprecated, see https://www.pomerium.com/docs/" +
		"reference/routes/tls#tls-downstream-client-certificate-authority for more information"

	if p.TLSDownstreamClientCA != "" {
		log.Info().Msgf(clientCADeprecationMsg, "tls_downstream_client_ca")
		_, err := base64.StdEncoding.DecodeString(p.TLSDownstreamClientCA)
		if err != nil {
			return fmt.Errorf("config: couldn't decode downstream client ca: %w", err)
		}
	}

	if p.TLSDownstreamClientCAFile != "" {
		log.Info().Msgf(clientCADeprecationMsg, "tls_downstream_client_ca_file")
		bs, err := os.ReadFile(p.TLSDownstreamClientCAFile)
		if err != nil {
			return fmt.Errorf("config: couldn't load downstream client ca: %w", err)
		}
		p.TLSDownstreamClientCA = base64.StdEncoding.EncodeToString(bs)
	}

	if p.KubernetesServiceAccountTokenFile != "" && p.KubernetesServiceAccountToken != "" {
		return fmt.Errorf("config: specified both `kubernetes_service_account_token_file` and `kubernetes_service_account_token`")
	}

	if p.PrefixRewrite != "" && p.RegexRewritePattern != "" {
		return fmt.Errorf("config: only prefix_rewrite or regex_rewrite_pattern can be specified, but not both")
	}

	if p.Regex != "" {
		rawRE := p.Regex
		if !strings.HasPrefix(rawRE, "^") {
			rawRE = "^" + rawRE
		}
		if !strings.HasSuffix(rawRE, "$") {
			rawRE += "$"
		}
		p.compiledRegex, _ = regexp.Compile(rawRE)
	}

	if !p.JWTIssuerFormat.Valid() {
		return fmt.Errorf("config: unsupported jwt_issuer_format value %q", p.JWTIssuerFormat)
	}

	if len(p.DependsOn) > 5 {
		return fmt.Errorf("config: depends_on is limited to 5 additional redirect hosts, got %v", p.DependsOn)
	}
	for i, v := range p.DependsOn {
		if strings.Contains(v, "/") {
			u, err := url.Parse(v)
			if err == nil && u.Scheme != "" && u.Host != "" {
				p.DependsOn[i] = u.Host
			} else {
				return fmt.Errorf("config: unsupported depends_on value %q", p.DependsOn[i])
			}
		}
	}

	if p.MCP != nil && p.MCP.Server == nil && p.MCP.Client == nil {
		return fmt.Errorf("config: mcp must have either server or client set")
	}
	return nil
}

// Checksum returns the xxh3 hash for the policy.
func (p *Policy) Checksum() uint64 {
	return hashutil.MustHash(p)
}

// RouteID returns a unique identifier for a route.
//
// The following fields are used to compute the ID:
// - from
// - prefix
// - path
// - regex
// - to/redirect/response (whichever is set)
func (p *Policy) RouteID() (string, error) {
	if p.ID != "" {
		return p.ID, nil
	}

	return p.generateRouteID()
}

func (p *Policy) generateRouteID() (string, error) {
	// this function is in the hot path, try not to allocate too much memory here
	hash := hashutil.NewDigest()
	hash.WriteStringWithLen(p.From)
	hash.WriteStringWithLen(p.Prefix)
	hash.WriteStringWithLen(p.Path)
	hash.WriteStringWithLen(p.Regex)
	switch {
	case len(p.To) > 0:
		_, _ = hash.Write([]byte{1}) // case 1
		hash.WriteInt32(int32(len(p.To)))
		for _, to := range p.To {
			hash.WriteStringWithLen(to.URL.Scheme)
			hash.WriteStringWithLen(to.URL.Opaque)
			if to.URL.User == nil {
				_, _ = hash.Write([]byte{0})
			} else {
				_, _ = hash.Write([]byte{1})
				hash.WriteStringWithLen(to.URL.User.Username())
				p, _ := to.URL.User.Password()
				hash.WriteStringWithLen(p)
			}
			hash.WriteStringWithLen(to.URL.Host)
			hash.WriteStringWithLen(to.URL.Path)
			hash.WriteStringWithLen(to.URL.RawPath)
			hash.WriteBool(to.URL.OmitHost)
			hash.WriteBool(to.URL.ForceQuery)
			hash.WriteStringWithLen(to.URL.Fragment)
			hash.WriteStringWithLen(to.URL.RawFragment)
			hash.WriteUint32(to.LbWeight)
		}
	case p.Redirect != nil:
		_, _ = hash.Write([]byte{2}) // case 2
		hash.WriteBoolPtr(p.Redirect.HTTPSRedirect)
		hash.WriteStringPtrWithLen(p.Redirect.SchemeRedirect)
		hash.WriteStringPtrWithLen(p.Redirect.HostRedirect)
		hash.WriteUint32Ptr(p.Redirect.PortRedirect)
		hash.WriteStringPtrWithLen(p.Redirect.PathRedirect)
		hash.WriteStringPtrWithLen(p.Redirect.PrefixRewrite)
		hash.WriteInt32Ptr(p.Redirect.ResponseCode)
		hash.WriteBoolPtr(p.Redirect.StripQuery)
	case p.Response != nil:
		_, _ = hash.Write([]byte{3}) // case 3
		hash.WriteInt32(int32(p.Response.Status))
		hash.WriteStringWithLen(p.Response.Body)
	default:
		return "", errEitherToOrRedirectOrResponseRequired
	}

	return hex.EncodeToString(hash.Sum(nil)), nil
}

func (p *Policy) MustRouteID() string {
	id, err := p.RouteID()
	if err != nil {
		panic(err)
	}
	return id
}

func (p *Policy) String() string {
	to := "?"
	if len(p.To) > 0 {
		var dsts []string
		for _, dst := range p.To {
			dsts = append(dsts, dst.URL.String())
		}
		to = strings.Join(dsts, ",")
	}

	return fmt.Sprintf("%s → %s", p.From, to)
}

// Matches returns true if the policy would match the given URL.
func (p *Policy) Matches(requestURL *url.URL, stripPort bool) bool {
	// an invalid from URL should not match anything
	fromURL, err := urlutil.ParseAndValidateURL(p.From)
	if err != nil {
		return false
	}

	if !FromURLMatchesRequestURL(fromURL, requestURL, stripPort) {
		return false
	}

	if p.Prefix != "" {
		if !strings.HasPrefix(requestURL.Path, p.Prefix) {
			return false
		}
	}

	if p.Path != "" {
		if requestURL.Path != p.Path {
			return false
		}
	}

	if p.compiledRegex != nil {
		if !p.compiledRegex.MatchString(requestURL.Path) {
			return false
		}
	}

	return true
}

// IsForKubernetes returns true if the policy is for kubernetes.
func (p *Policy) IsForKubernetes() bool {
	return p.KubernetesServiceAccountTokenFile != "" || p.KubernetesServiceAccountToken != ""
}

// IsMCPServer returns true if the route is for the Model Context Protocol upstream server.
func (p *Policy) IsMCPServer() bool {
	return p != nil && p.MCP != nil && p.MCP.Server != nil
}

// IsMCPClient returns true if the route is for the Model Context Protocol client application upstream.
func (p *Policy) IsMCPClient() bool {
	return p != nil && p.MCP != nil && p.MCP.Client != nil
}

// IsTCP returns true if the route is for TCP.
func (p *Policy) IsTCP() bool {
	return strings.HasPrefix(p.From, "tcp")
}

// IsTCPUpstream returns true if the route has a TCP upstream (To) URL
func (p *Policy) IsTCPUpstream() bool {
	return len(p.To) > 0 && p.To[0].URL.Scheme == "tcp"
}

// IsUDP returns true if the route is for UDP.
func (p *Policy) IsUDP() bool {
	return strings.HasPrefix(p.From, "udp")
}

// IsUDPUpstream returns true if the route has a UDP upstream (To) URL
func (p *Policy) IsUDPUpstream() bool {
	return len(p.To) > 0 && p.To[0].URL.Scheme == "udp"
}

// IsSSH returns true if the route is for SSH.
func (p *Policy) IsSSH() bool {
	return strings.HasPrefix(p.From, "ssh://")
}

// AllAllowedDomains returns all the allowed domains.
func (p *Policy) AllAllowedDomains() []string {
	var ads []string
	ads = append(ads, p.AllowedDomains...)
	for _, sp := range p.SubPolicies {
		ads = append(ads, sp.AllowedDomains...)
	}
	return ads
}

// AllAllowedIDPClaims returns all the allowed IDP claims.
func (p *Policy) AllAllowedIDPClaims() []identity.FlattenedClaims {
	var aics []identity.FlattenedClaims
	if len(p.AllowedIDPClaims) > 0 {
		aics = append(aics, p.AllowedIDPClaims)
	}
	for _, sp := range p.SubPolicies {
		if len(sp.AllowedIDPClaims) > 0 {
			aics = append(aics, sp.AllowedIDPClaims)
		}
	}
	return aics
}

// AllAllowedUsers returns all the allowed users.
func (p *Policy) AllAllowedUsers() []string {
	var aus []string
	aus = append(aus, p.AllowedUsers...)
	for _, sp := range p.SubPolicies {
		aus = append(aus, sp.AllowedUsers...)
	}
	return aus
}

// GetKubernetesServiceAccountToken gets the kubernetes service account token from a file or from the config option.
func (p *Policy) GetKubernetesServiceAccountToken() (string, error) {
	if p.KubernetesServiceAccountTokenFile != "" {
		bs, err := os.ReadFile(p.KubernetesServiceAccountTokenFile)
		return string(bs), err
	}

	if p.KubernetesServiceAccountToken != "" {
		return p.KubernetesServiceAccountToken, nil
	}

	return "", nil
}

// GetPassIdentityHeaders gets the pass identity headers option. If not set in the policy, use the setting from the
// options. If not set in either, return false.
func (p *Policy) GetPassIdentityHeaders(options *Options) bool {
	if p != nil && p.PassIdentityHeaders != nil {
		return *p.PassIdentityHeaders
	}

	if options != nil && options.PassIdentityHeaders != nil {
		return *options.PassIdentityHeaders
	}

	return false
}

// GetFrom gets the from URL.
func (p *Policy) GetFrom() string {
	return p.From
}

// GetPath gets the path.
func (p *Policy) GetPath() string {
	return p.Path
}

// GetPrefix gets the prefix.
func (p *Policy) GetPrefix() string {
	return p.Prefix
}

// GetRegex gets the regex.
func (p *Policy) GetRegex() string {
	return p.Regex
}

/*
SortPolicies sorts policies to match the following SQL order:

	  ORDER BY from ASC,
		path DESC NULLS LAST,
		regex_priority_order DESC NULLS LAST,
		regex DESC NULLS LAST
		prefix DESC NULLS LAST,
		id ASC
*/
func SortPolicies(pp []Policy) {
	sort.SliceStable(pp, func(i, j int) bool {
		strDesc := func(a, b string) (val bool, equal bool) {
			return a > b, a == b
		}

		strAsc := func(a, b string) (val bool, equal bool) {
			return a < b, a == b
		}

		intPDesc := func(a, b *int64) (val bool, equal bool) {
			if a == nil && b == nil {
				return false, true
			}
			if a == nil && b != nil {
				return false, false
			}
			if a != nil && b == nil {
				return true, false
			}
			return *a > *b, *a == *b
		}

		if val, equal := strAsc(pp[i].From, pp[j].From); !equal {
			return val
		}

		if val, equal := strDesc(pp[i].Path, pp[j].Path); !equal {
			return val
		}

		if val, equal := intPDesc(pp[i].RegexPriorityOrder, pp[j].RegexPriorityOrder); !equal {
			return val
		}

		if val, equal := strDesc(pp[i].Regex, pp[j].Regex); !equal {
			return val
		}

		if val, equal := strDesc(pp[i].Prefix, pp[j].Prefix); !equal {
			return val
		}

		return pp[i].ID < pp[j].ID // Ascending order for ID
	})
}
