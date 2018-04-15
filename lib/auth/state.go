package auth

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/lib/backend"
	"github.com/gravitational/teleport/lib/backend/dir"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/utils"

	"github.com/gravitational/trace"
)

// ProcessStorage is a special local process state backend
// helps to manage rotation for certificate authorities
// and process-local state management
type ProcessStorage struct {
	b backend.Backend
}

func NewProcessStorage(path string) (*ProcessStorage, error) {
	if path == "" {
		return nil, trace.BadParameter("missing parameter state")
	}
	backend, err := dir.New(backend.Params{"path": path})
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return &ProcessStorage{b: backend}, nil
}

func (p *ProcessStorage) Close() error {
	return p.b.Close()
}

const (
	// IdentityNameCurrent current is for the identity that is currently used
	IdentityCurrent = "current"
	// IdentityReplacement replacement is the identity that is replacing current
	IdentityReplacement = "replacement"
)

// stateName is a shared common state resource name used internally
const stateName = "state"

// GetState reads rotation state
func (p *ProcessStorage) GetState(role teleport.Role) (*StateV2, error) {
	data, err := p.b.GetVal([]string{"states", strings.ToLower(role.String())}, stateName)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	var res StateV2
	if err := utils.UnmarshalWithSchema(GetStateSchema(), &res, data); err != nil {
		return nil, trace.BadParameter(err.Error())
	}
	return &res, nil
}

// CreateState creates process state if it does not exist yet
func (p *ProcessStorage) CreateState(role teleport.Role, state StateV2) error {
	if err := state.CheckAndSetDefaults(); err != nil {
		return trace.Wrap(err)
	}
	data, err := json.Marshal(state)
	if err != nil {
		return trace.Wrap(err)
	}
	err = p.b.CreateVal([]string{"states", strings.ToLower(role.String())}, stateName, data, backend.Forever)
	if err != nil {
		return trace.Wrap(err)
	}
	return nil
}

// WriteState writes local cluster state
func (p *ProcessStorage) WriteState(role teleport.Role, state StateV2) error {
	if err := state.CheckAndSetDefaults(); err != nil {
		return trace.Wrap(err)
	}
	data, err := json.Marshal(state)
	if err != nil {
		return trace.Wrap(err)
	}
	err = p.b.UpsertVal([]string{"states", strings.ToLower(role.String())}, stateName, data, backend.Forever)
	if err != nil {
		return trace.Wrap(err)
	}
	return nil
}

// ReadIdentity reads identity using identity name and role
func (p *ProcessStorage) ReadIdentity(name string, role teleport.Role) (*Identity, error) {
	if name == "" {
		return nil, trace.BadParameter("missing parameter name")
	}
	data, err := p.b.GetVal([]string{"ids", strings.ToLower(role.String())}, name)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	var res IdentityV2
	if err := utils.UnmarshalWithSchema(GetIdentitySchema(), &res, data); err != nil {
		return nil, trace.BadParameter(err.Error())
	}
	return ReadIdentityFromKeyPair(res.Spec.Key, res.Spec.SSHCert, res.Spec.TLSCert, res.Spec.TLSCACerts)
}

// WriteIdentity writes identity to the local storage
func (p *ProcessStorage) WriteIdentity(name string, id Identity) error {
	res := IdentityV2{
		ResourceHeader: services.ResourceHeader{
			Kind:    services.KindIdentity,
			Version: services.V2,
			Metadata: services.Metadata{
				Name: name,
			},
		},
		Spec: IdentitySpecV2{
			Key:        id.KeyBytes,
			SSHCert:    id.CertBytes,
			TLSCert:    id.TLSCertBytes,
			TLSCACerts: id.TLSCACertsBytes,
		},
	}
	if err := res.CheckAndSetDefaults(); err != nil {
		return trace.Wrap(err)
	}
	data, err := json.Marshal(res)
	if err != nil {
		return trace.Wrap(err)
	}
	return p.b.UpsertVal([]string{"ids", strings.ToLower(id.ID.Role.String())}, name, data, backend.Forever)
}

// StateV2 is a local disk state
type StateV2 struct {
	services.ResourceHeader
	Spec StateSpecV2 `json:"spec"`
}

// CheckAndSetDefaults checks and sets defaults value for state
func (s *StateV2) CheckAndSetDefaults() error {
	s.Kind = services.KindState
	s.Version = services.V2
	// for state resource name does not matter
	if s.Metadata.Name == "" {
		s.Metadata.Name = stateName
	}
	if err := s.Metadata.CheckAndSetDefaults(); err != nil {
		return trace.Wrap(err)
	}
	return nil
}

// StateSpecV2 is a state spec
type StateSpecV2 struct {
	Rotation services.Rotation `json:"rotation"`
}

// IdentityV2 specifies local host identity
type IdentityV2 struct {
	services.ResourceHeader
	Spec IdentitySpecV2 `json:"spec"`
}

// CheckAndSetDefaults checks and sets defaults value for identity
func (s *IdentityV2) CheckAndSetDefaults() error {
	s.Kind = services.KindIdentity
	s.Version = services.V2
	if err := s.Metadata.CheckAndSetDefaults(); err != nil {
		return trace.Wrap(err)
	}
	if len(s.Spec.Key) == 0 {
		return trace.BadParameter("missing parameter Key")
	}
	if len(s.Spec.SSHCert) == 0 {
		return trace.BadParameter("missing parameter SSHCert")
	}
	if len(s.Spec.TLSCert) == 0 {
		return trace.BadParameter("missing parameter TLSCert")
	}
	if len(s.Spec.TLSCACerts) == 0 {
		return trace.BadParameter("missing parameter TLSCACerts")
	}
	return nil
}

// IdentitySpecV2 is PEM encoded data with host identity
type IdentitySpecV2 struct {
	// Key is a PEM encoded private key
	Key []byte `json:"key,omitempty"`
	// SSHCert is a PEM encoded SSH host cert
	SSHCert []byte `json:"ssh_cert,omitempty"`
	// TLSCert is a PEM encoded TLS x509 client certificate
	TLSCert []byte `json:"tls_cert,omitempty"`
	// TLSCACert is a list of PEM encoded TLS x509 certificate of certificate authority
	// associated with auth server services
	TLSCACerts [][]byte `json:"tls_ca_certs,omitempty"`
}

// IdentitySpecV2Schema is a schema for identity spec
const IdentitySpecV2Schema = `{
  "type": "object",
  "additionalProperties": false,
  "required": ["key", "ssh_cert", "tls_cert", "tls_ca_certs"],
  "properties": {
    "key": {"type": "string"},
    "ssh_cert": {"type": "string"},
    "tls_cert": {"type": "string"},
    "tls_ca_certs": {
      "type": "array",
      "items": {"type": "string"}
    }
  }
}`

// GetIdentitySchema returns JSON Schema for cert authorities
func GetIdentitySchema() string {
	return fmt.Sprintf(services.V2SchemaTemplate, services.MetadataSchema, IdentitySpecV2Schema, services.DefaultDefinitions)
}

// StateSpecV2Schema is a schema for local server state
const StateSpecV2Schema = `{
  "type": "object",
  "additionalProperties": false,
  "required": ["rotation"],
  "properties": {
    "rotation": %v
  }
}`

// GetStateSchema returns JSON Schema for cert authorities
func GetStateSchema() string {
	return fmt.Sprintf(services.V2SchemaTemplate, services.MetadataSchema, fmt.Sprintf(StateSpecV2Schema, services.RotationSchema), services.DefaultDefinitions)
}
