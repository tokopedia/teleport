/*
Copyright 2018 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package auth

import (
	"crypto/x509/pkix"
	"time"

	"github.com/gravitational/teleport/lib/auth/native"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/tlsca"

	"github.com/gravitational/trace"
	"github.com/jonboulle/clockwork"
	"github.com/pborman/uuid"
)

// RotateRequest is a request to start rotation of the certificate authority
type RotateRequest struct {
	// Type is certificate authority type, if omitted, both will be rotated
	Type services.CertAuthType `json:"type"`
	// GracePeriod is optional grace period, if omitted, default is set,
	// if 0 is supplied, means force rotate all certificate authorities
	// right away.
	GracePeriod *time.Duration `json:"grace_period,omitempty"`
}

// CheckAndSetDefaults checks and sets defaults
func (r *RotateRequest) CheckAndSetDefaults() error {
	switch r.Type {
	case "", services.HostCA, services.UserCA:
	default:
		return trace.BadParameter("unsupported certificate authority type: %q", r.Type)
	}
	if r.GracePeriod == nil {
		period := defaults.RotationGracePeriod
		r.GracePeriod = &period
	}
	return nil
}

// Rotate starts or updates certificate rotation
func (s *AuthServer) Rotate(req RotateRequest) error {
	if err := req.CheckAndSetDefaults(); err != nil {
		return trace.Wrap(err)
	}
	clusterName := a.clusterName.GetClusterName()

	s.GetCertAuthority()
}

// StartRotation starts certificate authority rotation
func StartRotation(clock clockwork.Clock, ca services.CertAuthority, gracePeriod time.Duration) error {
	log.Infof("Start rotation of %v", ca.GetName())
	rotation := ca.GetRotation()

	id := uuid.New()

	// first part of the function generates credentials
	sshPrivPEM, sshPubPEM, err := native.GenerateKeyPair("")
	if err != nil {
		return trace.Wrap(err)
	}

	var tlsKeyPair *services.TLSKeyPair
	if ca.GetType() == services.HostCA {
		keyPEM, certPEM, err := tlsca.GenerateSelfSignedCA(pkix.Name{
			CommonName:   ca.GetClusterName(),
			Organization: []string{ca.GetClusterName()},
		}, nil, defaults.CATTL)
		if err != nil {
			return trace.Wrap(err)
		}
		tlsKeyPair = &services.TLSKeyPair{
			Cert: certPEM,
			Key:  keyPEM,
		}
	}

	// second part of the function rotates the certificate authority
	rotation.Started = clock.Now().UTC()
	rotation.CurrentID = id
	rotation.State = services.RotationStateInProgress

	signingKeys := ca.GetSigningKeys()
	checkingKeys := ca.GetCheckingKeys()
	keyPairs := ca.GetTLSKeyPairs()

	switch {
	// drop old certificate authority without keeping it
	// as signing
	case gracePeriod == 0:
		signingKeys = [][]byte{sshPrivPEM}
		checkingKeys = [][]byte{sshPubPEM}
		if ca.GetType() == services.HostCA {
			keyPairs = []services.TLSKeyPair{*tlsKeyPair}
		}
	case rotation.State != services.RotationStateInProgress:
		// rotation sets the first key to be the new key
		// and keep only public keys/certs for the new CA
		signingKeys = [][]byte{sshPrivPEM}
		checkingKeys = [][]byte{sshPubPEM, checkingKeys[0]}
		if ca.GetType() == services.HostCA {
			oldKeyPair := keyPairs[0]
			oldKeyPair.Key = nil
			keyPairs = []services.TLSKeyPair{*tlsKeyPair, oldKeyPair}
		}
	default:
		// when rotate is called on the CA being rotated,
		// the new CA gets overriden, but old CA public keys are being kept
		// so the effect is "cancelling" the previous operation
		// and overriding it with a new one
		signingKeys = [][]byte{sshPrivPEM}
		checkingKeys[0] = sshPubPEM
		if ca.GetType() == services.HostCA {
			keyPairs[0] = *tlsKeyPair
		}
	}

	ca.SetSigningKeys(signingKeys)
	ca.SetCheckingKeys(checkingKeys)
	ca.SetTLSKeyPairs(keyPairs)
	ca.SetRotation(rotation)
	return nil
}

// EndRotation ends certificate authority rotation
func EndRotation(clock clockwork.Clock, ca services.CertAuthority) error {
	rotation := ca.GetRotation()
	if rotation.State != services.RotationStateInProgress {
		return trace.BadParameter("certificate authority is not being rotated")
	}
	signingKeys := ca.GetSigningKeys()
	checkingKeys := ca.GetCheckingKeys()
	keyPairs := ca.GetTLSKeyPairs()

	signingKeys = signingKeys[:1]
	checkingKeys = checkingKeys[:1]
	if ca.GetType() == services.HostCA {
		keyPairs = keyPairs[:1]
	}

	rotation.State = services.RotationStateStandby
	rotation.CurrentID = ""
	rotation.LastRotated = clock.Now()

	ca.SetSigningKeys(signingKeys)
	ca.SetCheckingKeys(checkingKeys)
	ca.SetTLSKeyPairs(keyPairs)
	ca.SetRotation(rotation)
	return nil
}
