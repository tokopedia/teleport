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
	"github.com/sirupsen/logrus"
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

// Types returns cert authority types requested to rotate
func (r *RotateRequest) Types() []services.CertAuthType {
	switch r.Type {
	case "":
		return []services.CertAuthType{services.HostCA, services.UserCA}
	case services.HostCA:
		return []services.CertAuthType{services.HostCA}
	case services.UserCA:
		return []services.CertAuthType{services.UserCA}
	}
	return nil
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

// RotateCertAuthority starts or restarts certificate rotation process
func (a *AuthServer) RotateCertAuthority(req RotateRequest) error {
	// TODO: For whatever reason rotation does not work on DynamoDB - get error.
	// TODO: For whatever reason cert rotation does not respect grace period.
	// TODO: What to do with local admin credentials in case of forced rotation?

	if err := req.CheckAndSetDefaults(); err != nil {
		return trace.Wrap(err)
	}
	clusterName := a.clusterName.GetClusterName()

	caTypes := req.Types()
	for _, caType := range caTypes {
		existing, err := a.GetCertAuthority(services.CertAuthID{
			Type:       caType,
			DomainName: clusterName,
		}, true)
		if err != nil {
			return trace.Wrap(err)
		}
		rotated, err := StartRotation(a.clock, existing, *req.GracePeriod)
		if err != nil {
			return trace.Wrap(err)
		}
		if err := a.CompareAndSwapCertAuthority(rotated, existing); err != nil {
			return trace.Wrap(err)
		}
		switch rotated.GetRotation().State {
		case services.RotationStateInProgress:
			log.WithFields(logrus.Fields{"type": caType}).Infof("Started graceful rotation - users and nodes will reload credentials.")
		case services.RotationStateStandby:
			log.WithFields(logrus.Fields{"type": caType}).Infof("Performed non-graceful rotation, existing users have to relogin and nodes have to re-register.")
		}
	}
	return nil
}

// completeRotation attempts to complete rotation, is safe to execute concurrently,
// as it is uses compare and swap operations.
func (a *AuthServer) completeRotation() error {
	clusterName := a.clusterName.GetClusterName()
	for _, caType := range []services.CertAuthType{services.HostCA, services.UserCA} {
		ca, err := a.GetCertAuthority(services.CertAuthID{
			Type:       caType,
			DomainName: clusterName,
		}, true)
		if err != nil {
			return trace.Wrap(err)
		}
		rotation := ca.GetRotation()
		// rotation is not in progress, there is nothing to do
		if rotation.State != services.RotationStateInProgress {
			continue
		}
		// too early to complete rotation
		log.WithFields(logrus.Fields{"type": caType}).Infof("BBB: start + grace period %v now: %v: %v", rotation.Started.Add(rotation.GracePeriod.Duration), a.clock.Now(), rotation.GracePeriod.Duration)
		if rotation.Started.Add(rotation.GracePeriod.Duration).After(a.clock.Now()) {
			continue
		}
		rotated, err := CompleteRotation(a.clock, ca)
		if err != nil {
			return trace.Wrap(err)
		}
		if err := a.CompareAndSwapCertAuthority(rotated, ca); err != nil {
			return trace.Wrap(err)
		}
		log.WithFields(logrus.Fields{"type": caType}).Infof("Completed rotation.")
	}
	return nil
}

// StartRotation starts certificate authority rotation
func StartRotation(clock clockwork.Clock, ca services.CertAuthority, gracePeriod time.Duration) (services.CertAuthority, error) {
	ca = ca.Clone()
	rotation := ca.GetRotation()

	id := uuid.New()

	// first part of the function generates credentials
	sshPrivPEM, sshPubPEM, err := native.GenerateKeyPair("")
	if err != nil {
		return nil, trace.Wrap(err)
	}

	keyPEM, certPEM, err := tlsca.GenerateSelfSignedCA(pkix.Name{
		CommonName:   ca.GetClusterName(),
		Organization: []string{ca.GetClusterName()},
	}, nil, defaults.CATTL)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	tlsKeyPair := &services.TLSKeyPair{
		Cert: certPEM,
		Key:  keyPEM,
	}

	// second part of the function rotates the certificate authority
	rotation.Started = clock.Now().UTC()
	rotation.GracePeriod = services.NewDuration(gracePeriod)
	rotation.CurrentID = id

	signingKeys := ca.GetSigningKeys()
	checkingKeys := ca.GetCheckingKeys()
	keyPairs := ca.GetTLSKeyPairs()

	switch {
	// drop old certificate authority without keeping it
	// as signing
	case gracePeriod == 0:
		signingKeys = [][]byte{sshPrivPEM}
		checkingKeys = [][]byte{sshPubPEM}
		keyPairs = []services.TLSKeyPair{*tlsKeyPair}
		// in case of force rotation, rotation has been started and completed
		// in the same step moving it to standby state
		rotation.State = services.RotationStateStandby
	case rotation.State != services.RotationStateInProgress:
		// rotation sets the first key to be the new key
		// and keep only public keys/certs for the new CA
		signingKeys = [][]byte{sshPrivPEM}
		checkingKeys = [][]byte{sshPubPEM, checkingKeys[0]}
		oldKeyPair := keyPairs[0]
		oldKeyPair.Key = nil
		keyPairs = []services.TLSKeyPair{*tlsKeyPair, oldKeyPair}
		rotation.State = services.RotationStateInProgress
	default:
		// when rotate is called on the CA being rotated,
		// the new CA gets overriden, but old CA public keys are being kept
		// so the effect is "cancelling" the previous operation
		// and overriding it with a new one
		signingKeys = [][]byte{sshPrivPEM}
		checkingKeys[0] = sshPubPEM
		keyPairs[0] = *tlsKeyPair
		rotation.State = services.RotationStateInProgress
	}

	ca.SetSigningKeys(signingKeys)
	ca.SetCheckingKeys(checkingKeys)
	ca.SetTLSKeyPairs(keyPairs)
	ca.SetRotation(rotation)
	return ca, nil
}

// CompleteRotation completes certificate authority rotation
func CompleteRotation(clock clockwork.Clock, ca services.CertAuthority) (services.CertAuthority, error) {
	rotation := ca.GetRotation()
	if rotation.State != services.RotationStateInProgress {
		return nil, trace.BadParameter("certificate authority is not being rotated")
	}
	ca = ca.Clone()
	signingKeys := ca.GetSigningKeys()
	checkingKeys := ca.GetCheckingKeys()
	keyPairs := ca.GetTLSKeyPairs()

	signingKeys = signingKeys[:1]
	checkingKeys = checkingKeys[:1]
	keyPairs = keyPairs[:1]

	rotation.State = services.RotationStateStandby
	rotation.CurrentID = ""
	rotation.LastRotated = clock.Now()

	ca.SetSigningKeys(signingKeys)
	ca.SetCheckingKeys(checkingKeys)
	ca.SetTLSKeyPairs(keyPairs)
	ca.SetRotation(rotation)
	return ca, nil
}
