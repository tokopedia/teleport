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
	// TargetPhase sets desired rotation phase to move to, if not set
	// will be set automatically, is a required argument
	// for manual rotation.
	TargetPhase string `json:"target_phase,omitempty"`
	// Mode sets manual mode with manually updated phases,
	// otherwise phases are set automatically
	Mode string `json:"mode"`
	// clock is set by the auth server internally
	clock clockwork.Clock
	// ca is a certificate authority to rotate, set by the auth server internally
	ca services.CertAuthority
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
	if r.TargetPhase == "" {
		// if phase if not set, imply that the first meaningful phase
		// is set as a target phase
		r.TargetPhase = services.RotationPhaseUpdateClients
	}
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
	// TODO: For whatever reason rotation does not work on DynamoDB - getting error.
	if err := req.CheckAndSetDefaults(); err != nil {
		return trace.Wrap(err)
	}
	req.clock = a.clock
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
		req.ca = existing
		rotated, err := processRotationRequest(req)
		if err != nil {
			return trace.Wrap(err)
		}
		if err := a.CompareAndSwapCertAuthority(rotated, existing); err != nil {
			return trace.Wrap(err)
		}
		rotation := rotated.GetRotation()
		switch rotation.State {
		case services.RotationStateInProgress:
			log.WithFields(logrus.Fields{"type": caType}).Infof("Rotation is in progress, current phase: %q.", rotation.Phase)
		case services.RotationStateStandby:
			log.WithFields(logrus.Fields{"type": caType}).Infof("Performed non-graceful rotation, existing users have to relogin and nodes have to re-register.")
		}
	}
	return nil
}

// completeRotation attempts to complete rotation, is safe to execute concurrently,
// as it is uses compare and swap operations.
func (a *AuthServer) completeRotation() error {
	return nil
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
		/*
				rotated, err := CompleteRotation(a.clock, ca)
				if err != nil {
					return trace.Wrap(err)
				}
			if err := a.CompareAndSwapCertAuthority(rotated, ca); err != nil {
				return trace.Wrap(err)
			}
			log.WithFields(logrus.Fields{"type": caType}).Infof("Completed rotation.")
		*/
	}
	return nil
}

// processRotationRequest processes rotation request FSM-style
// switches Phase and State
func processRotationRequest(req RotateRequest) (services.CertAuthority, error) {
	rotation := req.ca.GetRotation()
	ca := req.ca.Clone()

	switch req.TargetPhase {
	// this is the first stage of the rotation - new certificate authorities
	// are being generated and
	case services.RotationPhaseUpdateClients:
		switch rotation.State {
		case services.RotationStateStandby, "":
		default:
			return nil, trace.BadParameter("can not create new rotation phase")
		}
		if err := startNewRotation(req.clock, ca, *req.GracePeriod); err != nil {
			return nil, trace.Wrap(err)
		}
		return ca, nil
	case services.RotationPhaseUpdateServers:
		// this is simply update of the phase to signal nodes to restart
		// and start serving new signatures
		rotation.Phase = req.TargetPhase
		ca.SetRotation(rotation)
		return ca, nil
	case services.RotationPhaseRollback:
		switch rotation.Phase {
		case services.RotationPhaseUpdateClients, services.RotationPhaseUpdateServers:
			if err := startRollingBackRotation(ca); err != nil {
				return nil, trace.Wrap(err)
			}
			return ca, nil
		}
		// this is to complete rotation, moves overall rotation
		// to standby
	case services.RotationPhaseStandby:
		switch rotation.Phase {
		case services.RotationPhaseUpdateServers:
			if err := completeRotation(req.clock, ca); err != nil {
				return nil, trace.Wrap(err)
			}
			return ca, nil
		}
	default:
		return nil, trace.BadParameter("unsupported phase: %q", req.TargetPhase)
	}
	return nil, trace.BadParameter("internal error")
}

// startNewRotation starts new rotation and in place updates the certificate
// authority with new CA keys
func startNewRotation(clock clockwork.Clock, ca services.CertAuthority, gracePeriod time.Duration) error {
	rotation := ca.GetRotation()
	id := uuid.New()

	// first part of the function generates credentials
	sshPrivPEM, sshPubPEM, err := native.GenerateKeyPair("")
	if err != nil {
		return trace.Wrap(err)
	}

	keyPEM, certPEM, err := tlsca.GenerateSelfSignedCA(pkix.Name{
		CommonName:   ca.GetClusterName(),
		Organization: []string{ca.GetClusterName()},
	}, nil, defaults.CATTL)
	if err != nil {
		return trace.Wrap(err)
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

	// drop old certificate authority without keeping it as trusted
	if gracePeriod == 0 {
		signingKeys = [][]byte{sshPrivPEM}
		checkingKeys = [][]byte{sshPubPEM}
		keyPairs = []services.TLSKeyPair{*tlsKeyPair}
		// in case of force rotation, rotation has been started and completed
		// in the same step moving it to standby state
		rotation.State = services.RotationStateStandby
	} else {
		// rotation sets the first key to be the new key
		// and keep only public keys/certs for the new CA
		signingKeys = [][]byte{sshPrivPEM, signingKeys[0]}
		checkingKeys = [][]byte{sshPubPEM, checkingKeys[0]}
		oldKeyPair := keyPairs[0]
		keyPairs = []services.TLSKeyPair{*tlsKeyPair, oldKeyPair}
		rotation.State = services.RotationStateInProgress
		rotation.Phase = services.RotationPhaseUpdateClients
	}

	ca.SetSigningKeys(signingKeys)
	ca.SetCheckingKeys(checkingKeys)
	ca.SetTLSKeyPairs(keyPairs)
	ca.SetRotation(rotation)
	return nil
}

// startRollingBackRotation starts rolls back rotation to the previous state
func startRollingBackRotation(ca services.CertAuthority) error {
	rotation := ca.GetRotation()

	// second part of the function rotates the certificate authority
	signingKeys := ca.GetSigningKeys()
	checkingKeys := ca.GetCheckingKeys()
	keyPairs := ca.GetTLSKeyPairs()

	// rotation sets the first key to be the new key
	// and keep only public keys/certs for the new CA
	signingKeys = [][]byte{signingKeys[1]}
	checkingKeys = [][]byte{checkingKeys[1]}

	// here, keep the attempted key pair certificate as trusted
	// as during rollback phases, both types of clients may be present in the cluster
	keyPairs = []services.TLSKeyPair{keyPairs[1], TLSKeyPair{Cert: keyPairs[0].Cert}}
	rotation.State = services.RotationStateInProgress
	rotation.Phase = services.RotationPhaseRollback

	ca.SetSigningKeys(signingKeys)
	ca.SetCheckingKeys(checkingKeys)
	ca.SetTLSKeyPairs(keyPairs)
	ca.SetRotation(rotation)
	return nil
}

// completeRollingBackRotation completes rollback of the rotation
// sets it to the standby state
func completeRollingBackRotation(clock clockwork.Clock, ca services.CertAuthority) error {
	rotation := ca.GetRotation()

	// second part of the function rotates the certificate authority
	rotation.Started = time.Time{}
	rotation.CurrentID = ""
	rotation.State = services.RotationStateStandby
	rotation.Phase = services.RotationPhaseStandby

	keyPairs := ca.GetTLSKeyPairs()
	// only keep the original certificate authority as trusted
	// and remove all extra
	keyPairs = []services.TLSKeyPair{keyPairs[0]}

	ca.SetTLSKeyPairs(keyPairs)
	ca.SetRotation(rotation)
	return nil
}

// completeRotation completes certificate authority rotation
func completeRotation(clock clockwork.Clock, ca services.CertAuthority) error {
	rotation := ca.GetRotation()
	signingKeys := ca.GetSigningKeys()
	checkingKeys := ca.GetCheckingKeys()
	keyPairs := ca.GetTLSKeyPairs()

	signingKeys = signingKeys[:1]
	checkingKeys = checkingKeys[:1]
	keyPairs = keyPairs[:1]

	rotation.Started = time.Time{}
	rotation.CurrentID = ""
	rotation.State = services.RotationStateStandby
	rotation.Phase = services.RotationPhaseStandby
	rotation.LastRotated = clock.Now()

	ca.SetSigningKeys(signingKeys)
	ca.SetCheckingKeys(checkingKeys)
	ca.SetTLSKeyPairs(keyPairs)
	ca.SetRotation(rotation)
	return nil
}
