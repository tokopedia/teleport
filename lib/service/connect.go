package service

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/pprof"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/lib/auth"
	"github.com/gravitational/teleport/lib/auth/native"
	"github.com/gravitational/teleport/lib/backend"
	"github.com/gravitational/teleport/lib/backend/boltbk"
	"github.com/gravitational/teleport/lib/backend/dir"
	"github.com/gravitational/teleport/lib/backend/dynamo"
	"github.com/gravitational/teleport/lib/backend/etcdbk"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/events"
	"github.com/gravitational/teleport/lib/events/dynamoevents"
	"github.com/gravitational/teleport/lib/events/filesessions"
	"github.com/gravitational/teleport/lib/events/s3sessions"
	"github.com/gravitational/teleport/lib/limiter"
	"github.com/gravitational/teleport/lib/multiplexer"
	"github.com/gravitational/teleport/lib/reversetunnel"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/session"
	"github.com/gravitational/teleport/lib/srv/regular"
	"github.com/gravitational/teleport/lib/state"
	"github.com/gravitational/teleport/lib/system"
	"github.com/gravitational/teleport/lib/utils"
	"github.com/gravitational/teleport/lib/web"
	"github.com/gravitational/trace"

	"github.com/gravitational/roundtrip"
	"github.com/jonboulle/clockwork"
	"github.com/pborman/uuid"
	"github.com/sirupsen/logrus"
)

// connectToAuthService attempts to login into the auth servers specified in the
// configuration. Returns 'true' if successful
func (process *TeleportProcess) connectToAuthService(role teleport.Role) (*Connector, error) {
	connector, err := process.connect(role)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	process.addConnector(connector)
	return connector, nil
}

func (process *TeleportProcess) connect(role teleport.Role) (*Connector, error) {
	identity, err := process.GetIdentity(role)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	additionalPrincipals, err := process.getAdditionalPrincipals(role)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	state, err := process.storage.GetState(role)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	rotation := state.Rotation

	switch rotation.State {
	// rotation is on standby, so just use whatever re
	case "", state.RotationStateStandby:
		log.Infof("Connecting to the cluster %v with TLS client certificate.", identity.ClusterName)
		client, err := newClient(process.Config.AuthServers, identity)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		// check if need to re-register to get certificate with new principals
		if len(additionalPrincipals) != 0 && !identity.HasPrincipals(additionalPrincipals) {
			log.Infof("Identity %v needs principals %v, going to re-register.", identity.ID, additionalPrincipals)
			identity, err = auth.ReRegister(process.Config.DataDir, client, identity.ID, additionalPrincipals)
			if err != nil {
				return nil, trace.Wrap(err)
			}
			err := process.storage.WriteIdentity(auth.IdentityCurrent, identity)
			if err != nil {
				return nil, trace.Wrap(err)
			}
			client, err = newClient(process.Config.AuthServers, identity)
			if err != nil {
				return nil, trace.Wrap(err)
			}
		}
		return &Connector{Client: client, ClientIdentity: identity, ServerIdentity: identity}, nil
	case services.RotationStateInProgress:
		switch rotation.Phase {
		case services.RotationPhaseUpdateClients:
			// in this phase, clients should use updated credentials,
			// while servers should use old credentials to answer auth requests
			newIdentity, err := process.storage.ReadIdentity(auth.IdentityReplacement, role)
			if err != nil {
				return nil, trace.Wrap(err)
			}
			client, err := newClient(process.Config.AuthServers, newIdentity)
			if err != nil {
				return nil, trace.Wrap(err)
			}
			return &Connector{Client: client, ClientIdentity: newIdentity, ServerIdentity: identity}, nil
		case services.RotationPhaseUpdateServers:
			// in this phase, servers and clients are using new identity, but the
			// identity is still set up to trust the old certificate authority certificates
			newIdentity, err := process.storage.ReadIdentity(auth.IdentityReplacement, role)
			if err != nil {
				return nil, trace.Wrap(err)
			}
			client, err := newClient(process.Config.AuthServers, newIdentity)
			if err != nil {
				return nil, trace.Wrap(err)
			}
			return &Connector{Client: client, ClientIdentity: newIdentity, ServerIdentity: newIdentity}, nil
		case services.RotationPhaseRollback:
			// in rollback phase, clients and servers should switch back
			// to the old certificate authority-issued credentials,
			// but new certificate authority should be trusted
			// because not all clients can update at the same time
			client, err := newClient(process.Config.AuthServers, identity)
			if err != nil {
				return nil, trace.Wrap(err)
			}
			return &Connector{Client: client, ClientIdentity: identity, ServerIdentity: identity}, nil
		default:
			return nil, trace.BadParameter("unsupported rotation phase: %q", state)
		}
	default:
		return nil, trace.BadParameter("unsupported rotation state: %q", state.State)
	}
}

// periodicSyncRotationState checks rotation state periodically and
// takes action if necessary
func (process *TeleportProcess) periodicSyncRotationState() error {
	t := time.NewTicker(defaults.HighResPollingPeriod)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			needsReload, err := process.syncRotationState()
			if err != nil {
				log.Warningf("Failed to sync rotation state: %v", err)
			} else if needsReload {
				// TODO: set context?
				process.BroadcastEvent(Event{Name: TeleportReloadEvent})
				return nil
			}
		case <-process.Exiting():
			return nil
		}
	}
}

// syncRotationState compares cluster rotation state with local services state
// and performs rotation if necessary
func (process *TeleportProcess) syncRotationState() (bool, error) {
	var needsReload bool
	connectors := process.getConnectors()
	for _, conn := range connectors {
		reload, err := process.syncServiceRotationState(conn.ClientIdentity.ID, conn.Client)
		if err != nil {
			return false, trace.Wrap(err)
		}
		if reload {
			needsReload = true
		}
	}
	return needsReload, nil
}

// syncServiceRotationState syncs up rotation state for individual service (Auth, Proxy, Node) and
// if necessary, updates credentials. Returns true if the service will need to reload.
func (process *TeleportProcess) syncServiceRotationState(identityID auth.IdentityID, client auth.ClientI) (bool, error) {
	state, err := process.storage.GetState(role)
	if err != nil {
		return trace.Wrap(err)
	}

	// check if there is a need to re-register with new client credentials
	ca, err := client.GetCertAuthority(services.CertAuthID{
		DomainName: identity.ClusterName,
		Type:       services.HostCA,
	}, false)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return process.rotate(identityID, client, state.Rotation, ca.GetRotation())
}

// rotate is called to check if rotation should be triggered locally
func (process *TeleportProcess) rotate(id auth.IdentityID, client auth.ClientI, localState auth.StateV2, remote services.Rotation) (bool, error) {
	local := localState.Spec.Rotation
	if local.Matches(remote) {
		// nothing to do, local state and rotation state are in sync
		return false, nil
	}

	additionalPrincipals, err := process.getAdditionalPrincipals(id.Role)
	if err != nil {
		return trace.Wrap(err)
	}

	storage := process.storage

	const outOfSync = "%v and cluster rotation state (%v) is out of sync with local (%v). Clear local state and re-register this %v."

	// now, need to evaluate what is exact difference, there are
	// several supported scenarios, that this logic should handle
	switch remote.State {
	case "", services.RotationStateStandby:
		//		if local.State
	//	check current id here and in other places

	case services.RotationStateInProgress:
		switch remote.Phase {
		case services.RotationPhaseStandby:

		case services.RotationPhaseUpdateClients:
			// only allow transition in case if local rotation state is standby
			// so this server is in the "clean" state
			if local.State != services.RotationStateStandby {
				return trace.CompareFailed(outOfSync, role, remote, local, id.Role)
			}
			identity, err := auth.ReRegister(process.Config.DataDir, client, id, additionalPrincipals)
			if err != nil {
				return nil, trace.Wrap(err)
			}
			err = storage.WriteIdentity(auth.IdentityReplacement, identity)
			if err != nil {
				return trace.Wrap(err)
			}
			state.Spec.Rotation = remote
			err = storage.WriteState(id.Role, state)
			if err != nil {
				return trace.Wrap(err)
			}
		case services.RotationPhaseUpdateServers:
			// allow transition to this phase only if the previous
			// phase was UpdateClients - as this is a happy scenario
			// when all phases are traversed in succession
			if local.Phase != services.RotationPhaseUpdateClients && local.CurrentID != remote.CurrentID {
				return trace.CompareFailed(outOfSync, role, remote, local, id.Role)
			}
			state.Spec.Rotation = remote
			err = storage.WriteState(id.Role, state)
			if err != nil {
				return trace.Wrap(err)
			}
			// update of the servers requires reload of teleport process
			return true, nil
		case services.RotationPhaseRollback:
			// allow transition to this phase from any other local phase
			// because it will be widely used to recover cluster state to
			// the previously valid state
			// client will re-register to receive credentials signed by "old" CA
			identity, err := auth.ReRegister(process.Config.DataDir, client, id, additionalPrincipals)
			if err != nil {
				return nil, trace.Wrap(err)
			}
			err = storage.WriteIdentity(auth.IdentityCurrent, identity)
			if err != nil {
				return trace.Wrap(err)
			}
			state.Spec.Rotation = remote
			err = storage.WriteState(id.Role, state)
			if err != nil {
				return trace.Wrap(err)
			}
			return true, nil
		default:
			return false, trace.BadParameter("unsupported phase: %q", remote.Phase)
		}
	}
	return nil
}

func newClient(authServers []utils.NetAddr, identity *auth.Identity) (*auth.Client, error) {
	tlsConfig, err := newIdentity.TLSConfig()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return auth.NewTLSClient(process.Config.AuthServers, tlsConfig)
}
