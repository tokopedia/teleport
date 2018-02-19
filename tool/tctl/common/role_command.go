/*
Copyright 2015-2017 Gravitational, Inc.

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

package common

import (
	"fmt"
	"strings"
	"time"

	"github.com/gravitational/kingpin"
	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/lib/asciitable"
	"github.com/gravitational/teleport/lib/auth"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/service"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/trace"
)

// RoleCommand implements `tctl roles` set of commands
// It implements CLICommand interface
type RoleCommand struct {
	config        *service.Config
	name          string
	allowedLogins string
	nodeLabels    string
	roles         string
	identities    []string
	ttl           time.Duration

	roleAdd    *kingpin.CmdClause
	roleUpdate *kingpin.CmdClause
	roleList   *kingpin.CmdClause
	roleDelete *kingpin.CmdClause
}

// Initialize allows RoleCommand to plug itself into the CLI parser
func (u *RoleCommand) Initialize(app *kingpin.Application, config *service.Config) {
	u.config = config
	roles := app.Command("roles", "Manage role accounts")

	u.roleAdd = roles.Command("add", "Create a role")
	u.roleAdd.Arg("name", "Teleport role name").Required().StringVar(&u.name)
	u.roleAdd.Arg("local-logins", "Local UNIX user this role can log in").
		Required().StringVar(&u.allowedLogins)
	u.roleAdd.Arg("node-labels", "Node labels this role can log in").
		Required().StringVar(&u.nodeLabels)

	u.roleUpdate = roles.Command("update", "Update properties for existing role").Hidden()
	u.roleUpdate.Arg("login", "Teleport role login").Required().StringVar(&u.name)
	u.roleUpdate.Flag("set-roles", "Roles to assign to this role").
		Default("").StringVar(&u.roles)

	u.roleList = roles.Command("ls", "List all role accounts")

	u.roleDelete = roles.Command("rm", "Deletes role accounts").Alias("del")
	u.roleDelete.Arg("logins", "Comma-separated list of role logins to delete").
		Required().StringVar(&u.name)
}

// TryRun takes the CLI command as an argument (like "roles add") and executes it.
func (u *RoleCommand) TryRun(cmd string, client auth.ClientI) (match bool, err error) {
	switch cmd {
	case u.roleAdd.FullCommand():
		err = u.Add(client)
	case u.roleUpdate.FullCommand():
		err = u.Update(client)
	case u.roleList.FullCommand():
		err = u.List(client)
	case u.roleDelete.FullCommand():
		err = u.Delete(client)
	default:
		return false, nil
	}
	return true, trace.Wrap(err)
}

// Add creates a role.
func (u *RoleCommand) Add(client auth.ClientI) error {
	// check if role already exists or not
	existedRole, _ := client.GetRole(u.name)
	if existedRole != nil {
		fmt.Printf("Role %s already exists", u.name)
		return nil
	}
	nodeLabels := make(map[string]string, 0)
	for _, pair := range strings.Split(u.nodeLabels, " ") {
		k := strings.Split(pair, "=")[0]
		v := strings.Split(pair, "=")[1]
		nodeLabels[k] = v
	}

	role, _ := services.NewRole(
		u.name,
		services.RoleSpecV3{
			Options: services.RoleOptions{
				services.CertificateFormat: teleport.CertificateFormatStandard,
				services.MaxSessionTTL:     services.NewDuration(defaults.CertDuration),
				services.PortForwarding:    true,
				services.ForwardAgent:      true,
			},
			Allow: services.RoleConditions{
				Namespaces: []string{defaults.Namespace},
				NodeLabels: nodeLabels,
				Rules:      services.CopyRulesSlice(services.AdminUserRules),
			},
		},
	)
	role.SetLogins(services.Allow, strings.Split(u.allowedLogins, ","))
	err := client.UpsertRole(role, time.Minute)
	if err != nil {
		return err
	}

	fmt.Printf("Role '%s' has been created!\n", u.name)
	return nil
}

// Update updates existing role
func (u *RoleCommand) Update(client auth.ClientI) error {
	// role, err := client.GetUser(u.login)
	// if err != nil {
	// 	return trace.Wrap(err)
	// }
	// roles := strings.Split(u.roles, ",")
	// for _, role := range roles {
	// 	if _, err := client.GetRole(role); err != nil {
	// 		return trace.Wrap(err)
	// 	}
	// }
	// role.SetRoles(roles)
	// if err := client.UpsertUser(role); err != nil {
	// 	return trace.Wrap(err)
	// }
	// fmt.Printf("%v has been updated with roles %v\n", role.GetName(), strings.Join(role.GetRoles(), ","))
	return nil
}

// List prints all existing user accounts
func (u *RoleCommand) List(client auth.ClientI) error {
	roles, err := client.GetRoles()
	fmt.Printf("roles = %+v\n", roles)
	if err != nil {
		return trace.Wrap(err)
	}
	if len(roles) == 0 {
		fmt.Println("No roles found")
		return nil
	}

	t := asciitable.MakeTable([]string{"Role", "Allowed logins", "Node Labels"})
	for _, r := range roles {
		logins := r.GetLogins(services.Allow)
		labels := make([]string, 0)
		for k, v := range r.GetNodeLabels(services.Allow) {
			labels = append(labels, k+":"+v)
		}
		t.AddRow([]string{r.GetName(), strings.Join(logins, ","), strings.Join(labels, " ")})
	}
	fmt.Println(t.AsBuffer().String())
	return nil
}

// Delete deletes teleport role(s). Role Names are passed as a comma-separated
func (u *RoleCommand) Delete(client auth.ClientI) error {
	for _, l := range strings.Split(u.name, ",") {
		if err := client.DeleteRole(l); err != nil {
			return trace.Wrap(err)
		}
		fmt.Printf("Role '%v' has been deleted\n", l)
	}
	return nil
}
