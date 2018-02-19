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
	login         string
	allowedLogins string
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

	u.roleAdd = roles.Command("add", "Generate a role invitation token")
	u.roleAdd.Arg("account", "Teleport role account name").Required().StringVar(&u.login)
	u.roleAdd.Arg("local-logins", "Local UNIX roles this account can log in as [login]").
		Default("").StringVar(&u.allowedLogins)
	u.roleAdd.Flag("ttl", fmt.Sprintf("Set expiration time for token, default is %v hour, maximum is %v hours",
		int(defaults.SignupTokenTTL/time.Hour), int(defaults.MaxSignupTokenTTL/time.Hour))).
		Default(fmt.Sprintf("%v", defaults.SignupTokenTTL)).DurationVar(&u.ttl)
	u.roleAdd.Alias(AddUserHelp)

	u.roleUpdate = roles.Command("update", "Update properties for existing role").Hidden()
	u.roleUpdate.Arg("login", "Teleport role login").Required().StringVar(&u.login)
	u.roleUpdate.Flag("set-roles", "Roles to assign to this role").
		Default("").StringVar(&u.roles)

	u.roleList = roles.Command("ls", "List all role accounts")

	u.roleDelete = roles.Command("rm", "Deletes role accounts").Alias("del")
	u.roleDelete.Arg("logins", "Comma-separated list of role logins to delete").
		Required().StringVar(&u.login)
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

// Add creates a new sign-up token and prints a token URL to stdout.
// A role is not created until he visits the sign-up URL and completes the process
func (u *RoleCommand) Add(client auth.ClientI) error {
	// if no local logins were specified, default to 'login'
	// if u.allowedLogins == "" {
	// 	u.allowedLogins = u.login
	// }
	// role := services.UserV1{
	// 	Name:          u.login,
	// 	AllowedLogins: strings.Split(u.allowedLogins, ","),
	// }
	// token, err := client.CreateSignupToken(role, u.ttl)
	// if err != nil {
	// 	return err
	// }

	// // try to auto-suggest the activation link
	// u.PrintSignupURL(client, token, u.ttl)
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
		t.AddRow([]string{r.GetName(), strings.Join(logins, ","), strings.Join(labels, ",")})
	}
	fmt.Println(t.AsBuffer().String())
	return nil
}

// Delete deletes teleport user(s). User IDs are passed as a comma-separated
// list in RoleCommand.login
func (u *RoleCommand) Delete(client auth.ClientI) error {
	// for _, l := range strings.Split(u.login, ",") {
	// 	if err := client.DeleteUser(l); err != nil {
	// 		return trace.Wrap(err)
	// 	}
	// 	fmt.Printf("User '%v' has been deleted\n", l)
	// }
	return nil
}
