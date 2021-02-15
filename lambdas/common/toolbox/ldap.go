package toolbox

import (
	"os"

	"github.secureserver.net/threat/go-ldap"
)

// GetADGroupsLDAP will get the AD groups from the jomax AD server using the provided username.
// Note that you must have the LDAP_USERNAME and LDAP_PASSWORD env vars set.
func GetADGroupsLDAP(username string) ([]string, error) {
	// Connect to AD server
	// TODO: Get user/pass from somewhere
	c, err := ldap.New(os.Getenv("LDAP_USERNAME"), os.Getenv("LDAP_PASSWORD"), ldap.DC1Env)
	if err != nil {
		return nil, err
	}

	groups, err := c.GetUserGroups(username)
	if err != nil {
		return nil, err
	}

	// Return string list of groups from the groups DN (distinguished name)
	groupsStr := []string{}
	for _, group := range groups {
		groupsStr = append(groupsStr, group.DN)
	}

	return groupsStr, nil

}
