# CICD using Github Actions

## Secrets
- Can be accessed from [Settings -> Secrets](https://github.com/gdcorp-infosec/threat-api/settings/secrets/actions)
    - Needs admin access to create/ remove Secrets
    - Anyone with collaborator access to this repository can use these secrets for Actions
    - Secrets are not passed to workflows that are triggered by a pull request from a fork
    - [Github Docs](https://docs.github.com/en/actions/reference/encrypted-secrets) for more

- Github account `SVCOJtJzC2BlV1MvD-godaddy` is a Jomax service account targetted to be used for addition of secrets
    - `github.com` password for this username can be retrieved from AWS Secrets Manager
    - Created from the service account `SVCOJtJzC2BlV1MvD` with email address `SVCOJtJzC2BlV1MvD@godaddy.com` whose credentials can be retrieved from CyberArk
    - Part of `gdcorp-infosec` and `gdcorp-cp` organisations
    - PAT `threat-repo-github-actions ` defined for usage with GitHub API, authorised by  `gdcorp-infosec` and `gdcorp-cp`. Secret value is available through AWS Secrets Manager for team's access
    - SSH key pair `GITHUBCLOUD_SSH_PRIVATE_KEY` is attached and authorised by this account to clone private repositories with Go and from `github.com`. Secret value pair is available through AWS Secrets Manager with the same name for the team's access

- `025f610c17f9ecm` is a DC1 Service account to handle connections with `github.secureserver.net`
    - Secrets for DC1 can be accessed via OpenStack
    - `GITHUB_ACTIONS_GHC_SA` SSH key pair is linked with this account to handle repo clones from `github.secureserver.net`. The email address used for this key pair generation points to `SVCOJtJzC2BlV1MvD@godaddy.com`. Secret value pair is available through AWS Secrets Manager with the same name for the team's access


### Github Actions code
- All workflows `.yml` must be placed under `.github/workflows` directory
- `dependabot.yml` lives in `.github/` and creates a PR if any new SHA is found on dependencies

##### code-check.yml
- Triggers on every Pull Request made to `main` branch
- Runs Tartufo as the first check
- On success of Tartufo triggers jobs `python-code-check`,  `go-code-check`, `go-code-check-lambdas`
- `go-code-check` triggers for every module in `/apis`
- `go-code-check-lambdas` triggers for every infrastructure lambdas mentioned in the strategy matrix as shown below.

```yaml
go-code-check-lambdas:
    needs: tartufo
    runs-on: self-hosted

    strategy:
      matrix:
        go-lambdas: [manager] # Add golang infrastructure lambdas here
```
