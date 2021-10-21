# Development Workflow

## Requirements
- Make sure your requirements are granular from JIRA with proper acceptance criteria
- If development is for a feature, make sure you have all the access to keys, API limits, third party library (if needed)
etc., all before starting the development

## Implement
- Create a branch following the [naming conventions](development-practices.md)
- If you are writing a new threat module in GoLang, you can use the [`create-templates.py`](../../tools/create-api-module-golang/create-templates.py) to get you the templates required
to write your code


  **(DISCLAIMER: This script is only to make the code less error prone and make the life of the developer easier.
  It's not a runnable ready code to completely trust upon. The developer is still expected to understand the codes
  to know what it does**)

- If you are making any architecture changes, make sure you run the [`generate_sceptre.py`](../../tools/generate_sceptre.py)
to make necessary changes to your sceptre files.
    - As a follow up, if you are planning on changing the sceptre files, make sure it's automated from the above script
- The sceptre files are needed for your infrastructure to be deployed, so make sure they are committed to your code base before triggering the deployment.


## Test features

- Once you are sure the code works in your local as expected, trigger a dev-private deployment to test
    - Since dev-private is not CICD controlled, you can expect a race condition with your teammates
      running/ testing code. Please make sure you are sure that no one is testing the code/ post in the
      team channel

- Test the features in AWS Dev-Private/ [Swagger](../../README.md) to make sure everything works good

- Check if you have completed all the pre-reqs from the [PR template](../../.github/pull_request_template.md)

- All set to create a PR for code review!

## Post code completion

- Create a PR to `develop` on the repository for review
  - If you are testing, convert the PR to draft and add necessary labels as available
- Check the required pre-reqs on the PR template before tagging any reviewers
- Tag reviewers and notify in the slack channel if it's urgent
- If there are requested changes, implement them and re-request review
- Once everything, check if your code is ready for AWS Dev (check in secrets in AWS Secrets Manager)
- Squash and Merge the PR (This ensures that we just have one single commit for your entire code)
- Check if everything works as intended in AWS Dev environment
- Delete you branch if everything works good

## Prod Release

- Create a PR from `develop` to `main`
- Check if all the code is ready for Prod release
- Transfer any secrets, certs, configurations needed for AWS Production
- After the code is reviewed from the reviewers, merge it to `main`
- Create a separate release with proper [semantic versioning](https://semver.org/)
- Add the features as Release notes
- Notify the users and add it in the infosec demo
