### Standards / Best Practices

The Threat API repository uses the [git-flow](https://nvie.com/posts/a-successful-git-branching-model/) branching model. There are two branches
that should always be present, `main` and `develop`. The code in the `main` branch should always build successfully. Releases/tags are made off of this
`main` branch. The `develop` branch is where new features should be added. At the time of a release, the `develop` branch is merged back into the `main`
branch.

All branches should be named according to this convention:
* The branch name should always begin with `hotfix`, `bug`, or `feature`.
    * `hotfix` is for critical bugs found in production. A `hotfix` can be branched off of `main`, but must be merged into both `main` and `develop`.
    * `bug` is a non-critical bug addressed in a JIRA ticket. A `bug` should be branched off of `develop`.
    * `feature` addresses all other changes/additions and should be branched off of `develop`.
* Next is a forward slash divider.
* Finally, the human-readable portion of the branch name that is all in lowercase with dashes separating words.

As an example, a story for adding a new field to a module could have a branch name like, `feature/module-add-ssdeep-field`.


### Developer resources
* Development of the ThreatTools API will follow the [CTO
  Guidelines](https://github.secureserver.net/CTO/guidelines/blob/master/Standards-Best-Practices/MustHaveShouldDo.md)
  for applications that are onboarding to AWS.  Alternative formatted document
  is
  [here](https://confluence.godaddy.com/display/AS/Phase+3+-+Must+Haves+to+go+to+Public+cloud).

* [GoDaddy API Design Standards](https://github.secureserver.net/CTO/guidelines/tree/master/api-design)

* [Best practices for REST API design](https://stackoverflow.blog/2020/03/02/best-practices-for-rest-api-design/)

* [Asynchronous REST operations](https://restcookbook.com/Resources/asynchroneous-operations/)

* [Tracing Fields](https://www.elastic.co/guide/en/ecs/current/ecs-tracing.html)

* [Opentracing](https://opentracing.io/docs/overview/)

### Go tutorial Quicklinks

* Highly recommend the [Tour of Go](https://tour.golang.org/list)

* Package docs for some commonly used packages - http, net, json, context

    Eg, [net/http](https://pkg.go.dev/net/http)

* Understand how contexts work in Go
    * http://p.agnihotry.com/post/understanding_the_context_package_in_golang/
    * https://medium.com/codex/go-context-101-ebfaf655fa95

* [Effective Go](https://golang.org/doc/effective_go)

* [Official docs](https://golang.org/doc/)

* [Practical Go](https://dave.cheney.net/practical-go/presentations/qcon-china.html)

* Get used to your choice of IDE!
    - Goland by Jetbrains (if you need software license contact GetHelp)
    - VSCode (Free of cost, just download and start using)
