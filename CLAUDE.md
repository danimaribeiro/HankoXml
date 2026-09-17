# CLAUDE.md

## Workflow

- Never push straight to `main`. Work on a branch, open a PR, wait for CI to go
  green, then merge it.
- Locally, run only the specs for the code you touched
  (`bundle exec rspec spec/path/to_spec.rb`, plus `bundle exec rubocop` on changed
  files). Leave the full suite and the OS/Ruby matrix to CI.
- If CI fails, fix it on the same branch and wait for green again before merging.
