# Notes for agents

README.md's Contributing section holds the rules for every contributor. These add what only Vault's own work needs.

- xicap is a brick of Vault (`ffxi-dev/vault`). CI calls Vault's shared workflows; change CI logic there. A change that
  spans bricks starts as an OpenSpec change in `ffxi-dev/vault`.
- Mogsafe, Memoria, Scholar, Theater, and Lens depend on xicap. Read how they use an API before changing it.
- Prose (docs, comments, commit messages) follows the writing rules in `ffxi-dev/vault`'s AGENTS.md.
- Run clang-format on C++ you touch.
