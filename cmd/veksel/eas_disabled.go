//go:build noeas

package main

import "github.com/lkarlslund/veksel/pkg/migration"

const easCompiled = false

func registerEAS(exchangeDependencies) error                  { return nil }
func registerEASMigration(map[string]migration.SourceFactory) {}
