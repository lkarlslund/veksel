//go:build noews

package main

import "github.com/lkarlslund/veksel/pkg/migration"

const ewsCompiled = false

func registerEWS(exchangeDependencies) error                  { return nil }
func registerEWSMigration(map[string]migration.SourceFactory) {}
