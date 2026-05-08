// Package main is the entry point for the scafctl-plugin-auth-github plugin.
package main

import (
	"github.com/oakwood-commons/scafctl-plugin-auth-github/internal/github"

	sdkplugin "github.com/oakwood-commons/scafctl-plugin-sdk/plugin"
)

func main() {
	sdkplugin.ServeAuthHandler(&github.Plugin{})
}
