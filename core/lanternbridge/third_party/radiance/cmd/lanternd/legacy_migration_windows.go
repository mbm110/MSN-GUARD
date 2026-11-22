package main

import (
	"context"
	"encoding/json"
	"path/filepath"
	"time"

	"github.com/getlantern/radiance/account"
	"github.com/getlantern/radiance/common/legacymigration"
	"github.com/getlantern/radiance/common/serviceowner"
	"github.com/getlantern/radiance/kindling"
	"golang.org/x/sys/windows"
)

func migrateLegacy(command *migrateCmd) error {
	environment := command.Environment
	if environment == "" {
		environment = daemonEnvironmentProd
	}
	if err := configureDaemonEnvironment(environment); err != nil {
		return err
	}
	_, proURL := daemonBackendURLs(environment)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	return legacymigration.Import(ctx, command.SID, command.Source, command.MigrationID, command.Request,
		func(ctx context.Context, request legacymigration.Request) (json.RawMessage, string, error) {
			programData, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, windows.KF_FLAG_DEFAULT)
			if err != nil {
				return nil, "", err
			}
			client, err := kindling.NewKindling(filepath.Join(programData, "Lantern"))
			if err != nil {
				return nil, "", err
			}
			defer client.Close()
			user, err := account.VerifyLegacyIdentity(ctx, client.NewHTTPClient(), proURL, request.UserID, request.Token, request.DeviceID)
			if err != nil {
				return nil, "", err
			}
			raw, err := json.Marshal(user)
			return raw, user.LegacyUserData.UserLevel, err
		}, serviceowner.Save)
}
