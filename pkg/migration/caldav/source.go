// Package caldav provides a CalDAV synchronization source.
package caldav

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/emersion/go-ical"
	"github.com/emersion/go-webdav"
	client "github.com/emersion/go-webdav/caldav"
	"github.com/lkarlslund/veksel/pkg/migration"
	"github.com/lkarlslund/veksel/pkg/model"
)

type Config struct {
	Endpoint   string
	Username   string
	Password   string
	HTTPClient *http.Client
	TLSConfig  *tls.Config
}

type Source struct {
	endpoint string
	username string
	client   *client.Client
	home     string
}

func New(cfg Config) (*Source, error) {
	u, err := url.Parse(strings.TrimSpace(cfg.Endpoint))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, errors.New("valid CalDAV endpoint is required")
	}
	if strings.TrimSpace(cfg.Username) == "" {
		return nil, errors.New("CalDAV username is required")
	}
	httpClient := cfg.HTTPClient
	if httpClient == nil {
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.TLSClientConfig = cfg.TLSConfig
		httpClient = &http.Client{Transport: transport, Timeout: 90 * time.Second}
	}
	authenticated := webdav.HTTPClientWithBasicAuth(httpClient, cfg.Username, cfg.Password)
	davClient, err := client.NewClient(authenticated, u.String())
	if err != nil {
		return nil, err
	}
	return &Source{endpoint: u.String(), username: cfg.Username, client: davClient, home: u.Path}, nil
}

func (s *Source) ID() string {
	return "caldav://" + s.username + "@" + strings.TrimPrefix(strings.TrimPrefix(s.endpoint, "https://"), "http://")
}
func (s *Source) Close() error           { return nil }
func (s *Source) FolderConcurrency() int { return 4 }

func (s *Source) Folders(ctx context.Context) ([]migration.Folder, error) {
	calendars, err := s.client.FindCalendars(ctx, s.home)
	if err != nil {
		return nil, err
	}
	result := make([]migration.Folder, 0, len(calendars))
	for _, calendar := range calendars {
		name := calendar.Name
		if name == "" {
			name = path.Base(strings.TrimSuffix(calendar.Path, "/"))
		}
		result = append(result, migration.Folder{ID: calendar.Path, Name: name, Type: model.FolderTypeCalendar})
	}
	return result, nil
}

func (s *Source) Inventory(ctx context.Context) ([]migration.Folder, error) {
	folders, err := s.Folders(ctx)
	if err != nil {
		return nil, err
	}
	for i := range folders {
		objects, queryErr := s.query(ctx, folders[i].ID)
		if queryErr != nil {
			return nil, queryErr
		}
		folders[i].Estimate, folders[i].EstimateKnown = int64(len(objects)), true
	}
	return folders, nil
}

func (s *Source) Items(ctx context.Context, folder migration.Folder, checkpoint string) (migration.Page, error) {
	prior := make(map[string]string)
	if checkpoint != "" {
		if err := json.Unmarshal([]byte(checkpoint), &prior); err != nil {
			return migration.Page{}, errors.New("invalid CalDAV checkpoint")
		}
	}
	objects, err := s.query(ctx, folder.ID)
	if err != nil {
		return migration.Page{}, err
	}
	next := make(map[string]string, len(objects))
	items := make([]migration.Item, 0, len(objects))
	for _, object := range objects {
		var data bytes.Buffer
		if object.Data == nil {
			continue
		}
		if err := ical.NewEncoder(&data).Encode(object.Data); err != nil {
			return migration.Page{}, err
		}
		version := strings.Trim(object.ETag, `"`)
		if version == "" {
			hash := sha256.Sum256(data.Bytes())
			version = hex.EncodeToString(hash[:])
		}
		next[object.Path] = version
		if prior[object.Path] == version {
			continue
		}
		items = append(items, migration.Item{ID: object.Path, Version: version, Name: path.Base(object.Path), Data: data.Bytes(), InternalDate: object.ModTime})
	}
	deletedIDs := make([]string, 0)
	for objectPath := range prior {
		if _, exists := next[objectPath]; !exists {
			deletedIDs = append(deletedIDs, objectPath)
		}
	}
	sort.Strings(deletedIDs)
	encoded, err := json.Marshal(next)
	if err != nil {
		return migration.Page{}, err
	}
	return migration.Page{Items: items, DeletedIDs: deletedIDs, Checkpoint: string(encoded), Done: true}, nil
}

func (s *Source) query(ctx context.Context, calendarPath string) ([]client.CalendarObject, error) {
	return s.client.QueryCalendar(ctx, calendarPath, &client.CalendarQuery{CompFilter: client.CompFilter{Name: "VCALENDAR"}})
}
