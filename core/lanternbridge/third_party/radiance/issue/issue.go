package issue

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"runtime"

	"github.com/getlantern/osversion"
	"go.opentelemetry.io/otel"

	"github.com/getlantern/radiance/common"
	"github.com/getlantern/radiance/common/settings"
	"github.com/getlantern/radiance/traces"

	"google.golang.org/protobuf/proto"
)

const (
	maxTotalAttachmentBytes = int64(19.5 * 1024 * 1024)
	tracerName              = "github.com/getlantern/radiance/issue"
)

// IssueReporter is used to send issue reports to backend.
type IssueReporter struct {
	tunnelClient *http.Client
	httpClient   *http.Client
	logger       *slog.Logger
}

// NewIssueReporter returns an IssueReporter that sends reports with
// tunnelClient, falling back to httpClient when tunnelClient returns an error.
// A nil tunnelClient sends with httpClient only. A nil logger uses [slog.Default].
func NewIssueReporter(tunnelClient, httpClient *http.Client, logger *slog.Logger) *IssueReporter {
	if logger == nil {
		logger = slog.Default()
	}
	return &IssueReporter{tunnelClient: tunnelClient, httpClient: httpClient, logger: logger}
}

type IssueType int

type Attachment struct {
	Name string
	Type string
	Data []byte
}

// Values are wire format: they are cast directly to
// ReportIssueRequest_ISSUE_TYPE, so they must stay in sync with
// issue.proto and must never be renumbered.
const (
	CannotCompletePurchase   IssueType = 0
	CannotSignIn             IssueType = 1
	SpinnerLoadsEndlessly    IssueType = 2
	CannotAccessBlockedSites IssueType = 3
	Slow                     IssueType = 4
	CannotLinkDevice         IssueType = 5
	ApplicationCrashes       IssueType = 6
	Other                    IssueType = 9
	UpdateFails              IssueType = 10
	SplitTunnel              IssueType = 11
	SmartRouting             IssueType = 12
	ServerSelection          IssueType = 13
	UpgradeFail              IssueType = 14
)

type IssueReport struct {
	// Type is one of the predefined IssueType constants.
	Type        IssueType
	Description string
	Email       string
	CountryCode string
	// device common name
	Device            string
	DeviceID          string
	UserID            string
	SubscriptionLevel string
	Locale            string
	// device alphanumeric name
	Model string
	// Attachments contains in-memory screenshot attachments supplied by the caller.
	// They are sent as separate multipart files, with at most
	// [MaxFirstClassAttachmentCount] files and [MaxFirstClassAttachmentBytes] bytes.
	Attachments []*Attachment
	// AdditionalAttachments is a list of additional files to be attached. The log file will be
	// automatically included.
	AdditionalAttachments []string
}

// Report sends an issue report, substituting a random support address when report.Email is empty.
func (ir *IssueReporter) Report(ctx context.Context, report IssueReport) error {
	ctx, span := otel.Tracer(tracerName).Start(ctx, "Report")
	defer span.End()
	if report.Email == "" {
		report.Email = "support+" + randStr(8) + "@getlantern.org"
	}

	osVersion, err := osversion.GetHumanReadable()
	if err != nil {
		ir.logger.Error("Unable to get OS version", "error", err)
		// Android still returns its release number when it can't name the API level.
		if osVersion == "" {
			osVersion = runtime.GOARCH
		}
		osVersion = runtime.GOOS + " " + osVersion
	}
	r := &ReportIssueRequest{
		Type:              ReportIssueRequest_ISSUE_TYPE(report.Type),
		AppVersion:        common.Version,
		Platform:          common.Platform,
		CountryCode:       report.CountryCode,
		SubscriptionLevel: report.SubscriptionLevel,
		Description:       report.Description,
		UserEmail:         report.Email,
		DeviceId:          report.DeviceID,
		UserId:            report.UserID,
		Device:            report.Device,
		Model:             report.Model,
		Language:          report.Locale,
		OsVersion:         osVersion,
	}

	firstClassAttachments := make([]*Attachment, 0, len(report.Attachments))
	for _, attachment := range report.Attachments {
		if attachment == nil {
			continue
		}
		firstClassAttachments = append(firstClassAttachments, attachment)
	}

	if len(firstClassAttachments) > 0 {
		if err := validateFirstClassAttachments(firstClassAttachments); err != nil {
			ir.logger.Error("invalid issue attachments", "error", err)
			return err
		}
	}

	screenshotBytes := 0
	for _, attachment := range firstClassAttachments {
		screenshotBytes += len(attachment.Data)
	}
	archiveBudget := maxTotalAttachmentBytes - int64(screenshotBytes)
	archiveBudget = max(archiveBudget, 0)

	logDir := settings.GetString(settings.LogPathKey)
	archive, err := buildIssueArchive(ir.logger, logDir, report.AdditionalAttachments, archiveBudget)
	if err != nil {
		ir.logger.Error("failed to build issue archive", "error", err)
	}
	if len(archive) > 0 {
		r.Attachments = append(r.Attachments, &ReportIssueRequest_Attachment{
			Type:    "application/zip",
			Name:    "logs.zip",
			Content: archive,
		})
	}

	out, err := proto.Marshal(r)
	if err != nil {
		ir.logger.Error("unable to marshal issue report", "error", err)
		return fmt.Errorf("error marshaling proto: %w", err)
	}

	contentType := "application/x-protobuf"
	body := bytes.NewReader(out)
	if len(firstClassAttachments) > 0 {
		multipartBody, multipartContentType, err := buildMultipartIssueBody(out, firstClassAttachments)
		if err != nil {
			ir.logger.Error("unable to build multipart issue report", "error", err)
			return fmt.Errorf("build multipart issue report: %w", err)
		}
		body = bytes.NewReader(multipartBody.Bytes())
		contentType = multipartContentType
	}

	issueURL := common.GetBaseURL() + "/issue"
	req, err := newIssueRequest(
		ctx,
		http.MethodPost,
		issueURL,
		body,
		contentType,
	)
	if err != nil {
		ir.logger.Error("unable to create issue report request", "error", err)
		return traces.RecordError(ctx, err)
	}

	resp, err := ir.send(req)
	if err != nil {
		ir.logger.Error("failed to send issue report", "error", err, "requestURL", issueURL)
		return traces.RecordError(ctx, err)
	}

	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		// The remote body may echo submitted report fields.
		ir.logger.Error("issue report failed", "statusCode", resp.StatusCode)
		return traces.RecordError(ctx, fmt.Errorf("issue report failed with status code %d", resp.StatusCode))
	}

	ir.logger.Debug("issue report sent")
	return nil
}

func (ir *IssueReporter) send(req *http.Request) (*http.Response, error) {
	if ir.tunnelClient == nil {
		return ir.httpClient.Do(req)
	}
	resp, err := ir.tunnelClient.Do(req)
	if err == nil {
		return resp, nil
	}
	ir.logger.Info("issue report via tunnel failed, falling back to kindling", "error", err)
	body, err := req.GetBody()
	if err != nil {
		return nil, err
	}
	req = req.Clone(req.Context())
	req.Body = body
	return ir.httpClient.Do(req)
}

// newIssueRequest creates a new HTTP request with the required headers for issue reporting.
func newIssueRequest(ctx context.Context, method, url string, body io.Reader, contentType string) (*http.Request, error) {
	req, err := common.NewRequestWithHeaders(ctx, method, url, body)
	if err != nil {
		return nil, err
	}

	if contentType == "" {
		contentType = "application/x-protobuf"
	}
	req.Header.Set(common.ContentTypeHeader, contentType)
	req.Header.Set(common.SupportedDataCapsHeader, "monthly,weekly,daily")

	return req, nil
}

func randStr(n int) string {
	var hexStr string
	for range n {
		hexStr += fmt.Sprintf("%x", rand.IntN(16))
	}
	return hexStr
}
