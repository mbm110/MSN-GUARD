package issue

import (
	"bytes"
	"fmt"
	"mime"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"path/filepath"
	"strings"
)

const (
	// MaxFirstClassAttachmentCount is the maximum number of screenshot
	// attachments that can be sent as first-class multipart files.
	MaxFirstClassAttachmentCount = 3
	// MaxFirstClassAttachmentBytes is the maximum combined size of screenshot
	// attachments that can be sent as first-class multipart files.
	MaxFirstClassAttachmentBytes = 15 * 1024 * 1024

	requestPartName        = "request"
	requestPartFilename    = "request.pb"
	attachmentPartName     = "attachments[]"
	octetStreamContentType = "application/octet-stream"
)

var allowedFirstClassAttachmentTypes = map[string]struct{}{
	"image/gif":  {},
	"image/jpeg": {},
	"image/png":  {},
}

var attachmentTypeAliases = map[string]string{
	"image/jpg": "image/jpeg",
}

// normalizeAttachmentType trims parameters and folds a few common aliases so
// validation and multipart writing can reason about one canonical content type.
func normalizeAttachmentType(contentType string) string {
	contentType = strings.TrimSpace(strings.ToLower(contentType))
	if contentType == "" {
		return ""
	}

	mediaType, _, err := mime.ParseMediaType(contentType)
	if err == nil {
		contentType = mediaType
	}

	if alias, ok := attachmentTypeAliases[contentType]; ok {
		return alias
	}
	return contentType
}

// attachmentContentType prefers an explicitly supplied type, then falls back to
// the filename, and finally sniffs the payload when we have to.
func attachmentContentType(attachment *Attachment) string {
	if attachment == nil || len(attachment.Data) == 0 {
		return octetStreamContentType
	}

	if contentType := normalizeAttachmentType(attachment.Type); contentType != "" {
		return contentType
	}

	name := strings.TrimSpace(attachment.Name)
	if contentType := normalizeAttachmentType(
		mime.TypeByExtension(strings.ToLower(filepath.Ext(name))),
	); contentType != "" {
		return contentType
	}

	return normalizeAttachmentType(http.DetectContentType(attachment.Data))
}

// validateFirstClassAttachments applies the screenshot limits before we switch
// the issue request from the protobuf-only path to multipart/form-data.
func validateFirstClassAttachments(attachments []*Attachment) error {
	count := 0
	totalBytes := 0

	for _, attachment := range attachments {
		if attachment == nil {
			continue
		}

		if len(attachment.Data) == 0 {
			name := strings.TrimSpace(attachment.Name)
			if name == "" {
				return fmt.Errorf("attachment is empty")
			}
			return fmt.Errorf("attachment %q is empty", name)
		}

		name, err := normalizeAttachmentName(attachment.Name)
		if err != nil {
			return err
		}

		count++
		if count > MaxFirstClassAttachmentCount {
			return fmt.Errorf(
				"too many screenshot attachments: max %d",
				MaxFirstClassAttachmentCount,
			)
		}

		contentType := attachmentContentType(attachment)
		if _, ok := allowedFirstClassAttachmentTypes[contentType]; !ok {
			return fmt.Errorf(
				"unsupported screenshot attachment type %q for %q",
				contentType,
				name,
			)
		}

		totalBytes += len(attachment.Data)
		if totalBytes > MaxFirstClassAttachmentBytes {
			return fmt.Errorf(
				"total screenshot attachment size exceeds %d bytes",
				MaxFirstClassAttachmentBytes,
			)
		}
	}

	return nil
}

// buildMultipartIssueBody keeps the protobuf request as one part and sends each
// screenshot as its own attachment so the ticketing side can surface them directly.
func buildMultipartIssueBody(
	requestPayload []byte,
	attachments []*Attachment,
) (*bytes.Buffer, string, error) {
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	requestHeader := make(textproto.MIMEHeader)
	requestHeader.Set(
		"Content-Disposition",
		multipartContentDisposition(requestPartName, requestPartFilename),
	)
	requestHeader.Set("Content-Type", "application/x-protobuf")

	requestPart, err := writer.CreatePart(requestHeader)
	if err != nil {
		return nil, "", fmt.Errorf("create issue request part: %w", err)
	}
	if _, err := requestPart.Write(requestPayload); err != nil {
		return nil, "", fmt.Errorf("write issue request part: %w", err)
	}

	for _, attachment := range attachments {
		if attachment == nil {
			continue
		}

		filename, err := normalizeAttachmentName(attachment.Name)
		if err != nil {
			return nil, "", err
		}

		partHeader := make(textproto.MIMEHeader)
		partHeader.Set(
			"Content-Disposition",
			multipartContentDisposition(attachmentPartName, filename),
		)
		partHeader.Set("Content-Type", attachmentContentType(attachment))

		part, err := writer.CreatePart(partHeader)
		if err != nil {
			return nil, "", fmt.Errorf(
				"create attachment part for %q: %w",
				attachment.Name,
				err,
			)
		}
		if _, err := part.Write(attachment.Data); err != nil {
			return nil, "", fmt.Errorf(
				"write attachment part for %q: %w",
				attachment.Name,
				err,
			)
		}
	}

	contentType := writer.FormDataContentType()
	if err := writer.Close(); err != nil {
		return nil, "", fmt.Errorf("close multipart writer: %w", err)
	}

	return body, contentType, nil
}

// Keep disposition quoting in one place since filenames can come from users.
func multipartContentDisposition(fieldName, filename string) string {
	return fmt.Sprintf(
		`form-data; name="%s"; filename="%s"`,
		escapeMultipartToken(fieldName),
		escapeMultipartToken(filename),
	)
}

// normalizeAttachmentName trims the filename and rejects characters that would
// make the multipart header invalid.
func normalizeAttachmentName(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", fmt.Errorf("attachment name is required")
	}

	for _, r := range name {
		if r < 0x20 || r == 0x7f {
			return "", fmt.Errorf("attachment %q contains invalid control characters", name)
		}
	}

	return name, nil
}

// escapeMultipartToken quotes characters that are special in Content-Disposition
// parameter values.
func escapeMultipartToken(value string) string {
	replacer := strings.NewReplacer("\\", "\\\\", `"`, "\\\"")
	return replacer.Replace(value)
}
