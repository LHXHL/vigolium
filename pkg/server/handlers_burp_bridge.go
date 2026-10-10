package server

import (
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/gofiber/fiber/v3"
	"github.com/vigolium/vigolium/pkg/httpmsg"
)

const maxSiteMapSnapshotChunk = 200

type siteMapSnapshotRecord struct {
	URL                 string `json:"url"`
	RequestBase64       string `json:"request_base64"`
	ResponseBase64      string `json:"response_base64,omitempty"`
	IdentityFingerprint string `json:"identity_fingerprint,omitempty"`
	ContentFingerprint  string `json:"content_fingerprint,omitempty"`
}

type siteMapSnapshotRequest struct {
	SnapshotID string                  `json:"snapshot_id"`
	ChunkIndex int                     `json:"chunk_index"`
	FinalChunk bool                    `json:"final_chunk"`
	CapturedAt string                  `json:"captured_at,omitempty"`
	Records    []siteMapSnapshotRecord `json:"records"`
}

type siteMapSnapshotResponse struct {
	Received  int      `json:"received"`
	Inserted  int      `json:"inserted"`
	Updated   int      `json:"updated"`
	Unchanged int      `json:"unchanged"`
	Skipped   int      `json:"skipped"`
	Errors    []string `json:"errors,omitempty"`
}

func (h *Handlers) HandleBurpSiteMapSnapshot(c fiber.Ctx) error {
	if h.repo == nil {
		return respondError(c, fiber.StatusServiceUnavailable, ErrDatabaseRequired)
	}
	var req siteMapSnapshotRequest
	if err := c.Bind().JSON(&req); err != nil {
		return respondError(c, fiber.StatusBadRequest, fmt.Errorf("invalid snapshot: %w", err))
	}
	if len(req.Records) > maxSiteMapSnapshotChunk {
		return respondErrorMsg(c, fiber.StatusBadRequest, "snapshot chunk exceeds 200 records")
	}
	resp := siteMapSnapshotResponse{Received: len(req.Records)}
	projectUUID := getProjectUUID(c)
	for _, item := range req.Records {
		rr, err := parseSnapshotRecord(item)
		if err != nil {
			resp.Skipped++
			resp.Errors = append(resp.Errors, err.Error())
			continue
		}
		_, outcome, err := h.repo.UpsertSnapshotRecord(c.Context(), rr, "burp-sitemap", projectUUID)
		if err != nil {
			resp.Skipped++
			resp.Errors = append(resp.Errors, err.Error())
			continue
		}
		switch outcome {
		case "inserted":
			resp.Inserted++
		case "updated":
			resp.Updated++
		default:
			resp.Unchanged++
		}
	}
	return c.JSON(resp)
}

func parseSnapshotRecord(item siteMapSnapshotRecord) (*httpmsg.HttpRequestResponse, error) {
	rawRequest, err := base64.StdEncoding.DecodeString(item.RequestBase64)
	if err != nil {
		return nil, errors.New("invalid snapshot request encoding")
	}
	var rr *httpmsg.HttpRequestResponse
	if item.URL != "" {
		rr, err = httpmsg.ParseRawRequestWithURL(string(rawRequest), item.URL)
	} else {
		rr, err = httpmsg.ParseRawRequest(string(rawRequest))
	}
	if err != nil {
		return nil, err
	}
	if item.ResponseBase64 != "" {
		rawResponse, decodeErr := base64.StdEncoding.DecodeString(item.ResponseBase64)
		if decodeErr != nil {
			return nil, errors.New("invalid snapshot response encoding")
		}
		rr = rr.WithResponse(httpmsg.NewHttpResponse(rawResponse))
	}
	return rr, nil
}
