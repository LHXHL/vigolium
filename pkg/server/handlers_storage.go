package server

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/vigolium/vigolium/pkg/storage"
	"go.uber.org/zap"
)

// HandleStorageUploadSource handles POST /api/storage/upload-source.
// Accepts multipart file upload and stores it in <bucket>/<project-uuid>/ugc/<filename>.
func (h *Handlers) HandleStorageUploadSource(c fiber.Ctx) error {
	if h.settings == nil || !h.settings.Storage.IsEnabled() {
		return respondErrorMsg(c, fiber.StatusServiceUnavailable, "cloud storage is not enabled")
	}

	projectUUID := c.Locals("project_uuid").(string)

	file, err := c.FormFile("file")
	if err != nil {
		return respondErrorMsg(c, fiber.StatusBadRequest, "file field is required")
	}

	sc, err := storage.NewClient(&h.settings.Storage)
	if err != nil {
		return respondErrorMsg(c, fiber.StatusInternalServerError, "failed to create storage client")
	}

	f, err := file.Open()
	if err != nil {
		return respondErrorMsg(c, fiber.StatusInternalServerError, "failed to open uploaded file")
	}
	defer func() { _ = f.Close() }()

	filename := filepath.Base(file.Filename)
	key := storage.UGCKey(filename)

	if err := sc.Upload(c.Context(), projectUUID, key, f, file.Size, file.Header.Get("Content-Type")); err != nil {
		zap.L().Error("Failed to upload source to storage", zap.Error(err))
		return respondErrorMsg(c, fiber.StatusInternalServerError, "failed to upload file to storage")
	}

	storageURL := storage.StorageURL(projectUUID, key)
	return c.JSON(StorageUploadResponse{
		StorageURL: storageURL,
		Key:        key,
		Filename:   filename,
		Size:       file.Size,
		Message:    "source uploaded successfully",
	})
}

// HandleStorageDownloadSource handles GET /api/storage/source/:key.
// Downloads a source file from <bucket>/<project-uuid>/ugc/:key.
func (h *Handlers) HandleStorageDownloadSource(c fiber.Ctx) error {
	if h.settings == nil || !h.settings.Storage.IsEnabled() {
		return respondErrorMsg(c, fiber.StatusServiceUnavailable, "cloud storage is not enabled")
	}

	projectUUID := c.Locals("project_uuid").(string)
	key := c.Params("key")
	if key == "" {
		return respondErrorMsg(c, fiber.StatusBadRequest, "key parameter is required")
	}

	cleanKey, validateErr := storage.ValidateKey(key)
	if validateErr != nil {
		return respondError(c, fiber.StatusBadRequest, fmt.Errorf("invalid key: %w", validateErr))
	}
	fullKey := storage.UGCKey(cleanKey)

	sc, err := storage.NewClient(&h.settings.Storage)
	if err != nil {
		return respondErrorMsg(c, fiber.StatusInternalServerError, "failed to create storage client")
	}

	// Stat before committing headers: it resolves existence (so a miss is still a
	// clean JSON 404 rather than a truncated stream) and yields the size we need
	// for Content-Length, in the same round trip Exists would have cost.
	info, err := sc.Stat(c.Context(), projectUUID, fullKey)
	if err != nil {
		if errors.Is(err, storage.ErrObjectNotFound) {
			return respondErrorMsg(c, fiber.StatusNotFound, "file not found in storage")
		}
		return respondError(c, fiber.StatusInternalServerError, fmt.Errorf("failed to check storage: %w", err))
	}

	reader, err := sc.Download(c.Context(), projectUUID, fullKey)
	if err != nil {
		return respondErrorMsg(c, fiber.StatusNotFound, "file not found in storage")
	}

	c.Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", key))
	c.Set("Content-Type", "application/octet-stream")
	return c.SendStream(reader, objectStreamSize(info.Size))
}

// objectStreamSize narrows a bucket object's size to the int c.SendStream
// takes, falling back to -1 (chunked) rather than a wrong Content-Length when
// the value doesn't survive the conversion.
//
// The point of streaming here at all: the obvious spelling — io.Copy into
// c.Response().BodyWriter() — is not a stream. BodyWriter appends into the
// response's in-memory body buffer, so the whole object is retained before a
// single byte is transmitted and RSS scales with object size times
// concurrency. SendStream copies during response write instead, so a slow
// client backpressures the bucket read rather than the server racing ahead
// into memory. Two consequences: fasthttp closes the reader (it is an
// io.Closer) on every completion path, so callers must not also defer a Close;
// and headers are committed before the body is read, so an upstream failure
// partway through is a short read on an otherwise-200 response, not a JSON
// error.
func objectStreamSize(size int64) int {
	if size >= 0 && int64(int(size)) == size {
		return int(size)
	}
	return -1
}

// HandleStorageDownloadResults handles GET /api/storage/results/:scan_uuid.
// Downloads the result bundle for a native scan or agentic scan.
func (h *Handlers) HandleStorageDownloadResults(c fiber.Ctx) error {
	if h.settings == nil || !h.settings.Storage.IsEnabled() {
		return respondErrorMsg(c, fiber.StatusServiceUnavailable, "cloud storage is not enabled")
	}

	projectUUID := c.Locals("project_uuid").(string)
	scanUUID := c.Params("scan_uuid")
	if scanUUID == "" {
		return respondErrorMsg(c, fiber.StatusBadRequest, "scan_uuid parameter is required")
	}
	if _, err := storage.ValidateKey(scanUUID); err != nil {
		return respondError(c, fiber.StatusBadRequest, fmt.Errorf("invalid scan UUID: %w", err))
	}

	sc, err := storage.NewClient(&h.settings.Storage)
	if err != nil {
		return respondErrorMsg(c, fiber.StatusInternalServerError, "failed to create storage client")
	}

	keys := []string{
		storage.NativeScanResultKey(scanUUID),
		storage.AgenticScanResultKey(scanUUID),
	}

	// Stat for existence first — minio's GetObject is lazy, so a non-existent
	// key only surfaces an error once the body is read, by which point we've
	// already committed to that key and can't fall back to the next one.
	for _, key := range keys {
		info, err := sc.Stat(c.Context(), projectUUID, key)
		if err != nil {
			if errors.Is(err, storage.ErrObjectNotFound) {
				continue
			}
			return respondError(c, fiber.StatusInternalServerError, fmt.Errorf("failed to check storage: %w", err))
		}

		reader, err := sc.Download(c.Context(), projectUUID, key)
		if err != nil {
			return respondError(c, fiber.StatusInternalServerError, fmt.Errorf("failed to open storage object: %w", err))
		}

		c.Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filepath.Base(key)))
		c.Set("Content-Type", "application/gzip")
		return c.SendStream(reader, objectStreamSize(info.Size))
	}

	return respondErrorMsg(c, fiber.StatusNotFound, "no results found for this scan UUID")
}

// HandleStoragePresign handles POST /api/storage/presign.
// Generates presigned URLs for direct upload/download.
func (h *Handlers) HandleStoragePresign(c fiber.Ctx) error {
	if h.settings == nil || !h.settings.Storage.IsEnabled() {
		return respondErrorMsg(c, fiber.StatusServiceUnavailable, "cloud storage is not enabled")
	}

	projectUUID := c.Locals("project_uuid").(string)

	var req StoragePresignRequest
	if err := c.Bind().JSON(&req); err != nil {
		return respondErrorMsg(c, fiber.StatusBadRequest, "invalid request body")
	}

	if req.Key == "" {
		return respondErrorMsg(c, fiber.StatusBadRequest, "key is required")
	}
	cleanKey, validateErr := storage.ValidateKey(req.Key)
	if validateErr != nil {
		return respondError(c, fiber.StatusBadRequest, fmt.Errorf("invalid key: %w", validateErr))
	}
	req.Key = cleanKey

	sc, err := storage.NewClient(&h.settings.Storage)
	if err != nil {
		return respondErrorMsg(c, fiber.StatusInternalServerError, "failed to create storage client")
	}

	expiry := 1 * time.Hour
	if req.ExpirySeconds > 0 {
		expiry = time.Duration(req.ExpirySeconds) * time.Second
	}

	var url string
	switch req.Method {
	case "PUT", "put":
		url, err = sc.PresignedPutURL(c.Context(), projectUUID, req.Key, expiry)
	default:
		url, err = sc.PresignedGetURL(c.Context(), projectUUID, req.Key, expiry)
	}

	if err != nil {
		return respondErrorMsg(c, fiber.StatusInternalServerError, "failed to generate presigned URL")
	}

	return c.JSON(StoragePresignResponse{
		URL:    url,
		Key:    req.Key,
		Method: strings.ToUpper(req.Method),
		Expiry: int(expiry.Seconds()),
	})
}

// --- Storage request/response types ---

// StorageUploadResponse is the response for POST /api/storage/upload-source.
type StorageUploadResponse struct {
	StorageURL string `json:"storage_url"`
	Key        string `json:"key"`
	Filename   string `json:"filename"`
	Size       int64  `json:"size"`
	Message    string `json:"message"`
}

// StoragePresignRequest is the request body for POST /api/storage/presign.
type StoragePresignRequest struct {
	Key           string `json:"key"`
	Method        string `json:"method,omitempty"` // GET (default) or PUT
	ExpirySeconds int    `json:"expiry_seconds,omitempty"`
}

// StoragePresignResponse is the response for POST /api/storage/presign.
type StoragePresignResponse struct {
	URL    string `json:"url"`
	Key    string `json:"key"`
	Method string `json:"method"`
	Expiry int    `json:"expiry_seconds"`
}
