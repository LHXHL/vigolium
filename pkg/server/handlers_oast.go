package server

import (
	"database/sql"
	"errors"
	"fmt"
	"strconv"

	"github.com/gofiber/fiber/v3"
	"github.com/vigolium/vigolium/pkg/database"
)

// HandleListOASTInteractions handles GET /api/oast-interactions
func (h *Handlers) HandleListOASTInteractions(c fiber.Ctx) error {
	if h.db == nil {
		return respondError(c, fiber.StatusServiceUnavailable, ErrDatabaseRequired)
	}

	scanUUID := c.Query("scan_uuid")
	protocol := c.Query("protocol")
	moduleID := c.Query("module_id")
	search := c.Query("search")

	limit := 50
	if l := c.Query("limit"); l != "" {
		if v, err := strconv.Atoi(l); err == nil && v > 0 {
			limit = v
		}
	}
	if limit > 500 {
		limit = 500
	}

	offset := 0
	if o := c.Query("offset"); o != "" {
		if v, err := strconv.Atoi(o); err == nil && v >= 0 {
			offset = v
		}
	}

	projectUUID := getProjectUUID(c)
	var (
		interactions []*database.OASTInteraction
		total        int64
	)
	ctx := c.Context()
	if err := retryRead(ctx, func() error {
		var err error
		interactions, total, err = h.readerRepo().ListOASTInteractions(ctx, projectUUID, scanUUID, protocol, moduleID, search, limit, offset)
		return err
	}); err != nil {
		return respondQueryError(c, err)
	}

	return respondList(c, PaginatedResponse{
		ProjectUUID: projectUUID,
		Data:        interactions,
		Total:       total,
		Limit:       limit,
		Offset:      offset,
		HasMore:     int64(offset+limit) < total,
	})
}

// HandleGetOASTInteraction handles GET /api/oast-interactions/:id
func (h *Handlers) HandleGetOASTInteraction(c fiber.Ctx) error {
	if h.db == nil {
		return respondError(c, fiber.StatusServiceUnavailable, ErrDatabaseRequired)
	}

	idStr := c.Params("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		return respondErrorMsg(c, fiber.StatusBadRequest, "invalid OAST interaction ID: must be a number")
	}

	interaction, err := h.repo.GetOASTInteractionByID(c.Context(), id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return respondError(c, fiber.StatusNotFound, ErrOASTInteractionNotFound)
		}
		return respondError(c, fiber.StatusInternalServerError, fmt.Errorf("failed to retrieve OAST interaction: %w", err))
	}
	if !inRequestProject(c, interaction.ProjectUUID) {
		return respondError(c, fiber.StatusNotFound, ErrOASTInteractionNotFound)
	}

	return c.JSON(interaction)
}

// HandleDeleteOASTInteraction handles DELETE /api/oast-interactions/:id
func (h *Handlers) HandleDeleteOASTInteraction(c fiber.Ctx) error {
	if h.db == nil {
		return respondError(c, fiber.StatusServiceUnavailable, ErrDatabaseRequired)
	}

	idStr := c.Params("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		return respondErrorMsg(c, fiber.StatusBadRequest, "invalid OAST interaction ID: must be a number")
	}

	// Verify it exists and belongs to the request's project first
	interaction, err := h.repo.GetOASTInteractionByID(c.Context(), id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return respondError(c, fiber.StatusNotFound, ErrOASTInteractionNotFound)
		}
		return respondError(c, fiber.StatusInternalServerError, fmt.Errorf("failed to retrieve OAST interaction: %w", err))
	}
	if !inRequestProject(c, interaction.ProjectUUID) {
		return respondError(c, fiber.StatusNotFound, ErrOASTInteractionNotFound)
	}

	if err := h.repo.DeleteOASTInteraction(c.Context(), id); err != nil {
		return respondError(c, fiber.StatusInternalServerError, fmt.Errorf("failed to delete OAST interaction: %w", err))
	}

	return c.JSON(fiber.Map{"message": "OAST interaction deleted", "id": id})
}
