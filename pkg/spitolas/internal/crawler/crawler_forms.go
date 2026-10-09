package crawler

import (
	"context"
	"slices"

	"go.uber.org/zap"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/action"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/browser"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/condition"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/form"
)

// maxWaitConditionFailures caps the failing selectors kept in Stats.
const maxWaitConditionFailures = 5

// checkWaitConditions applies wait conditions to the page and returns how many
// timed out. Each timeout is counted in Stats.WaitConditionsFailed (with the
// selector, up to maxWaitConditionFailures distinct ones) so a run that never
// met a readiness condition says so instead of reading as an empty site. A
// condition whose URL does not match, or a cancelled crawl, is not a failure.
func (c *Crawler) checkWaitConditions(ctx context.Context, page *browser.Page) int {
	failed := 0
	for _, wc := range c.waitConditions {
		if wc.Wait(ctx, page) != condition.WaitTimeout {
			continue
		}
		failed++
		c.recordWaitConditionFailure(wc.Selector)
	}
	return failed
}

// recordWaitConditionFailure counts one timed-out readiness condition.
func (c *Crawler) recordWaitConditionFailure(selector string) {
	zap.L().Warn("Wait condition timed out", zap.String("selector", selector))
	c.mu.Lock()
	defer c.mu.Unlock()
	c.stats.WaitConditionsFailed++
	if len(c.stats.WaitConditionFailures) < maxWaitConditionFailures && !slices.Contains(c.stats.WaitConditionFailures, selector) {
		c.stats.WaitConditionFailures = append(c.stats.WaitConditionFailures, selector)
	}
}

// getInputElements merges related form inputs with DOM-detected inputs.
//  1. Start with eventable.getRelatedFormInputs() (inputs linked to this action)
//  2. Add the inputs detected on the current DOM that belong to the action's
//     own form (see mergeActionInputs) — an action never edits a form it
//     cannot submit
//  3. Remove duplicates (based on Identification)
//  4. Order by FormFillOrder (NORMAL, DOM, VISUAL) - not implemented yet
//
// Returns DetectedInput for Go extension (value rotation, detection metadata).
func (c *Crawler) getInputElements(page *browser.Page, eventable *action.Eventable) []*form.DetectedInput {
	// Step 1: Start with related inputs from eventable
	related := make([]*form.DetectedInput, 0)
	for _, actionInput := range eventable.GetRelatedFormInputs() {
		if detected := form.FromFormInput(actionInput); detected != nil {
			related = append(related, detected)
		}
	}

	// Step 2: Merge with the DOM inputs of the action's own form. The owning
	// form is resolved in the same page evaluation as the inputs, so both sides
	// of the comparison come from one DOM snapshot.
	actionXPath := ""
	if id := eventable.Identification; id != nil && id.How == action.HowXPath {
		actionXPath = id.Value
	}
	domInputs, actionForm, _ := c.formHandler.DetectInputsForAction(page, actionXPath)
	formInputs, excluded := c.mergeActionInputs(related, domInputs, actionForm)

	zap.L().Debug("Changing related inputs",
		zap.Int64("eventable_id", eventable.ID),
		zap.Int("existing", len(related)),
		zap.Int("merged", len(formInputs)-len(related)),
		zap.Int("excluded_other_forms", excluded),
		zap.String("action_form", actionForm),
		zap.Int("total", len(formInputs)))

	// TODO: Step 3 - Order by FormFillOrder (VISUAL ordering)
	// For now, use DOM order (default)

	return formInputs
}

// mergeActionInputs appends to related every DOM input the action could submit
// and returns the merged list plus how many DOM inputs were left out because
// they belong to a different form.
//
// When the action sits inside a form (actionForm != ""), only that form's
// controls are merged: clicking form A's submit button must not edit form B,
// nor the orphan controls around it. When the action is outside any form — a
// plain link, or an SPA "form" built from orphan inputs and a script-driven
// button — every DOM input is merged, as before form scoping existed: there is
// no owning form to scope by, and SPA login/registration flows depend on it.
func (c *Crawler) mergeActionInputs(related, dom []*form.DetectedInput, actionForm string) ([]*form.DetectedInput, int) {
	merged := related
	excluded := 0
	for _, domInput := range dom {
		if actionForm != "" && domInput.FormKey != actionForm {
			excluded++
			continue
		}
		exists := false
		for _, existing := range merged {
			if c.detectedInputEquals(existing, domInput) {
				exists = true
				break
			}
		}
		if !exists {
			merged = append(merged, domInput)
		}
	}
	return merged, excluded
}

// detectedInputEquals checks if two detected inputs are equal based on Identification.
func (c *Crawler) detectedInputEquals(a, b *form.DetectedInput) bool {
	if a == nil || b == nil || a.FormInput == nil || b.FormInput == nil {
		return false
	}

	// Compare by Identification first
	if a.Identification != nil && b.Identification != nil {
		return a.Identification.How == b.Identification.How &&
			a.Identification.Value == b.Identification.Value
	}

	// Fallback: compare by ID or Name (from DetectedInput metadata)
	if a.ID != "" && a.ID == b.ID {
		return true
	}
	if a.Name != "" && a.Name == b.Name {
		return true
	}

	return false
}

// handleInputElements fills form inputs and returns the handled list.
//  1. List<FormInput> formInputs = getInputElements(eventable);
//  2. return formHandler.handleFormElements(formInputs);
//
// Returns action.FormInput (used in candidates cache).
func (c *Crawler) handleInputElements(page *browser.Page, eventable *action.Eventable) []*action.FormInput {
	formInputs := c.getInputElements(page, eventable)
	return c.formHandler.HandleFormElements(page, formInputs)
}

// fillFormsIfPresent detects and fills forms on the page.
// If actionID is provided, caches the form inputs for reuse.
func (c *Crawler) fillFormsIfPresent(page *browser.Page, actionID string) []*action.FormInput {
	// Check if we have cached inputs for this action
	if actionID != "" {
		if cached, ok := c.formCache[actionID]; ok && len(cached) > 0 {
			zap.L().Debug("Using cached form inputs for action", zap.String("action_id", actionID))
			result := c.formHandler.FillInputs(page, cached)
			if result.HasErrors() {
				zap.L().Debug("Form fill had failures", zap.Int("failed", result.Failed), zap.Int("total", len(cached)))
			}
			// Return as action.FormInput
			return form.ToFormInputs(cached)
		}
	}

	inputs, err := c.formHandler.DetectInputs(page)
	if err != nil {
		return nil
	}

	if len(inputs) > 0 {
		// The trainer keys values by page origin and owning form, so a value
		// learned on one origin is never replayed into another's form.
		origin := ""
		if c.formTrainer != nil {
			if u, uerr := page.URL(); uerr == nil {
				origin = httpmsg.OriginFromURL(u)
			}
		}

		// Form trainer replay mode: use trained inputs
		if c.formTrainer != nil && c.formTrainer.GetMode() == form.FillReplay {
			for _, input := range inputs {
				inputType := ""
				if input.FormInput != nil {
					inputType = string(input.Type)
				}
				trained := c.formTrainer.MatchInput(input.XPath, input.ID, input.Name, inputType, origin, input.FormKey)
				if trained != nil && trained.Value != "" {
					input.SetValues([]string{trained.Value})
				}
			}
		}

		zap.L().Debug("Found form inputs, filling...", zap.Int("count", len(inputs)))

		// This returns list with XPath-based identification for backtracking
		handled := c.formHandler.HandleFormElements(page, inputs)

		// Check if we have failures by comparing handled vs inputs
		if len(handled) < len(inputs) {
			zap.L().Debug("Normal form fill had failures, trying pairwise",
				zap.Int("handled", len(handled)),
				zap.Int("total", len(inputs)))
			success, worked := c.formHandler.FillInputsPairwise(page, inputs)
			if success && len(worked) > 0 {
				zap.L().Debug("Pairwise form fill succeeded", zap.Int("worked", len(worked)))
				// Update inputs with worked inputs for caching
				inputs = worked
				handled = form.ToFormInputs(worked)
			} else {
				zap.L().Debug("Pairwise form fill also failed")
			}
		}

		// Form trainer training mode: record inputs from DetectedInput (has metadata)
		if c.formTrainer != nil && (c.formTrainer.GetMode() == form.FillTraining || c.formTrainer.GetMode() == form.FillXPathTraining) {
			for _, input := range inputs {
				value := ""
				values := input.GetValues()
				if len(values) > 0 {
					value = values[0]
				}
				inputType := ""
				if input.FormInput != nil {
					inputType = string(input.Type)
				}
				c.formTrainer.RecordInput(&form.TrainedInput{
					XPath:   input.XPath,
					Type:    inputType,
					Name:    input.Name,
					ID:      input.ID,
					Value:   value,
					Values:  values,
					Origin:  origin,
					FormKey: input.FormKey,
				})
			}
		}

		// Cache the DetectedInput for this action (has metadata for value rotation)
		if actionID != "" {
			c.formCache[actionID] = inputs
		}

		return handled
	}

	return nil
}

// fillFormsWithInputs fills forms using cached action.FormInput data.
func (c *Crawler) fillFormsWithInputs(page *browser.Page, inputs []*action.FormInput) {
	for _, formInput := range inputs {
		if formInput.Identification == nil {
			continue
		}

		selector := formInput.Identification.Value
		if selector == "" {
			continue
		}

		// Get value to fill
		var value string
		if len(formInput.InputValues) > 0 {
			value = formInput.InputValues[0].Value
		}

		if value == "" {
			continue
		}

		// Fill the input by finding element based on selector type
		var elem *browser.Element
		var err error
		isXPath := formInput.Identification.How == action.HowXPath
		if isXPath {
			elem, err = page.ElementX(selector)
		} else {
			elem, err = page.Element(selector)
		}
		if err != nil {
			zap.L().Debug("Failed to find cached form input element",
				zap.String("selector", selector),
				zap.Bool("is_xpath", isXPath),
				zap.Error(err))
			continue
		}
		if err := elem.Input(value); err != nil {
			zap.L().Debug("Failed to fill cached form input",
				zap.String("selector", selector),
				zap.Error(err))
		} else {
			zap.L().Debug("Filled cached form input",
				zap.String("selector", selector),
				zap.String("value", value))
		}
	}
}

// formHandlerAdapter adapts EventableConditionChecker to action.FormHandler interface.
type formHandlerAdapter struct {
	checker *condition.EventableConditionChecker
}

// GetCandidateElementsForInputs implements action.FormHandler.
func (a *formHandlerAdapter) GetCandidateElementsForInputs(elementXPath string, baseCandidate *action.CandidateElement) []*action.CandidateElement {
	if a.checker == nil || a.checker.Count() == 0 {
		return []*action.CandidateElement{baseCandidate}
	}
	return a.checker.GetCandidateElementsForInputs(elementXPath, baseCandidate)
}

// GetFormInputs implements action.FormHandler.
// Returns all form inputs from the EventableConditions.
func (a *formHandlerAdapter) GetFormInputs() []*action.FormInput {
	if a.checker == nil {
		return nil
	}
	return a.checker.GetFormInputs()
}

// HandleFormElements implements action.FormHandler.
// This is a no-op in this adapter as form filling is handled elsewhere.
func (a *formHandlerAdapter) HandleFormElements(formInputs []*action.FormInput) []*action.FormInput {
	return formInputs
}
