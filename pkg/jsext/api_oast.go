package jsext

import (
	"context"
	"strings"
	"time"

	"github.com/grafana/sobek"
	"github.com/vigolium/vigolium/pkg/oast/oastclass"
	"go.uber.org/zap"
)

// oastFuncDefs returns declarative definitions for vigolium.oast.* functions.
// Provides out-of-band testing capabilities via interactsh.
func oastFuncDefs() []JSFuncDef {
	return []JSFuncDef{
		{
			Namespace: NsOAST, Name: "enabled",
			Effect:   EffectPure,
			Category: "OAST", Signature: ".enabled()", Returns: "boolean",
			Description: "Returns whether the OAST service is enabled and available.",
			Example:     "",
			MakeHandler: func(vm *sobek.Runtime, opts APIOptions) func(sobek.FunctionCall) sobek.Value {
				svc := opts.OASTService
				return func(call sobek.FunctionCall) sobek.Value {
					return vm.ToValue(svc != nil && svc.Enabled())
				}
			},
		},
		{
			Namespace: NsOAST, Name: "payload",
			Effect:   EffectOAST,
			Category: "OAST", Signature: ".payload(targetURL?: string, paramName?: string, injectionType?: string)", Returns: "{url: string}|null",
			Description: "Generates a unique OAST callback URL for out-of-band testing.",
			Example:     "",
			MakeHandler: func(vm *sobek.Runtime, opts APIOptions) func(sobek.FunctionCall) sobek.Value {
				svc := opts.OASTService
				return func(call sobek.FunctionCall) sobek.Value {
					if svc == nil || !svc.Enabled() {
						return sobek.Null()
					}

					targetURL := ""
					paramName := ""
					injectionType := "extension"
					if v := call.Argument(0); !sobek.IsUndefined(v) {
						targetURL = v.String()
					}
					if v := call.Argument(1); !sobek.IsUndefined(v) {
						paramName = v.String()
					}
					if v := call.Argument(2); !sobek.IsUndefined(v) {
						injectionType = v.String()
					}

					url := svc.GenerateURL(targetURL, paramName, injectionType, "ext-"+opts.ScriptID, "")
					if url == "" {
						return sobek.Null()
					}

					result := vm.NewObject()
					_ = result.Set("url", url)
					return result
				}
			},
		},
		{
			Namespace: NsOAST, Name: "url",
			Effect:   EffectOAST,
			Category: "OAST", Signature: ".url(opts?: {class?: OASTClass, target?: string, param?: string, label?: string})", Returns: "string|null",
			Description: "Generates a unique OAST callback URL whose callbacks are rated as the given vulnerability class (" + strings.Join(oastclass.Names(), ", ") + "; default generic). An unknown class throws. Returns null if OAST is unavailable.",
			Example:     `vigolium.oast.url({class: "ssrf", target: ctx.url, param: "next"})`,
			MakeHandler: func(vm *sobek.Runtime, opts APIOptions) func(sobek.FunctionCall) sobek.Value {
				svc := opts.OASTService
				return func(call sobek.FunctionCall) sobek.Value {
					cls, targetURL, paramName, label := oastclass.Generic, "", "", ""
					if v := call.Argument(0); !sobek.IsUndefined(v) && !sobek.IsNull(v) {
						o := v.ToObject(vm)
						if c := o.Get("class"); c != nil && !sobek.IsUndefined(c) && !sobek.IsNull(c) {
							parsed, ok := oastclass.Parse(c.String())
							if !ok {
								panic(vm.NewTypeError("vigolium.oast.url: unknown class %q (valid: %s)", c.String(), strings.Join(oastclass.Names(), ", ")))
							}
							cls = parsed
						}
						targetURL = stringField(vm, o, "target", "")
						paramName = stringField(vm, o, "param", "")
						label = stringField(vm, o, "label", "")
					}
					if svc == nil || !svc.Enabled() {
						return sobek.Null()
					}
					if label == "" {
						label = string(cls)
					}
					url := svc.GenerateURLFor(cls, targetURL, paramName, label, "ext-"+opts.ScriptID, "")
					if url == "" {
						return sobek.Null()
					}
					return vm.ToValue(url)
				}
			},
		},
		{
			Namespace: NsOAST, Name: "poll",
			Effect:   EffectOAST,
			Category: "OAST", Signature: ".poll(timeoutMs?: number)", Returns: "OASTInteraction[]",
			Description: "Waits for the specified timeout then queries for OAST interactions from the current scan.",
			Example:     "",
			MakeHandler: func(vm *sobek.Runtime, opts APIOptions) func(sobek.FunctionCall) sobek.Value {
				svc := opts.OASTService
				return func(call sobek.FunctionCall) sobek.Value {
					if svc == nil || !svc.Enabled() {
						return vm.NewArray()
					}

					timeoutMs := int64(5000) // default 5s
					if v := call.Argument(0); !sobek.IsUndefined(v) {
						timeoutMs = v.ToInteger()
					}
					if timeoutMs > 30000 {
						timeoutMs = 30000 // cap at 30s
					}
					if timeoutMs > 0 {
						time.Sleep(time.Duration(timeoutMs) * time.Millisecond)
					}

					// Query OAST interactions from the database
					if opts.Repository == nil || opts.ScanUUID == "" {
						return vm.NewArray()
					}

					interactions, err := opts.Repository.GetOASTInteractionsByScan(context.Background(), opts.ScanUUID)
					if err != nil {
						zap.L().Debug("OAST poll: failed to query interactions", zap.Error(err))
						return vm.NewArray()
					}

					if len(interactions) == 0 {
						return vm.NewArray()
					}

					results := make([]interface{}, 0, len(interactions))
					for _, ix := range interactions {
						obj := vm.NewObject()
						_ = obj.Set("protocol", ix.Protocol)
						_ = obj.Set("unique_id", ix.UniqueID)
						_ = obj.Set("full_id", ix.FullID)
						_ = obj.Set("remote_address", ix.RemoteAddress)
						_ = obj.Set("target_url", ix.TargetURL)
						_ = obj.Set("parameter_name", ix.ParameterName)
						_ = obj.Set("module_id", ix.ModuleID)
						_ = obj.Set("interacted_at", ix.InteractedAt.Format(time.RFC3339))
						results = append(results, obj)
					}

					return vm.ToValue(results)
				}
			},
		},
	}
}
