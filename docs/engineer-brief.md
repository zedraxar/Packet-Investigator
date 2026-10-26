# Engineer context, focused summary and PDF brief

This development increment builds on desktop preview PR #28. The evidence engine
and its JSON schemas remain unchanged. Context is an optional view over retained
evidence, not a new root-cause diagnosis.

## Workflow

1. Choose a capture. Optionally select a reported symptom, target hostname/IP,
   client IP and capture point. Leave fields blank for general review.
2. Investigate. The default view is the engineer brief: scope, prioritized
   observations, uncertainty and next capture steps.
3. Select Technical evidence for the existing full report. Show DNS details
   expands the DNS portion only.
4. Save PDF brief creates a local graphical summary with capture metrics,
   context, DNS exchange coverage, findings, evidence references and next steps.
   Save text uses the visible brief or technical view; Save JSON preserves the
   original complete investigation JSON without adding context fields.

Editing context or choosing another file clears the previous result and disables
exports until a new investigation completes. Controls are disabled during workers.
PDFs are rendered in memory and published without replacing existing files, using
the same safe writer as text/JSON.

## Evidence relevance and limits

Hostname focus includes exact names and subdomains, using label boundaries.
Candidate TCP relevance uses retained A/AAAA answers from those DNS exchanges.
No external lookup is performed. Candidate addresses are capped at 256 with
explicit limitations. Shared addresses, caches, aliases, encrypted DNS, incomplete
answers and missing visibility can yield missed or misleading candidates.
This increment does not bind DNS TTLs/times or prove website/process identity.
Use an exact target IP for a narrower endpoint view.

Client IP intersects TCP endpoints and DNS requester identity. The symptom changes
finding order; it does not turn an observation into a causal diagnosis or change
severity thresholds. Capture point is user-supplied context, not inferred topology.
No target means background traffic remains in scope.

Coverage describes evidence completeness, not network health. Response matching
describes observed DNS exchanges, not guaranteed name resolution or page rendering.
No health score or invented network-latency chart is presented. Complete evidence
remains available in the technical report and JSON.

The first PDF is a short summary, not a full evidence archive. It retains up to
six finding groups, three source IDs and eight sampled frames per finding.
Non-ASCII filename characters are escaped in the PDF to avoid unsupported glyphs;
the raw report retains its original metadata. No remote fonts, HTML, payloads,
LLM calls, capture upload, automatic report history or external telemetry is added.

## Packaging and verification

Source installations can use the pdf optional dependency. The desktop build
includes pinned ReportLab and its image/text dependencies. PDF remains optional
to the headless CLI. No CLI flags or raw report schemas change.

The sample PDF generated for the user is based on supplied report text and clearly
labels itself a design preview, not capture re-analysis. It and the private source
text are not committed. Tests use synthetic documentation addresses/names.

Independent review, native/frozen UI acceptance, clean-machine installation,
accessibility/scaling, signing and public distribution remain separate gates.
