# Save and revisit reports

`--output FILE` is available on `investigate`, `quality`, `tcp`, `dns`, `inspect`,
and `compare`. Without it, existing stdout and terminal behavior are unchanged.

```powershell
packet-investigator investigate capture.pcapng --output investigation.txt
packet-investigator investigate capture.pcapng --json --output investigation.json
packet-investigator dns capture.pcapng --details --output dns-details.txt
packet-investigator compare left.pcapng right.pcapng --assume-synchronized --output comparison.txt
```

Only assert synchronized clocks when independently verified. Other comparison
clock options retain their existing meaning.

## Formats and retained evidence

- Text files are UTF-8 with LF line endings, no terminal colors, and a fixed
  120-column layout. They use the existing readable report and its explicit
  omission notices. `--details` expands DNS evidence in `dns` and `investigate`.
- `--json --output FILE` saves the complete versioned JSON document, including
  retained transactions and conversations beyond terminal preview limits.
- The `--json` flag selects the format; a `.json` extension alone does not.
- Successful saving prints no duplicate report or confirmation to stdout/stderr.
  Check the destination file and the command exit status.
- Saved reports keep each command's existing privacy behavior. In particular,
  `inspect` metadata includes the resolved capture path, while the quality,
  TCP, DNS, combined investigation and comparison reports retain their path privacy.
  Endpoint addresses, ports, filenames and DNS names remain potentially sensitive.

## Safe creation and failures

Choose a new filename in an existing writable directory. The command never
replaces an existing file, directory, hard link or symbolic link, even if another
process creates the destination during saving. Using an input capture as the
output is refused. There is no force-overwrite option, and missing directories
are not created automatically.

Analysis and rendering finish before file publication. The report is staged in
an exclusively created sibling temporary file and published without replacement.
A failed analysis, renderer or write does not publish a partial destination report;
temporary files are cleaned up on handled failures. Windows uses no-replacement
rename; Unix uses a same-directory hard link followed by temporary-name cleanup.
A Unix filesystem without hard-link support will fail safely rather than overwrite
an existing destination. This protects complete publication, not durability across
power loss or guarantees about files changed later by other processes.

After successful saving, the command retains its usual analysis exit code:
0, 1 or 2 depending on that command and report status. A report can therefore be
saved successfully even when evidence is limited or insufficient. An output-file
failure instead emits a concise error on stderr and exits 1. Input/analysis errors
retain their existing exit codes and do not create a report. File-error messages
omit absolute destination paths.

Regression coverage includes Unicode/spaced filenames, both formats for all six
commands, complete JSON beyond display limits, details mode, existing captures,
file-creation races, partial-write and publication failures, explicit permissions
errors, missing directories and generated offline real-TShark acceptance. Filesystem
link cases skip only when the test environment cannot create the required links;
those skips are reported separately from executed checks.
