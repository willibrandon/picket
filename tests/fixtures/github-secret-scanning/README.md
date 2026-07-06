# GitHub Secret Scanning Fixture

This fixture is sanitized benchmark input for hosted-alert parity work. The alert
metadata never stores GitHub's raw `secret` value, and the source template uses a
placeholder that benchmark code replaces with a synthetic structurally valid
value at runtime.
