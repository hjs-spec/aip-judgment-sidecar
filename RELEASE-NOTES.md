# Release 0.2.0

Reject missing/invalid request context before signing. Without an explicit policy evaluator, issue an `undetermined` receipt; evaluator failures abort issuance. Bind stable public-key fingerprints into signed receipts and expose integrity verification using caller-trusted keys.

Fix the documented installation of the src-layout package. Label this AIP prototype's versioned envelope and preserved sorted-ASCII signature format explicitly, independently of JEP-Core-0.6. Historical signed receipts are not rewritten.
