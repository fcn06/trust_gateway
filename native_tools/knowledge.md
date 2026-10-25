# Data Analyst Safe Sequencing Patterns

To analyze a dataset securely:
1. First run `inspect_schema` to understand dataset structure.
2. If authorized, run `sample_rows` to preview contents.
3. Compute statistics and aggregates using `compute_statistics`.
4. Perform cross-dataset operations or anomaly detection if needed.
5. Generate a finalized report via `generate_markdown`.
