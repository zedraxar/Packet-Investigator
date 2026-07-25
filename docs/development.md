# Development workflow

Use the repository's virtual environment and keep each change focused:

1. Activate the virtual environment:

   ```bash
   source .venv/bin/activate
   ```

2. Install the project in editable mode with development dependencies:

   ```bash
   python -m pip install --editable ".[dev]"
   ```

3. Implement one focused change.

4. Run Ruff linting:

   ```bash
   ruff check .
   ```

5. Check Ruff formatting:

   ```bash
   ruff format --check .
   ```

6. Run static type checking:

   ```bash
   mypy src
   ```

7. Run the test suite:

   ```bash
   pytest
   ```

8. Review the complete Git diff:

   ```bash
   git diff --check
   git diff
   git status --short
   ```

9. Commit only after the diff has been reviewed and approved:

   ```bash
   git add <reviewed-files>
   git commit
   ```
