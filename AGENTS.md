# Repository workflow

- Before modifying files, check the current Git branch.
- Never edit on `main` or `master`; create and switch to a short descriptive
  branch such as `codex/<task-summary>` first. Continue on an existing feature
  branch unless the user requests a new one.
- Automatically commit completed, coherent changes after appropriate validation.
  This is standing authorization to create local commits; do not wait for a
  separate request to commit each task.
- Inspect the diff and stage only files or hunks belonging to the current task.
  Do not include unrelated pre-existing changes or secrets.
- Use concise, descriptive commit messages. Report the commit hash and validation
  results when the task is complete.
- If validation fails or work is incomplete, report the issue and leave the work
  uncommitted unless the user requests a checkpoint commit.
- Do not amend existing commits, rewrite history, push, or open a pull request
  unless the user explicitly requests it.
- A newer user instruction takes precedence over these defaults.
