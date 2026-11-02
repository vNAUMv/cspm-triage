# AI-assisted development log

Short entries while working. One entry per notable moment.

## Template
- **Date / stage:**
- **Task given to the agent:**
- **What worked:**
- **What went wrong:** (hallucinated fields/APIs, wrong tests, insecure code, lost context...)
- **How I caught it:** (tests, docs, manual run, bandit...)
- **What I changed:** (prompt, CLAUDE.md rule, task size, approval mode)
- **Time saved / lost (rough):**

## Entries

- по умолчанию стоял auto mode, переключил на ручное подтверждение, потому что давать полный контроль агенту небезопасно
- One problem along the way: ruff first failed on 9 files because they had no newline at the end. I ran ruff check --fix to add them, and nothing else changed.