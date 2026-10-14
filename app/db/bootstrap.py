from __future__ import annotations

import os
from collections.abc import Callable
from typing import Any

from sqlalchemy.orm import Session


def _is_truthy(value: str | None) -> bool:
    if value is None:
        return False
    return value.strip().lower() in {"1", "true", "yes", "on"}


def init_db(base: Any, engine: Any) -> None:
    base.metadata.create_all(bind=engine)


def maybe_seed_sample_data(
    session_factory: Callable[[], Session],
    seed_fn: Callable[[Session], None],
    env_var: str = "SEED_SAMPLE_DATA",
) -> bool:
    if not _is_truthy(os.getenv(env_var)):
        return False

    with session_factory() as db:
        seed_fn(db)
        db.commit()

    return True
