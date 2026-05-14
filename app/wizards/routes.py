from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session as OrmSession

from app.auth.deps import require_permission
from app.db import fastapi_dep_db
from app.models.user import User
from app.wizards.engine import list_wizards, run_wizard

router = APIRouter(prefix="/wizards", tags=["wizards"])


class WizardSummary(BaseModel):
    key: str
    # Category + name are stored in the `wizards` table seeded by schema.sql;
    # for the first cut we expose just the keys and let the UI join the labels.


@router.get("/list")
async def list_available(user: User = Depends(require_permission("dns.sandbox"))) -> dict:
    return {"keys": list_wizards()}


class RunInput(BaseModel):
    wizard_key: str = Field(..., min_length=3, max_length=64)
    target: str = Field(..., min_length=1, max_length=253)


@router.post("/run")
async def run(
    request: Request,
    body: RunInput,
    user: User = Depends(require_permission("dns.sandbox")),
    db: OrmSession = Depends(fastapi_dep_db),
) -> dict:
    try:
        return await run_wizard(
            wizard_key=body.wizard_key,
            target=body.target,
            user=user,
            db=db,
        )
    except ValueError as e:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(e))
