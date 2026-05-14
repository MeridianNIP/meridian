from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
import uuid

from sqlalchemy import and_, select
from sqlalchemy.orm import Session as OrmSession

from app.audit.logger import record as audit
from app.models.audit import Approval
from app.models.user import User


class ApprovalError(Exception):
    pass


def request(
    db: OrmSession,
    *,
    requester: User,
    action: str,
    target_type: str | None,
    target_key: str | None,
    payload: dict[str, Any],
    justification: str,
    expires_hours: int = 24,
) -> Approval:
    if len(justification.strip()) < 10:
        raise ApprovalError("justification must be at least 10 characters")

    now = datetime.now(UTC)
    appr = Approval(
        id=uuid.uuid4(),
        requested_by=requester.id,
        action=action,
        target_type=target_type,
        target_key=target_key,
        payload=payload,
        justification=justification,
        state="pending",
        requested_at=now,
        expires_at=now + timedelta(hours=expires_hours),
    )
    db.add(appr)

    audit(
        db,
        user_id=requester.id,
        action="approval.requested",
        target_type="approval",
        target_key=str(appr.id),
        payload={"for_action": action, "for_target": target_key, "expires_in_h": expires_hours},
        justification=justification,
    )
    return appr


def decide(
    db: OrmSession,
    *,
    approval_id: uuid.UUID,
    approver: User,
    decision: str,  # 'approved' or 'denied'
    decision_note: str | None = None,
) -> Approval:
    if decision not in ("approved", "denied"):
        raise ApprovalError("decision must be 'approved' or 'denied'")

    appr = db.get(Approval, approval_id)
    if appr is None:
        raise ApprovalError("approval not found")
    if appr.state != "pending":
        raise ApprovalError(f"approval is {appr.state}, not pending")
    if appr.requested_by == approver.id:
        raise ApprovalError("cannot approve your own request (two-person rule)")

    now = datetime.now(UTC)
    if appr.expires_at <= now:
        appr.state = "expired"
        audit(
            db,
            action="approval.expired",
            target_type="approval",
            target_key=str(appr.id),
            payload={"for_action": appr.action},
        )
        raise ApprovalError("approval has expired")

    appr.state = decision
    appr.approver_id = approver.id
    appr.decided_at = now
    appr.decision_note = decision_note

    audit(
        db,
        user_id=approver.id,
        action=f"approval.{decision}",
        target_type="approval",
        target_key=str(appr.id),
        payload={
            "for_action": appr.action,
            "for_target": appr.target_key,
            "requester": str(appr.requested_by),
        },
        justification=decision_note or "",
        outcome="ok" if decision == "approved" else "denied",
    )
    return appr


def cancel(db: OrmSession, *, approval_id: uuid.UUID, by: User) -> Approval:
    appr = db.get(Approval, approval_id)
    if appr is None:
        raise ApprovalError("approval not found")
    if appr.state != "pending":
        raise ApprovalError(f"approval is {appr.state}, not pending")
    if appr.requested_by != by.id and by.role not in ("admin", "super_admin"):
        raise ApprovalError("only the requester or an admin can cancel")
    appr.state = "cancelled"
    appr.decided_at = datetime.now(UTC)

    audit(
        db,
        user_id=by.id,
        action="approval.cancelled",
        target_type="approval",
        target_key=str(appr.id),
        payload={"for_action": appr.action},
    )
    return appr


def list_pending(db: OrmSession, *, limit: int = 100) -> list[Approval]:
    now = datetime.now(UTC)
    return list(
        db.execute(
            select(Approval)
            .where(and_(Approval.state == "pending", Approval.expires_at > now))
            .order_by(Approval.requested_at.desc())
            .limit(limit)
        ).scalars()
    )


def list_mine(db: OrmSession, *, user: User, limit: int = 50) -> list[Approval]:
    return list(
        db.execute(
            select(Approval)
            .where(Approval.requested_by == user.id)
            .order_by(Approval.requested_at.desc())
            .limit(limit)
        ).scalars()
    )


def get_approved_for(db: OrmSession, *, action: str, target_key: str, requester: User) -> Approval | None:
    """Look up an approved + unexpired approval that authorizes a given action+target
    for the current requester. Used by handlers that want to verify they have a
    valid sign-off before executing a destructive operation.
    """
    now = datetime.now(UTC)
    return db.execute(
        select(Approval)
        .where(
            and_(
                Approval.state == "approved",
                Approval.action == action,
                Approval.target_key == target_key,
                Approval.requested_by == requester.id,
                Approval.expires_at > now,
            )
        )
        .order_by(Approval.decided_at.desc())
    ).scalar_one_or_none()
