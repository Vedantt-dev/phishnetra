from collections import Counter, defaultdict
from datetime import timedelta
from typing import List, Optional

from fastapi import APIRouter, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.concurrency import run_in_threadpool
from sqlalchemy import select

from app import db, scanner
from app.api.live import hub
from app.features.domain import parse_url
from app.layers import dom_model, url_model
from app.layers.reputation import intel
from app.schemas import DomScanRequest, FeedbackRequest, OverrideRequest, ScanRequest, ScanResult

router = APIRouter(prefix="/api/v1")


def _row_to_result(row: db.Scan) -> dict:
    return {
        "scan_id": row.id, "url": row.url, "domain": row.domain, "stage": row.stage,
        "risk": row.risk, "verdict": row.verdict, "trust": row.trust,
        "impersonated_brand": row.impersonated_brand, "reasons": row.reasons,
        "layers": row.layers, "latency_ms": row.latency_ms, "cached": False,
        "created_at": row.created_at, "overridden": row.overridden, "source": row.source,
    }


@router.post("/scan", response_model=ScanResult)
async def scan(req: ScanRequest):
    result = await run_in_threadpool(scanner.scan_url, req.url, req.source, req.network)
    if not result.get("cached"):
        await hub.broadcast({"type": "scan", "scan": result})
    return result


@router.post("/scan/dom", response_model=ScanResult)
async def scan_dom(req: DomScanRequest):
    result = await run_in_threadpool(scanner.scan_dom, req)
    await hub.broadcast({"type": "scan", "scan": result})
    return result


@router.get("/scans")
def list_scans(limit: int = Query(50, le=500), verdict: Optional[str] = None, q: Optional[str] = None):
    with db.SessionLocal() as session:
        stmt = select(db.Scan).order_by(db.Scan.id.desc()).limit(limit)
        if verdict:
            stmt = stmt.where(db.Scan.verdict == verdict.upper())
        if q:
            stmt = stmt.where(db.Scan.url.contains(q))
        return [_row_to_result(r) for r in session.scalars(stmt)]


@router.get("/scans/{scan_id}")
def get_scan(scan_id: int):
    with db.SessionLocal() as session:
        row = session.get(db.Scan, scan_id)
        if not row:
            raise HTTPException(404, "scan not found")
        return _row_to_result(row)


@router.get("/stats")
def stats(days: int = Query(14, ge=1, le=90)):
    since = db.utcnow() - timedelta(days=days)
    with db.SessionLocal() as session:
        rows: List[db.Scan] = list(session.scalars(select(db.Scan).where(db.Scan.created_at >= since)))
        feedback = Counter(f.label for f in session.scalars(select(db.Feedback)))

    verdicts = Counter(r.verdict for r in rows)
    timeline = defaultdict(Counter)
    layer_scores = defaultdict(list)
    for r in rows:
        timeline[r.created_at.date().isoformat()][r.verdict] += 1
        for layer in r.layers:
            if layer.get("available"):
                layer_scores[layer["name"]].append(layer["score"])
    day_keys = [(db.utcnow() - timedelta(days=i)).date().isoformat() for i in range(days - 1, -1, -1)]
    threats = [r for r in rows if r.verdict in ("BLOCK", "RESTRICT")]
    return {
        "window_days": days,
        "total_scans": len(rows),
        "unique_domains": len({r.domain for r in rows}),
        "verdicts": {v: verdicts.get(v, 0) for v in ("ALLOW", "WARN", "RESTRICT", "BLOCK")},
        "threats_mitigated": len(threats),
        "overrides": sum(1 for r in rows if r.overridden),
        "avg_latency_ms": round(sum(r.latency_ms or 0 for r in rows) / len(rows), 1) if rows else 0,
        "avg_risk": round(sum(r.risk for r in rows) / len(rows), 1) if rows else 0,
        "timeline": [{"date": d, **{v: timeline[d].get(v, 0) for v in ("ALLOW", "WARN", "RESTRICT", "BLOCK")}}
                     for d in day_keys],
        "top_brands": [{"brand": b, "count": c} for b, c in
                       Counter(r.impersonated_brand for r in rows if r.impersonated_brand).most_common(8)],
        "top_threat_domains": [{"domain": d, "count": c} for d, c in
                               Counter(r.domain for r in threats).most_common(8)],
        "layer_avg": {k: round(sum(v) / len(v), 1) for k, v in layer_scores.items()},
        "feedback": dict(feedback),
        "blocklist_size": len(intel.blocklist()),
    }


@router.get("/blocklist")
def blocklist():
    return {"domains": intel.blocklist()}


@router.post("/feedback")
def feedback(req: FeedbackRequest):
    with db.SessionLocal() as session:
        session.add(db.Feedback(url=req.url, label=req.label, scan_id=req.scan_id, comment=req.comment))
        session.commit()
    if req.label == "phishing":
        intel.add_block(req.url)
    else:
        intel.add_allow(parse_url(req.url).registrable)
    scanner.cache.clear()
    return {"ok": True}


@router.post("/override")
def override(req: OverrideRequest):
    """User chose to proceed past a warning — recorded for audit, never silently trusted."""
    with db.SessionLocal() as session:
        row = session.get(db.Scan, req.scan_id)
        if not row:
            raise HTTPException(404, "scan not found")
        row.overridden = True
        session.commit()
    return {"ok": True}


@router.get("/models")
def models():
    url_m, dom_m = url_model.load_model(), dom_model.load_model()
    return {
        "url_model": url_m.meta if url_m else None,
        "dom_model": {k: v for k, v in dom_m.items() if k != "model"} if dom_m else None,
    }


@router.websocket("/ws/live")
async def live(ws: WebSocket):
    await hub.connect(ws)
    try:
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        hub.disconnect(ws)
