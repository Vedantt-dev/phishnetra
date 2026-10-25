"""PhishNetra detection API."""
import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles

from app import db
from app.api.routes import router
from app.config import DASHBOARD_DIST, DEMO_DIR, OFFLINE, get_config
from app.layers import dom_model, url_model
from app.layers.reputation import intel

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("phishnetra")


async def _feed_refresher():
    minutes = get_config()["reputation"]["feed_refresh_minutes"]
    while True:
        try:
            count = await asyncio.to_thread(intel.refresh_openphish)
            log.info("OpenPhish feed refreshed: %d entries", count)
        except Exception as exc:  # noqa: BLE001
            log.warning("OpenPhish refresh failed: %s", exc)
        await asyncio.sleep(minutes * 60)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    db.init_db()
    url_model.load_model()
    dom_model.load_model()
    task = None
    if get_config()["reputation"].get("feed_enabled") and not OFFLINE:
        task = asyncio.create_task(_feed_refresher())
    yield
    if task:
        task.cancel()


db.init_db()  # idempotent; serverless runtimes may not run the lifespan hook

app = FastAPI(title="PhishNetra", version="1.0.0", lifespan=lifespan,
              description="Multi-layered AI-driven zero-trust phishing detection API")
app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"^(chrome-extension://.*|http://(localhost|127\.0\.0\.1)(:\d+)?)$",
    allow_methods=["*"],
    allow_headers=["*"],
)
app.include_router(router)


@app.get("/health")
def health():
    return {"status": "ok", "url_model": url_model.load_model() is not None,
            "dom_model": dom_model.load_model() is not None, "offline": OFFLINE}


app.mount("/demo", StaticFiles(directory=DEMO_DIR, html=True, check_dir=False), name="demo")
if DASHBOARD_DIST.exists():
    app.mount("/dashboard", StaticFiles(directory=DASHBOARD_DIST, html=True), name="dashboard")


@app.get("/")
def root():
    return RedirectResponse("/dashboard/" if DASHBOARD_DIST.exists() else "/docs")
