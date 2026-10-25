import os
import tempfile
import warnings

warnings.filterwarnings("ignore", message="urllib3 v2 only supports OpenSSL")
os.environ["PHISHNETRA_OFFLINE"] = "1"
_tmp = tempfile.mkdtemp()
os.environ["PHISHNETRA_DB"] = f"sqlite:///{_tmp}/test.db"
os.environ["PHISHNETRA_STATE_DIR"] = _tmp
