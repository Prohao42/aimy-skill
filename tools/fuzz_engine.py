import itertools, time, concurrent.futures
from typing import Callable, Dict, Any, List

from tools.log_utils import get_logger

logger = get_logger("fuzz_engine")

class FuzzEngine:
    def __init__(self, threads: int = 5, delay: float = 0):
        self.threads = threads
        self.delay = delay

    def fuzz(self, payloads: List[str], target_fn: Callable, **fixed_kw) -> List[Dict]:
        results = []
        def _test(p):
            if self.delay > 0:
                time.sleep(self.delay)
            try:
                r = target_fn(payload=p, **fixed_kw)
                return {"payload": p, "result": r}
            except Exception as e:
                logger.debug("fuzz %s: %s", str(p)[:30], e)
                return {"payload": p, "error": True}
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as ex:
            for res in ex.map(_test, payloads):
                results.append(res)
        return results

    def product_fuzz(self, param_sets: List[List[str]], target_fn: Callable) -> List[Dict]:
        results = []
        for combo in itertools.product(*param_sets):
            try:
                r = target_fn(**dict(zip(["p%d" % i for i in range(len(combo))], combo)))
                results.append({"params": combo, "result": r})
            except Exception as e:
                logger.debug("product_fuzz %s: %s", combo, e)
                results.append({"params": combo, "error": True})
        return results
