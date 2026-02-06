import asyncio
import importlib.util
import sys
import types
import os

# Ensure project root is on path so 'app' package can be imported
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

def run_module(module_path):
    spec = importlib.util.spec_from_file_location("testmod", module_path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

def run_tests_in_module(mod):
    failures = 0
    for name in dir(mod):
        if name.startswith("test_") and callable(getattr(mod, name)):
            fn = getattr(mod, name)
            try:
                if asyncio.iscoroutinefunction(fn):
                    asyncio.run(fn())
                else:
                    fn()
                print(f"PASS {mod.__name__}.{name}")
            except Exception as e:
                failures += 1
                print(f"FAIL {mod.__name__}.{name}: {e}")
    return failures

def main():
    tests = [
        "test_unsubscribe_header_parser.py",
        "test_unsubscribe_execution.py",
    ]
    total_fail = 0
    for t in tests:
        path = __file__.replace("run_tests_simple.py", t)
        mod = run_module(path)
        total_fail += run_tests_in_module(mod)
    if total_fail:
        print(f"{total_fail} test(s) failed")
        sys.exit(1)
    print("All tests passed")

if __name__ == '__main__':
    main()
