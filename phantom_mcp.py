import sys
import os

# Add assets/lib to path to find phantom package
# This keeps the root directory clean as requested
current_dir = os.path.dirname(os.path.abspath(__file__))
lib_path = os.path.join(current_dir, "assets", "lib")
if os.path.exists(lib_path):
    sys.path.insert(0, lib_path)

if __name__ == "__main__":
    try:
        from phantom.server import main
        main()
    except ImportError:
        # Fallback if phantom is still in root (during migration)
        try:
            from phantom.server import main
            main()
        except ImportError as e:
            print(f"Error: Could not load Phantom Server. Ensure 'phantom' package is in 'assets/lib' or root. Details: {e}", file=sys.stderr)
            sys.exit(1)
