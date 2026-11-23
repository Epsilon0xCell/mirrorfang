import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from mirrorfang.validator import main
if __name__ == "__main__":
    main()
