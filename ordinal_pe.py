import pefile
import sys

def find_ordinal(dll_path, function_name):
    try:
        pe = pefile.PE(dll_path)
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if exp.name.decode() == function_name:
                return exp.ordinal
    except Exception as e:
        print(f"Error: {e}")
    return None

def main():
    if len(sys.argv) != 3:
        print("Usage: python script.py [path_to_dll] [function_name]")
        sys.exit(1)

    dll_path = sys.argv[1]
    function_name = sys.argv[2]

    ordinal = find_ordinal(dll_path, function_name)
    if ordinal is not None:
        print(f"Function '{function_name}' has ordinal: {ordinal} (Decimal)")
    else:
        print(f"Function '{function_name}' not found.")

if __name__ == "__main__":
    main()
