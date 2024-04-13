import pefile
import sys

def extract_iat(pe_file):
    try:
        # Load the PE file
        pe = pefile.PE(pe_file)

        # Check if the file has an imports table
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            print(f"IAT for {pe_file}:")

            # Iterate over each entry in the imports table
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                print(f"Imports from {entry.dll.decode()}:")
                for imp in entry.imports:
                    address = hex(imp.address)
                    name = imp.name.decode() if imp.name else 'Ordinal Import'
                    print(f"    {address} {name}")
        else:
            print("No imports found.")
    
    except Exception as e:
        print(f"Error processing the file: {e}")

if __name__ == '__main__':
    if len(sys.argv) > 1:
        extract_iat(sys.argv[1])
    else:
        print("Please provide the path to the PE file as an argument.")
