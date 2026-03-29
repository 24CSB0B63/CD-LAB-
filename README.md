# LLVM SQL Injection Detection Compiler Pass

A static analysis tool built as an LLVM compiler pass to detect SQL injection vulnerabilities in C++ source code during the compilation process.

## Features

- **Taint Analysis Engine**: Tracks untrusted data from known sources (like `std::cin`, `getenv`, etc.) across variables, memory loads/stores, and string operations.
- **Inter-Procedural Tracking**: Propagates taint across function boundaries, including bi-directional argument tracking and return value analysis.
- **String Operation Awareness**: Specifically handles `std::string` concatenations (`operator+`), assignments, and accessors like `.c_str()` and `.data()`.
- **SQL Pattern Detection**: Heuristics to identify vulnerable SQL query constructions by detecting SQL keywords in concatenated strings.
- **Sanitization Support**: Recognizes common sanitization functions (e.g., `mysql_real_escape_string`) and clears the taint status accordingly.
- **Binary Instrumentation**: Automatically injects a `__sqli_warning` function call into the LLVM IR right before a vulnerable query execution point.
- **Visual Dashboard**: A web-based GUI for uploading C++ code and visualizing the "Taint Path" and Control Flow Graph (CFG) with source code line highlighting.

## Project Structure

- `src/`: Core implementation of the LLVM pass in C++.
- `tests/`: Suite of test cases (`safe`, `vulnerable`, `inter-procedural`) and a shell runner.
- `gui/`: Web application for visualization (Python/Cytoscape.js).
- `build/`: Compiled binaries and intermediate artifacts.

## Getting Started

### Prerequisites

- LLVM 18+ and Clang
- CMake
- Python 3

### Building the Pass

1. Create a build directory and run CMake:
   ```bash
   mkdir -p build && cd build
   cmake ../src
   make
   ```

### Running Tests

1. Navigate to the tests directory:
   ```bash
   cd tests
   ./run_tests.sh
   ```

### Using the GUI

1. Navigate to the gui directory:
   ```bash
   cd gui
   python3 app.py
   ```
2. Open `http://localhost:5000` in your browser.
3. Paste C++ code into the editor and click **Analyze Source** to see the taint path.

## How it Works

The pass operates on the LLVM Intermediate Representation (IR). It uses a fixed-point iteration algorithm to propagate "taint" labels from input sources to SQL sinks. If a tainted value reaches a sensitive database API call, the pass generates a warning and modifies the IR to include a security flag.
