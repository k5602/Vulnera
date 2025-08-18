#!/bin/bash

# Dependency Vulnerability Analyzer - Easy Run Script
# This script provides convenient ways to run the vulnerability analyzer

set -e  # Exit on any error

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ANALYZER_SCRIPT="$SCRIPT_DIR/vulnerability_analyzer.py"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_color() {
    printf "${1}${2}${NC}\n"
}

# Function to show usage
show_usage() {
    echo "Dependency Vulnerability Analyzer - Run Script"
    echo "============================================="
    echo ""
    echo "Usage: $0 [OPTIONS] <requirements_file>"
    echo ""
    echo "Options:"
    echo "  -h, --help          Show this help message"
    echo "  -f, --format FORMAT Output format (text|html) [default: text]"
    echo "  -o, --output FILE   Output file path [default: stdout]"
    echo "  -k, --api-key KEY   API key for vulnerability database"
    echo "  -t, --test          Run tests instead of analysis"
    echo "  -e, --example       Run example usage demonstrations"
    echo "  -s, --sample        Analyze the sample requirements file"
    echo ""
    echo "Examples:"
    echo "  $0 requirements.txt                    # Basic analysis"
    echo "  $0 -f html -o report.html requirements.txt  # HTML report"
    echo "  $0 -s                                  # Analyze sample file"
    echo "  $0 -t                                  # Run tests"
    echo "  $0 -e                                  # Run examples"
    echo ""
}

# Function to check if Python is available
check_python() {
    if ! command -v python3 &> /dev/null; then
        print_color $RED "Error: Python 3 is required but not installed."
        print_color $YELLOW "Please install Python 3.6 or higher."
        exit 1
    fi

    # Check Python version
    python_version=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
    required_version="3.6"

    if ! python3 -c "import sys; exit(0 if sys.version_info >= (3, 6) else 1)" 2>/dev/null; then
        print_color $RED "Error: Python 3.6 or higher is required."
        print_color $YELLOW "Current version: $python_version"
        exit 1
    fi
}

# Function to check if analyzer script exists
check_analyzer_script() {
    if [[ ! -f "$ANALYZER_SCRIPT" ]]; then
        print_color $RED "Error: vulnerability_analyzer.py not found in $SCRIPT_DIR"
        print_color $YELLOW "Please ensure the script is in the same directory as this runner."
        exit 1
    fi
}

# Function to run tests
run_tests() {
    print_color $BLUE "Running vulnerability analyzer tests..."

    if [[ -f "$SCRIPT_DIR/test_analyzer.py" ]]; then
        cd "$SCRIPT_DIR"
        python3 test_analyzer.py
    else
        print_color $YELLOW "Warning: test_analyzer.py not found. Skipping tests."
        return 1
    fi
}

# Function to run examples
run_examples() {
    print_color $BLUE "Running vulnerability analyzer examples..."

    if [[ -f "$SCRIPT_DIR/example_usage.py" ]]; then
        cd "$SCRIPT_DIR"
        python3 example_usage.py
    else
        print_color $YELLOW "Warning: example_usage.py not found. Skipping examples."
        return 1
    fi
}

# Function to analyze sample file
analyze_sample() {
    local sample_file="$SCRIPT_DIR/sample_requirements.txt"

    if [[ ! -f "$sample_file" ]]; then
        print_color $YELLOW "Sample requirements file not found. Creating one..."
        create_sample_file "$sample_file"
    fi

    print_color $BLUE "Analyzing sample requirements file..."
    python3 "$ANALYZER_SCRIPT" "$sample_file" "${analyzer_args[@]}"
}

# Function to create sample requirements file if it doesn't exist
create_sample_file() {
    local file_path="$1"

    cat > "$file_path" << 'EOF'
# Sample requirements.txt for testing
django==3.2.0
flask==1.1.0
requests==2.25.0
pandas==1.3.0
pillow==8.0.0
cryptography==3.0.0
pyjwt==1.7.0
setuptools
EOF

    print_color $GREEN "Created sample requirements file: $file_path"
}

# Function to validate file exists
validate_file() {
    local file_path="$1"

    if [[ ! -f "$file_path" ]]; then
        print_color $RED "Error: File '$file_path' not found."
        exit 1
    fi

    if [[ ! -r "$file_path" ]]; then
        print_color $RED "Error: File '$file_path' is not readable."
        exit 1
    fi
}

# Main function
main() {
    local requirements_file=""
    local format="text"
    local output=""
    local api_key=""
    local run_tests_flag=false
    local run_examples_flag=false
    local analyze_sample_flag=false

    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_usage
                exit 0
                ;;
            -f|--format)
                format="$2"
                shift 2
                ;;
            -o|--output)
                output="$2"
                shift 2
                ;;
            -k|--api-key)
                api_key="$2"
                shift 2
                ;;
            -t|--test)
                run_tests_flag=true
                shift
                ;;
            -e|--example)
                run_examples_flag=true
                shift
                ;;
            -s|--sample)
                analyze_sample_flag=true
                shift
                ;;
            -*)
                print_color $RED "Unknown option: $1"
                show_usage
                exit 1
                ;;
            *)
                if [[ -z "$requirements_file" ]]; then
                    requirements_file="$1"
                else
                    print_color $RED "Multiple files specified. Please specify only one requirements file."
                    exit 1
                fi
                shift
                ;;
        esac
    done

    # Check prerequisites
    check_python
    check_analyzer_script

    # Handle special modes
    if [[ "$run_tests_flag" == true ]]; then
        run_tests
        exit $?
    fi

    if [[ "$run_examples_flag" == true ]]; then
        run_examples
        exit $?
    fi

    if [[ "$analyze_sample_flag" == true ]]; then
        # Build analyzer arguments
        analyzer_args=()
        [[ -n "$format" ]] && analyzer_args+=(--format "$format")
        [[ -n "$output" ]] && analyzer_args+=(--output "$output")
        [[ -n "$api_key" ]] && analyzer_args+=(--api-key "$api_key")

        analyze_sample
        exit $?
    fi

    # Validate requirements file is provided
    if [[ -z "$requirements_file" ]]; then
        print_color $RED "Error: Requirements file is required."
        echo ""
        show_usage
        exit 1
    fi

    # Validate requirements file exists
    validate_file "$requirements_file"

    # Validate format
    if [[ "$format" != "text" && "$format" != "html" ]]; then
        print_color $RED "Error: Format must be 'text' or 'html'."
        exit 1
    fi

    # Build analyzer command arguments
    analyzer_args=("$requirements_file")
    [[ -n "$format" ]] && analyzer_args+=(--format "$format")
    [[ -n "$output" ]] && analyzer_args+=(--output "$output")
    [[ -n "$api_key" ]] && analyzer_args+=(--api-key "$api_key")

    # Set API key environment variable if provided
    if [[ -n "$api_key" ]]; then
        export VULNERABILITY_API_KEY="$api_key"
    fi

    # Run the analyzer
    print_color $BLUE "Starting vulnerability analysis..."
    print_color $BLUE "File: $requirements_file"
    print_color $BLUE "Format: $format"
    [[ -n "$output" ]] && print_color $BLUE "Output: $output"
    echo ""

    cd "$SCRIPT_DIR"
    python3 "$ANALYZER_SCRIPT" "${analyzer_args[@]}"

    local exit_code=$?

    if [[ $exit_code -eq 0 ]]; then
        print_color $GREEN "Analysis completed successfully!"
        if [[ -n "$output" ]]; then
            print_color $GREEN "Report saved to: $output"
        fi
    else
        print_color $RED "Analysis failed with exit code: $exit_code"
    fi

    exit $exit_code
}

# Check if script is being sourced or executed
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
