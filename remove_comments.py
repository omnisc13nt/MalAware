#!/usr/bin/env python3
import os
import re
import sys

def remove_cpp_comments(content):
    """Remove C++ style comments from source code while preserving strings."""
    # State tracking
    in_string = False
    in_char = False
    in_single_comment = False
    in_multi_comment = False
    escaped = False
    
    result = []
    i = 0
    length = len(content)
    
    while i < length:
        char = content[i]
        
        # Handle escape sequences
        if escaped:
            result.append(char)
            escaped = False
            i += 1
            continue
            
        if char == '\\' and (in_string or in_char):
            escaped = True
            result.append(char)
            i += 1
            continue
        
        # Handle string literals
        if char == '"' and not in_char and not in_single_comment and not in_multi_comment:
            in_string = not in_string
            result.append(char)
            i += 1
            continue
            
        # Handle character literals
        if char == "'" and not in_string and not in_single_comment and not in_multi_comment:
            in_char = not in_char
            result.append(char)
            i += 1
            continue
        
        # Skip if we're in a string or character literal
        if in_string or in_char:
            result.append(char)
            i += 1
            continue
        
        # Handle end of single-line comment
        if in_single_comment:
            if char == '\n':
                in_single_comment = False
                result.append(char)  # Keep the newline
            i += 1
            continue
        
        # Handle end of multi-line comment
        if in_multi_comment:
            if char == '*' and i + 1 < length and content[i + 1] == '/':
                in_multi_comment = False
                i += 2  # Skip both * and /
                continue
            i += 1
            continue
        
        # Check for start of comments
        if char == '/':
            if i + 1 < length:
                next_char = content[i + 1]
                if next_char == '/':
                    in_single_comment = True
                    i += 2
                    continue
                elif next_char == '*':
                    in_multi_comment = True
                    i += 2
                    continue
        
        # Regular character
        result.append(char)
        i += 1
    
    return ''.join(result)

def clean_whitespace(content):
    """Clean up excessive whitespace while preserving code structure."""
    lines = content.split('\n')
    cleaned_lines = []
    
    for line in lines:
        # Remove trailing whitespace
        line = line.rstrip()
        cleaned_lines.append(line)
    
    # Remove multiple consecutive empty lines
    result_lines = []
    empty_count = 0
    
    for line in cleaned_lines:
        if line.strip() == '':
            empty_count += 1
            if empty_count <= 2:  # Keep at most 2 consecutive empty lines
                result_lines.append(line)
        else:
            empty_count = 0
            result_lines.append(line)
    
    return '\n'.join(result_lines)

def process_file(filepath):
    """Process a single file to remove comments."""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Remove comments
        content = remove_cpp_comments(content)
        
        # Clean whitespace
        content = clean_whitespace(content)
        
        # Write back
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)
        
        print(f"Processed: {filepath}")
        
    except Exception as e:
        print(f"Error processing {filepath}: {e}")

def main():
    # Find all C++ source files
    extensions = ['.cpp', '.c', '.h', '.hpp']
    root_dir = '/workspaces/peFileParser'
    
    for root, dirs, files in os.walk(root_dir):
        # Skip certain directories
        if any(skip in root for skip in ['.git', '.venv', '__pycache__', 'theZoo']):
            continue
            
        for file in files:
            if any(file.endswith(ext) for ext in extensions):
                filepath = os.path.join(root, file)
                process_file(filepath)

if __name__ == "__main__":
    main()
