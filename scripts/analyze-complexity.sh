#!/bin/bash
# Analyze Haskell code complexity metrics

echo "=== Haskell Code Complexity Analysis ==="
echo ""

echo "1. File Sizes (lines of code):"
find src -name "*.hs" -exec wc -l {} \; | sort -rn | head -10
echo ""

echo "2. Functions with most lines (approximate):"
echo "   (Functions with 30+ lines are considered long)"
echo ""

for file in src/**/*.hs; do
  if [ -f "$file" ]; then
    # Count function definitions and approximate their sizes
    awk '
    BEGIN { in_func=0; func_start=0; func_name="" }
    /^[a-zA-Z_][a-zA-Z0-9_]*\s*::/ { 
      if (in_func && func_name != "") {
        lines = NR - func_start
        if (lines > 30) print lines, func_name, FILENAME
      }
      func_name = $1
      func_start = NR
      in_func = 1
    }
    /^[a-zA-Z_][a-zA-Z0-9_]*\s*=/ && !/^[a-zA-Z_][a-zA-Z0-9_]*\s*::/ {
      if (in_func && func_name != "") {
        lines = NR - func_start
        if (lines > 30) print lines, func_name, FILENAME
      }
      func_name = $1
      func_start = NR
      in_func = 1
    }
    /^[a-z]/ && !/^[a-zA-Z_][a-zA-Z0-9_]*\s*(::|=)/ {
      if (in_func && func_name != "") {
        lines = NR - func_start
        if (lines > 30) print lines, func_name, FILENAME
        in_func = 0
      }
    }
    ' "$file" | sort -rn | head -5
  fi
done

echo ""
echo "3. Nesting depth analysis (case/if statements):"
for file in src/**/*.hs; do
  if [ -f "$file" ]; then
    max_depth=$(awk '
    BEGIN { depth=0; max_depth=0 }
    /case|if|do|let|where/ { depth++; if (depth > max_depth) max_depth = depth }
    /^[a-zA-Z]/ && !/^[a-zA-Z_][a-zA-Z0-9_]*\s*(::|=)/ { depth=0 }
    END { print max_depth }
    ' "$file")
    if [ "$max_depth" -gt 5 ]; then
      echo "   $file: max nesting depth = $max_depth"
    fi
  fi
done

echo ""
echo "4. Functions with many parameters (5+):"
grep -h "^[a-zA-Z_][a-zA-Z0-9_]*\s*::" src/**/*.hs | awk -F'->' '{print $1}' | awk -F'::' '{print $2}' | awk -F'->' '{print NF-1}' | awk '{if ($1 > 4) print $1}' | wc -l | xargs echo "   Functions with 5+ parameters:"

echo ""
echo "=== Recommendations ==="
echo "- Functions > 50 lines: Consider breaking into smaller functions"
echo "- Nesting depth > 5: Consider extracting helper functions"
echo "- Functions with 5+ parameters: Consider using records or data types"

