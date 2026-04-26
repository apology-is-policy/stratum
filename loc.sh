#!/bin/zsh

cloc v2 \
  --include-lang="C,C/C++ Header,Rust,Assembly,TLA+" \
  --exclude-dir=build,cmake-build-debug,cmake-build-release,CMakeFiles,.cache \
  --not-match-d='(^|/)\.(git|idea|vscode)$'
