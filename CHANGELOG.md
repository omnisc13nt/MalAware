# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.1] - 2025-07-25

### Added
- Explicit ignore rules for test_samples.sh in .gitignore
- Release directory structure for better organization
- Security policy and vulnerability reporting guidelines
- Contribution guidelines and code of conduct
- Comprehensive documentation updates

### Changed
- Improved .gitignore to better handle malware samples
- Enhanced documentation structure
- Updated build system for better cross-platform support

### Security
- Added malware sample isolation guidelines
- Improved handling of potentially malicious files

## [1.0.1] - 2025-07-25

### Fixed
- Cross-platform compilation issues in FuzzyHashCalculator
  - Added proper `#ifdef NO_FUZZY_HASH` guards for fuzzy.h dependencies
  - Added `[[maybe_unused]]` attributes to prevent Windows build warnings
  - Implemented default return value (-1) for disabled SSDeep functions
  - Removed duplicate code blocks and improved formatting
  - Fixed unused parameter warnings in Windows builds

### Added
- Graceful fallback messages for Windows builds
  - Clear indication when SSDeep features are unavailable
  - Proper error handling for platform-specific limitations

### Technical
- Modified: `src/FuzzyHashCalculator.cpp`
  - Added conditional compilation guards
  - Improved cross-platform compatibility
  - Maintained Linux functionality
- Build System
  - Clean Windows builds with no warnings
  - Static linking of GCC and STL libraries
  - Optimized binary size

