"""VSGuard MCP Server - Vulnerability Scanner & Guard for AI Coding Agents."""

import logging
import os
from typing import Optional

from fastmcp import FastMCP
from smithery.decorators import smithery
#from smithery.schema import ConfigSchema

from src.asvs.loader import get_asvs_collection
from src.config import settings
from src.utils.formatters import (
    format_fix_suggestion,
    format_scan_results,
    format_security_requirements,
)

# Configure logging
log_handlers = []

# Console handler
console_handler = logging.StreamHandler()
console_handler.setFormatter(
    logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
)
log_handlers.append(console_handler)

# File handler (if log file is specified)
log_file = os.environ.get("VSGUARD_LOG_FILE")
if log_file:
    file_handler = logging.FileHandler(log_file, mode="a")
    file_handler.setFormatter(
        logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    )
    log_handlers.append(file_handler)

logging.basicConfig(
    level=getattr(logging, settings.log_level), handlers=log_handlers, force=True
)
logger = logging.getLogger(__name__)



# Create FastMCP server
mcp = FastMCP("vsguard")


from src.scanners.semgrep_scanner import SemgrepScanner
from src.fixes.generator import FixGenerator

SCANNERS_AVAILABLE = True
logger.info("Security scanners loaded successfully")


@mcp.tool
def list_asvs_categories() -> str:
    """
    List all available ASVS 5.0 categories and chapters for search.
    
    Use this tool to discover what categories and chapters are available
    before calling check_security_requirements.
    
    Returns:
        Formatted list of all chapters and their categories with requirement counts
    """
    try:
        collection = get_asvs_collection()
        
        output = ["=" * 70]
        output.append("ASVS 5.0 CATEGORIES & CHAPTERS")
        output.append("=" * 70)
        
        # Group by chapter
        chapters_data = {}
        for req in collection.get_all():
            if req.chapter not in chapters_data:
                chapters_data[req.chapter] = {}
            if req.category not in chapters_data[req.chapter]:
                chapters_data[req.chapter][req.category] = 0
            chapters_data[req.chapter][req.category] += 1
        
        output.append(f"\n📊 Total: {len(chapters_data)} chapters, {len(collection.get_categories())} categories, {collection.count()} requirements\n")
        
        # Format output
        for chapter in sorted(chapters_data.keys()):
            categories = chapters_data[chapter]
            total_reqs = sum(categories.values())
            output.append(f"\n📘 Chapter: '{chapter}' ({total_reqs} requirements)")
            output.append("   Categories:")
            for category in sorted(categories.keys()):
                count = categories[category]
                output.append(f"     • '{category}' ({count} reqs)")
        
        output.append("\n" + "=" * 70)
        output.append("💡 USAGE EXAMPLES:")
        output.append("=" * 70)
        output.append("\n# Search by chapter (broad):")
        output.append("check_security_requirements(chapter='Authentication')")
        output.append("\n# Search by category (precise):")
        output.append("check_security_requirements(category='Password Security')")
        output.append("\n# Search with level filter (efficient):")
        output.append("check_security_requirements(category='Password Security', level=1)")
        
        return "\n".join(output)
    
    except Exception as e:
        logger.error(f"Error in list_asvs_categories: {e}", exc_info=True)
        return f"Error listing categories: {str(e)}"


@mcp.tool
def check_security_requirements(
    category: Optional[str] = None,
    chapter: Optional[str] = None,
    query: Optional[str] = None,
    level: Optional[str] = None,
    language: Optional[str] = None,
    context: Optional[str] = None,
) -> str:
    """
    PRIMARY TOOL: Get relevant OWASP ASVS 5.0 security requirements.
    
    Search by category (most precise), chapter (broader), or free-text query.
    Use level filter to reduce results and token usage.
    
    Always use the 'list_asvs_categories' tool first to see available categories and chapters.
    
    Args:
        category: ASVS category name (e.g., "Password Security")
        chapter: ASVS chapter name (e.g., "Authentication")
        query: Free-text search across requirements
        level: Filter by ASVS level - "1", "2", "3" for exact match, or "1,2" for multiple levels
               Examples: "1" (only L1), "1,2" (L1 and L2), "2,3" (L2 and L3)
        language: Programming language for context (optional)
        context: Additional context about what you're building (optional)
    
    Returns:
        Formatted ASVS requirements with implementation guidance
    
    Examples:
        # Precise:
        category="Password Security" → 12 requirements
        
        # Broad:
        chapter="Authentication" → 47 requirements
        
        # Filtered (exact level):
        category="Password Security", level="1" → ONLY L1 requirements
        
        # Multiple levels:
        category="Password Security", level="1,2" → L1 and L2 (not L3)
        
        # Natural language:
        query="brute force protection" → 2-5 requirements
    """
    try:
        # Parse level parameter (string to int or list[int])
        parsed_level: Optional[int | list[int]] = None
        if level:
            try:
                # Check if it's a comma-separated list
                if ',' in level:
                    parsed_level = [int(x.strip()) for x in level.split(',')]
                else:
                    parsed_level = int(level)
                
                # Validate level values
                levels_to_check = parsed_level if isinstance(parsed_level, list) else [parsed_level]
                for lvl in levels_to_check:
                    if lvl not in [1, 2, 3]:
                        return f"Error: Invalid level '{lvl}'. Must be 1, 2, or 3."
            except ValueError:
                return f"Error: Invalid level format '{level}'. Use '1', '2', '3', or comma-separated like '1,2'."
        
        # Validation
        if not any([category, chapter, query]):
            return (
                "Error: At least one of 'category', 'chapter', or 'query' must be provided.\n\n"
                "Examples:\n"
                "  • category='Password Security'\n"
                "  • chapter='Authentication'\n"
                "  • query='brute force protection'\n"
            )
        
        if category and chapter:
            return "Error: 'category' and 'chapter' are mutually exclusive. Use one or the other."
        
        logger.info(f"Checking requirements: category={category}, chapter={chapter}, query={query}, level={level}")
        
        # Load ASVS collection
        collection = get_asvs_collection()
        
        # Perform search based on parameters
        if category:
            requirements = collection.get_by_category(category)
            search_desc = f"category '{category}'"
        elif chapter:
            requirements = collection.get_by_chapter(chapter)
            search_desc = f"chapter '{chapter}'"
        elif query:
            requirements = collection.search(query=query)
            search_desc = f"query '{query}'"
        
        # Apply level filter (exact match or multiple levels)
        if parsed_level is not None:
            if isinstance(parsed_level, int):
                # Single level: exact match
                requirements = [r for r in requirements if r.level == parsed_level]
            elif isinstance(parsed_level, list):
                # Multiple levels: match any in list
                requirements = [r for r in requirements if r.level in parsed_level]
        else:
            # No level specified: use min_level from env var (backwards compatible)
            min_level = settings.min_asvs_level
            requirements = [r for r in requirements if r.level >= min_level]
        
        # Remove duplicates
        seen_ids = set()
        unique_requirements = []
        for req in requirements:
            if req.id not in seen_ids:
                seen_ids.add(req.id)
                unique_requirements.append(req)
        
        if not unique_requirements:
            return (
                f"No requirements found for {search_desc}.\n\n"
                "Try a broader search:\n"
                f"  • Use chapter instead of category\n"
                f"  • Use a different search term\n"
                f"  • Check spelling of category/chapter name\n"
            )
        
        logger.info(f"Found {len(unique_requirements)} requirements for {search_desc}")
        
        # Format output
        req_context = f"Requirements for {search_desc}"
        if parsed_level:
            if isinstance(parsed_level, int):
                req_context += f" (Level {parsed_level})"
            else:
                req_context += f" (Levels {', '.join(map(str, parsed_level))})"
        if language:
            req_context += f" in {language}"
        if context:
            req_context += f". Context: {context}"
        
        return format_security_requirements(
            unique_requirements, 
            context=req_context, 
            include_examples=True
        )
    
    except Exception as e:
        logger.error(f"Error in check_security_requirements: {e}", exc_info=True)
        return f"Error checking requirements: {str(e)}"


@mcp.tool
async def scan_code(
    code: str,
    language: str,
    filename: Optional[str] = None,
    context: Optional[str] = None,
) -> str:
    """
    Scan code for security vulnerabilities using static analysis. Do not use this tool unless user explicitly asks to scan/audit existing code.
    
    Detects SQL injection, XSS, weak cryptography, hardcoded secrets, and more.
    Returns findings with severity, ASVS mappings, and remediation guidance.
    
    Args:
        code: The code to analyze
        language: Programming language (python, javascript, java, etc.)
        filename: Filename for context (optional)
        context: What the code is supposed to do (optional)
        
    Returns:
        Detailed scan results with vulnerabilities, ASVS mappings, and fixes
    """
    try:
        logger.info(f"Scanning {language} code ({len(code)} chars)")

        # Check code size
        if len(code) > settings.max_code_size:
            return f"Error: Code size ({len(code)} chars) exceeds maximum ({settings.max_code_size} chars)"

        if not SCANNERS_AVAILABLE:
            return (
                "**Scanner Not Yet Implemented**\n\n"
                "The code scanner is being implemented. "
                "For now, please use the 'check_security_requirements' tool "
                "to understand security requirements before writing code.\n\n"
                f"Code to scan ({language}):\n```\n{code[:500]}...\n```"
            )

        # Initialize scanner
        scanner = SemgrepScanner()

        # Run scan
        results = await scanner.scan(
            code=code,
            language=language,
            filename=filename or f"input.{language}",
        )

        logger.info(f"Scan complete: {len(results)} findings")

        # Format output
        return format_scan_results(results, show_all=True)

    except Exception as e:
        logger.error(f"Error in scan_code: {e}", exc_info=True)
        return f"Error scanning code: {str(e)}"


@mcp.tool
async def suggest_fix(
    vulnerable_code: str,
    vulnerability_type: str,
    language: str,
    context: Optional[str] = None,
) -> str:
    """
    Generate secure code alternatives for vulnerabilities.
    
    Provides side-by-side comparison with explanation of changes.
    Returns code that satisfies ASVS requirements.
    Use this to GET SECURE IMPLEMENTATIONS of vulnerable code patterns.
    
    Args:
        vulnerable_code: Code with security issue
        vulnerability_type: Type of vulnerability (e.g., 'sql_injection', 'xss')
        language: Programming language
        context: Additional context (optional)
        
    Returns:
        Secure code alternative with explanation and ASVS requirements
    """
    try:
        logger.info(f"Generating fix for {vulnerability_type} in {language}")

        if not SCANNERS_AVAILABLE:
            return (
                "**Fix Generator Not Yet Implemented**\n\n"
                "The fix generator is being implemented. "
                "For now, please refer to the code examples in the ASVS requirements.\n\n"
                f"Vulnerability type: {vulnerability_type}\n"
                f"Language: {language}\n\n"
                "You can use 'check_security_requirements' to see secure code examples."
            )

        # Initialize fix generator
        fix_generator = FixGenerator()

        # Generate fix
        fix = await fix_generator.generate_fix(
            vulnerable_code=vulnerable_code,
            vulnerability_type=vulnerability_type,
            language=language,
            context=context,
        )

        # Format output
        return format_fix_suggestion(fix)

    except Exception as e:
        logger.error(f"Error in suggest_fix: {e}", exc_info=True)
        return f"Error generating fix: {str(e)}"


# # Startup logic
# def startup():
#     """Initialize server on startup."""
#     logger.info("🛡️  Starting VSGuard MCP Server")
#     logger.info(f"ASVS data directory: {settings.asvs_data_path}")
#     logger.info(f"Minimum ASVS level: {settings.min_asvs_level}")

#     # Pre-load ASVS requirements
#     try:
#         collection = get_asvs_collection()
#         logger.info(f"Loaded {collection.count()} ASVS requirements")
#         categories = collection.get_categories()
#         logger.info(f"Categories: {', '.join(categories)}")
#     except Exception as e:
#         logger.error(f"Failed to load ASVS requirements: {e}", exc_info=True)
#         logger.error("Server will start but check_security_requirements will fail")

#     logger.info("VSGuard MCP Server ready!")


# # Run startup
# startup()
@smithery.server() 
def create_server(): 
    return mcp

# Entry point
if __name__ == "__main__":
    create_server().run()
