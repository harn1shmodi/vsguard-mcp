"""VSGuard MCP Server - Vulnerability Scanner & Guard for AI Coding Agents."""

import logging
import os
from typing import Optional

from fastmcp import FastMCP
from smithery.decorators import smithery
#from smithery.schema import ConfigSchema

from src.asvs.loader import get_asvs_collection
from src.asvs.mapper import get_asvs_mapper
from src.config import settings
from src.models import CodeType
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
mcp = FastMCP(
    "vsguard",
    dependencies=["semgrep", "pyyaml", "pydantic"]
)


from src.scanners.semgrep_scanner import SemgrepScanner
from src.fixes.generator import FixGenerator

SCANNERS_AVAILABLE = True
logger.info("Security scanners loaded successfully")


@mcp.tool
def check_security_requirements(
    code_type: CodeType,
    language: Optional[str] = None,
    context: Optional[str] = None,
) -> str:
    """
    Get relevant OWASP ASVS security requirements for a specific code pattern or security domain.
    
    Returns detailed requirements with implementation guidance and code examples.
    Use this BEFORE writing security-critical code to understand requirements.
    
    Args:
        code_type: Type of code pattern (authentication, cryptography, input_validation, etc.)
        language: Programming language for language-specific examples (optional)
        context: Additional context about what you're building (optional)
        
    Returns:
        Formatted ASVS requirements with implementation guidance and code examples
    """
    try:
        logger.info(f"Checking security requirements for: {code_type.value}")

        # Load ASVS collection
        collection = get_asvs_collection()
        mapper = get_asvs_mapper()

        # Get relevant categories for this code type
        categories = mapper.map_code_type_to_categories(code_type)

        # Gather requirements from these categories
        requirements = []
        for category in categories:
            reqs = collection.get_by_category(category)
            requirements.extend(reqs)

        # Filter by minimum ASVS level
        requirements = [r for r in requirements if r.level >= settings.min_asvs_level]

        # Remove duplicates (by ID)
        seen_ids = set()
        unique_requirements = []
        for req in requirements:
            if req.id not in seen_ids:
                seen_ids.add(req.id)
                unique_requirements.append(req)

        logger.info(f"Found {len(unique_requirements)} relevant requirements")

        # Format output
        req_context = f"Requirements for {code_type.value}"
        if language:
            req_context += f" in {language}"
        if context:
            req_context += f". Context: {context}"

        return format_security_requirements(
            unique_requirements, context=req_context, include_examples=True
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
    Scan code for security vulnerabilities using static analysis.
    
    Detects SQL injection, XSS, weak cryptography, hardcoded secrets, and more.
    Returns findings with severity, ASVS mappings, and remediation guidance.
    Use this to VALIDATE code security after implementation.
    
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
                "⚠️ **Scanner Not Yet Implemented**\n\n"
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
                "⚠️ **Fix Generator Not Yet Implemented**\n\n"
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
#         logger.info(f"✅ Loaded {collection.count()} ASVS requirements")
#         categories = collection.get_categories()
#         logger.info(f"📋 Categories: {', '.join(categories)}")
#     except Exception as e:
#         logger.error(f"❌ Failed to load ASVS requirements: {e}", exc_info=True)
#         logger.error("Server will start but check_security_requirements will fail")

#     logger.info("🚀 VSGuard MCP Server ready!")


# # Run startup
# startup()
@smithery.server() 
def create_server(): 
    return mcp

# Entry point
if __name__ == "__main__":
    create_server().run()
