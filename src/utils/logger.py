"""
Logging utility for CodeGuardian
"""

import logging
import sys
from pathlib import Path
from datetime import datetime
import codecs

# Fix Windows console encoding BEFORE any logging
if sys.platform == 'win32':
    try:
        # Try modern Python 3.7+ method
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
    except (AttributeError, OSError):
        # Fallback for older Python or if reconfigure fails
        try:
            sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer, 'strict')
            sys.stderr = codecs.getwriter('utf-8')(sys.stderr.buffer, 'strict')
        except:
            # Last resort: just continue with default encoding
            pass


def setup_logger(name: str, log_level: str = "INFO") -> logging.Logger:
    """
    Set up a logger with console and file handlers.
    
    Args:
        name: Logger name
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        
    Returns:
        Configured logger
    """
    
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, log_level.upper()))
    
    # Avoid duplicate handlers
    if logger.handlers:
        return logger
    
    # Console handler with UTF-8 encoding
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    
    # Use a custom formatter that handles emojis gracefully
    class SafeFormatter(logging.Formatter):
        """Formatter that strips emojis if encoding fails"""
        def format(self, record):
            msg = super().format(record)
            try:
                # Test if message can be encoded
                msg.encode(sys.stdout.encoding or 'utf-8')
                return msg
            except (UnicodeEncodeError, AttributeError):
                # Strip emojis if encoding fails
                import re
                # Remove all emoji characters
                emoji_pattern = re.compile("["
                    u"\U0001F600-\U0001F64F"  # emoticons
                    u"\U0001F300-\U0001F5FF"  # symbols & pictographs
                    u"\U0001F680-\U0001F6FF"  # transport & map symbols
                    u"\U0001F1E0-\U0001F1FF"  # flags (iOS)
                    u"\U00002702-\U000027B0"
                    u"\U000024C2-\U0001F251"
                    "]+", flags=re.UNICODE)
                return emoji_pattern.sub('', msg)
    
    console_format = SafeFormatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    console_handler.setFormatter(console_format)
    
    # File handler - write without emojis to avoid encoding issues
    log_dir = Path("logs")
    log_dir.mkdir(exist_ok=True)
    
    log_file = log_dir / f"codeguardian_{datetime.now().strftime('%Y%m%d')}.log"
    file_handler = logging.FileHandler(log_file, encoding='utf-8')
    file_handler.setLevel(logging.DEBUG)
    
    # File format - simpler, no emojis
    file_format = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    file_handler.setFormatter(file_format)
    
    logger.addHandler(console_handler)
    logger.addHandler(file_handler)
    
    return logger


def get_logger(name: str, log_level: str = "INFO") -> logging.Logger:
    """
    Backward-compatible logger accessor used across modules.
    """
    return setup_logger(name, log_level)
