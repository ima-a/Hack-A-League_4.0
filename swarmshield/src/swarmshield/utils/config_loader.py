"""
Configuration Loader

Helpers for loading and parsing YAML configuration files.
"""

import logging
from pathlib import Path
from typing import Dict, Any

import yaml

logger = logging.getLogger(__name__)


def load_yaml_config(config_path: str) -> Dict[str, Any]:
    """
    Load YAML configuration file.
    
    Args:
        config_path: Path to YAML config file
        
    Returns:
        Parsed configuration dictionary
    """
    try:
        config_file = Path(config_path)
        if not config_file.exists():
            logger.warning(f"Config file not found: {config_path}")
            return {}
        
        with open(config_file, 'r') as f:
            config = yaml.safe_load(f)
            logger.info(f"Loaded config from {config_path}")
            return config or {}
    
    except Exception as e:
        logger.error(f"Error loading config: {e}")
        return {}


def load_agents_config() -> Dict[str, Any]:
    """Load agents configuration."""
    config_dir = Path(__file__).parent.parent / "config"
    return load_yaml_config(str(config_dir / "agents.yaml"))


def load_tasks_config() -> Dict[str, Any]:
    """Load tasks configuration."""
    config_dir = Path(__file__).parent.parent / "config"
    return load_yaml_config(str(config_dir / "tasks.yaml"))


def load_tools_config() -> Dict[str, Any]:
    """Load tools configuration."""
    config_dir = Path(__file__).parent.parent / "config"
    return load_yaml_config(str(config_dir / "tools_config.yaml"))
