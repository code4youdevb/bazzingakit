"""Carga y persistencia de configuración."""

from pathlib import Path
from typing import Optional

import yaml

from .models import BazzingakitConfig, DeviceProfile, Platform

DEFAULT_CONFIG_PATH = Path.home() / ".bazzingakit" / "config.yaml"


def get_config_path() -> Path:
    return DEFAULT_CONFIG_PATH


def load_config(path: Optional[Path] = None) -> BazzingakitConfig:
    """Carga configuración desde YAML, crea default si no existe."""
    path = path or get_config_path()

    if not path.exists():
        return BazzingakitConfig()

    with open(path, encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}

    return BazzingakitConfig(**data)


def save_config(config: BazzingakitConfig, path: Optional[Path] = None) -> None:
    """Persiste configuración a YAML."""
    path = path or get_config_path()
    path.parent.mkdir(parents=True, exist_ok=True)

    data = config.model_dump(mode="json", exclude_none=True)

    with open(path, "w", encoding="utf-8") as f:
        yaml.safe_dump(data, f, default_flow_style=False, sort_keys=False)


def init_config(force: bool = False) -> Path:
    """Crea directorio y archivo de config inicial."""
    path = get_config_path()

    if path.exists() and not force:
        return path

    config = BazzingakitConfig()
    config.paths.config_dir.mkdir(parents=True, exist_ok=True)
    config.paths.sessions_dir.mkdir(parents=True, exist_ok=True)
    config.paths.user_scripts_dir.mkdir(parents=True, exist_ok=True)

    save_config(config, path)
    return path


def add_profile(config: BazzingakitConfig, profile: DeviceProfile) -> BazzingakitConfig:
    config.profiles[profile.name] = profile
    if config.active_profile is None:
        config.active_profile = profile.name
    return config


def set_active_profile(config: BazzingakitConfig, name: str) -> BazzingakitConfig:
    if name not in config.profiles:
        raise ValueError(f"Perfil '{name}' no existe")
    config.active_profile = name
    return config


__all__ = [
    "BazzingakitConfig",
    "DeviceProfile",
    "Platform",
    "load_config",
    "save_config",
    "init_config",
    "add_profile",
    "set_active_profile",
    "get_config_path",
]
