"""App Textual de bazzingakit.

Pestañas:
  - Dashboard   : resumen de config, perfil activo y conteos.
  - Dispositivo : estado del device del perfil activo (adb/ssh), bajo demanda.
  - Sesiones    : explorador de sesiones persistidas + sus findings.
  - Scripts     : catálogo de scripts Frida del registry (offline).
  - Análisis    : demo del pipeline EventAnalyzer -> Recommender en vivo.

Las operaciones que tocan el dispositivo (adb/ssh, pull de APK) corren en un
worker en hilo para no congelar la UI.
"""

from __future__ import annotations

import time
from typing import Optional

from textual import work
from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.widgets import (
    Button,
    DataTable,
    Footer,
    Header,
    Input,
    Label,
    RichLog,
    Static,
    TabbedContent,
    TabPane,
)

from bazzingakit import __version__
from bazzingakit.config import BazzingakitConfig, load_config


# --------------------------------------------------------------------------- #
# Helpers de acceso al core (todo tolerante a fallos: la TUI nunca debe caerse
# porque falte una dependencia opcional o un dispositivo).
# --------------------------------------------------------------------------- #
def _safe_config() -> BazzingakitConfig:
    try:
        return load_config()
    except Exception:
        return BazzingakitConfig()


def _session_manager(cfg: BazzingakitConfig):
    from bazzingakit.core import SessionManager

    return SessionManager(cfg.paths.sessions_dir)


# Eventos sintéticos para la demo del pipeline de análisis. En uso real estos
# llegan desde el script Frida reactive_probe.js a través de FridaManager.
_DEMO_EVENTS: list[dict] = [
    {"event": "build_prop", "fingerprint": "generic/sdk_gphone_x86/emulator"},
    {"event": "rasp_indicator", "rasp": "promon_shield",
     "class": "com.promon.shield.AntiHook"},
    {"event": "rasp_indicator", "rasp": "promon_shield",
     "class": "com.promon.shield.IntegrityCheck"},
    {"event": "file_exists", "path": "/system/bin/su"},
    {"event": "file_exists", "path": "/system/app/Superuser.apk"},
    {"event": "runtime_exec", "command": "which su"},
    {"event": "exception", "type": "SSLPeerUnverifiedException",
     "message": "Certificate pinning failure for api.banco.app"},
    {"event": "ui_text", "widget": "TextView",
     "text": "Dispositivo rooteado detectado", "blocking_keyword": "rooteado"},
    {"event": "system_exit", "code": 0, "caller": "SecurityManager.enforce"},
]


class BazzingakitTUI(App):
    """Interfaz de texto para bazzingakit."""

    TITLE = "bazzingakit"
    SUB_TITLE = f"TUI v{__version__}"

    CSS = """
    Screen { layout: vertical; }

    TabbedContent { height: 1fr; }

    #dashboard-body { padding: 1 2; }
    .card {
        border: round $panel-lighten-2;
        padding: 1 2;
        margin: 0 0 1 0;
    }
    .card-title { text-style: bold; color: $accent; }

    #device-status, #session-detail {
        border: round $panel-lighten-2;
        padding: 1 2;
        height: 1fr;
    }

    .toolbar { height: auto; padding: 1 2 0 2; }
    .toolbar Button { margin: 0 1 0 0; }

    Input { margin: 0 1 0 0; width: 1fr; }

    DataTable { height: 1fr; }

    RichLog {
        border: round $panel-lighten-2;
        padding: 0 1;
        height: 1fr;
    }

    .hint { color: $text-muted; padding: 1 2; }
    """

    BINDINGS = [
        ("r", "refresh", "Refrescar"),
        ("d", "toggle_dark", "Claro/Oscuro"),
        ("q", "quit", "Salir"),
    ]

    def __init__(self) -> None:
        super().__init__()
        self.cfg: BazzingakitConfig = _safe_config()

    # ------------------------------------------------------------------ #
    # Composición
    # ------------------------------------------------------------------ #
    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with TabbedContent(initial="tab-dashboard"):
            with TabPane("Dashboard", id="tab-dashboard"):
                with VerticalScroll(id="dashboard-body"):
                    yield Static(id="dash-content")
            with TabPane("Dispositivo", id="tab-device"):
                with Horizontal(classes="toolbar"):
                    yield Button("Comprobar dispositivo", id="btn-device", variant="primary")
                yield Static("Pulsa «Comprobar dispositivo» para consultar el estado.",
                             id="device-status")
            with TabPane("Sesiones", id="tab-sessions"):
                with Horizontal(classes="toolbar"):
                    yield Button("Refrescar", id="btn-sessions", variant="primary")
                with Horizontal():
                    yield DataTable(id="sessions-table", cursor_type="row")
                    yield Static("Selecciona una sesión para ver detalle.",
                                 id="session-detail")
            with TabPane("Scripts", id="tab-scripts"):
                with Horizontal(classes="toolbar"):
                    yield Button("Recargar catálogo", id="btn-scripts", variant="primary")
                    yield Label("", id="scripts-count")
                yield DataTable(id="scripts-table", cursor_type="row")
            with TabPane("Análisis", id="tab-analysis"):
                yield Static(
                    "DEMO: inyecta eventos sintéticos en el EventAnalyzer real y "
                    "muestra findings + recomendaciones. En uso real los eventos "
                    "llegan de un script Frida en vivo (reactive_probe.js).",
                    classes="hint",
                )
                with Horizontal(classes="toolbar"):
                    yield Button("Ejecutar análisis (demo)", id="btn-analysis",
                                 variant="success")
                    yield Button("Limpiar", id="btn-analysis-clear")
                yield RichLog(id="analysis-log", highlight=True, markup=True, wrap=True)
        yield Footer()

    # ------------------------------------------------------------------ #
    # Ciclo de vida
    # ------------------------------------------------------------------ #
    def on_mount(self) -> None:
        self._setup_tables()
        self._render_dashboard()
        self._load_sessions()
        self._load_scripts()

    def _setup_tables(self) -> None:
        sessions = self.query_one("#sessions-table", DataTable)
        sessions.add_columns("Sesión", "Paquete", "Plat.", "Findings")
        scripts = self.query_one("#scripts-table", DataTable)
        scripts.add_columns("Plataforma", "Categoría", "Nombre", "Técnica", "Descripción")

    # ------------------------------------------------------------------ #
    # Dashboard
    # ------------------------------------------------------------------ #
    def _render_dashboard(self) -> None:
        cfg = self.cfg
        active = cfg.get_active_profile()
        n_sessions = "?"
        try:
            n_sessions = str(len(_session_manager(cfg).list_sessions()))
        except Exception:
            pass
        n_scripts = "?"
        try:
            from bazzingakit.core import default_registry

            n_scripts = str(len(default_registry()))
        except Exception:
            pass

        try:
            from bazzingakit.config import get_config_path

            cfg_path = str(get_config_path())
        except Exception:
            cfg_path = "(desconocida)"

        if active is not None:
            profile_line = (
                f"[b]{active.name}[/b]  ·  plataforma: [b]{active.platform.value}[/b]"
            )
            if active.platform.value == "ios":
                profile_line += f"  ·  ssh: {active.ssh_user}@{active.ssh_host or '—'}"
            else:
                profile_line += f"  ·  adb: {active.adb_host}:{active.adb_port}"
        else:
            profile_line = "[yellow]Sin perfil activo. Usa `bzk config add-profile`.[/yellow]"

        ai = cfg.ai
        ai_line = (
            f"{'[green]activada[/green]' if ai.enabled else '[dim]desactivada[/dim]'}"
            f"  ·  proveedor: {ai.provider}  ·  modelo: {ai.model}"
            f"  ·  redacción: {'sí' if ai.redact_sensitive else 'no'}"
        )

        body = (
            f"[reverse] bazzingakit v{__version__} [/reverse]\n\n"
            f"[b $accent]Perfil activo[/]\n{profile_line}\n\n"
            f"[b $accent]IA[/]\n{ai_line}\n\n"
            f"[b $accent]Datos[/]\n"
            f"Config: {cfg_path}\n"
            f"Perfiles configurados: {len(cfg.profiles)}\n"
            f"Sesiones guardadas: {n_sessions}\n"
            f"Scripts en el registry: {n_scripts}\n\n"
            f"[dim]Atajos: r refrescar · d claro/oscuro · q salir[/dim]"
        )
        self.query_one("#dash-content", Static).update(body)

    # ------------------------------------------------------------------ #
    # Sesiones
    # ------------------------------------------------------------------ #
    def _load_sessions(self) -> None:
        table = self.query_one("#sessions-table", DataTable)
        table.clear()
        try:
            sm = _session_manager(self.cfg)
            ids = sm.list_sessions()
        except Exception as exc:  # pragma: no cover - defensivo
            self.query_one("#session-detail", Static).update(
                f"[red]No se pudieron listar sesiones:[/red] {exc}"
            )
            return

        if not ids:
            self.query_one("#session-detail", Static).update(
                "[dim]No hay sesiones guardadas todavía.[/dim]"
            )
            return

        for sid in ids:
            pkg, plat, nfind = "?", "?", "?"
            try:
                meta = sm.load(sid).metadata
                pkg, plat = meta.package_name, meta.platform
                nfind = str(len(meta.findings))
            except Exception:
                pass
            table.add_row(sid, pkg, plat, nfind, key=sid)

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        if event.data_table.id != "sessions-table":
            return
        sid = event.row_key.value
        if sid is None:
            return
        try:
            meta = _session_manager(self.cfg).load(sid).metadata
        except Exception as exc:
            self.query_one("#session-detail", Static).update(
                f"[red]Error cargando {sid}:[/red] {exc}"
            )
            return

        lines = [
            f"[b $accent]{meta.session_id}[/]",
            f"Paquete:  {meta.package_name}",
            f"Plataforma: {meta.platform}",
            f"Perfil:   {meta.profile_name or '—'}",
            f"Playbook: {meta.playbook_name or '—'}",
            f"Inicio:   {meta.started_at}",
            f"Fin:      {meta.ended_at or '(abierta)'}",
            f"Scripts:  {', '.join(meta.scripts_loaded) or '—'}",
            "",
            f"[b $accent]Findings ({len(meta.findings)})[/]",
        ]
        if meta.findings:
            for f in meta.findings:
                cat = f.get("category", "?")
                detail = f.get("detail", "")
                conf = f.get("confidence")
                conf_s = f" ({int(conf * 100)}%)" if isinstance(conf, (int, float)) else ""
                lines.append(f"  • [b]{cat}[/b] — {detail}{conf_s}")
        else:
            lines.append("  [dim]sin findings[/dim]")
        self.query_one("#session-detail", Static).update("\n".join(lines))

    # ------------------------------------------------------------------ #
    # Scripts
    # ------------------------------------------------------------------ #
    def _load_scripts(self) -> None:
        table = self.query_one("#scripts-table", DataTable)
        table.clear()
        try:
            from bazzingakit.core import default_registry

            scripts = sorted(
                default_registry().all(),
                key=lambda s: (s.platform, s.category, s.name),
            )
        except Exception as exc:
            self.query_one("#scripts-count", Label).update(
                f"[red]Error cargando catálogo: {exc}[/red]"
            )
            return

        for s in scripts:
            table.add_row(
                s.platform,
                s.category,
                s.name,
                s.technique or "—",
                (s.description or "—")[:60],
            )
        self.query_one("#scripts-count", Label).update(
            f"{len(scripts)} scripts registrados"
        )

    # ------------------------------------------------------------------ #
    # Dispositivo (worker en hilo: adb/ssh pueden bloquear)
    # ------------------------------------------------------------------ #
    @work(thread=True, exclusive=True, group="device")
    def _check_device(self) -> None:
        status = self.query_one("#device-status", Static)
        self.call_from_thread(status.update, "[dim]Comprobando dispositivo…[/dim]")

        profile = self.cfg.get_active_profile()
        if profile is None:
            self.call_from_thread(
                status.update,
                "[yellow]Sin perfil activo.[/yellow]\n\n"
                "Configura uno con:\n"
                "  [b]bzk config add-profile <nombre> --platform android[/b]",
            )
            return

        try:
            from bazzingakit.core import get_device_manager

            dm = get_device_manager(profile)
            available = dm.is_available()
            connected = dm.is_connected() if available else False
            info = dm.get_device_info() if connected else None
        except Exception as exc:
            self.call_from_thread(
                status.update, f"[red]Error consultando el dispositivo:[/red] {exc}"
            )
            return

        lines = [
            f"[b $accent]Perfil:[/] {profile.name}  ({profile.platform.value})",
            f"Herramientas disponibles (adb/ssh): "
            f"{'[green]sí[/green]' if available else '[red]no[/red]'}",
            f"Dispositivo conectado: "
            f"{'[green]sí[/green]' if connected else '[red]no[/red]'}",
        ]
        if info is not None:
            lines += [
                "",
                "[b $accent]Device[/]",
                f"  id:      {info.identifier}",
                f"  modelo:  {info.model or '—'}",
                f"  OS:      {info.os_version or '—'}",
                f"  arch:    {info.arch or '—'}",
                f"  rooted:  {info.is_rooted if info.is_rooted is not None else '—'}",
            ]
        elif available and not connected:
            lines.append("\n[dim]No se detectó ningún dispositivo alcanzable.[/dim]")
        self.call_from_thread(status.update, "\n".join(lines))

    # ------------------------------------------------------------------ #
    # Análisis (demo del pipeline real)
    # ------------------------------------------------------------------ #
    @work(thread=True, exclusive=True, group="analysis")
    def _run_demo_analysis(self) -> None:
        from bazzingakit.core import EventAnalyzer, Recommender

        log = self.query_one("#analysis-log", RichLog)
        self.call_from_thread(
            log.write, "[b yellow]── DEMO: flujo de eventos en vivo ──[/b yellow]"
        )
        analyzer = EventAnalyzer()
        for evt in _DEMO_EVENTS:
            analyzer.ingest(evt)
            etype = evt.get("event")
            summary = {k: v for k, v in evt.items() if k != "event"}
            self.call_from_thread(
                log.write, f"  [cyan]{etype}[/cyan] [dim]{summary}[/dim]"
            )
            time.sleep(0.25)

        result = analyzer.analyze()
        self.call_from_thread(
            log.write,
            f"\n[b]Eventos:[/b] {result.total_events}  ·  "
            f"[b]tipos:[/b] {result.events_by_type}",
        )
        self.call_from_thread(
            log.write, f"[b $accent]Findings ({len(result.findings)}):[/]"
        )
        for f in result.findings:
            icon = "[red]⚠[/red]" if f.confidence > 0.7 else "[yellow]•[/yellow]"
            self.call_from_thread(
                log.write,
                f"  {icon} [b]{f.category}[/b] — {f.detail} "
                f"[dim]({int(f.confidence * 100)}%)[/dim]",
            )

        try:
            recs = Recommender().recommend(result)
        except Exception as exc:
            self.call_from_thread(
                log.write, f"[red]Recommender falló:[/red] {exc}"
            )
            return

        self.call_from_thread(
            log.write, f"\n[b $accent]Bypasses recomendados ({len(recs)}):[/]"
        )
        if not recs:
            self.call_from_thread(
                log.write,
                "  [dim]sin scripts en el registry para estos findings[/dim]",
            )
        for i, rec in enumerate(recs, 1):
            self.call_from_thread(
                log.write,
                f"  {i}. [cyan]{rec.script.name}[/cyan] "
                f"[dim](prioridad {rec.priority}) — {rec.reason}[/dim]",
            )

    # ------------------------------------------------------------------ #
    # Eventos de UI
    # ------------------------------------------------------------------ #
    def on_button_pressed(self, event: Button.Pressed) -> None:
        bid = event.button.id
        if bid == "btn-device":
            self._check_device()
        elif bid == "btn-sessions":
            self._load_sessions()
        elif bid == "btn-scripts":
            self._load_scripts()
        elif bid == "btn-analysis":
            self._run_demo_analysis()
        elif bid == "btn-analysis-clear":
            self.query_one("#analysis-log", RichLog).clear()

    # ------------------------------------------------------------------ #
    # Acciones (atajos)
    # ------------------------------------------------------------------ #
    def action_refresh(self) -> None:
        self.cfg = _safe_config()
        self._render_dashboard()
        self._load_sessions()
        self._load_scripts()
        self.notify("Datos recargados.")

    def action_toggle_dark(self) -> None:
        self.theme = (
            "textual-light" if self.theme == "textual-dark" else "textual-dark"
        )


def run() -> None:
    """Punto de entrada: lanza la TUI."""
    BazzingakitTUI().run()
