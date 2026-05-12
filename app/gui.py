"""Qt GUI for forensic-mvp.

The GUI is a local desktop interface built with PySide6/Qt. It keeps the same
project model as the CLI: a case directory contains case.db and vault/.
"""

from __future__ import annotations

import json
import sys
import traceback
from pathlib import Path
from typing import Any

from app.core.enums import ArtifactType, EvidenceObjectType, InvestigationStatus
from app.ingestion.files import FileIngestor, FileVerifier
from app.ingestion.logs.linux_log_ingestor import LinuxLogIngestor
from app.models import InvestigationMetadata
from app.services.audit_service import audit_error, audit_success
from app.services.evidence_service import EvidenceService
from app.services.report_service import ReportService
from app.settings import CASE_DB_NAME
from app.storage.db import get_session, init_db
from app.storage.encryption import ProjectEncryptionRepository
from app.storage.repositories import (
    ArtifactRepository,
    AuditLogRepository,
    EvidenceObjectRepository,
    EvidenceSourceRepository,
    InvestigationMetadataRepository,
)
from app.utils.paths import get_case_db_path, get_case_vault_dir

try:  # PySide6 is optional for CLI usage and required only for GUI usage.
    from PySide6.QtCore import Qt
    from PySide6.QtGui import QFont, QGuiApplication
    from PySide6.QtWidgets import (
        QApplication,
        QCheckBox,
        QComboBox,
        QFileDialog,
        QFormLayout,
        QFrame,
        QGridLayout,
        QGroupBox,
        QHBoxLayout,
        QHeaderView,
        QLabel,
        QLineEdit,
        QMainWindow,
        QMessageBox,
        QPushButton,
        QSizePolicy,
        QStackedWidget,
        QStatusBar,
        QSplitter,
        QTabWidget,
        QTableWidget,
        QTableWidgetItem,
        QTextEdit,
        QVBoxLayout,
        QWidget,
    )
    _PYSIDE6_IMPORT_ERROR: Exception | None = None
except Exception as exc:  # pragma: no cover - depends on user environment.
    _PYSIDE6_IMPORT_ERROR = exc


DEFAULT_CASE_DIR = "./investigations/default"
NEW_CASE_DIR = "./investigations/case_001"


def _ensure_pyside6_available() -> None:
    if _PYSIDE6_IMPORT_ERROR is None:
        return

    message = (
        "PySide6 не установлен или не смог загрузиться.\n\n"
        "Для нового GUI установите зависимости проекта:\n"
        "  uv sync\n"
        "или:\n"
        "  python -m pip install PySide6\n\n"
        "На Ubuntu, если Qt ругается на системные библиотеки, обычно помогают:\n"
        "  sudo apt install libxcb-cursor0 libxkbcommon-x11-0 fonts-noto-core\n\n"
        f"Исходная ошибка: {_PYSIDE6_IMPORT_ERROR}"
    )
    raise SystemExit(message)


if _PYSIDE6_IMPORT_ERROR is None:

    class ForensicMvpQtGui(QMainWindow):
        """Two-step GUI: project page first, workspace with tabs second."""

        def __init__(self) -> None:
            super().__init__()
            self.setWindowTitle("forensic-mvp")
            self.resize(1280, 820)
            self.setMinimumSize(1080, 700)

            self.case_dir: str | None = None
            self.encryption_key: str | None = None
            self.vault_encryption_enabled = False
            self.objects_by_id: dict[int, Any] = {}
            self.artifacts_by_id: dict[int, Any] = {}
            self.all_objects: list[Any] = []
            self.all_artifacts: list[Any] = []
            self.all_sources: list[Any] = []
            self.all_audit_entries: list[Any] = []
            self.audit_by_id: dict[int, Any] = {}
            self.report_artifact_ids: set[int] = set()
            self.metadata: Any | None = None

            self._setup_fonts_and_style()

            self.stack = QStackedWidget()
            self.setCentralWidget(self.stack)
            self.setStatusBar(QStatusBar())

            self.project_page = self._build_project_page()
            self.workspace_page = self._build_workspace_page()
            self.stack.addWidget(self.project_page)
            self.stack.addWidget(self.workspace_page)
            self.stack.setCurrentWidget(self.project_page)
            self._set_status("Выберите или создайте проект")

        # ------------------------------------------------------------------
        # Styling
        # ------------------------------------------------------------------
        def _setup_fonts_and_style(self) -> None:
            # Qt on Ubuntu normally resolves this to Ubuntu/Noto/DejaVu via
            # fontconfig. It avoids the Tk/X11 bitmap fallback that caused the
            # spaced-out Cyrillic rendering.
            font = QFont("Noto Sans", 10)
            if not QFont("Noto Sans").exactMatch():
                font = QGuiApplication.font()
                font.setPointSize(10)
            QApplication.setFont(font)

            self.setStyleSheet(
                """
                QMainWindow, QWidget {
                    font-size: 10pt;
                }
                QLabel#TitleLabel {
                    font-size: 24px;
                    font-weight: 700;
                }
                QLabel#SectionLabel {
                    font-size: 16px;
                    font-weight: 700;
                }
                QGroupBox {
                    font-weight: 600;
                    margin-top: 12px;
                    padding-top: 14px;
                }
                QGroupBox::title {
                    subcontrol-origin: margin;
                    left: 10px;
                    padding: 0 4px;
                }
                QPushButton {
                    padding: 6px 10px;
                }
                QLineEdit, QComboBox {
                    padding: 4px;
                }
                QTabWidget::pane {
                    border: 1px solid #c8c8c8;
                }
                QTabBar::tab {
                    padding: 8px 14px;
                }
                QTableWidget {
                    gridline-color: #dddddd;
                    selection-background-color: #d7e7ff;
                }
                QTextEdit {
                    font-family: "DejaVu Sans Mono", "Noto Sans Mono", monospace;
                    font-size: 10pt;
                }
                """
            )

        # ------------------------------------------------------------------
        # Project page
        # ------------------------------------------------------------------
        def _build_project_page(self) -> QWidget:
            page = QWidget()
            root = QVBoxLayout(page)
            root.setContentsMargins(22, 22, 22, 22)
            root.setSpacing(14)

            title = QLabel("forensic-mvp")
            title.setObjectName("TitleLabel")
            root.addWidget(title)

            subtitle = QLabel(
                "Сначала откройте существующий проект или создайте новый. "
                "После этого откроется рабочая область с вкладками."
            )
            subtitle.setWordWrap(True)
            root.addWidget(subtitle)

            tabs = QTabWidget()
            tabs.addTab(self._build_open_project_tab(), "Открыть проект")
            tabs.addTab(self._build_create_project_tab(), "Создать проект")
            root.addWidget(tabs, stretch=1)

            return page

        def _build_open_project_tab(self) -> QWidget:
            tab = QWidget()
            layout = QVBoxLayout(tab)
            layout.setContentsMargins(18, 18, 18, 18)
            layout.setSpacing(12)

            section = QLabel("Открыть существующий проект")
            section.setObjectName("SectionLabel")
            layout.addWidget(section)

            row = QHBoxLayout()
            self.open_dir_edit = QLineEdit(DEFAULT_CASE_DIR)
            row.addWidget(QLabel("Папка проекта:"))
            row.addWidget(self.open_dir_edit, stretch=1)
            browse_btn = QPushButton("Выбрать…")
            browse_btn.clicked.connect(self._browse_open_case_dir)
            row.addWidget(browse_btn)
            layout.addLayout(row)

            note = QLabel(
                f"Выберите папку, где уже есть {CASE_DB_NAME}. "
                "Например: investigations/case_001"
            )
            note.setWordWrap(True)
            layout.addWidget(note)

            key_box = QGroupBox("Шифрование vault")
            key_form = QFormLayout(key_box)
            self.open_key_edit = QLineEdit()
            self.open_key_edit.setEchoMode(QLineEdit.EchoMode.Password)
            self.open_key_edit.setPlaceholderText("Оставьте пустым для проекта без шифрования")
            key_form.addRow("Ключ проекта:", self.open_key_edit)
            key_note = QLabel("Если проект создан с шифрованием, без этого ключа нельзя добавлять и проверять файлы vault.")
            key_note.setWordWrap(True)
            key_form.addRow("", key_note)
            layout.addWidget(key_box)

            open_btn = QPushButton("Открыть проект")
            open_btn.clicked.connect(self._open_existing_project)
            layout.addWidget(open_btn)
            layout.addStretch(1)
            return tab

        def _build_create_project_tab(self) -> QWidget:
            tab = QWidget()
            layout = QVBoxLayout(tab)
            layout.setContentsMargins(18, 18, 18, 18)
            layout.setSpacing(12)

            section = QLabel("Создать новый проект")
            section.setObjectName("SectionLabel")
            layout.addWidget(section)

            form_box = QGroupBox("Параметры проекта")
            form = QFormLayout(form_box)
            form.setLabelAlignment(Qt.AlignmentFlag.AlignRight)

            dir_row = QWidget()
            dir_layout = QHBoxLayout(dir_row)
            dir_layout.setContentsMargins(0, 0, 0, 0)
            self.new_dir_edit = QLineEdit(NEW_CASE_DIR)
            choose_btn = QPushButton("Выбрать…")
            choose_btn.clicked.connect(self._browse_new_case_dir)
            dir_layout.addWidget(self.new_dir_edit, stretch=1)
            dir_layout.addWidget(choose_btn)
            form.addRow("Папка проекта:", dir_row)

            self.title_edit = QLineEdit()
            self.case_number_edit = QLineEdit()
            self.examiner_edit = QLineEdit()
            self.organization_edit = QLineEdit()
            self.description_edit = QLineEdit()

            form.addRow("Название:", self.title_edit)
            form.addRow("Номер дела:", self.case_number_edit)
            form.addRow("Эксперт:", self.examiner_edit)
            form.addRow("Организация:", self.organization_edit)
            form.addRow("Описание:", self.description_edit)
            layout.addWidget(form_box)

            encryption_box = QGroupBox("Шифрование vault")
            encryption_form = QFormLayout(encryption_box)
            self.encrypt_vault_checkbox = QCheckBox("Шифровать файлы, которые сохраняются в vault")
            self.new_key_edit = QLineEdit()
            self.new_key_edit.setEchoMode(QLineEdit.EchoMode.Password)
            self.new_key_edit.setPlaceholderText("Ключ не сохраняется в проекте")
            encryption_form.addRow("", self.encrypt_vault_checkbox)
            encryption_form.addRow("Ключ:", self.new_key_edit)
            encryption_note = QLabel(
                "Если ключ указан, новые файлы в vault будут храниться в зашифрованном виде. "
                "База case.db не шифруется. Потерянный ключ восстановить нельзя."
            )
            encryption_note.setWordWrap(True)
            encryption_form.addRow("", encryption_note)
            layout.addWidget(encryption_box)

            note = QLabel(
                f"При создании будут инициализированы {CASE_DB_NAME} и vault/. "
                "Метаданные расследования создаются один раз. Режим шифрования выбирается только для нового проекта."
            )
            note.setWordWrap(True)
            layout.addWidget(note)

            create_btn = QPushButton("Создать и открыть")
            create_btn.clicked.connect(self._create_project)
            layout.addWidget(create_btn)
            layout.addStretch(1)
            return tab

        def _browse_open_case_dir(self) -> None:
            path = QFileDialog.getExistingDirectory(self, "Выберите папку проекта", self.open_dir_edit.text())
            if path:
                self.open_dir_edit.setText(path)

        def _browse_new_case_dir(self) -> None:
            path = QFileDialog.getExistingDirectory(self, "Выберите или создайте папку проекта", self.new_dir_edit.text())
            if path:
                self.new_dir_edit.setText(path)

        def _open_existing_project(self) -> None:
            case_dir = self.open_dir_edit.text().strip()
            if not case_dir:
                self._error("Папка проекта не указана")
                return
            db_path = Path(case_dir) / CASE_DB_NAME
            if not db_path.exists():
                self._error(f"В выбранной папке не найден {CASE_DB_NAME}")
                return

            encryption_key = self.open_key_edit.text().strip() or None
            try:
                # Re-run init_db for existing projects too. It is idempotent and
                # also applies lightweight schema migrations added by newer
                # versions of the application. Without this, older projects can
                # open but fail to load artifacts/journal rows if a new column or
                # table is missing.
                init_db(str(db_path))
                with get_session(str(db_path)) as session:
                    encryption_repo = ProjectEncryptionRepository(session)
                    encryption_config = encryption_repo.get_config()
                    if encryption_config.enabled:
                        encryption_repo.require_valid_key(encryption_key)
            except Exception as exc:
                self._error(str(exc), traceback.format_exc())
                return

            self._open_project(case_dir, encryption_key=encryption_key)

        def _create_project(self) -> None:
            case_dir = self.new_dir_edit.text().strip()
            if not case_dir:
                self._error("Папка проекта не указана")
                return

            title = self.title_edit.text().strip() or Path(case_dir).name or "Untitled investigation"
            encryption_key = self.new_key_edit.text().strip() or None
            if self.encrypt_vault_checkbox.isChecked() and not encryption_key:
                self._error("Для шифрования vault укажите ключ проекта")
                return
            if not self.encrypt_vault_checkbox.isChecked():
                encryption_key = None

            try:
                db_path = get_case_db_path(case_dir)
                get_case_vault_dir(case_dir)
                init_db(db_path)

                with get_session(db_path) as session:
                    encryption_repo = ProjectEncryptionRepository(session)
                    encryption_repo.configure(encryption_key)
                    repo = InvestigationMetadataRepository(session)
                    existing = repo.get()
                    if existing is None:
                        repo.create(
                            InvestigationMetadata(
                                id=None,
                                title=title,
                                description=self.description_edit.text().strip() or None,
                                status=InvestigationStatus.OPEN,
                                examiner=self.examiner_edit.text().strip() or None,
                                organization=self.organization_edit.text().strip() or None,
                                case_number=self.case_number_edit.text().strip() or None,
                            )
                        )
                    audit_success(
                        session,
                        "project_created",
                        interface="gui",
                        target_type="project",
                        target_path=case_dir,
                        message=f"Project created: {title}",
                        details={
                            "title": title,
                            "case_number": self.case_number_edit.text().strip() or None,
                            "examiner": self.examiner_edit.text().strip() or None,
                            "organization": self.organization_edit.text().strip() or None,
                            "vault_encryption_enabled": bool(encryption_key),
                        },
                    )
                self._open_project(case_dir, encryption_key=encryption_key)
            except Exception as exc:
                self._error(str(exc), traceback.format_exc())

        def _open_project(self, case_dir: str, encryption_key: str | None = None) -> None:
            self.case_dir = case_dir
            self.encryption_key = encryption_key
            self.vault_encryption_enabled = False
            try:
                # Safe for both new and existing projects. Keeps old case.db
                # files compatible with the current GUI.
                init_db(self._db_path())
                with get_session(self._db_path()) as session:
                    self.vault_encryption_enabled = ProjectEncryptionRepository(session).get_config().enabled
            except Exception:
                self.vault_encryption_enabled = False
            self._write_gui_audit(
                "project_opened",
                message="Project opened in GUI",
                target_type="project",
                target_path=case_dir,
                details={"vault_encryption_enabled": self.vault_encryption_enabled},
            )
            self._refresh_all(show_errors=True)
            self.stack.setCurrentWidget(self.workspace_page)
            self._set_status(f"Открыт проект: {case_dir}")

        # ------------------------------------------------------------------
        # Workspace
        # ------------------------------------------------------------------
        def _build_workspace_page(self) -> QWidget:
            page = QWidget()
            root = QVBoxLayout(page)
            root.setContentsMargins(18, 18, 18, 18)
            root.setSpacing(10)

            header = QHBoxLayout()
            self.project_label = QLabel("Проект не открыт")
            self.project_label.setObjectName("SectionLabel")
            header.addWidget(self.project_label, stretch=1)
            refresh_btn = QPushButton("Обновить")
            refresh_btn.clicked.connect(lambda: self._refresh_all(show_errors=True))
            back_btn = QPushButton("К выбору проекта")
            back_btn.clicked.connect(self._back_to_project_page)
            header.addWidget(refresh_btn)
            header.addWidget(back_btn)
            root.addLayout(header)

            self.summary_label = QLabel("")
            self.summary_label.setWordWrap(True)
            root.addWidget(self.summary_label)

            self.workspace_tabs = QTabWidget()
            self.workspace_tabs.addTab(self._build_ingest_tab(), "Добавить новые")
            self.workspace_tabs.addTab(self._build_artifacts_tab(), "Посмотреть артефакты")
            self.workspace_tabs.addTab(self._build_report_tab(), "Генерация отчёта")
            self.workspace_tabs.addTab(self._build_journal_tab(), "Журнал")
            root.addWidget(self.workspace_tabs, stretch=1)

            return page

        def _back_to_project_page(self) -> None:
            self.stack.setCurrentWidget(self.project_page)
            self._set_status("Выберите или создайте проект")

        def _build_ingest_tab(self) -> QWidget:
            tab = QWidget()
            root = QVBoxLayout(tab)
            root.setSpacing(12)

            controls_box = QGroupBox("Что добавить")
            controls = QFormLayout(controls_box)

            self.source_name_edit = QLineEdit()
            self.source_name_edit.setPlaceholderText("Необязательно. Например: USB drive, /var/log/auth.log, traffic capture")
            controls.addRow("Название источника:", self.source_name_edit)

            self.ingest_type_combo = QComboBox()
            self.ingest_type_combo.addItem("Файл", "file")
            self.ingest_type_combo.addItem("Директория", "directory")
            self.ingest_type_combo.addItem("Linux log", "log")
            self.ingest_type_combo.addItem("PCAP", "pcap")
            controls.addRow("Тип добавления:", self.ingest_type_combo)

            hint = QLabel(
                "Выберите тип материала — ниже будет показана только подходящая форма. "
                "Так удобнее, чем держать все варианты на экране одновременно."
            )
            hint.setWordWrap(True)
            controls.addRow("", hint)
            root.addWidget(controls_box)

            self.ingest_form_stack = QStackedWidget()
            self.ingest_form_stack.addWidget(self._build_file_ingest_box())
            self.ingest_form_stack.addWidget(self._build_directory_ingest_box())
            self.ingest_form_stack.addWidget(self._build_log_ingest_box())
            self.ingest_form_stack.addWidget(self._build_pcap_ingest_box())
            self.ingest_type_combo.currentIndexChanged.connect(self.ingest_form_stack.setCurrentIndex)
            root.addWidget(self.ingest_form_stack)

            self.operation_log = QTextEdit()
            self.operation_log.setReadOnly(True)
            self.operation_log.setPlaceholderText("Здесь будет результат операций…")
            root.addWidget(self.operation_log, stretch=1)
            return tab

        def _build_file_ingest_box(self) -> QGroupBox:
            box = QGroupBox("Файл")
            layout = QVBoxLayout(box)
            row = QHBoxLayout()
            self.file_path_edit = QLineEdit()
            choose = QPushButton("Выбрать…")
            choose.clicked.connect(lambda: self._choose_file(self.file_path_edit, "Выберите файл"))
            row.addWidget(self.file_path_edit, stretch=1)
            row.addWidget(choose)
            layout.addLayout(row)
            btn = QPushButton("Добавить файл")
            btn.clicked.connect(self._ingest_file)
            layout.addWidget(btn)
            return box

        def _build_directory_ingest_box(self) -> QGroupBox:
            box = QGroupBox("Директория")
            layout = QVBoxLayout(box)
            row = QHBoxLayout()
            self.dir_path_edit = QLineEdit()
            choose = QPushButton("Выбрать…")
            choose.clicked.connect(lambda: self._choose_directory(self.dir_path_edit, "Выберите директорию"))
            row.addWidget(self.dir_path_edit, stretch=1)
            row.addWidget(choose)
            layout.addLayout(row)
            btn = QPushButton("Добавить директорию")
            btn.clicked.connect(self._ingest_directory)
            layout.addWidget(btn)
            return box

        def _build_log_ingest_box(self) -> QGroupBox:
            box = QGroupBox("Linux log")
            layout = QVBoxLayout(box)
            row = QHBoxLayout()
            self.log_path_edit = QLineEdit()
            choose = QPushButton("Выбрать…")
            choose.clicked.connect(lambda: self._choose_file(self.log_path_edit, "Выберите log-файл"))
            row.addWidget(self.log_path_edit, stretch=1)
            row.addWidget(choose)
            layout.addLayout(row)

            opts = QHBoxLayout()
            self.log_type_combo = QComboBox()
            self.log_type_combo.addItems(["auth", "syslog", "kern"])
            self.log_year_edit = QLineEdit()
            self.log_year_edit.setPlaceholderText("например 2025")
            opts.addWidget(QLabel("Тип:"))
            opts.addWidget(self.log_type_combo)
            opts.addWidget(QLabel("Год:"))
            opts.addWidget(self.log_year_edit)
            layout.addLayout(opts)

            btn = QPushButton("Добавить Linux log")
            btn.clicked.connect(self._ingest_log)
            layout.addWidget(btn)
            return box

        def _build_pcap_ingest_box(self) -> QGroupBox:
            box = QGroupBox("PCAP")
            layout = QVBoxLayout(box)
            row = QHBoxLayout()
            self.pcap_path_edit = QLineEdit()
            choose = QPushButton("Выбрать…")
            choose.clicked.connect(lambda: self._choose_file(self.pcap_path_edit, "Выберите PCAP-файл"))
            row.addWidget(self.pcap_path_edit, stretch=1)
            row.addWidget(choose)
            layout.addLayout(row)
            btn = QPushButton("Добавить PCAP")
            btn.clicked.connect(self._ingest_pcap)
            layout.addWidget(btn)
            return box

        def _build_artifacts_tab(self) -> QWidget:
            tab = QWidget()
            root = QVBoxLayout(tab)
            root.setSpacing(10)

            filters = QHBoxLayout()
            self.object_filter_combo = QComboBox()
            self.object_filter_combo.addItem("all")
            self.object_filter_combo.addItems([item.value for item in EvidenceObjectType])
            self.object_filter_combo.currentTextChanged.connect(self._apply_filters)

            self.artifact_filter_combo = QComboBox()
            self.artifact_filter_combo.addItem("all")
            self.artifact_filter_combo.addItems([item.value for item in ArtifactType])
            self.artifact_filter_combo.currentTextChanged.connect(self._apply_filters)

            self.artifact_search_edit = QLineEdit()
            self.artifact_search_edit.setPlaceholderText("Поиск по имени, пути, title, JSON…")
            self.artifact_search_edit.textChanged.connect(self._apply_filters)

            self.selected_only_checkbox = QCheckBox("Только выбранный object")
            self.selected_only_checkbox.stateChanged.connect(self._apply_filters)

            filters.addWidget(QLabel("Object type:"))
            filters.addWidget(self.object_filter_combo)
            filters.addWidget(QLabel("Artifact type:"))
            filters.addWidget(self.artifact_filter_combo)
            filters.addWidget(self.artifact_search_edit, stretch=1)
            filters.addWidget(self.selected_only_checkbox)
            root.addLayout(filters)

            main_splitter = QSplitter(Qt.Orientation.Vertical)
            tables_splitter = QSplitter(Qt.Orientation.Horizontal)

            left_widget = QWidget()
            left = QVBoxLayout(left_widget)
            left.setContentsMargins(0, 0, 0, 0)
            self.objects_count_label = QLabel("Evidence objects")
            left.addWidget(self.objects_count_label)
            self.objects_table = QTableWidget(0, 8)
            self.objects_table.setHorizontalHeaderLabels([
                "ID", "Тип", "Имя", "Размер", "MIME", "SHA-256", "Дата ingest", "Путь"
            ])
            self._configure_table(self.objects_table, [55, 100, 230, 85, 130, 300, 170, 380])
            self.objects_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
            self.objects_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
            self.objects_table.itemSelectionChanged.connect(self._on_object_selection_changed)
            left.addWidget(self.objects_table, stretch=1)

            actions = QHBoxLayout()
            verify_selected = QPushButton("Verify selected")
            verify_selected.clicked.connect(self._verify_selected)
            verify_all = QPushButton("Verify all")
            verify_all.clicked.connect(self._verify_all)
            delete_selected = QPushButton("Delete selected")
            delete_selected.clicked.connect(self._delete_selected)
            actions.addWidget(verify_selected)
            actions.addWidget(verify_all)
            actions.addWidget(delete_selected)
            actions.addStretch(1)
            left.addLayout(actions)

            right_widget = QWidget()
            right = QVBoxLayout(right_widget)
            right.setContentsMargins(0, 0, 0, 0)
            self.artifacts_count_label = QLabel("Artifacts")
            right.addWidget(self.artifacts_count_label)

            report_actions = QHBoxLayout()
            self.report_selection_label = QLabel("В отчёт выбрано: 0")
            select_visible = QPushButton("Выбрать видимые")
            select_visible.clicked.connect(self._select_visible_artifacts_for_report)
            unselect_visible = QPushButton("Снять видимые")
            unselect_visible.clicked.connect(self._unselect_visible_artifacts_for_report)
            clear_report_selection = QPushButton("Снять все")
            clear_report_selection.clicked.connect(self._clear_report_artifact_selection)
            report_actions.addWidget(self.report_selection_label)
            report_actions.addStretch(1)
            report_actions.addWidget(select_visible)
            report_actions.addWidget(unselect_visible)
            report_actions.addWidget(clear_report_selection)
            right.addLayout(report_actions)

            self.artifacts_table = QTableWidget(0, 7)
            self.artifacts_table.setHorizontalHeaderLabels([
                "В отчёт", "ID", "Obj", "Тип", "Время", "Title", "Data preview"
            ])
            self._configure_table(self.artifacts_table, [78, 55, 60, 175, 165, 300, 440])
            self.artifacts_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
            self.artifacts_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
            self.artifacts_table.itemChanged.connect(self._on_artifact_item_changed)
            self.artifacts_table.itemSelectionChanged.connect(self._on_artifact_selection_changed)
            right.addWidget(self.artifacts_table, stretch=1)

            tables_splitter.addWidget(left_widget)
            tables_splitter.addWidget(right_widget)
            tables_splitter.setSizes([610, 670])
            main_splitter.addWidget(tables_splitter)

            details_splitter = QSplitter(Qt.Orientation.Horizontal)
            self.object_details = QTextEdit()
            self.object_details.setReadOnly(True)
            self.object_details.setPlaceholderText("Детали evidence object…")
            self.artifact_details = QTextEdit()
            self.artifact_details.setReadOnly(True)
            self.artifact_details.setPlaceholderText("Детали artifact…")
            details_splitter.addWidget(self.object_details)
            details_splitter.addWidget(self.artifact_details)
            details_splitter.setSizes([520, 760])
            main_splitter.addWidget(details_splitter)
            main_splitter.setSizes([520, 210])

            resize_hint = QLabel(
                "Подсказка: отметьте чекбоксом артефакты, которые нужно включить в PDF-отчёт. "
                "Ширину колонок и границы панелей можно менять мышью. "
                "Колонки ID/Obj сделаны компактными, длинные значения раскрываются в деталях ниже."
            )
            resize_hint.setWordWrap(True)
            root.addWidget(main_splitter, stretch=1)
            root.addWidget(resize_hint)
            return tab

        def _build_report_tab(self) -> QWidget:
            tab = QWidget()
            root = QVBoxLayout(tab)
            root.setSpacing(10)

            form_box = QGroupBox("Параметры PDF-отчёта")
            form = QFormLayout(form_box)
            self.report_title_edit = QLineEdit()
            self.report_title_edit.setPlaceholderText("Например: Timeline report по инциденту")
            self.report_description_edit = QTextEdit()
            self.report_description_edit.setPlaceholderText(
                "Краткое описание отчёта. Этот текст попадёт внутрь PDF."
            )
            self.report_description_edit.setFixedHeight(95)
            self.report_selected_count_label = QLabel("Выбрано артефактов: 0")
            form.addRow("Title:", self.report_title_edit)
            form.addRow("Description:", self.report_description_edit)
            form.addRow("Выбор:", self.report_selected_count_label)
            root.addWidget(form_box)

            actions = QHBoxLayout()
            preview = QPushButton("Предпросмотр")
            preview.clicked.connect(self._generate_report_preview)
            save_pdf = QPushButton("Сохранить PDF")
            save_pdf.clicked.connect(self._save_pdf_report)
            actions.addWidget(preview)
            actions.addWidget(save_pdf)
            actions.addStretch(1)
            root.addLayout(actions)

            note = QLabel(
                "В PDF попадут только те артефакты, которые отмечены чекбоксом на вкладке "
                "«Посмотреть артефакты». Таймлайн сортируется по времени артефактов."
            )
            note.setWordWrap(True)
            root.addWidget(note)

            self.report_text = QTextEdit()
            self.report_text.setPlaceholderText("Предпросмотр отчёта появится здесь…")
            root.addWidget(self.report_text, stretch=1)
            return tab

        def _build_journal_tab(self) -> QWidget:
            tab = QWidget()
            root = QVBoxLayout(tab)
            root.setSpacing(10)

            filters = QHBoxLayout()
            self.audit_action_combo = QComboBox()
            self.audit_action_combo.addItem("all")
            self.audit_action_combo.currentTextChanged.connect(self._apply_journal_filters)

            self.audit_status_combo = QComboBox()
            self.audit_status_combo.addItems(["all", "success", "error"])
            self.audit_status_combo.currentTextChanged.connect(self._apply_journal_filters)

            self.audit_search_edit = QLineEdit()
            self.audit_search_edit.setPlaceholderText("Поиск по действию / сообщению / пути / JSON…")
            self.audit_search_edit.textChanged.connect(self._apply_journal_filters)

            refresh = QPushButton("Обновить журнал")
            refresh.clicked.connect(lambda: self._refresh_all(show_errors=True))

            filters.addWidget(QLabel("Action:"))
            filters.addWidget(self.audit_action_combo)
            filters.addWidget(QLabel("Status:"))
            filters.addWidget(self.audit_status_combo)
            filters.addWidget(self.audit_search_edit, stretch=1)
            filters.addWidget(refresh)
            root.addLayout(filters)

            self.audit_table = QTableWidget(0, 7)
            self.audit_table.setHorizontalHeaderLabels([
                "ID", "Время", "Status", "Action", "Actor", "Target", "Message"
            ])
            self._configure_table(self.audit_table, [55, 170, 75, 190, 95, 260, 460])
            self.audit_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
            self.audit_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
            self.audit_table.itemSelectionChanged.connect(self._on_audit_selection_changed)
            root.addWidget(self.audit_table, stretch=3)

            self.audit_details = QTextEdit()
            self.audit_details.setReadOnly(True)
            self.audit_details.setPlaceholderText("Детали записи журнала…")
            root.addWidget(self.audit_details, stretch=2)

            return tab

        def _configure_table(self, table: QTableWidget, column_widths: list[int]) -> None:
            """Make data tables compact but manually resizable."""
            table.setAlternatingRowColors(True)
            table.setWordWrap(False)
            table.setTextElideMode(Qt.TextElideMode.ElideRight)
            # Sorting is intentionally left disabled. In Qt, enabling sorting
            # while a table is being rebuilt can move rows during insertion and
            # make selection/filter logic look as if artifacts disappeared.
            # Users can still resize and reorder columns manually.
            table.setSortingEnabled(False)
            table.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
            table.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
            table.verticalHeader().setVisible(False)
            table.verticalHeader().setDefaultSectionSize(26)

            header = table.horizontalHeader()
            header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
            header.setSectionsMovable(True)
            header.setStretchLastSection(True)
            header.setMinimumSectionSize(42)
            for index, width in enumerate(column_widths):
                table.setColumnWidth(index, width)

        def _set_table_row_values(self, table: QTableWidget, row: int, values: list[str], row_id: int | None = None) -> None:
            for col, value in enumerate(values):
                text = "" if value is None else str(value)
                item = QTableWidgetItem(text)
                item.setToolTip(text)
                if col == 0 and row_id is not None:
                    item.setData(Qt.ItemDataRole.UserRole, row_id)
                table.setItem(row, col, item)

        def _json_preview(self, value: Any, max_len: int = 180) -> str:
            if not value:
                return ""
            if isinstance(value, dict):
                priority_keys = [
                    "event", "username", "user", "src_ip", "dst_ip", "domain", "host",
                    "process", "pid", "message", "method", "path", "status", "protocol",
                ]
                chunks = []
                for key in priority_keys:
                    if key in value and value[key] not in (None, ""):
                        chunks.append(f"{key}={value[key]}")
                    if len(chunks) >= 4:
                        break
                if chunks:
                    preview = "; ".join(chunks)
                else:
                    preview = ", ".join(f"{k}={v}" for k, v in list(value.items())[:4])
            else:
                preview = str(value)
            preview = preview.replace("\n", " ")
            return preview if len(preview) <= max_len else preview[: max_len - 1] + "…"

        def _refresh_journal_filters(self) -> None:
            if not hasattr(self, "audit_action_combo"):
                return

            current = self.audit_action_combo.currentText()
            actions = sorted({entry.action for entry in self.all_audit_entries})
            self.audit_action_combo.blockSignals(True)
            self.audit_action_combo.clear()
            self.audit_action_combo.addItem("all")
            self.audit_action_combo.addItems(actions)
            index = self.audit_action_combo.findText(current)
            self.audit_action_combo.setCurrentIndex(index if index >= 0 else 0)
            self.audit_action_combo.blockSignals(False)

        def _apply_journal_filters(self) -> None:
            if not hasattr(self, "audit_table"):
                return

            action_filter = self.audit_action_combo.currentText()
            status_filter = self.audit_status_combo.currentText()
            query = self.audit_search_edit.text().strip().lower()

            visible = []
            for entry in self.all_audit_entries:
                if action_filter != "all" and entry.action != action_filter:
                    continue
                if status_filter != "all" and entry.status != status_filter:
                    continue
                if query:
                    haystack = (
                        f"{entry.action}\n{entry.status}\n{entry.actor}\n{entry.interface}\n"
                        f"{entry.target_type}\n{entry.target_id}\n{entry.target_path}\n"
                        f"{entry.message}\n{self._json(entry.details_json)}"
                    ).lower()
                    if query not in haystack:
                        continue
                visible.append(entry)

            self._fill_audit_table(visible)

        def _fill_audit_table(self, entries: list[Any]) -> None:
            self.audit_table.setSortingEnabled(False)
            self.audit_table.setRowCount(0)
            for row, entry in enumerate(entries):
                self.audit_table.insertRow(row)
                target = ""
                if entry.target_type or entry.target_id:
                    target = f"{entry.target_type or ''}:{entry.target_id or ''}"
                if entry.target_path:
                    target = f"{target} {entry.target_path}".strip()
                values = [
                    str(entry.id),
                    self._dt(entry.created_at),
                    entry.status,
                    entry.action,
                    entry.actor or "",
                    target,
                    entry.message or "",
                ]
                self._set_table_row_values(self.audit_table, row, values, row_id=entry.id)
            self.audit_table.setSortingEnabled(True)

        def _selected_audit_id(self) -> int | None:
            items = self.audit_table.selectedItems()
            if not items:
                return None
            row = items[0].row()
            item = self.audit_table.item(row, 0)
            return int(item.text()) if item else None

        def _on_audit_selection_changed(self) -> None:
            audit_id = self._selected_audit_id()
            entry = self.audit_by_id.get(audit_id) if audit_id is not None else None
            if entry is None:
                self.audit_details.clear()
            else:
                self.audit_details.setPlainText(self._audit_to_text(entry))

        def _audit_to_text(self, entry: Any) -> str:
            return "\n".join(
                [
                    f"ID: {entry.id}",
                    f"Created at: {self._dt(entry.created_at)}",
                    f"Status: {entry.status}",
                    f"Action: {entry.action}",
                    f"Actor: {entry.actor or ''}",
                    f"Interface: {entry.interface or ''}",
                    f"Target type: {entry.target_type or ''}",
                    f"Target id: {entry.target_id or ''}",
                    f"Target path: {entry.target_path or ''}",
                    f"Message: {entry.message or ''}",
                    "",
                    "Details:",
                    self._json(entry.details_json),
                ]
            )

        def _write_gui_audit(
            self,
            action: str,
            *,
            status: str = "success",
            target_type: str | None = None,
            target_id: int | str | None = None,
            target_path: str | Path | None = None,
            message: str | None = None,
            details: dict[str, Any] | None = None,
        ) -> None:
            if self.case_dir is None:
                return

            try:
                with get_session(self._db_path()) as session:
                    if status == "error":
                        audit_error(
                            session,
                            action,
                            details.get("error", "unknown error") if details else "unknown error",
                            interface="gui",
                            target_type=target_type or "project",
                            target_id=target_id,
                            target_path=target_path or self.case_dir,
                            message=message,
                            details=details,
                        )
                    else:
                        audit_success(
                            session,
                            action,
                            interface="gui",
                            target_type=target_type or "project",
                            target_id=target_id,
                            target_path=target_path or self.case_dir,
                            message=message,
                            details=details,
                        )
            except Exception:
                # GUI audit logging should not break the user operation.
                print(traceback.format_exc(), file=sys.stderr)

        # ------------------------------------------------------------------
        # Helpers
        # ------------------------------------------------------------------
        def _db_path(self) -> str:
            if self.case_dir is None:
                raise RuntimeError("Проект не открыт")
            return get_case_db_path(self.case_dir)

        def _vault_dir(self) -> Path:
            if self.case_dir is None:
                raise RuntimeError("Проект не открыт")
            return get_case_vault_dir(self.case_dir)

        def _source_name(self) -> str | None:
            value = self.source_name_edit.text().strip()
            return value or None

        def _choose_file(self, target: QLineEdit, title: str) -> None:
            path, _ = QFileDialog.getOpenFileName(self, title)
            if path:
                target.setText(path)

        def _choose_directory(self, target: QLineEdit, title: str) -> None:
            path = QFileDialog.getExistingDirectory(self, title)
            if path:
                target.setText(path)

        def _require_file(self, edit: QLineEdit) -> Path:
            path = Path(edit.text().strip())
            if not path.is_file():
                raise ValueError(f"Файл не найден: {path}")
            return path

        def _require_directory(self, edit: QLineEdit) -> Path:
            path = Path(edit.text().strip())
            if not path.is_dir():
                raise ValueError(f"Директория не найдена: {path}")
            return path

        def _run_operation(self, label: str, func, refresh: bool = True) -> None:
            QApplication.setOverrideCursor(Qt.CursorShape.WaitCursor)
            self._set_status(f"Выполняется: {label}")
            try:
                result = func()
                if result:
                    self._append_operation_log(str(result))
                if refresh:
                    self._refresh_all(show_errors=False)
                self._set_status(f"Готово: {label}")
            except Exception as exc:
                self._append_operation_log(f"ERROR: {label}\n{traceback.format_exc()}")
                self._error(str(exc), traceback.format_exc())
                self._set_status(f"Ошибка: {label}")
            finally:
                QApplication.restoreOverrideCursor()

        def _append_operation_log(self, text: str) -> None:
            self.operation_log.append(text.rstrip())
            self.operation_log.append("")

        def _error(self, message: str, details: str | None = None) -> None:
            if details:
                message = f"{message}\n\nПодробности записаны в окно операций или консоль."
                print(details, file=sys.stderr)
            QMessageBox.critical(self, "Ошибка", message)

        def _info(self, message: str) -> None:
            QMessageBox.information(self, "Информация", message)

        def _set_status(self, text: str) -> None:
            self.statusBar().showMessage(text)

        @staticmethod
        def _dt(value: Any) -> str:
            return value.isoformat(sep=" ", timespec="seconds") if value else ""

        @staticmethod
        def _json(value: Any) -> str:
            return json.dumps(value, ensure_ascii=False, indent=2, default=str)

        # ------------------------------------------------------------------
        # Ingest operations
        # ------------------------------------------------------------------
        def _ingest_file(self) -> None:
            def op() -> str:
                path = self._require_file(self.file_path_edit)
                with get_session(self._db_path()) as session:
                    ingestor = FileIngestor(session, self._vault_dir(), encryption_key=self.encryption_key)
                    obj, artifacts, changed = ingestor.collect_file(path=path, source_name=self._source_name())
                if not changed:
                    return f"Файл уже есть и не изменился\nEvidence object id: {obj.id}\nSHA-256: {obj.sha256}"
                return (
                    "Файл добавлен\n"
                    f"Evidence object id: {obj.id}\n"
                    f"Original name: {obj.original_name}\n"
                    f"Stored name: {obj.stored_name}\n"
                    f"SHA-256: {obj.sha256}\n"
                    f"Artifacts created: {len(artifacts)}"
                )

            self._run_operation("добавление файла", op)

        def _ingest_directory(self) -> None:
            def op() -> str:
                path = self._require_directory(self.dir_path_edit)
                with get_session(self._db_path()) as session:
                    ingestor = FileIngestor(session, self._vault_dir(), encryption_key=self.encryption_key)
                    objects, artifacts, changed_count, skipped_count = ingestor.collect_directory(
                        path=path,
                        source_name=self._source_name(),
                    )
                return (
                    "Директория обработана\n"
                    f"Files found: {len(objects)}\n"
                    f"Files added or updated: {changed_count}\n"
                    f"Files skipped: {skipped_count}\n"
                    f"Artifacts created: {len(artifacts)}"
                )

            self._run_operation("добавление директории", op)

        def _ingest_log(self) -> None:
            def op() -> str:
                path = self._require_file(self.log_path_edit)
                year_text = self.log_year_edit.text().strip()
                year = int(year_text) if year_text else None
                with get_session(self._db_path()) as session:
                    ingestor = LinuxLogIngestor(session, self._vault_dir(), encryption_key=self.encryption_key)
                    obj, artifacts, changed = ingestor.collect(
                        path=path,
                        log_type=self.log_type_combo.currentText(),
                        year=year,
                        source_name=self._source_name(),
                    )
                if not changed:
                    return f"Лог уже есть и не изменился\nEvidence object id: {obj.id}\nSHA-256: {obj.sha256}"
                return (
                    "Linux log добавлен\n"
                    f"Log type: {self.log_type_combo.currentText()}\n"
                    f"Evidence object id: {obj.id}\n"
                    f"Original name: {obj.original_name}\n"
                    f"Stored name: {obj.stored_name}\n"
                    f"SHA-256: {obj.sha256}\n"
                    f"Artifacts found: {len(artifacts)}"
                )

            self._run_operation("добавление Linux log", op)

        def _ingest_pcap(self) -> None:
            def op() -> str:
                from app.ingestion.pcap.pcap_ingestor import PcapIngestor

                path = self._require_file(self.pcap_path_edit)
                with get_session(self._db_path()) as session:
                    ingestor = PcapIngestor(session, self._vault_dir(), encryption_key=self.encryption_key)
                    obj, artifacts, changed = ingestor.collect(path=path, source_name=self._source_name())
                if not changed:
                    return f"PCAP уже есть и не изменился\nEvidence object id: {obj.id}\nSHA-256: {obj.sha256}"
                return (
                    "PCAP добавлен\n"
                    f"Evidence object id: {obj.id}\n"
                    f"Original name: {obj.original_name}\n"
                    f"Stored name: {obj.stored_name}\n"
                    f"SHA-256: {obj.sha256}\n"
                    f"Artifacts found: {len(artifacts)}"
                )

            self._run_operation("добавление PCAP", op)

        # ------------------------------------------------------------------
        # Data loading and filtering
        # ------------------------------------------------------------------
        def _refresh_all(self, show_errors: bool) -> None:
            if self.case_dir is None:
                return
            try:
                with get_session(self._db_path()) as session:
                    self.metadata = InvestigationMetadataRepository(session).get()
                    self.all_sources = EvidenceSourceRepository(session).list_all()
                    self.all_objects = EvidenceObjectRepository(session).list_all()
                    self.all_artifacts = ArtifactRepository(session).list_all()
                    self.all_audit_entries = AuditLogRepository(session).list_all(limit=2000)

                self.objects_by_id = {obj.id: obj for obj in self.all_objects if obj.id is not None}
                self.artifacts_by_id = {art.id: art for art in self.all_artifacts if art.id is not None}
                self.audit_by_id = {entry.id: entry for entry in self.all_audit_entries if entry.id is not None}
                self.report_artifact_ids.intersection_update(set(self.artifacts_by_id))
                self._update_report_selection_label()
                self._update_project_summary()
                self._apply_filters()
                self._refresh_journal_filters()
                self._apply_journal_filters()
            except Exception as exc:
                if show_errors:
                    self._error(str(exc), traceback.format_exc())

        def _update_project_summary(self) -> None:
            title = self.metadata.title if self.metadata else "Без metadata"
            self.project_label.setText(f"Проект: {title}")
            self.summary_label.setText(
                f"Папка: {self.case_dir} | "
                f"Шифрование vault: {'включено' if self.vault_encryption_enabled else 'выключено'} | "
                f"Sources: {len(self.all_sources)} | "
                f"Objects: {len(self.all_objects)} | "
                f"Artifacts: {len(self.all_artifacts)} | "
                f"Journal: {len(self.all_audit_entries)}"
            )

        def _apply_filters(self) -> None:
            if not hasattr(self, "objects_table"):
                return

            # Preserve the selected object while rebuilding the object table.
            # The artifact filter should not accidentally become empty only
            # because QTableWidget clears selection during setRowCount(0).
            selected_object_id = self._selected_object_id()
            object_filter = self.object_filter_combo.currentText()
            artifact_filter = self.artifact_filter_combo.currentText()
            query = self.artifact_search_edit.text().strip().lower()
            selected_only = self.selected_only_checkbox.isChecked()

            visible_objects = []
            for obj in self.all_objects:
                if object_filter != "all" and obj.object_type.value != object_filter:
                    continue
                visible_objects.append(obj)

            self._fill_objects_table(visible_objects, preserve_object_id=selected_object_id)

            # If "Только выбранный object" is enabled but nothing is selected
            # yet, do not hide all artifacts. This keeps the page informative
            # after refresh/open and avoids the "empty artifacts" state.
            effective_selected_id = selected_object_id if selected_only and selected_object_id is not None else None

            visible_artifacts = []
            for artifact in self.all_artifacts:
                if effective_selected_id is not None and artifact.evidence_object_id != effective_selected_id:
                    continue
                if artifact_filter != "all" and artifact.artifact_type.value != artifact_filter:
                    continue
                if query:
                    related_object = self.objects_by_id.get(artifact.evidence_object_id)
                    haystack = (
                        f"{artifact.id}\n"
                        f"{artifact.evidence_object_id}\n"
                        f"{artifact.title}\n"
                        f"{artifact.artifact_type.value}\n"
                        f"{self._json(artifact.raw_data_json)}\n"
                        f"{self._json(artifact.parsed_data_json)}\n"
                        f"{related_object.original_name if related_object else ''}\n"
                        f"{related_object.original_path if related_object else ''}"
                    ).lower()
                    if query not in haystack:
                        continue
                visible_artifacts.append(artifact)

            self._fill_artifacts_table(visible_artifacts)

        def _fill_objects_table(self, objects: list[Any], preserve_object_id: int | None = None) -> None:
            self.objects_table.blockSignals(True)
            self.objects_table.setRowCount(0)
            row_to_select: int | None = None
            for row, obj in enumerate(objects):
                self.objects_table.insertRow(row)
                values = [
                    str(obj.id),
                    obj.object_type.value,
                    obj.original_name,
                    str(obj.size_bytes),
                    obj.mime_type or "",
                    obj.sha256,
                    self._dt(obj.ingested_at),
                    obj.original_path,
                ]
                self._set_table_row_values(self.objects_table, row, values, row_id=obj.id)
                if preserve_object_id is not None and obj.id == preserve_object_id:
                    row_to_select = row
            self.objects_table.blockSignals(False)
            if hasattr(self, "objects_count_label"):
                self.objects_count_label.setText(f"Evidence objects: {len(objects)} / {len(self.all_objects)}")
            if row_to_select is not None:
                self.objects_table.selectRow(row_to_select)

        def _fill_artifacts_table(self, artifacts: list[Any]) -> None:
            self.artifacts_table.blockSignals(True)
            self.artifacts_table.setRowCount(0)
            for row, artifact in enumerate(artifacts):
                self.artifacts_table.insertRow(row)

                artifact_id = int(artifact.id)
                check_item = QTableWidgetItem("")
                check_item.setFlags(
                    Qt.ItemFlag.ItemIsEnabled
                    | Qt.ItemFlag.ItemIsSelectable
                    | Qt.ItemFlag.ItemIsUserCheckable
                )
                check_item.setCheckState(
                    Qt.CheckState.Checked
                    if artifact_id in self.report_artifact_ids
                    else Qt.CheckState.Unchecked
                )
                check_item.setData(Qt.ItemDataRole.UserRole, artifact_id)
                check_item.setToolTip("Включить этот артефакт в PDF-отчёт")
                self.artifacts_table.setItem(row, 0, check_item)

                preview = self._json_preview(artifact.parsed_data_json) or self._json_preview(artifact.raw_data_json)
                values = [
                    str(artifact.id),
                    str(artifact.evidence_object_id),
                    artifact.artifact_type.value,
                    self._dt(artifact.timestamp_start or artifact.timestamp),
                    artifact.title,
                    preview,
                ]
                for offset, value in enumerate(values, start=1):
                    text = "" if value is None else str(value)
                    item = QTableWidgetItem(text)
                    item.setToolTip(text)
                    item.setData(Qt.ItemDataRole.UserRole, artifact_id)
                    self.artifacts_table.setItem(row, offset, item)
            self.artifacts_table.blockSignals(False)
            if hasattr(self, "artifacts_count_label"):
                self.artifacts_count_label.setText(f"Artifacts: {len(artifacts)} / {len(self.all_artifacts)}")
            self._update_report_selection_label()
            if not artifacts:
                self.artifact_details.setPlainText(
                    "Артефактов по текущим фильтрам нет. "
                    "Проверьте фильтр типа, строку поиска и переключатель "
                    "«Только выбранный object»."
                )

        def _selected_object_id(self) -> int | None:
            items = self.objects_table.selectedItems()
            if not items:
                return None
            row = items[0].row()
            item = self.objects_table.item(row, 0)
            if item is None:
                return None
            value = item.data(Qt.ItemDataRole.UserRole)
            return int(value if value is not None else item.text())

        def _selected_artifact_id(self) -> int | None:
            items = self.artifacts_table.selectedItems()
            if not items:
                return None
            row = items[0].row()
            item = self.artifacts_table.item(row, 0) or self.artifacts_table.item(row, 1)
            if item is None:
                return None
            value = item.data(Qt.ItemDataRole.UserRole)
            if value is not None:
                return int(value)
            id_item = self.artifacts_table.item(row, 1)
            return int(id_item.text()) if id_item else None

        def _visible_artifact_ids(self) -> list[int]:
            ids: list[int] = []
            for row in range(self.artifacts_table.rowCount()):
                item = self.artifacts_table.item(row, 0) or self.artifacts_table.item(row, 1)
                if item is None:
                    continue
                value = item.data(Qt.ItemDataRole.UserRole)
                if value is not None:
                    ids.append(int(value))
            return ids

        def _on_artifact_item_changed(self, item: QTableWidgetItem) -> None:
            if item.column() != 0:
                return
            value = item.data(Qt.ItemDataRole.UserRole)
            if value is None:
                return
            artifact_id = int(value)
            if item.checkState() == Qt.CheckState.Checked:
                self.report_artifact_ids.add(artifact_id)
            else:
                self.report_artifact_ids.discard(artifact_id)
            self._update_report_selection_label()

        def _select_visible_artifacts_for_report(self) -> None:
            self.report_artifact_ids.update(self._visible_artifact_ids())
            self._apply_filters()

        def _unselect_visible_artifacts_for_report(self) -> None:
            for artifact_id in self._visible_artifact_ids():
                self.report_artifact_ids.discard(artifact_id)
            self._apply_filters()

        def _clear_report_artifact_selection(self) -> None:
            self.report_artifact_ids.clear()
            self._apply_filters()

        def _update_report_selection_label(self) -> None:
            text = f"В отчёт выбрано: {len(self.report_artifact_ids)}"
            if hasattr(self, "report_selection_label"):
                self.report_selection_label.setText(text)
            if hasattr(self, "report_selected_count_label"):
                self.report_selected_count_label.setText(f"Выбрано артефактов: {len(self.report_artifact_ids)}")

        def _on_object_selection_changed(self) -> None:
            object_id = self._selected_object_id()
            obj = self.objects_by_id.get(object_id) if object_id is not None else None
            if obj is None:
                self.object_details.clear()
            else:
                self.object_details.setPlainText(self._object_to_text(obj))
            if self.selected_only_checkbox.isChecked():
                self._apply_filters()

        def _on_artifact_selection_changed(self) -> None:
            artifact_id = self._selected_artifact_id()
            artifact = self.artifacts_by_id.get(artifact_id) if artifact_id is not None else None
            if artifact is None:
                self.artifact_details.clear()
            else:
                self.artifact_details.setPlainText(self._artifact_to_text(artifact))

        def _object_to_text(self, obj: Any) -> str:
            return "\n".join(
                [
                    f"ID: {obj.id}",
                    f"Source ID: {obj.source_id}",
                    f"Type: {obj.object_type.value}",
                    f"Original path: {obj.original_path}",
                    f"Original name: {obj.original_name}",
                    f"Stored path: {obj.stored_path}",
                    f"Stored name: {obj.stored_name}",
                    f"Vault encrypted: {self.vault_encryption_enabled}",
                    f"Size: {obj.size_bytes}",
                    f"MIME: {obj.mime_type or ''}",
                    f"SHA-256: {obj.sha256}",
                    f"MD5: {obj.md5 or ''}",
                    f"Ingested at: {self._dt(obj.ingested_at)}",
                    f"Original exists flag: {obj.is_original}",
                    f"Stored exists flag: {obj.is_stored}",
                ]
            )

        def _artifact_to_text(self, artifact: Any) -> str:
            return "\n".join(
                [
                    f"ID: {artifact.id}",
                    f"Evidence object ID: {artifact.evidence_object_id}",
                    f"Type: {artifact.artifact_type.value}",
                    f"Timestamp: {self._dt(artifact.timestamp)}",
                    f"Timestamp start: {self._dt(artifact.timestamp_start)}",
                    f"Timestamp end: {self._dt(artifact.timestamp_end)}",
                    f"Title: {artifact.title}",
                    "",
                    "Raw data:",
                    self._json(artifact.raw_data_json),
                    "",
                    "Parsed data:",
                    self._json(artifact.parsed_data_json),
                ]
            )

        # ------------------------------------------------------------------
        # Verify/delete/report
        # ------------------------------------------------------------------
        def _verify_selected(self) -> None:
            object_id = self._selected_object_id()
            if object_id is None:
                self._info("Сначала выберите evidence object")
                return

            def op() -> str:
                with get_session(self._db_path()) as session:
                    verifier = FileVerifier(session, self._vault_dir(), encryption_key=self.encryption_key)
                    result, artifact = verifier.verify_object(object_id)
                return self._verify_result_to_text(result, artifact)

            self._run_operation(f"verify object {object_id}", op)

        def _verify_all(self) -> None:
            def op() -> str:
                object_filter = self.object_filter_combo.currentText()
                object_type = None if object_filter == "all" else EvidenceObjectType(object_filter)
                with get_session(self._db_path()) as session:
                    verifier = FileVerifier(session, self._vault_dir(), encryption_key=self.encryption_key)
                    results, artifacts = verifier.verify_all(object_type=object_type)
                modified = [item for item in results if item["is_modified"]]
                refreshed = [
                    item
                    for item in modified
                    if item.get("refresh_result") is not None
                    and item["refresh_result"].get("status") == "refreshed"
                ]
                lines = [
                    f"Object type filter: {object_filter}",
                    f"Objects checked: {len(results)}",
                    f"Modified or missing: {len(modified)}",
                    f"Vault refreshed: {len(refreshed)}",
                    f"Artifacts created: {len(artifacts)}",
                ]
                for item in modified:
                    lines.extend(
                        [
                            "",
                            f"Evidence object id: {item['object_id']}",
                            f"Object type: {item['object_type']}",
                            f"File: {item['original_name']}",
                            f"Original status: {item['original_check']['status']}",
                            f"Stored status: {item['stored_check']['status']}",
                        ]
                    )
                return "\n".join(lines)

            self._run_operation("verify all", op)

        def _verify_result_to_text(self, result: dict[str, Any], artifact: Any | None) -> str:
            lines = [
                f"Evidence object id: {result['object_id']}",
                f"File: {result['original_name']}",
                f"Original status: {result['original_check']['status']}",
                f"Stored status: {result['stored_check']['status']}",
            ]
            if result["is_modified"]:
                lines.append("Result: modified or missing")
                if artifact is not None:
                    lines.append(f"Modification artifact created: id={artifact.id}")
                refresh_result = result.get("refresh_result") or {}
                lines.append(f"Refresh status: {refresh_result.get('status', 'unknown')}")
                if refresh_result.get("new_sha256"):
                    lines.append(f"New SHA-256: {refresh_result['new_sha256']}")
                if refresh_result.get("reason"):
                    lines.append(f"Reason: {refresh_result['reason']}")
            else:
                lines.append("Result: not modified")
            return "\n".join(lines)

        def _delete_selected(self) -> None:
            object_id = self._selected_object_id()
            if object_id is None:
                self._info("Сначала выберите evidence object")
                return
            answer = QMessageBox.question(
                self,
                "Удалить evidence?",
                f"Удалить evidence object id={object_id} и его artifacts?",
            )
            if answer != QMessageBox.StandardButton.Yes:
                return

            def op() -> str:
                with get_session(self._db_path()) as session:
                    service = EvidenceService(session, self._vault_dir(), encryption_key=self.encryption_key)
                    result = service.delete_evidence(object_id)
                return (
                    "Evidence deleted\n"
                    f"Evidence object id: {result['object_id']}\n"
                    f"Original name: {result['original_name']}\n"
                    f"SHA-256: {result['sha256']}\n"
                    f"Stored path: {result['stored_path']}\n"
                    f"Vault file deleted: {result['file_deleted']}"
                )

            self._run_operation(f"delete object {object_id}", op)

        def _current_report_title(self) -> str:
            value = self.report_title_edit.text().strip() if hasattr(self, "report_title_edit") else ""
            if value:
                return value
            if self.metadata is not None and getattr(self.metadata, "title", None):
                return f"{self.metadata.title} - timeline report"
            return "Forensic timeline report"

        def _current_report_description(self) -> str:
            if not hasattr(self, "report_description_edit"):
                return ""
            return self.report_description_edit.toPlainText().strip()

        def _selected_report_artifact_ids(self) -> list[int]:
            return sorted(self.report_artifact_ids)

        def _require_report_artifacts(self) -> list[int] | None:
            artifact_ids = self._selected_report_artifact_ids()
            if not artifact_ids:
                self._info(
                    "Сначала отметьте артефакты чекбоксом на вкладке «Посмотреть артефакты». "
                    "Именно они попадут в PDF-таймлайн."
                )
                return None
            return artifact_ids

        def _generate_report_preview(self) -> None:
            artifact_ids = self._require_report_artifacts()
            if artifact_ids is None:
                return
            try:
                title = self._current_report_title()
                description = self._current_report_description()
                with get_session(self._db_path()) as session:
                    report = ReportService(session).make_timeline_text_report(
                        title=title,
                        description=description,
                        artifact_ids=artifact_ids,
                    )
                    audit_success(
                        session,
                        "report_preview_generated",
                        interface="gui",
                        target_type="report",
                        target_path=self.case_dir,
                        message="Timeline report preview generated",
                        details={
                            "title": title,
                            "artifact_ids": artifact_ids,
                            "artifact_count": len(artifact_ids),
                        },
                    )
                self.report_text.setPlainText(report)
                self._refresh_all(show_errors=False)
                self._set_status("Предпросмотр отчёта сгенерирован")
            except Exception as exc:
                self._error(str(exc), traceback.format_exc())

        def _save_pdf_report(self) -> None:
            artifact_ids = self._require_report_artifacts()
            if artifact_ids is None:
                return

            default_name = "timeline_report.pdf"
            path, _ = QFileDialog.getSaveFileName(
                self,
                "Сохранить PDF-отчёт",
                default_name,
                "PDF files (*.pdf);;All files (*)",
            )
            if not path:
                return
            if not path.lower().endswith(".pdf"):
                path += ".pdf"

            try:
                title = self._current_report_title()
                description = self._current_report_description()
                QApplication.setOverrideCursor(Qt.CursorShape.WaitCursor)
                with get_session(self._db_path()) as session:
                    result = ReportService(session).export_timeline_pdf(
                        path,
                        title=title,
                        description=description,
                        artifact_ids=artifact_ids,
                    )
                    audit_success(
                        session,
                        "pdf_report_saved",
                        interface="gui",
                        target_type="report",
                        target_path=path,
                        message="PDF timeline report saved",
                        details={
                            "title": title,
                            "path": path,
                            "artifact_ids": artifact_ids,
                            "artifact_count": len(artifact_ids),
                            "evidence_objects": result.get("evidence_objects"),
                        },
                    )
                with get_session(self._db_path()) as session:
                    preview = ReportService(session).make_timeline_text_report(
                        title=title,
                        description=description,
                        artifact_ids=artifact_ids,
                    )
                self.report_text.setPlainText(preview)
                self._refresh_all(show_errors=False)
                self._set_status(f"PDF-отчёт сохранён: {path}")
                self._info(f"PDF-отчёт сохранён:\n{path}")
            except Exception as exc:
                self._error(str(exc), traceback.format_exc())
            finally:
                QApplication.restoreOverrideCursor()

        # Backward-compatible wrappers for old signal names, if a stale UI hook
        # calls them from a previous version.
        def _generate_report(self) -> None:
            self._generate_report_preview()

        def _save_report(self) -> None:
            self._save_pdf_report()


def main() -> None:
    _ensure_pyside6_available()
    app = QApplication.instance() or QApplication(sys.argv)
    window = ForensicMvpQtGui()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
