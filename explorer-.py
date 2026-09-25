# -*- coding: utf-8 -*-
import sys
import os
import shutil
import string
import ctypes
import stat
import time

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLineEdit, QPushButton, QListWidget, QListWidgetItem,
    QSplitter, QTreeWidget, QTreeWidgetItem, QLabel, QMenu,
    QMessageBox, QInputDialog, QCheckBox, QAbstractItemView,
    QFileIconProvider, QDialog, QDialogButtonBox
)
from PyQt6.QtCore import Qt, QFileInfo, QMimeData, QUrl, QThread, pyqtSignal
from PyQt6.QtGui import QAction

import psutil


DARK_QSS = """
QMainWindow, QWidget       { background-color: #1e1e1e; color: #d4d4d4; }
QLineEdit                  { background-color: #2d2d2d; border: 1px solid #3c3c3c;
                             border-radius: 3px; padding: 4px 8px; color: #d4d4d4; }
QPushButton                { background-color: #2d2d2d; border: 1px solid #3c3c3c;
                             border-radius: 3px; padding: 4px 10px; color: #d4d4d4; }
QPushButton:hover          { background-color: #3c3c3c; }
QPushButton:pressed        { background-color: #094771; }
QTreeWidget, QListWidget   { background-color: #252526; border: 1px solid #3c3c3c;
                             color: #d4d4d4; outline: none; }
QTreeWidget::item:selected,
QListWidget::item:selected { background-color: #094771; color: #ffffff; }
QTreeWidget::item:hover,
QListWidget::item:hover    { background-color: #2a2d2e; }
QSplitter::handle          { background-color: #3c3c3c; }
QLabel                     { color: #808080; }
QCheckBox                  { color: #d4d4d4; spacing: 5px; }
QMenu                      { background-color: #2d2d2d; border: 1px solid #3c3c3c;
                             color: #d4d4d4; }
QMenu::item:selected       { background-color: #094771; }
QDialog                    { background-color: #1e1e1e; }
"""


def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def relaunch_as_admin():
    if is_admin():
        return False
    params = " ".join(f'"{a}"' for a in sys.argv)
    try:
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, params, None, 1
        )
        return True
    except Exception as e:
        print("Не удалось запросить права:", e)
        return False


class ProcessSearchWorker(QThread):
    found = pyqtSignal(str, list)

    def __init__(self, filepath):
        super().__init__()
        self.filepath = filepath

    @staticmethod
    def _variants(text):
        if not text:
            return set()
        t = text.lower()
        return {
            t,
            t.replace("_", " "),
            t.replace("-", " "),
            t.replace("_", " ").replace("-", " "),
            t.replace("_", "").replace("-", ""),
            t.replace("_", "").replace("-", "").replace(" ", ""),
        }

    @staticmethod
    def _proc_info(proc):
        try:
            info = proc.info
            return {
                "pid": info.get("pid"),
                "name": info.get("name") or "?",
                "exe": info.get("exe") or "",
                "cmdline": " ".join(info.get("cmdline") or [])[:200],
            }
        except Exception:
            return {"pid": proc.pid, "name": "?", "exe": "", "cmdline": ""}

    def run(self):
        try:
            result = self._search()
        except Exception as e:
            print("Ошибка поиска процесса:", e)
            result = []
        self.found.emit(self.filepath, result)

    def _search(self):
        filepath = os.path.abspath(self.filepath)
        basename = os.path.basename(filepath)
        stem, _ = os.path.splitext(basename)

        target_variants = self._variants(stem)
        target_variants.add(basename.lower())

        exact, name_match = [], []

        for proc in psutil.process_iter(["pid", "name", "exe", "cmdline"]):
            try:
                info = proc.info
                pname = (info.get("name") or "").lower()
                pexe = (info.get("exe") or "").lower() if info.get("exe") else ""
                if not pname:
                    continue

                pname_stem, _ = os.path.splitext(pname)
                pexe_base = os.path.basename(pexe) if pexe else ""
                pexe_stem, _ = os.path.splitext(pexe_base)

                if pexe and pexe == filepath.lower():
                    exact.append(self._proc_info(proc))
                    continue

                if (target_variants & self._variants(pname_stem)) or \
                   (target_variants & self._variants(pexe_stem)):
                    name_match.append(self._proc_info(proc))

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        if not exact:
            for proc in psutil.process_iter(["pid", "name", "exe", "cmdline"]):
                try:
                    for f in proc.open_files():
                        try:
                            if os.path.samefile(f.path, filepath):
                                info = self._proc_info(proc)
                                if info not in exact:
                                    exact.append(info)
                                break
                        except OSError:
                            continue
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    continue

        seen, result = set(), []
        for p in exact + name_match:
            if p["pid"] not in seen:
                seen.add(p["pid"])
                result.append(p)
        return result


class ProcessChooserDialog(QDialog):
    def __init__(self, procs, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Выберите процессы для завершения")
        self.resize(700, 400)

        layout = QVBoxLayout(self)
        layout.addWidget(QLabel(
            f"Найдено процессов: {len(procs)}.\n"
            "Отметьте те, которые нужно завершить:"
        ))

        self.list_widget = QListWidget()
        for p in procs:
            text = f"{p['name']}  (PID {p['pid']})"
            if p["exe"]:
                text += f"  —  {p['exe']}"
            it = QListWidgetItem(text)
            it.setData(Qt.ItemDataRole.UserRole, p)
            it.setFlags(it.flags() | Qt.ItemFlag.ItemIsUserCheckable)
            it.setCheckState(Qt.CheckState.Checked)
            self.list_widget.addItem(it)
        layout.addWidget(self.list_widget)

        btns = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok |
            QDialogButtonBox.StandardButton.Cancel
        )
        btns.button(QDialogButtonBox.StandardButton.Ok).setText("Завершить")
        btns.button(QDialogButtonBox.StandardButton.Cancel).setText("Отмена")
        btns.accepted.connect(self.accept)
        btns.rejected.connect(self.reject)
        layout.addWidget(btns)

    def selected(self):
        return [
            self.list_widget.item(i).data(Qt.ItemDataRole.UserRole)
            for i in range(self.list_widget.count())
            if self.list_widget.item(i).checkState() == Qt.CheckState.Checked
        ]


class FileListWidget(QListWidget):
    def __init__(self, explorer, parent=None):
        super().__init__(parent)
        self.explorer = explorer
        self.setDragEnabled(True)
        self.setAcceptDrops(True)
        self.setDropIndicatorShown(True)
        self.setDragDropMode(QAbstractItemView.DragDropMode.DragDrop)

    def mimeData(self, items):
        mime = QMimeData()
        urls = []
        for it in items:
            path = it.data(Qt.ItemDataRole.UserRole)
            if path:
                urls.append(QUrl.fromLocalFile(path))
        mime.setUrls(urls)
        return mime

    def dropEvent(self, event):
        if not event.mimeData().hasUrls():
            super().dropEvent(event)
            return

        for url in event.mimeData().urls():
            src = url.toLocalFile()
            if not src or not os.path.exists(src):
                continue
            dst = os.path.join(self.explorer.current_dir, os.path.basename(src))
            try:
                if os.path.isdir(src):
                    shutil.copytree(src, dst)
                else:
                    shutil.copy2(src, dst)
            except OSError as e:
                QMessageBox.warning(self, "Ошибка", str(e))

        self.explorer.refresh_current()
        event.acceptProposedAction()


class FolderTreeWidget(QTreeWidget):
    def __init__(self, explorer, parent=None):
        super().__init__(parent)
        self.explorer = explorer
        self.setAcceptDrops(True)
        self.setDragDropMode(QAbstractItemView.DragDropMode.DropOnly)

    def dragEnterEvent(self, event):
        event.acceptProposedAction() if event.mimeData().hasUrls() else event.ignore()

    def dragMoveEvent(self, event):
        event.acceptProposedAction() if event.mimeData().hasUrls() else event.ignore()

    def dropEvent(self, event):
        if not event.mimeData().hasUrls():
            event.ignore()
            return

        item = self.itemAt(event.position().toPoint())
        if item is None:
            event.ignore()
            return

        target_dir = item.text(0)
        if not os.path.isdir(target_dir):
            event.ignore()
            return

        for url in event.mimeData().urls():
            src = url.toLocalFile()
            if not src or not os.path.exists(src):
                continue
            dst = os.path.join(target_dir, os.path.basename(src))
            try:
                shutil.move(src, dst)
            except OSError as e:
                QMessageBox.warning(self, "Ошибка перемещения", str(e))

        self.explorer.refresh_current()
        event.acceptProposedAction()


class ExplorerWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self._update_title()
        self.resize(1200, 720)

        self.history = []
        self.history_index = -1
        self.clipboard = None
        self.current_dir = ""
        self.show_hidden = True
        self.icon_provider = QFileIconProvider()

        self._delete_queue = []
        self._workers = []

        central = QWidget()
        self.setCentralWidget(central)

        main_layout = QVBoxLayout(central)
        main_layout.setContentsMargins(6, 6, 6, 4)
        main_layout.setSpacing(4)

        top_bar = QHBoxLayout()
        top_bar.setSpacing(4)

        self.btn_back = QPushButton("←")
        self.btn_forward = QPushButton("→")
        self.btn_up = QPushButton("↑")
        self.btn_refresh = QPushButton("⟳")
        self.btn_new = QPushButton("＋")
        self.address_bar = QLineEdit()
        self.cb_hidden = QCheckBox("Скрытые")
        self.cb_hidden.setChecked(True)

        for w in (self.btn_back, self.btn_forward, self.btn_up,
                  self.btn_refresh, self.btn_new):
            top_bar.addWidget(w)
        top_bar.addWidget(self.address_bar)
        top_bar.addWidget(self.cb_hidden)
        main_layout.addLayout(top_bar)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        self.tree = FolderTreeWidget(self)
        self.tree.setHeaderLabel("Папки")
        self.file_list = FileListWidget(self)
        self.file_list.setSelectionMode(QListWidget.SelectionMode.ExtendedSelection)
        self.file_list.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)

        splitter.addWidget(self.tree)
        splitter.addWidget(self.file_list)
        splitter.setSizes([320, 880])
        main_layout.addWidget(splitter)

        self.status = QLabel("Готов")
        self.status.setFixedHeight(16)
        self.status.setWordWrap(False)
        self.status.setStyleSheet("font-size: 11px; padding: 0 4px;")
        main_layout.addWidget(self.status)

        self.btn_back.clicked.connect(self.go_back)
        self.btn_forward.clicked.connect(self.go_forward)
        self.btn_up.clicked.connect(self.go_up)
        self.btn_refresh.clicked.connect(self.refresh_current)
        self.btn_new.clicked.connect(self.create_folder)
        self.address_bar.returnPressed.connect(self.open_path_from_bar)
        self.cb_hidden.toggled.connect(self._on_hidden_toggled)
        self.tree.itemDoubleClicked.connect(self.on_tree_double_click)
        self.tree.itemExpanded.connect(self.on_tree_expanded)
        self.file_list.itemDoubleClicked.connect(self.on_file_double_click)
        self.file_list.customContextMenuRequested.connect(self.show_context_menu)

        self.populate_drives()

    def _update_title(self):
        suffix = "" if is_admin() else "  [не админ]"
        self.setWindowTitle(f"Explorer-{suffix}")

    def _is_hidden(self, path):
        try:
            attrs = os.stat(path).st_file_attributes
            return bool(attrs & stat.FILE_ATTRIBUTE_HIDDEN or
                        attrs & stat.FILE_ATTRIBUTE_SYSTEM)
        except (OSError, AttributeError):
            return False

    def _on_hidden_toggled(self, checked):
        self.show_hidden = checked
        if self.current_dir:
            self._refresh_file_list()

    def populate_drives(self):
        self.tree.clear()
        if os.name == "nt":
            bitmask = ctypes.windll.kernel32.GetLogicalDrives()
            drives = [f"{letter}:\\"
                      for i, letter in enumerate(string.ascii_uppercase)
                      if bitmask & (1 << i)]
        else:
            drives = ["/"]

        for drive in drives:
            item = QTreeWidgetItem([drive])
            item.addChild(QTreeWidgetItem(["Загрузка..."]))
            self.tree.addTopLevelItem(item)

    def on_tree_expanded(self, item):
        if item.childCount() == 1 and item.child(0).text(0) == "Загрузка...":
            item.takeChild(0)
            self._fill_tree_node(item, item.text(0))

    def _fill_tree_node(self, parent_item, path):
        try:
            entries = sorted(os.listdir(path), key=str.lower)
        except PermissionError:
            return

        for name in entries:
            full = os.path.join(path, name)
            if not os.path.isdir(full):
                continue
            if not self.show_hidden and self._is_hidden(full):
                continue
            child = QTreeWidgetItem([full])
            child.addChild(QTreeWidgetItem(["Загрузка..."]))
            parent_item.addChild(child)

    def on_tree_double_click(self, item, column):
        path = item.text(0)
        if os.path.isdir(path):
            self.navigate_to(path)

    def navigate_to(self, path, add_history=True):
        if not os.path.isdir(path):
            self.status.setText(f"Не папка: {path}")
            return
        self.current_dir = path
        self.address_bar.setText(path)
        self._refresh_file_list()
        if add_history:
            self.history = self.history[:self.history_index + 1]
            if not self.history or self.history[-1] != path:
                self.history.append(path)
                self.history_index = len(self.history) - 1

    def go_back(self):
        if self.history_index > 0:
            self.history_index -= 1
            self.navigate_to(self.history[self.history_index], add_history=False)

    def go_forward(self):
        if self.history_index < len(self.history) - 1:
            self.history_index += 1
            self.navigate_to(self.history[self.history_index], add_history=False)

    def go_up(self):
        if not self.current_dir:
            return
        parent = os.path.dirname(self.current_dir.rstrip("\\/"))
        if parent and os.path.isdir(parent):
            self.navigate_to(parent)

    def refresh_current(self):
        if self.current_dir:
            self._refresh_file_list()

    def open_path_from_bar(self):
        path = self.address_bar.text().strip().strip('"')
        if os.path.isdir(path):
            self.navigate_to(path)
        elif os.path.isfile(path):
            os.startfile(path)
        else:
            self.status.setText(f"Путь не найден: {path}")

    def _refresh_file_list(self):
        self.file_list.clear()
        try:
            entries = os.listdir(self.current_dir)
        except PermissionError:
            self.status.setText(f"Нет доступа: {self.current_dir}")
            return
        except OSError as e:
            self.status.setText(f"Ошибка: {e}")
            return

        dirs, files = [], []
        for name in entries:
            full = os.path.join(self.current_dir, name)
            if not self.show_hidden and self._is_hidden(full):
                continue
            (dirs if os.path.isdir(full) else files).append(name)

        dirs.sort(key=str.lower)
        files.sort(key=str.lower)

        for name in dirs + files:
            full = os.path.join(self.current_dir, name)
            is_dir = name in dirs
            it = QListWidgetItem(name)
            it.setIcon(self.icon_provider.icon(QFileInfo(full)))
            it.setData(Qt.ItemDataRole.UserRole, full)
            it.setData(Qt.ItemDataRole.UserRole + 1, is_dir)
            self.file_list.addItem(it)

        self.status.setText(
            f"{self.current_dir}   |   папок: {len(dirs)}, файлов: {len(files)}"
        )

    def on_file_double_click(self, item):
        path = item.data(Qt.ItemDataRole.UserRole)
        if item.data(Qt.ItemDataRole.UserRole + 1):
            self.navigate_to(path)
        else:
            try:
                os.startfile(path)
            except OSError as e:
                self.status.setText(f"Не удалось открыть: {e}")

    def create_folder(self):
        if not self.current_dir:
            return
        name, ok = QInputDialog.getText(self, "Новая папка", "Имя папки:")
        if ok and name:
            try:
                os.mkdir(os.path.join(self.current_dir, name))
                self._refresh_file_list()
            except OSError as e:
                QMessageBox.warning(self, "Ошибка", str(e))

    def show_context_menu(self, pos):
        item = self.file_list.itemAt(pos)
        menu = QMenu(self)

        if item is not None:
            act_open = QAction("Открыть", self)
            act_open.triggered.connect(lambda: self.on_file_double_click(item))
            act_rename = QAction("Переименовать", self)
            act_rename.triggered.connect(lambda: self.rename_item(item))
            act_delete = QAction("Удалить", self)
            act_delete.triggered.connect(self.delete_items)
            act_copy = QAction("Копировать", self)
            act_copy.triggered.connect(lambda: self.copy_items(cut=False))
            act_cut = QAction("Вырезать", self)
            act_cut.triggered.connect(lambda: self.copy_items(cut=True))

            menu.addAction(act_open)
            menu.addSeparator()
            menu.addAction(act_copy)
            menu.addAction(act_cut)
            menu.addAction(act_rename)
            menu.addSeparator()
            menu.addAction(act_delete)
        else:
            act_new = QAction("Создать папку", self)
            act_new.triggered.connect(self.create_folder)
            menu.addAction(act_new)
            if self.clipboard:
                act_paste = QAction("Вставить", self)
                act_paste.triggered.connect(self.paste_items)
                menu.addAction(act_paste)

        menu.exec(self.file_list.mapToGlobal(pos))

    def rename_item(self, item):
        old_path = item.data(Qt.ItemDataRole.UserRole)
        old_name = os.path.basename(old_path)
        new_name, ok = QInputDialog.getText(
            self, "Переименовать", "Новое имя:", text=old_name
        )
        if ok and new_name and new_name != old_name:
            new_path = os.path.join(os.path.dirname(old_path), new_name)
            try:
                os.rename(old_path, new_path)
                self._refresh_file_list()
            except OSError as e:
                QMessageBox.warning(self, "Ошибка", str(e))

    def copy_items(self, cut=False):
        items = self.file_list.selectedItems()
        if not items:
            return
        path = items[0].data(Qt.ItemDataRole.UserRole)
        self.clipboard = (path, "cut" if cut else "copy")
        self.status.setText(f"{'Вырезано' if cut else 'Скопировано'}: {path}")

    def paste_items(self):
        if not self.clipboard:
            return
        src, mode = self.clipboard
        dst = os.path.join(self.current_dir, os.path.basename(src))
        try:
            if mode == "copy":
                (shutil.copytree if os.path.isdir(src) else shutil.copy2)(src, dst)
            else:
                shutil.move(src, dst)
                self.clipboard = None
            self._refresh_file_list()
        except OSError as e:
            QMessageBox.warning(self, "Ошибка", str(e))

    def delete_items(self):
        items = self.file_list.selectedItems()
        if not items:
            return
        reply = QMessageBox.question(
            self, "Удаление",
            f"Удалить {len(items)} объект(ов)?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if reply != QMessageBox.StandardButton.Yes:
            return

        self._delete_queue = [it.data(Qt.ItemDataRole.UserRole) for it in items]
        self._process_next_delete()

    def _process_next_delete(self):
        if not self._delete_queue:
            self._refresh_file_list()
            self.status.setText("Готов")
            return

        path = self._delete_queue.pop(0)
        if not os.path.exists(path):
            self._process_next_delete()
            return

        try:
            self._plain_delete(path)
            self.status.setText(f"Удалено: {path}")
            self._process_next_delete()
            return
        except PermissionError:
            pass
        except OSError as e:
            QMessageBox.warning(self, "Ошибка удаления", f"{path}\n{e}")
            self._process_next_delete()
            return

        self.status.setText(f"Поиск процесса для {os.path.basename(path)}...")
        worker = ProcessSearchWorker(path)
        worker.found.connect(self._on_processes_found)
        self._workers.append(worker)
        worker.finished.connect(
            lambda w=worker: self._workers.remove(w) if w in self._workers else None
        )
        worker.start()

    def _on_processes_found(self, path, procs):
        if not procs:
            QMessageBox.warning(
                self, "Процесс не найден",
                f"Не удалось определить процесс,\nдержащий файл:\n{path}"
            )
            self._process_next_delete()
            return

        if len(procs) == 1:
            p = procs[0]
            reply = QMessageBox.question(
                self, "Завершить процесс?",
                f"Файл:\n{path}\n\nдержит процесс:\n"
                f"  {p['name']} (PID {p['pid']})\n"
                f"  {p['exe']}\n\nЗавершить его и повторить удаление?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            if reply != QMessageBox.StandardButton.Yes:
                self._process_next_delete()
                return
            self._kill_processes([p])
            self._retry_delete(path)
            self._process_next_delete()
            return

        dlg = ProcessChooserDialog(procs, self)
        if dlg.exec() != QDialog.DialogCode.Accepted:
            self._process_next_delete()
            return
        chosen = dlg.selected()
        if not chosen:
            self._process_next_delete()
            return
        self._kill_processes(chosen)
        self._retry_delete(path)
        self._process_next_delete()

    def _plain_delete(self, path):
        if os.path.isdir(path):
            def on_rm_error(func, p, exc_info):
                try:
                    os.chmod(p, stat.S_IWRITE)
                    func(p)
                except OSError:
                    raise
            shutil.rmtree(path, onerror=on_rm_error)
        else:
            try:
                os.chmod(path, stat.S_IWRITE)
            except OSError:
                pass
            os.remove(path)

    def _retry_delete(self, path):
        try:
            time.sleep(0.4)
            self._plain_delete(path)
            self.status.setText(f"Удалено: {path}")
        except OSError as e:
            QMessageBox.warning(
                self, "Не получается удалить файл",
                f"{path}\n\n{e}"
            )

    def _kill_processes(self, procs):
        for p in procs:
            try:
                proc = psutil.Process(p["pid"])
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                except psutil.TimeoutExpired:
                    proc.kill()
                self.status.setText(f"Завершён: {p['name']} (PID {p['pid']})")
            except psutil.NoSuchProcess:
                continue
            except psutil.AccessDenied:
                QMessageBox.warning(
                    self, "Ошибка",
                    f"Не удалось завершить {p['name']} (PID {p['pid']})."
                )


def main():
    app = QApplication(sys.argv)
    app.setStyleSheet(DARK_QSS)

    if relaunch_as_admin():
        sys.exit(0)

    window = ExplorerWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()