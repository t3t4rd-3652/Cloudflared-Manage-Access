"""Boîtes de dialogue et pont moteur ↔ interface."""

from __future__ import annotations

import json

import asyncssh
from PySide6.QtWidgets import QCheckBox, QDialog, QFileDialog, QInputDialog, QLineEdit, QMessageBox

from cma.core.migrations import MigrationReport
from cma.core.models import AuthMode, CloudflareProfile, ServiceToken, SshProfile
from cma.core.prompts import PassphraseRequest, PasswordRequest
from cma.core.ssh.discovery import RemotePort
from cma.core.ssh.hostkeys import HostKeyPrompt, KnownHostsFile
from cma.ui.bridge import GuiPrompter
from cma.ui.dialogs import misc, prompts, transfer
from cma.ui.dialogs.onboarding import OnboardingWizard
from cma.ui.dialogs.redirect import RedirectDialog


def fill_line_edits(*values):
    def filler(dialog):
        edits = [
            e
            for e in dialog.findChildren(QLineEdit)
            if e.isEnabled() and e.echoMode() == QLineEdit.EchoMode.Password
        ] or dialog.findChildren(QLineEdit)
        for edit, value in zip(edits, values, strict=False):
            edit.setText(value)
        for box in dialog.findChildren(QCheckBox):
            box.setChecked(True)

    return filler


def test_prompt_dialogs(qapp, accept_dialogs):
    prompt = HostKeyPrompt(
        "srv",
        2222,
        "ssh-ed25519",
        "SHA256:abc",
        changed=True,
        previous_fingerprints=("SHA256:old",),
        via="ssh.ex.fr",
    )
    assert prompts.confirm_host_key(None, prompt)
    assert prompts.confirm_host_key(
        None, HostKeyPrompt("srv", 22, "ssh-ed25519", "SHA256:abc", changed=False)
    )
    accept_dialogs.append(fill_line_edits("mdp-secret"))
    answer = prompts.ask_password(None, PasswordRequest("P", "u@srv:22", error="Mot de passe refusé"))
    assert answer is not None
    assert answer.password == "mdp-secret"
    assert answer.remember
    assert prompts.ask_passphrase(None, PassphraseRequest("cle", error="faux")) == "mdp-secret"
    accept_dialogs.clear()
    accept_dialogs.append(fill_line_edits("phrase-longue", "phrase-longue"))
    assert prompts.ask_new_passphrase(None, "t", "x") == "phrase-longue"


def test_new_passphrase_validation(qapp, monkeypatch):
    def run(first, second):
        def fake_exec(self):
            edits = self.findChildren(QLineEdit)
            edits[0].setText(first)
            edits[1].setText(second)
            from PySide6.QtWidgets import QDialogButtonBox

            self.findChild(QDialogButtonBox).accepted.emit()
            return self.result()

        monkeypatch.setattr(QDialog, "exec", fake_exec)
        return prompts.ask_new_passphrase(None, "t", "x")

    assert run("court", "court") is None
    assert run("phrase-longue", "differente") is None


def test_gui_prompter_answers_the_engine(qtbot, gui, accept_dialogs):
    ctx, window = gui
    prompter = GuiPrompter()
    prompter.parent_provider = lambda: window
    accept_dialogs.append(fill_line_edits("depuis-l-interface"))
    future = ctx.engine.submit(prompter.ask_password(PasswordRequest("P", "u@h:22")))
    qtbot.waitUntil(future.done, timeout=5000)
    assert future.result().password == "depuis-l-interface"
    future = ctx.engine.submit(prompter.ask_passphrase(PassphraseRequest("cle")))
    qtbot.waitUntil(future.done, timeout=5000)
    assert future.result() == "depuis-l-interface"
    future = ctx.engine.submit(prompter.confirm_host_key(HostKeyPrompt("h", 22, "a", "f", False)))
    qtbot.waitUntil(future.done, timeout=5000)
    assert future.result() is True


def test_export_then_import(qtbot, gui, accept_dialogs, monkeypatch, tmp_path):
    ctx, window = gui
    token = ServiceToken(name="Prod", client_id="prod.access")
    profile = CloudflareProfile(
        name="Mongo", hostname="m.ex.fr", local_port=27017, auth=AuthMode.SERVICE_TOKEN, token_id=token.id
    )
    ctx.update_config(lambda c: (c.tokens.append(token), c.cloudflare_profiles.append(profile)))
    ctx.core.secrets.set(token.secret_key, "secret-prod")
    target = tmp_path / "export.json"
    monkeypatch.setattr(QFileDialog, "getSaveFileName", lambda *a, **k: (str(target), ""))
    monkeypatch.setattr(transfer, "ask_new_passphrase", lambda *a, **k: "phrase-longue")
    accept_dialogs.append(
        lambda d: d.with_secrets.setChecked(True) if isinstance(d, transfer.ExportDialog) else None
    )
    transfer.run_export(ctx, window)
    data = json.loads(target.read_text(encoding="utf-8"))
    assert "secrets" in data
    assert "secret-prod" not in target.read_text(encoding="utf-8")

    ctx.update_config(lambda c: (c.cloudflare_profiles.clear(), c.tokens.clear()))
    monkeypatch.setattr(QFileDialog, "getOpenFileName", lambda *a, **k: (str(target), ""))
    accept_dialogs.clear()
    accept_dialogs.append(
        lambda d: d.passphrase.setText("phrase-longue") if isinstance(d, transfer.ImportDialog) else None
    )
    transfer.run_import(ctx, window)
    config = ctx.config()
    assert [p.name for p in config.cloudflare_profiles] == ["Mongo"]
    assert ctx.core.secrets.get(config.tokens[0].secret_key) == "secret-prod"

    bad = tmp_path / "mauvais.json"
    bad.write_text("[]", encoding="utf-8")
    monkeypatch.setattr(QFileDialog, "getOpenFileName", lambda *a, **k: (str(bad), ""))
    transfer.run_import(ctx, window)
    assert not window.banners.isHidden()


def test_import_with_wrong_passphrase_is_refused(qtbot, gui, monkeypatch):
    ctx, window = gui
    from cma.core.transfer import build_export, plan_import

    ctx.update_config(lambda c: c.tokens.append(ServiceToken(name="T", client_id="t")))
    plan = plan_import(build_export(ctx.config(), ctx.core.secrets, passphrase="bonne-phrase"), ctx.config())
    dialog = transfer.ImportDialog(window, plan)
    dialog.passphrase.setText("mauvaise")
    dialog._accept()
    assert dialog.passphrase_error.text()
    assert dialog.result() != QDialog.DialogCode.Accepted


def test_migration_report_and_v1_cleanup(qtbot, gui, accept_dialogs, monkeypatch):
    ctx, window = gui
    (ctx.paths.data_dir / "cloudflared_tokens.json").write_text("{}", encoding="utf-8")
    report = MigrationReport(
        profiles=1, tokens=1, created_tokens=["X (migré)"], warnings=["à voir"], backup_dir=ctx.paths.data_dir
    )
    misc.show_migration_report(ctx, window, report)
    monkeypatch.setattr(QMessageBox, "question", lambda *a, **k: QMessageBox.StandardButton.No)
    assert not misc.confirm_delete_v1(ctx, window)
    monkeypatch.setattr(QMessageBox, "question", lambda *a, **k: QMessageBox.StandardButton.Yes)
    assert misc.confirm_delete_v1(ctx, window)
    assert not (ctx.paths.data_dir / "cloudflared_tokens.json").exists()
    assert ctx.config().settings.v1_files_handled
    misc.show_text(window, "t", "intro", "texte à copier")


def test_known_hosts_and_keys_dialogs(qtbot, gui, accept_dialogs, monkeypatch):
    ctx, window = gui
    key = asyncssh.generate_private_key("ssh-ed25519")
    KnownHostsFile(ctx.paths.known_hosts).add("srv.ex.fr", 22, key, replace=True)
    dialog = misc.KnownHostsDialog(window, ctx)
    assert dialog.table.rowCount() >= 1
    dialog.table.selectRow(0)
    dialog._remove()
    assert dialog.table.rowCount() == 0

    keys_dialog = misc.KeysDialog(window, ctx)
    monkeypatch.setattr(QInputDialog, "getText", lambda *a, **k: ("testui", True))
    monkeypatch.setattr(QMessageBox, "question", lambda *a, **k: QMessageBox.StandardButton.No)
    keys_dialog._generate()
    names = [k.name for k in keys_dialog.keys]
    assert "id_ed25519_testui" in names
    keys_dialog.table.selectRow(names.index("id_ed25519_testui"))
    keys_dialog._copy()
    monkeypatch.setattr(QMessageBox, "question", lambda *a, **k: QMessageBox.StandardButton.Yes)
    monkeypatch.setattr(misc, "ask_new_passphrase", lambda *a, **k: "phrase-longue")
    monkeypatch.setattr(QInputDialog, "getText", lambda *a, **k: ("protegee", True))
    keys_dialog._generate()
    protected = next(k for k in keys_dialog.keys if k.name == "id_ed25519_protegee")
    assert protected.encrypted
    keys_dialog.table.selectRow([k.name for k in keys_dialog.keys].index("id_ed25519_testui"))
    keys_dialog._delete()
    assert "id_ed25519_testui" not in [k.name for k in keys_dialog.keys]


def test_redirect_dialog(qtbot, gui):
    ctx, window = gui
    remote = RemotePort(3000, ("127.0.0.1",), container="grafana", scheme="https", http_code=302)
    dialog = RedirectDialog(window, ctx, remote=remote)
    assert dialog.label_edit.text() == "grafana"
    dialog._accept()
    assert dialog.choice is not None
    assert dialog.choice.forward.remote_port == 3000
    assert dialog.choice.forward.scheme == "https"
    editing = RedirectDialog(window, ctx, existing=dialog.choice.forward)
    editing.remote_host.setText("pas une adresse")
    editing._accept()
    assert editing.choice is None
    assert editing.error.text()
    empty = RedirectDialog(window, ctx)
    empty.remote_port.setText("")
    empty._accept()
    assert "requis" in empty.error.text()


def test_onboarding_creates_a_first_profile(qtbot, gui):
    ctx, window = gui
    wizard = OnboardingWizard(window, ctx, None)
    wizard.show()
    wizard.next()
    wizard.next()
    assert wizard.currentId() == 2
    wizard.hostname.setText("ssh.exemple.fr")
    wizard.token.setChecked(True)
    assert not wizard.validateCurrentPage()
    wizard.client_id.setText("id.access")
    wizard.secret.edit.setText("secret-assistant")
    assert wizard.validateCurrentPage()
    config = ctx.config()
    assert config.cloudflare_profiles[0].favorite
    assert ctx.core.secrets.get(config.tokens[0].secret_key) == "secret-assistant"
    wizard.hostname.setText("avec espace")
    assert not wizard.validateCurrentPage()
    wizard.close()


def test_choose_secret_store(qapp, monkeypatch, tmp_path):
    clicked = {}

    def fake_exec(self):
        clicked["button"] = self.buttons()[0]
        return 0

    monkeypatch.setattr(QMessageBox, "exec", fake_exec)
    monkeypatch.setattr(QMessageBox, "clickedButton", lambda self: clicked.get("button"))
    monkeypatch.setattr(misc, "ask_new_passphrase", lambda *a, **k: "phrase-longue")
    assert misc.choose_secret_store(None, tmp_path / "absent.json") == "phrase-longue"
    existing = tmp_path / "coffre.json"
    existing.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(QInputDialog, "getText", lambda *a, **k: ("phrase", True))
    assert misc.choose_secret_store(None, existing) == "phrase"
    monkeypatch.setattr(QMessageBox, "clickedButton", lambda self: None)
    assert misc.choose_secret_store(None, existing) is None
    assert SshProfile(name="x")  # modèle importé pour les autres tests
