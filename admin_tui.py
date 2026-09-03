"""
Author: Richard Baldwin
Date:   2026
Email:  eyeclept@pm.me

Description:
    Terminal admin UI for CCChatShare using Textual. Provides a DataTable
    view of all shared chats with keybindings to regenerate access codes,
    toggle revocation status, and permanently delete chats. Reads from
    CCCHATSHARE_DB_PATH environment variable (default /data/ccchatshare.db).
"""
# Imports
import logging
import os
import sqlite3
from datetime import datetime

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Vertical
from textual.screen import Screen, ModalScreen
from textual.widgets import DataTable, Footer, Header, Static, Button
from textual.containers import Horizontal
from rich.text import Text
from textual.widgets._data_table import RowDoesNotExist

from app.db import connect
from app.models import list_chats, regenerate_access_code, set_revoked, delete_chat

logger = logging.getLogger(__name__)


class ConfirmationModal(ModalScreen[bool]):
    """
    A simple yes/no confirmation dialog.
    
    Input: title (str), message (str)
    Output: True if user clicked Yes, False if Cancel
    """

    DEFAULT_CSS = """
    ConfirmationModal {
        align: center middle;
    }
    ConfirmationModal #confirm-box {
        width: 60;
        height: auto;
        border: tall $panel;
        padding: 1 2;
    }
    ConfirmationModal #confirm-message {
        margin-bottom: 1;
        width: 1fr;
    }
    ConfirmationModal Horizontal {
        margin-top: 1;
    }
    """

    def __init__(self, title: str, message: str) -> None:
        """
        Input: title -- dialog title, message -- message text
        Output: None
        Details: Stores title/message to display in compose()
        """
        super().__init__()
        self.title = title
        self.message = message

    def compose(self) -> ComposeResult:
        """Render the confirmation dialog."""
        with Vertical(id="confirm-box"):
            yield Static(self.title, classes="heading")
            yield Static(self.message, id="confirm-message")
            with Horizontal():
                yield Button("Yes", id="yes-btn", variant="primary")
                yield Button("Cancel", id="cancel-btn")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """
        Input: event -- Button.Pressed from Yes or Cancel
        Output: None
        Details: Dismisses with True (Yes) or False (Cancel)
        """
        if event.button.id == "yes-btn":
            self.dismiss(True)
        else:
            self.dismiss(False)


class CodeDisplayModal(ModalScreen[None]):
    """
    Modal that shows a newly regenerated access code. The user must
    dismiss it. The TUI shows the plaintext regenerated code only here.

    Input: new_code (str)
    Output: None (dismissed on button click)
    """

    DEFAULT_CSS = """
    CodeDisplayModal {
        align: center middle;
    }
    CodeDisplayModal #code-box {
        width: 70;
        height: auto;
        border: tall $panel;
        padding: 1 2;
    }
    CodeDisplayModal #code-display {
        margin: 1 0;
        width: 1fr;
        text-align: center;
    }
    CodeDisplayModal #code-text {
        background: $boost;
        padding: 1;
        text-align: center;
        margin-bottom: 1;
    }
    """

    def __init__(self, new_code: str) -> None:
        """
        Input: new_code -- the plaintext access code to display
        Output: None
        Details: Stores code for display in compose()
        """
        super().__init__()
        self.new_code = new_code

    def compose(self) -> ComposeResult:
        """Render the code display dialog."""
        with Vertical(id="code-box"):
            yield Static("New Access Code Generated", classes="heading")
            yield Static(
                "This is the only time the plaintext code is shown. "
                "Save it or share it now.",
                id="code-display",
            )
            yield Static(self.new_code, id="code-text", classes="code")
            with Horizontal():
                yield Button("Dismiss", id="dismiss-btn", variant="primary")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """
        Input: event -- Button.Pressed from Dismiss
        Output: None
        Details: Closes the modal
        """
        self.dismiss(None)


class MainScreen(Screen):
    """
    Main admin screen showing all chats in a DataTable with keybindings to
    manage access codes, revocation status, and deletion.
    
    Input: conn (sqlite3.Connection) -- database connection
    Output: None
    Details: Sets self.conn for use in action methods
    """

    DEFAULT_CSS = """
    MainScreen #main-body {
        padding: 1 2;
    }
    MainScreen DataTable {
        width: 1fr;
        height: 1fr;
    }
    MainScreen #status-msg {
        dock: bottom;
        background: $boost;
        padding: 0 1;
    }
    """

    BINDINGS = [
        Binding("r", "regenerate", "Regenerate Code", show=True),
        Binding("x", "toggle_revoke", "Toggle Status", show=True),
        Binding("d", "delete_chat", "Delete", show=True),
        Binding("q", "quit", "Quit", show=True),
    ]

    def __init__(self, conn: sqlite3.Connection) -> None:
        """
        Input: conn -- open sqlite3.Connection to the chats database
        Output: None
        Details: Stores connection for DAO method calls
        """
        super().__init__()
        self.conn = conn

    def compose(self) -> ComposeResult:
        """Render the main screen with header, table, and footer."""
        yield Header()
        with Vertical(id="main-body"):
            yield Static("Chats Manager", classes="heading")
            table = DataTable()
            table.add_columns("Slug", "Title", "Created", "Views", "Last Viewed", "Status")
            yield table
        yield Footer()
        yield Static("", id="status-msg")

    def on_mount(self) -> None:
        """
        Input: None
        Output: None
        Details: Loads all chats from the database into the DataTable
        """
        self._refresh_table()

    def _refresh_table(self) -> None:
        """
        Input: None
        Output: None
        Details: Fetches list_chats() and repopulates the DataTable, resetting selection
        """
        try:
            chats = list_chats(self.conn)
            table = self.query_one(DataTable)
            table.clear()

            for chat in chats:
                created = chat.created_at.split("T")[0] if chat.created_at else ""
                views = str(chat.view_count)
                last_viewed = chat.last_viewed_at.split("T")[0] if chat.last_viewed_at else "-"
                status = "revoked" if chat.revoked else "active"

                table.add_row(
                    chat.slug,
                    Text(chat.title),
                    created,
                    views,
                    last_viewed,
                    status,
                    key=chat.slug,
                )

            self._show_status("")
        except sqlite3.OperationalError as e:
            logger.exception("Failed to refresh table: %s", e)
            self._show_status(f"Database error: {e}")

    def _show_status(self, msg: str) -> None:
        """
        Input: msg -- status message to display, empty string to clear
        Output: None
        Details: Updates the bottom status line
        """
        status = self.query_one("#status-msg", Static)
        status.update(msg)


    def _get_selected_slug(self) -> str | None:
        """
        Input: None
        Output: slug of the selected row, or None if nothing is selected
        Details: Reads column 0 of the cursor row. That column is the slug.
        """
        table = self.query_one(DataTable)
        if table.row_count == 0:
            return None
        cursor_row = table.cursor_row
        if cursor_row is None or cursor_row < 0:
            return None
        try:
            # Column 0 is the slug passed to add_row().
            return table.get_row_at(cursor_row)[0]
        except (RowDoesNotExist, IndexError):
            logger.warning("Failed to get slug from cursor_row %s", cursor_row)
            return None

    def action_regenerate(self) -> None:
        """
        Input: None
        Output: None
        Details:
            Confirms with the user, then calls regenerate_access_code().
            A modal shows the new plaintext code. That function returns
            the plaintext code once.
        """
        slug = self._get_selected_slug()
        if not slug:
            self.app.bell()
            self._show_status("No chat selected")
            return

        def on_confirm(yes: bool) -> None:
            """
            Input: yes -- True if user clicked Yes
            Output: None
            Details: Regenerates the code and shows it if confirmed
            """
            if not yes:
                return

            try:
                new_code = regenerate_access_code(self.conn, slug)
                if new_code is None:
                    self._show_status(f"Chat {slug} not found")
                    return

                self._refresh_table()
                self.app.push_screen(CodeDisplayModal(new_code))
            except sqlite3.OperationalError as e:
                logger.exception("Failed to regenerate code for %s: %s", slug, e)
                self._show_status(f"Database error: {e}")

        modal = ConfirmationModal(
            "Regenerate Access Code?",
            f"This will invalidate all existing unlocked sessions for {slug}.",
        )
        self.app.push_screen(modal, on_confirm)

    def action_toggle_revoke(self) -> None:
        """
        Input: None
        Output: None
        Details:
            Toggles the revoked status of the selected chat. No confirm
            dialog, because the change is reversible. Updates the table
            immediately.
        """
        slug = self._get_selected_slug()
        if not slug:
            self.app.bell()
            self._show_status("No chat selected")
            return

        try:
            # Get current state
            chat = next((c for c in list_chats(self.conn) if c.slug == slug), None)
            if not chat:
                self._show_status(f"Chat {slug} not found")
                return

            new_revoked = not chat.revoked
            success = set_revoked(self.conn, slug, new_revoked)
            if success:
                status_str = "revoked" if new_revoked else "active"
                self._refresh_table()
                self._show_status(f"Chat marked {status_str}")
            else:
                self._show_status(f"Failed to update chat {slug}")
        except sqlite3.OperationalError as e:
            logger.exception("Failed to toggle revoke for %s: %s", slug, e)
            self._show_status(f"Database error: {e}")
        except Exception:
            logger.exception("Unexpected error toggling revoke for %s", slug)
            self._show_status("Unexpected error toggling revoke")

    def action_delete_chat(self) -> None:
        """
        Input: None
        Output: None
        Details:
            Confirms with user (warning that deletion is permanent), then calls
            delete_chat() and refreshes the table.
        """
        slug = self._get_selected_slug()
        if not slug:
            self.app.bell()
            self._show_status("No chat selected")
            return

        def on_confirm(yes: bool) -> None:
            """
            Input: yes -- True if user clicked Yes
            Output: None
            Details: Deletes the chat if confirmed
            """
            if not yes:
                return

            try:
                success = delete_chat(self.conn, slug)
                if success:
                    self._refresh_table()
                    self._show_status(f"Chat {slug} deleted permanently")
                else:
                    self._show_status(f"Chat {slug} not found")
            except sqlite3.OperationalError as e:
                logger.exception("Failed to delete chat %s: %s", slug, e)
                self._show_status(f"Database error: {e}")

        modal = ConfirmationModal(
            "Permanently Delete Chat?",
            f"This cannot be undone. All shared links for {slug} will become inaccessible.",
        )
        self.app.push_screen(modal, on_confirm)

    def action_quit(self) -> None:
        """
        Input: None
        Output: None
        Details: Exits the application
        """
        self.app.exit()


class AdminApp(App):
    """
    Main Textual application for CCChatShare admin. Connects to the shared
    database and displays the MainScreen.
    
    Input: None
    Output: None
    Details: Reads CCCHATSHARE_DB_PATH env var (default /data/ccchatshare.db)
    """

    TITLE = "CCChatShare Admin"

    def __init__(self) -> None:
        """
        Input: None
        Output: None
        Details:
            Initializes the app and attempts to open the database connection.
            Stores any connection error for display in on_mount().
        """
        super().__init__()
        self.conn = None
        self.conn_error = None

        db_path = os.environ.get("CCCHATSHARE_DB_PATH", "/data/ccchatshare.db")
        try:
            self.conn = connect(db_path)
            logger.info("Connected to database at %s", db_path)
        except sqlite3.DatabaseError as e:
            logger.exception("Failed to connect to database at %s: %s", db_path, e)
            self.conn_error = str(e)

    def on_mount(self) -> None:
        """
        Input: None
        Output: None
        Details:
            Pushes either MainScreen (if database connection succeeded) or
            an error screen (if connection failed).
        """
        if self.conn_error:
            # Show error screen
            self.push_screen(ErrorScreen(self.conn_error))
        else:
            self.push_screen(MainScreen(self.conn))

    def on_unmount(self) -> None:
        """
        Input: None
        Output: None
        Details: Closes the database connection before exiting
        """
        if self.conn:
            self.conn.close()


class ErrorScreen(Screen):
    """
    Error screen displayed when the database cannot be opened.
    
    Input: error_msg (str)
    Output: None
    Details: Shows the error and allows the user to quit
    """

    DEFAULT_CSS = """
    ErrorScreen #error-body {
        padding: 2 4;
        align: center middle;
    }
    ErrorScreen #error-box {
        width: 70;
        height: auto;
        border: tall $panel;
        padding: 1 2;
    }
    ErrorScreen #error-text {
        margin: 1 0;
        width: 1fr;
    }
    """

    BINDINGS = [
        Binding("q", "quit", "Quit", show=True),
    ]

    def __init__(self, error_msg: str) -> None:
        """
        Input: error_msg -- the database error message
        Output: None
        Details: Stores error message for display in compose()
        """
        super().__init__()
        self.error_msg = error_msg

    def compose(self) -> ComposeResult:
        """Render the error screen."""
        with Vertical(id="error-body"):
            with Vertical(id="error-box"):
                yield Static("Database Connection Failed", classes="heading")
                yield Static(self.error_msg, id="error-text")
                yield Static(
                    "Press 'q' to quit.",
                    id="error-help",
                )

    def action_quit(self) -> None:
        """
        Input: None
        Output: None
        Details: Exits the application
        """
        self.app.exit()


if __name__ == "__main__":
    AdminApp().run()
