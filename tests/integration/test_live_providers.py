import os
import unittest

from mailfort.auth import get_gmail_credentials
from mailfort.connectors.gmail import GmailConnector
from mailfort.connectors.imap import ImapConnector


class LiveProviderIntegrationTests(unittest.TestCase):
    @unittest.skipUnless(
        os.getenv("MAILFORT_LIVE_GMAIL") == "1",
        "Set MAILFORT_LIVE_GMAIL=1 with valid Gmail OAuth files to run.",
    )
    def test_gmail_readonly_auth_and_list(self):
        credentials_path = os.getenv("MAILFORT_GMAIL_CREDENTIALS_PATH", "credentials.json")
        token_path = os.getenv("MAILFORT_GMAIL_TOKEN_PATH", os.path.join(os.getcwd(), ".mailfort_live_tokens.json"))

        creds = get_gmail_credentials(
            credentials_path=credentials_path,
            token_path=token_path,
            readonly=True,
        )
        connector = GmailConnector(creds)
        page = connector.list_messages_page(max_results=1)
        self.assertIsInstance(page, dict)

    @unittest.skipUnless(
        os.getenv("MAILFORT_LIVE_IMAP") == "1",
        "Set MAILFORT_LIVE_IMAP=1 with valid IMAP env vars to run.",
    )
    def test_imap_auth_and_list(self):
        host = os.environ["MAILFORT_IMAP_HOST"]
        username = os.environ["MAILFORT_IMAP_USERNAME"]
        password = os.environ["MAILFORT_IMAP_PASSWORD"]
        port = int(os.getenv("MAILFORT_IMAP_PORT", "993"))
        mailbox = os.getenv("MAILFORT_IMAP_MAILBOX", "INBOX")

        connector = ImapConnector(
            host=host,
            port=port,
            username=username,
            password=password,
            mailbox=mailbox,
            use_ssl=True,
        )

        try:
            connector.connect()
            stubs = list(connector.list_messages(max_messages=1))
            self.assertIsInstance(stubs, list)
        finally:
            connector.disconnect()


if __name__ == "__main__":
    unittest.main()
