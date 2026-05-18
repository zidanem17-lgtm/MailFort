import unittest
from unittest.mock import Mock, patch

import click

from mailfort.cli import _build_connector, _message_iterator
from mailfort.constants import MODE_MAILFORT, MODE_PHISHFINDER, PROVIDER_GMAIL, PROVIDER_IMAP


class BuildConnectorTests(unittest.TestCase):
    @patch("mailfort.connectors.gmail.GmailConnector")
    @patch("mailfort.auth.get_gmail_credentials")
    def test_build_gmail_connector_readonly_modes(self, mock_get_creds, mock_gmail_connector):
        mock_creds = object()
        mock_get_creds.return_value = mock_creds
        mock_connector_instance = Mock()
        mock_gmail_connector.return_value = mock_connector_instance

        test_cases = [
            (MODE_PHISHFINDER, False, True),
            (MODE_MAILFORT, True, True),
            (MODE_MAILFORT, False, False),
        ]

        for mode, dry_run, expected_readonly in test_cases:
            with self.subTest(mode=mode, dry_run=dry_run):
                connector = _build_connector(
                    provider=PROVIDER_GMAIL,
                    credentials="/tmp/credentials.json",
                    token=None,
                    imap_host=None,
                    imap_port=993,
                    username=None,
                    password=None,
                    mailbox="INBOX",
                    mode=mode,
                    dry_run=dry_run,
                )

                self.assertIs(connector, mock_connector_instance)
                mock_get_creds.assert_called_with(
                    credentials_path="/tmp/credentials.json",
                    token_path="/tmp/.mailfort_tokens.json",
                    readonly=expected_readonly,
                )

    def test_build_imap_connector_requires_host(self):
        with self.assertRaises(click.UsageError):
            _build_connector(
                provider=PROVIDER_IMAP,
                credentials="credentials.json",
                token=None,
                imap_host=None,
                imap_port=993,
                username="user@example.com",
                password="secret",
                mailbox="INBOX",
                mode=MODE_PHISHFINDER,
                dry_run=True,
            )

    def test_build_imap_connector_requires_username(self):
        with self.assertRaises(click.UsageError):
            _build_connector(
                provider=PROVIDER_IMAP,
                credentials="credentials.json",
                token=None,
                imap_host="mail.example.com",
                imap_port=993,
                username=None,
                password="secret",
                mailbox="INBOX",
                mode=MODE_PHISHFINDER,
                dry_run=True,
            )

    @patch("mailfort.connectors.imap.ImapConnector")
    @patch("click.prompt")
    def test_build_imap_connector_prompts_for_password(self, mock_prompt, mock_imap_connector):
        mock_prompt.return_value = "prompted-password"
        instance = Mock()
        mock_imap_connector.return_value = instance

        connector = _build_connector(
            provider=PROVIDER_IMAP,
            credentials="credentials.json",
            token=None,
            imap_host="mail.example.com",
            imap_port=993,
            username="user@example.com",
            password=None,
            mailbox="INBOX",
            mode=MODE_PHISHFINDER,
            dry_run=True,
        )

        self.assertIs(connector, instance)
        mock_prompt.assert_called_once()
        mock_imap_connector.assert_called_once_with(
            host="mail.example.com",
            port=993,
            username="user@example.com",
            password="prompted-password",
            use_ssl=True,
            mailbox="INBOX",
        )
        instance.connect.assert_called_once_with()


class MessageIteratorTests(unittest.TestCase):
    @patch("mailfort.connectors.message_normalizer.normalize_gmail_message")
    def test_message_iterator_gmail(self, mock_normalize_gmail):
        normalized_message = Mock()
        mock_normalize_gmail.return_value = normalized_message

        connector = Mock()
        connector.list_messages_all.return_value = [{"id": "msg-1"}]
        connector.get_message.return_value = {"id": "msg-1", "payload": {}}

        results = list(
            _message_iterator(
                provider=PROVIDER_GMAIL,
                connector=connector,
                label_ids=["INBOX"],
                query="from:test@example.com",
                max_messages=10,
            )
        )

        self.assertEqual(results, [normalized_message])
        connector.list_messages_all.assert_called_once_with(
            label_ids=["INBOX"],
            query="from:test@example.com",
            max_messages=10,
        )
        mock_normalize_gmail.assert_called_once_with(
            connector.get_message.return_value,
            attachment_fetcher=connector.fetch_attachment_bytes,
        )

    @patch("mailfort.connectors.message_normalizer.normalize_imap_message")
    def test_message_iterator_imap(self, mock_normalize_imap):
        normalized_message = Mock()
        mock_normalize_imap.return_value = normalized_message

        connector = Mock()
        connector.list_messages.return_value = [{"uid": "42"}, {"uid": "43"}]
        connector.fetch_message.side_effect = [Mock(), None]

        results = list(
            _message_iterator(
                provider=PROVIDER_IMAP,
                connector=connector,
                label_ids=None,
                query=None,
                max_messages=25,
            )
        )

        self.assertEqual(results, [normalized_message])
        connector.list_messages.assert_called_once_with(
            search_criteria="ALL",
            max_messages=25,
        )
        mock_normalize_imap.assert_called_once()


if __name__ == "__main__":
    unittest.main()
