import argparse
import time
from pathlib import Path

from aiosmtpd.controller import Controller

from storage import init_db, purge_expired, get_mailbox_by_address, save_message


class TempInboxHandler:
    def __init__(self, db_path: Path, domain: str):
        self.db_path = db_path
        self.domain = domain.lower()

    async def handle_RCPT(self, server, session, envelope, address, rcpt_options):
        purge_expired(self.db_path)
        address = address.strip().lower()
        if not address.endswith(f"@{self.domain}"):
            return "550 5.1.1 No such user"
        mailbox = get_mailbox_by_address(self.db_path, address)
        if not mailbox:
            return "550 5.1.1 No such user"
        envelope.rcpt_tos.append(address)
        return "250 OK"

    async def handle_DATA(self, server, session, envelope):
        peer_ip = ""
        if session and session.peer:
            peer_ip = session.peer[0]
        helo = getattr(session, "host_name", "") or getattr(session, "helo", "") or ""
        raw_bytes = getattr(envelope, "original_content", None) or envelope.content or b""
        if isinstance(raw_bytes, str):
            raw_bytes = raw_bytes.encode("utf-8", errors="replace")
        for rcpt in envelope.rcpt_tos:
            mailbox = get_mailbox_by_address(self.db_path, rcpt)
            if mailbox:
                save_message(
                    self.db_path,
                    mailbox["id"],
                    raw_bytes,
                    peer_ip,
                    helo,
                    envelope.mail_from or "",
                )
        return "250 Message accepted for delivery"


def main() -> None:
    parser = argparse.ArgumentParser(description="SMTP receiver for temporary inboxes.")
    parser.add_argument("--host", default="0.0.0.0", help="Bind host (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=25, help="Bind port (default: 25)")
    parser.add_argument(
        "--domain",
        required=True,
        help="Accepted domain for temporary inboxes (e.g. scheck.ml-analytic.online)",
    )
    parser.add_argument(
        "--db-path",
        default="data/spamcheck.db",
        help="Path to sqlite database (default: data/spamcheck.db)",
    )
    args = parser.parse_args()

    db_path = Path(args.db_path)
    init_db(db_path)
    handler = TempInboxHandler(db_path, args.domain)
    controller = Controller(handler, hostname=args.host, port=args.port)
    controller.start()
    print(f"SMTP receiver listening on {args.host}:{args.port} for {args.domain}")
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        controller.stop()


if __name__ == "__main__":
    main()
