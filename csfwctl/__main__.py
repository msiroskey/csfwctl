"""Entry point so `python -m csfwctl` invokes the CLI."""

from csfwctl.cli import app


def main() -> None:
    """Invoke the Typer app."""
    app()


if __name__ == "__main__":
    main()
