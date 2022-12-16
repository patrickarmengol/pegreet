from pathlib import Path

import typer
from rich import print

import pegreet.fetch
import pegreet.inout

app = typer.Typer()


# TODO: figure out how to do `pegreet FILEPATH [command] [command-options]`

@app.command()
def info(
    filepath: Path = typer.Argument(..., help='path to PE file to analyze'),
) -> None:
    """
    print useful info
    """
    pe = pegreet.inout.load(filepath)
    data = pegreet.fetch.info(pe)
    # print(data)
    print(pegreet.inout.pretty_info(data))


@app.command()
def strings(
    filepath: Path = typer.Argument(..., help='path to PE file to analyze'),
    show_uncategorized: bool = typer.Option(False, help='also show uncategorized strings'),
) -> None:
    """
    print strings
    """
    pe = pegreet.inout.load(filepath)
    sdata = pegreet.fetch.find_strings(pe)
    print(pegreet.inout.pretty_strings(sdata, show_uncategorized=show_uncategorized))


@app.command()
def disassemble(
    filepath: Path = typer.Argument(..., help='path to PE file to analyze'),
    num_instructions: int = typer.Argument(40, help='number of instructions from entry point to disassemble')
) -> None:
    """
    disassemble a specified number instructions from entry point
    """
    pass
